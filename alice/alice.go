/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Ethan Sung (baegjae@gmail.com)       *
 * since July 28, 2020                            *
 **************************************************/

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/r3labs/sse/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sktston/acapy-controller-go/util"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	httpClientTimeout = 30 * time.Second
	configFileName    = "alice-config.yml"
)

var (
	httpClient                                  = resty.New()
	sseClient                                   *sse.Client
	agentApiUrl, jwtToken, walletId, webhookUrl string

	sseCtx    context.Context
	sseCancel context.CancelFunc

	version = strconv.Itoa(util.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(util.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(util.GetRandomInt(1, 99))
	walletName = "alice." + version
	imageUrl   = "https://identicon-api.herokuapp.com/" + walletName + "/300?format=png"
)

func main() {
	// Initialization
	if err := initialization(); err != nil {
		log.Fatal().Err(err).Caller().Msg("")
	}

	// (multitenancy) Create wallet
	if viper.GetBool("use-multitenancy") == true {
		if err := provisionController(); err != nil {
			log.Fatal().Err(err).Caller().Msg("")
		}
	}

	// Establish Connection
	log.Info().Msg("Receive invitation to establish connection")
	if err := receiveInvitation(); err != nil {
		log.Fatal().Err(err).Caller().Msg("")
	}

	// Exit by pressing Ctrl-C or 'kill pid' in the shell
	ctrlC := make(chan os.Signal, 1)
	defer close(ctrlC)
	signal.Notify(ctrlC, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)

	<-ctrlC
	log.Info().Msg("Ctrl-C detected, it may take a couple of seconds to clean up...")

	// Delete acapy agent data
	if viper.GetBool("delete-data-at-exit") == true {
		err := util.DeleteAgentData(agentApiUrl, jwtToken, walletId,
			"connection", "credential", "credential_exchange", "presentation_exchange", "wallet")
		if err != nil {
			log.Fatal().Err(err).Caller().Msg("")
		}
	}

	// Shut down sse client
	if err := shutdownSseClient(); err != nil {
		log.Fatal().Err(err).Caller().Msg("")
	}

	log.Info().Msgf("Alice exiting")
}

func initialization() error {
	// Setting logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Read config file
	if err := util.LoadConfig(configFileName); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	agentApiUrl = viper.GetString("agent-api-url")

	// Set log level for zerolog and gin
	switch strings.ToUpper(viper.GetString("log-level")) {
	case "DEBUG":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		gin.SetMode(gin.DebugMode)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		gin.SetMode(gin.ReleaseMode)
	}

	// Set httpClient configuration
	httpClient.SetTimeout(httpClientTimeout)
	httpClient.SetHeader("Content-Type", "application/json")

	return nil
}

func provisionController() error {
	log.Info().Msgf("Create wallet")
	if err := createWallet(); err != nil {
		log.Fatal().Err(err).Caller().Msg("")
		return err
	}

	// SSE client starts using wallet ID
	if err := startSseClient(); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}

	log.Info().Msgf("Configuration of alice:")
	log.Info().Msgf("- wallet name: %s", walletName)
	log.Info().Msgf("- wallet ID: %s", walletId)
	log.Info().Msgf("- wallet type: %s", viper.GetString("wallet-type"))
	log.Info().Msgf("- jwt token: %s", jwtToken)
	log.Info().Msgf("- webhook url: %s", webhookUrl)

	return nil
}

func startSseClient() error {
	sseServerUrl := util.JoinURL(viper.GetString("sse-server-url"), "/server-sent-event")
	sseServerUrl += "?client_ip=" + util.GetOutboundIP().String()
	sseServerUrl += "&client_id=alice"

	// Set sse client configurations
	sseClient = sse.NewClient(sseServerUrl)
	sseClient.Headers = map[string]string{
		"Authorization": "Bearer " + jwtToken,
	}
	sseClient.OnConnect(func(c *sse.Client) {
		log.Info().Msgf("SSE client connected: '%s'", c.URL)
	})
	sseClient.OnDisconnect(func(c *sse.Client) {
		// SseServer.Close() 없이 webserver 강제로 shutdown하는 경우 발생
		log.Error().Msgf("SSE client disconnected abnormally: '%s'", c.URL)
	})

	subscribeDone := make(chan struct{})
	go func() {
		sseCtx, sseCancel = context.WithCancel(context.Background())
		log.Info().Msgf("Start SSE client and wait for connection to complete: %s", sseServerUrl)

		// Start sse client and connect to walletId stream
		// walletId로 지정된 stream으로 subscribe하면 서버 측에 해당 stream 생성
		// 주의: http 핸들러와는 달리 handleSseEvent()는 병렬 수행되지 않음. 한 event에 대해 모두 수행 후 다음 event에 대해 수행
		events := make(chan *sse.Event)
		if err := sseClient.SubscribeChanWithContext(sseCtx, walletId, events); err != nil {
			log.Fatal().Err(err).Caller().Msg("")
		}
		subscribeDone <- struct{}{}

		for event := range events {
			handleSseEvent(event)
		}
	}()

	// subscribe 완료 기다리지 않으면 server에 sse stream 생성되기 전 서버가 event publish하여 메시지 손실 발생
	<-subscribeDone
	return nil
}

func shutdownSseClient() error {
	var err error

	// Cancel sse context
	sseCancel()

	select {
	case <-sseCtx.Done(): // SSE context cancel success
		err = nil
		log.Info().Msgf("SSE client shutdown successfully")

	case <-time.After(1 * time.Second): // Timeout
		err = errors.New("sse context cancel timeout")
		log.Error().Err(err).Caller().Msg("")
	}

	return err
}

func createWallet() error {
	body := `{
		"wallet_name": "` + walletName + `",
		"wallet_key": "` + walletName + ".key" + `",
		"wallet_type": "` + viper.GetString("wallet-type") + `",
		"label": "` + walletName + ".label" + `",
		"image_url": "` + imageUrl + `"
	}`
	log.Info().Msgf("Create a new wallet: %s", util.PrettyJson(body))
	resp, err := httpClient.R().
		SetBody(body).
		Post(agentApiUrl + "/multitenancy/wallet")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
	walletId = gjson.Get(resp.String(), `settings.wallet\.id`).String()
	jwtToken = gjson.Get(resp.String(), "token").String()
	webhookUrl = util.JoinURL(viper.GetString("sse-server-url"), "/webhooks", walletId)

	body = `{
			"wallet_webhook_urls": ["` + webhookUrl + `"]
		}`
	log.Info().Msgf("Update the wallet: %s", util.PrettyJson(body))
	resp, err = httpClient.R().
		SetBody(body).
		Put(agentApiUrl + "/multitenancy/wallet/" + walletId)
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
	return nil
}

func receiveInvitation() error {
	resp, err := httpClient.R().
		Get(viper.GetString("issuer-invitation-url"))
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	invitation, err := util.ParseInvitationUrl(resp.String())
	if err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Info().Msgf("invitation: %s", invitation)

	invitationType := gjson.Get(invitation, `@type`).String()
	switch invitationType {
	case "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.0/invitation":
		resp, err = httpClient.R().
			SetBody(invitation).
			SetAuthToken(jwtToken).
			Post(agentApiUrl + "/out-of-band/receive-invitation")
	case "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation":
		resp, err = httpClient.R().
			SetBody(invitation).
			SetAuthToken(jwtToken).
			Post(agentApiUrl + "/connections/receive-invitation")
	default:
		err = errors.New("unexpected invitation type" + invitationType)
		return err
	}
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	return nil
}

func receiveInvitationWithProof() error {
	resp, err := httpClient.R().
		Get(viper.GetString("issuer-invitation-url-with-proof"))
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	invitation, err := util.ParseInvitationUrl(resp.String())
	if err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Info().Msgf("invitation: %s", invitation)

	invitationType := gjson.Get(invitation, `@type`).String()
	switch invitationType {
	case "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.0/invitation":
		resp, err = httpClient.R().
			SetBody(invitation).
			SetAuthToken(jwtToken).
			Post(agentApiUrl + "/out-of-band/receive-invitation")
	default:
		err = errors.New("unexpected invitation type" + invitationType)
		return err
	}

	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	return nil
}

func sendCredentialProposal(connectionId string) error {
	body := `{
		"connection_id": "` + connectionId + `"
	}`
	resp, err := httpClient.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/issue-credential/send-proposal")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	return nil
}

func sendCredentialRequest(credExId string) error {
	resp, err := httpClient.R().
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/issue-credential/records/" + credExId + "/send-request")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	return nil
}

func sendPresentationProposal(connectionId string) error {
	body := `{
		"connection_id": "` + connectionId + `",
		"presentation_proposal": {
			"attributes": [],
			"predicates": []
		}
	}`
	resp, err := httpClient.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/present-proof/send-proposal")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	return nil
}

func getMatchingCredentialId(credentials string, mAttr string) (string, error) {
	credIDList := gjson.Get(credentials, "#.cred_info.referent").Array()
	credRevIdList := gjson.Get(credentials, "#.cred_info.cred_rev_id").Array()
	presAttrsList := gjson.Get(credentials, "#.presentation_referents").Array()

	credId := ""
	maxCredRevId := 0
	for idx, presAttrs := range presAttrsList { // 각 credential에 대해서 loop
		for _, presAttr := range presAttrs.Array() { // credential의 각 attribute에 대해서 loop
			if presAttr.String() == mAttr { // 찾고자 하는 attribute라면
				if credRevIdList[idx].String() == "" { // case of not support revocation
					credId = credIDList[idx].String()
				} else { // case of support revocation
					curRevId, _ := strconv.Atoi(credRevIdList[idx].String()) // idx = credential index
					if curRevId > maxCredRevId {                             // cred_rev_id가 가장 큰 credential 선택
						maxCredRevId = curRevId
						credId = credIDList[idx].String()
					}
				}
			}
		}
	}
	if credId == "" {
		return "", errors.New("not found matching credential - matching attr:" + mAttr)
	}
	return credId, nil
}

func sendPresentation(presExId string) error {
	resp, err := httpClient.R().
		SetAuthToken(jwtToken).
		Get(agentApiUrl + "/present-proof/records/" + presExId)
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
	presReq := gjson.Get(resp.String(), "presentation_request").String()

	resp, err = httpClient.R().
		SetAuthToken(jwtToken).
		Get(agentApiUrl + "/present-proof/records/" + presExId + "/credentials")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
	credentials := resp.String()

	// sjon package: the dot and colon characters can be escaped with \
	replacer := strings.NewReplacer(`.`, `\.`, `:`, `\:`)

	newReqAttrs := "{}"
	newSelfAttrs := "{}"
	reqAttrs := gjson.Get(presReq, "requested_attributes").Map()
	for key := range reqAttrs {
		credId, err := getMatchingCredentialId(credentials, key)
		key = replacer.Replace(key)
		if err != nil {
			if key == "attr_address" {
				newSelfAttrs, _ = sjson.Set(newSelfAttrs, key, "self attested address value")
				continue
			}
			log.Error().Err(err).Caller().Msg("")
			return err
		}
		newReqAttrs, _ = sjson.Set(newReqAttrs, key+".cred_id", credId)
		newReqAttrs, _ = sjson.Set(newReqAttrs, key+".revealed", true)
	}

	newReqPreds := "{}"
	reqPreds := gjson.Get(presReq, "requested_predicates").Map()
	for key := range reqPreds {
		credId, err := getMatchingCredentialId(credentials, key)
		if err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}
		newReqPreds, _ = sjson.Set(newReqPreds, key+".cred_id", credId)
	}

	body := `{
		"requested_attributes": ` + newReqAttrs + `,
		"requested_predicates": ` + newReqPreds + `,
		"self_attested_attributes": ` + newSelfAttrs + `
	}`
	log.Debug().Msgf("send presentation body: %s", body)
	resp, err = httpClient.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/present-proof/records/" + presExId + "/send-presentation")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	return nil
}

func handleSseEvent(event *sse.Event) {
	var sseData map[string]interface{}
	_ = json.Unmarshal(event.Data, &sseData)

	topic := sseData["topic"].(string)
	state := sseData["state"].(string)

	log.Info().Msgf("handleSseEvent >>> topic:%s, state:%s", topic, state)
	log.Debug().Msgf("server-sent-event data: %s", util.PrettyJson(&sseData))

	switch topic {
	case "connections":
		if state == "active" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> sendCredentialProposal()", topic, state)

			if err := sendCredentialProposal(sseData["connection_id"].(string)); err != nil {
				log.Error().Err(err).Caller().Msg("")
				return
			}
		}

	case "issue_credential":
		// When credential offer is received, send credential request
		if state == "offer_received" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> sendCredentialRequest()", topic, state)

			if err := sendCredentialRequest(sseData["credential_exchange_id"].(string)); err != nil {
				log.Error().Err(err).Caller().Msg("")
				return
			}
		} else if state == "credential_acked" {
			if viper.GetBool("enable-invitation-with-proof") {
				// Send presentation via invitation
				// TODO: aca-py must booted with --auto-respond-presentation-request
				// Note: invitation's requests~attach.data.json.@id = pres_ex_record's thread_id
				if err := receiveInvitationWithProof(); err != nil {
					log.Error().Err(err).Caller().Msg("")
					return
				}
				log.Info().Msg("presentation sent")
			} else {
				log.Info().Msgf("- Case (topic:%s, state:%s) -> sendPresentationProposal()", topic, state)
				if err := sendPresentationProposal(sseData["connection_id"].(string)); err != nil {
					log.Error().Err(err).Caller().Msg("")
					return
				}
			}
		}

	case "present_proof":
		// When proof request is received, send presentation
		if state == "request_received" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> sendPresentation()", topic, state)

			if err := sendPresentation(sseData["presentation_exchange_id"].(string)); err != nil {
				log.Error().Err(err).Caller().Msgf("")
				return
			}
		} else if state == "presentation_acked" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> Exit", topic, state)

			// Send exit signal
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		}

	case "basicmessages":
	case "revocation_registry":
	case "problem_report":
	case "issuer_cred_rev":

	default:
		log.Warn().Msgf("- Warning Unexpected topic:" + topic)
		return
	}
}
