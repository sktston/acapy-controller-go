/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Ethan Sung (baegjae@gmail.com)       *
 * since July 28, 2020                            *
 **************************************************/

package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sktston/acapy-controller-go/util"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	client                          = resty.New()
	agentApiUrl, jwtToken, walletId string

	version = strconv.Itoa(util.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(util.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(util.GetRandomInt(1, 99))
	walletName = "alice." + version
	imageUrl   = "https://identicon-api.herokuapp.com/" + walletName + "/300?format=png"

	pollingCyclePeriod = time.Second
	pollingRetryMax = 100

	//go:embed alice-config.yaml
	config []byte
)

func main() {
	// Initialization
	initialization()

	// (multitenancy) Create wallet
	if viper.GetBool("use-multitenancy") == true {
		if err := provisionController(); err != nil {
			log.Fatal().Err(err).Caller().Msgf("")
		}
	}

	// Establish Connection
	log.Info().Msgf("Receive invitation to establish connection")
	connectionId, err := receiveInvitation()
	if err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	log.Info().Msgf("connection id: " + connectionId)
	if err = waitUntilConnectionActive(connectionId); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	log.Info().Msgf("connection established")

	// Receive Credential
	log.Info().Msgf("Send credential proposal to receive credential offer")
	if err = sendCredentialProposal(connectionId); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	credExId, err := waitUntilCredentialExchangeOfferReceived(connectionId)
	log.Info().Msgf("credential exchange id: " + credExId)

	log.Info().Msgf("Send credential request to receive credential")
	if err = sendCredentialRequest(credExId); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	if err = waitUntilCredentialExchangeAcked(credExId); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	log.Info().Msgf("credential received")

	// Send presentation
	log.Info().Msgf("Send presentation proposal to receive presentation request")
	if err = sendPresentationProposal(connectionId); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	presExId, err := waitUntilPresentationExchangeRequestReceived(connectionId)
	log.Info().Msgf("presentation exchange id: " + credExId)

	log.Info().Msgf("Send presentation")
	if err = sendPresentation(presExId); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	if err = waitUntilPresentationExchangeAcked(presExId); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	log.Info().Msgf("presentation acked")

	// (multitenancy) Delete wallet
	if viper.GetBool("use-multitenancy") == true {
		if err = deleteWallet(); err != nil {
			log.Fatal().Err(err).Caller().Msgf("")
		}
	}
}

func initialization() {
	// Setting logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Read config file
	if err := util.LoadConfig(config); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	agentApiUrl = viper.GetString("agent-api-url")

	// Set log level for zerolog and gin
	switch strings.ToUpper(viper.GetString("log-level")) {
	case "DEBUG" :
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		gin.SetMode(gin.DebugMode)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		gin.SetMode(gin.ReleaseMode)
	}

	// Set client configuration
	client.SetTimeout(30 * time.Minute)
	client.SetHeader("Content-Type", "application/json")
}

func provisionController() error {
	log.Info().Msgf("Create wallet")
	if err := createWallet(); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
		return err
	}

	log.Info().Msgf("Configuration of alice:")
	log.Info().Msgf("- wallet name: " + walletName)
	log.Info().Msgf("- wallet ID: " + walletId)
	log.Info().Msgf("- wallet type: " + viper.GetString("wallet-type"))
	log.Info().Msgf("- jwt token: " + jwtToken)

	return nil
}

func handleEvent(c *gin.Context) {
	topic := c.Param("topic")

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		log.Error().Err(err).Caller().Msgf("invalid JSON")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: "+ err.Error()})
		return
	}

	var state string
	if val, ok := body["state"]; ok {
		state = val.(string)
	}

	bodyAsBytes, _ := json.Marshal(body)
	log.Info().Msgf("handleEvent >>> topic:" + topic + ", state:" + state + ", body:" + string(bodyAsBytes))

	switch topic {
	case "connections":
		if state == "active" {
			log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> sendCredentialProposal()")

			if err := sendCredentialProposal(body["connection_id"].(string)); err != nil {
				log.Error().Err(err).Caller().Msgf("")
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}

	case "issue_credential":
		// When credential offer is received, send credential request
		if state == "offer_received" {
			log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> sendCredentialRequest()")

			if err := sendCredentialRequest(body["credential_exchange_id"].(string)); err != nil {
				log.Error().Err(err).Caller().Msgf("")
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		} else if state == "credential_acked" {
			log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> sendPresentationProposal()")

			if err := sendPresentationProposal(body["connection_id"].(string)); err != nil {
				log.Error().Err(err).Caller().Msgf("")
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}

	case "present_proof":
		// When proof request is received, send proof(presentation)
		if state == "request_received" {
			log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> sendPresentation()")

		} else if state == "presentation_acked" {
			if viper.GetBool("use-multitenancy") == true {
				log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> deleteWallet() & Exit")

				if err := deleteWallet(); err != nil {
					log.Error().Err(err).Caller().Msgf("")
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
			} else {
				log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> Exit")
			}

			// Send exit signal
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		}

	case "basicmessages":
	case "revocation_registry":
	case "problem_report":
	case "issuer_cred_rev":

	default:
		log.Warn().Msgf("- Warning Unexpected topic:" + topic)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid topic:"+ topic})
		return
	}
	c.Status(http.StatusOK)
}

func createWallet() error {
	body := `{
		"wallet_name": "` + walletName + `",
		"wallet_key": "` + walletName + ".key" + `",
		"wallet_type": "` + viper.GetString("wallet-type") + `",
		"label": "` + walletName + ".label" + `",
		"image_url": "` + imageUrl + `"
	}`
	log.Info().Msgf("Create a new wallet: " + util.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		Post(agentApiUrl + "/multitenancy/wallet")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Debug().Msgf("response: " + resp.String())
	walletId = gjson.Get(resp.String(), `settings.wallet\.id`).String()
	jwtToken = gjson.Get(resp.String(), "token").String()

	return nil
}

func receiveInvitation() (string, error) {
	resp, err := client.R().
		Get(viper.GetString("issuer-invitation-url"))
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return "", err
	}
	log.Debug().Msgf("response: " + resp.String())

	invitation, err := util.ParseInvitationUrl(resp.String())
	log.Info().Msgf("invitation: " + string(invitation))

	body := string(invitation)
	resp, err = client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/out-of-band/receive-invitation")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return "", err
	}
	log.Debug().Msgf("response: " + resp.String())
	connectionId := gjson.Get(resp.String(), `connection_id`).String()

	return connectionId, nil
}

func waitUntilConnectionActive(connectionId string) error {
	log.Info().Msgf("Wait until connection (state: active)")
	for retry := 0; retry < pollingRetryMax; retry++ {
		time.Sleep(pollingCyclePeriod)
		resp, err := client.R().
			SetAuthToken(jwtToken).
			Get(agentApiUrl + "/connections/" + connectionId)
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
		log.Debug().Msgf("response: " + resp.String())
		state := gjson.Get(resp.String(), `state`).String()
		log.Info().Msgf("connection state: " + state)
		if state == "active" {
			return nil
		}
	}
	err := errors.New("timeout - connection is not (state: active)")
	log.Error().Err(err).Caller().Msgf("")
	return err
}

func sendCredentialProposal(connectionId string) error {
	body := `{
		"connection_id": "` + connectionId + `"
	}`
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/issue-credential/send-proposal")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Debug().Msgf("response: " + resp.String())

	return nil
}

func waitUntilCredentialExchangeOfferReceived(connectionId string) (string, error) {
	log.Info().Msgf("Wait until credential exchange (state: offer_received)")
	for retry := 0; retry < pollingRetryMax; retry++ {
		time.Sleep(pollingCyclePeriod)
		params := "?state=offer_received&connection_id=" + connectionId
		resp, err := client.R().
			SetAuthToken(jwtToken).
			Get(agentApiUrl + "/issue-credential/records" + params)
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return "", err
		}
		log.Debug().Msgf("response: " + resp.String())

		credExes := gjson.Get(resp.String(), "results").Array()
		log.Info().Msgf("the number of credential exchange (state: offer_received): " + strconv.Itoa(len(credExes)) )
		if len(credExes) > 0 {
			return gjson.Get(credExes[0].String(), "credential_exchange_id").String(), nil
		}
	}
	err := errors.New("timeout - credential exchange is not (state: offer_received)")
	log.Error().Err(err).Caller().Msgf("")
	return "", err
}

func sendCredentialRequest(credExId string) error {
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/issue-credential/records/" + credExId + "/send-request")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Debug().Msgf("response: " + resp.String())

	return nil
}

func waitUntilCredentialExchangeAcked(credExId string) error {
	log.Info().Msgf("Wait until credential exchange (state: credential_acked)")
	for retry := 0; retry < pollingRetryMax; retry++ {
		time.Sleep(pollingCyclePeriod)
		resp, err := client.R().
			SetAuthToken(jwtToken).
			Get(agentApiUrl + "/issue-credential/records/" + credExId)
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
		log.Debug().Msgf("response: " + resp.String())
		state := gjson.Get(resp.String(), `state`).String()
		log.Info().Msgf("ccredential exchange state: " + state)
		if state == "credential_acked" {
			return nil
		}
	}
	err := errors.New("timeout - credential exchange is not (state: credential_acked)")
	log.Error().Err(err).Caller().Msgf("")
	return err
}

func sendPresentationProposal(connectionId string) error {
	body := `{
		"connection_id": "` + connectionId + `",
		"presentation_proposal": {
			"attributes": [],
			"predicates": []
		}
	}`
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/present-proof/send-proposal")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Debug().Msgf("response: " + resp.String())

	return nil
}

func waitUntilPresentationExchangeRequestReceived(connectionId string) (string, error) {
	log.Info().Msgf("Wait until presentation exchange (state: request_received)")
	for retry := 0; retry < pollingRetryMax; retry++ {
		time.Sleep(pollingCyclePeriod)
		params := "?state=request_received&connection_id=" + connectionId
		resp, err := client.R().
			SetAuthToken(jwtToken).
			Get(agentApiUrl + "/present-proof/records" + params)
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return "", err
		}
		log.Debug().Msgf("response: " + resp.String())

		presExes := gjson.Get(resp.String(), "results").Array()
		log.Info().Msgf("the number of presentation exchange (state: request_received): " + strconv.Itoa(len(presExes)) )
		if len(presExes) > 0 {
			return gjson.Get(presExes[0].String(), "presentation_exchange_id").String(), nil
		}
	}
	err := errors.New("timeout - presentation exchange is not (state: request_received)")
	log.Error().Err(err).Caller().Msgf("")
	return "", err
}

func sendPresentation(presExId string) error {
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Get(agentApiUrl + "/present-proof/records/" + presExId)
	log.Debug().Msgf("response: " + resp.String())
	presReq := gjson.Get(resp.String(), "presentation_request").String()

	resp, err = client.R().
		SetAuthToken(jwtToken).
		Get(agentApiUrl + "/present-proof/records/" + presExId + "/credentials")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Debug().Msgf("response: " + resp.String())

	credentials := resp.String()
	credRevIDs := gjson.Get(credentials, "#.cred_info.cred_rev_id").Array()
	credIDs := gjson.Get(credentials, "#.cred_info.referent").Array()

	var maxRevId uint64 = 0
	var credId string
	for idx, credRevID := range credRevIDs {
		if credRevID.Uint() >= maxRevId {
			maxRevId = credRevID.Uint()
			credId = credIDs[idx].String()
		}
	}
	log.Info().Msgf("Use latest credential in demo - credential id: " + credId)

	newReqAttrs := "{}"
	reqAttrs := gjson.Get(presReq, "requested_attributes").Map()
	for key := range reqAttrs {
		newReqAttrs, _ = sjson.Set(newReqAttrs, key+".cred_id", credId)
		newReqAttrs, _ = sjson.Set(newReqAttrs, key+".revealed", true)
	}

	newReqPreds := "{}"
	reqPreds := gjson.Get(presReq, "requested_predicates").Map()
	for key := range reqPreds {
		newReqPreds, _ = sjson.Set(newReqPreds, key+".cred_id", credId)
	}

	body := `{
		"requested_attributes": ` + newReqAttrs + `,
		"requested_predicates": ` + newReqPreds + `,
		"self_attested_attributes": {}
	}`
	resp, err = client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/present-proof/records/" + presExId + "/send-presentation")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Debug().Msgf("response: " + resp.String())

	return nil
}

func waitUntilPresentationExchangeAcked(presExId string) error {
	log.Info().Msgf("Wait until presentation exchange (state: presentation_acked)")
	for retry := 0; retry < pollingRetryMax; retry++ {
		time.Sleep(pollingCyclePeriod)
		resp, err := client.R().
			SetAuthToken(jwtToken).
			Get(agentApiUrl + "/present-proof/records/" + presExId)
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
		log.Debug().Msgf("response: " + resp.String())
		state := gjson.Get(resp.String(), `state`).String()
		log.Info().Msgf("presentation exchange state: " + state)
		if state == "presentation_acked" {
			return nil
		}
	}
	err := errors.New("timeout - presentation exchange is not (state: presentation_acked)")
	log.Error().Err(err).Caller().Msgf("")
	return err
}

func deleteWallet() error {
	// Delete wallet
	resp, err := client.R().
		Post(agentApiUrl + "/multitenancy/wallet/" + walletId + "/remove")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Debug().Msgf("response: " + resp.String())

	return nil
}
