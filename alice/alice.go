/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Ethan Sung (baegjae@gmail.com)       *
 * since July 28, 2020                            *
 **************************************************/

package main

import (
	_ "embed"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sktston/acapy-controller-go/util"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"os"
	"strconv"
	"strings"
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
	pollingRetryMax    = 100

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
	if err = waitUntilConnectionState(connectionId, "active"); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	log.Info().Msgf("connection established")

	// Receive Credential
	log.Info().Msgf("Send credential proposal to receive credential offer")
	credExId, err := sendCredentialProposal(connectionId)
	if err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	log.Info().Msgf("credential exchange id: " + credExId)
	if err = waitUntilCredentialExchangeState(credExId, "offer_received"); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}

	log.Info().Msgf("Send credential request to receive credential")
	if err = sendCredentialRequest(credExId); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	if err = waitUntilCredentialExchangeState(credExId, "credential_acked"); err != nil {
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
	if err = waitUntilPresentationExchangeState(presExId, "presentation_acked"); err != nil {
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
	case "DEBUG":
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

	invitationType := gjson.Get(invitation, `@type`).String()
	switch invitationType {
	case "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.0/invitation":
		resp, err = client.R().
			SetBody(invitation).
			SetAuthToken(jwtToken).
			Post(agentApiUrl + "/out-of-band/receive-invitation")
	case "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation":
		resp, err = client.R().
			SetBody(invitation).
			SetAuthToken(jwtToken).
			Post(agentApiUrl + "/connections/receive-invitation")
	default:
		err = errors.New("unexpected invitation type" + invitationType)
		return "", err
	}

	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return "", err
	}
	log.Debug().Msgf("response: " + resp.String())
	connectionId := gjson.Get(resp.String(), `connection_id`).String()

	return connectionId, nil
}

func waitUntilConnectionState(connectionId string, state string) error {
	log.Info().Msgf("Wait until connection (state: " + state + ")")
	for retry := 0; retry < pollingRetryMax; retry++ {
		resp, err := client.R().
			SetAuthToken(jwtToken).
			Get(agentApiUrl + "/connections/" + connectionId)
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
		log.Debug().Msgf("response: " + resp.String())
		resState := gjson.Get(resp.String(), `state`).String()
		log.Info().Msgf("connection state: " + resState)
		if resState == state {
			return nil
		}
		time.Sleep(pollingCyclePeriod)
	}
	err := errors.New("timeout - connection is not (state: " + state + ")")
	log.Error().Err(err).Caller().Msgf("")
	return err
}

func sendCredentialProposal(connectionId string) (string, error) {
	body := `{
		"connection_id": "` + connectionId + `"
	}`
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/issue-credential/send-proposal")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return "", err
	}
	log.Debug().Msgf("response: " + resp.String())
	credExId := gjson.Get(resp.String(), "credential_exchange_id").String()

	return credExId, nil
}

func waitUntilCredentialExchangeState(credExId string, state string) error {
	log.Info().Msgf("Wait until credential exchange (state: " + state + ")")
	for retry := 0; retry < pollingRetryMax; retry++ {
		resp, err := client.R().
			SetAuthToken(jwtToken).
			Get(agentApiUrl + "/issue-credential/records/" + credExId)
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
		log.Debug().Msgf("response: " + resp.String())

		resState := gjson.Get(resp.String(), "state").String()
		log.Info().Msgf("credential exchange state: " + resState)
		if resState == state {
			return nil
		} else if resState == "" {
			errorMsg := gjson.Get(resp.String(), "error_msg").String()
			log.Info().Msgf("received problem report error_msg: " + errorMsg)
			return errors.New(errorMsg)
		}
		time.Sleep(pollingCyclePeriod)
	}
	err := errors.New("timeout - credential exchange is not (state: " + state + ")")
	log.Error().Err(err).Caller().Msgf("")
	return err
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
		log.Info().Msgf("the number of presentation exchange (state: request_received): " + strconv.Itoa(len(presExes)))
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

func waitUntilPresentationExchangeState(presExId string, state string) error {
	log.Info().Msgf("Wait until presentation exchange (state: " + state + ")")
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
		resState := gjson.Get(resp.String(), `state`).String()
		log.Info().Msgf("presentation exchange state: " + resState)
		if resState == state {
			return nil
		} else if resState == "" {
			errorMsg := gjson.Get(resp.String(), "error_msg").String()
			log.Info().Msgf("received problem report error_msg: " + errorMsg)
			return errors.New(errorMsg)
		}
	}
	err := errors.New("timeout - presentation exchange is not (state: " + state + ")")
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
