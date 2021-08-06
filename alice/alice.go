/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Ethan Sung (baegjae@gmail.com)       *
 * since July 28, 2020                            *
 **************************************************/

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sktston/acapy-controller-go/utils"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var (
	consoleWriter                                = zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	client                                       = resty.New()
	config                                       utils.ControllerConfig
	jwtToken, walletId                           string

	version = strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99))
	walletName = "alice." + version
	imageUrl   = "https://identicon-api.herokuapp.com/" + walletName + "/300?format=png"
)

func main() {
	// Setting log
	log.Logger = log.Output(consoleWriter)

	// Read alice-config.yaml file
	err := config.ReadConfig("./alice-config.json")
	if err != nil { log.Fatal().Err(err).Msg("") }

	// Set log level debug
	utils.SetLogLevelDebug(config.Debug)

	// Set client configuration
	client.SetTimeout(30 * time.Minute)
	client.SetHeader("Content-Type", "application/json")

	// Start web hook server
	httpServer, err := startWebHookServer()
	if err != nil { log.Fatal().Err(err).Msg("") }

	// Set exit signal
	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Start Alice
	err = provisionController()
	if err != nil { log.Fatal().Err(err).Msg("") }

	// Receive invitation
	log.Info().Msg("Receive invitation from faber controller")
	err = receiveInvitation()
	if err != nil { log.Error().Err(err).Msg("") }

	// Wait exit signal
	<-exitSignal
	_ = shutdownWebHookServer(httpServer)
	close(exitSignal)

	return
}

func startWebHookServer() (*http.Server, error) {
	// Set up http router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logger.SetLogger(logger.WithWriter(consoleWriter)))

	router.POST("/webhooks/topic/:topic", handleEvent)

	// Get port from HolderWebhookUrl
	urlParse, _ := url.Parse(config.HolderWebhookUrl)
	_, port, _ := net.SplitHostPort(urlParse.Host)
	port = ":"+ port

	httpServer := &http.Server{
		Addr:    port,
		Handler: router,
	}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("")
		}
	}()
	log.Info().Msg("Listen on http://" + utils.GetOutboundIP().String() + port)

	return httpServer, nil
}

func shutdownWebHookServer(httpServer *http.Server) error {
	// Shutdown http server gracefully
	err := httpServer.Shutdown(context.Background())
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("Http server shutdown successfully")

	return nil
}

func provisionController() error {
	log.Info().Msg("Create wallet")
	err := createWallet()
	if err != nil { log.Error().Err(err).Msg(""); return err }

	log.Info().Msg("Configuration of alice:")
	log.Info().Msg("- wallet name: " + walletName)
	log.Info().Msg("- webhook url: " + config.HolderWebhookUrl)
	log.Info().Msg("- wallet ID: " + walletId)
	log.Info().Msg("- wallet type: " + config.WalletType)
	log.Info().Msg("- jwt token: " + jwtToken)

	return nil
}

func handleEvent(ctx *gin.Context) {
	var body map[string]interface{}
	err := ctx.ShouldBindJSON(&body)
	if err != nil { utils.HttpError(ctx, http.StatusBadRequest, err); return }
	topic := ctx.Param("topic")
	var state string
	if val, ok := body["state"]; ok {
		state = val.(string)
	}

	bodyAsBytes, _ := json.Marshal(body)
	log.Info().Msg("handleEvent >>> topic:"+topic+", state:"+state+", body:"+string(bodyAsBytes))

	switch topic {
	case "connections":
		if state == "active" {
			log.Info().Msg("- Case (topic:" + topic + ", state:" + state + ") -> sendCredentialProposal()")

			err = sendCredentialProposal(body["connection_id"].(string))
			if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
		}

	case "issue_credential":
		// When credential offer is received, send credential request
		if state == "offer_received" {
			log.Info().Msg("- Case (topic:" + topic + ", state:" + state + ") -> sendCredentialRequest()")

			err = sendCredentialRequest(body["credential_exchange_id"].(string))
			if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
		} else if state == "credential_acked" {
			log.Info().Msg("- Case (topic:" + topic + ", state:" + state + ") -> sendPresentationProposal()")

			err = sendPresentationProposal(body["connection_id"].(string))
			if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
		}

	case "present_proof":
		// When proof request is received, send proof(presentation)
		if state == "request_received" {
			log.Info().Msg("- Case (topic:" + topic + ", state:" + state + ") -> sendProof()")

			err = sendProof(
				body["presentation_exchange_id"].(string),
				body["presentation_request"].(map[string]interface{}),
				)
			if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
		} else if state == "presentation_acked" {
			log.Info().Msg("- Case (topic:" + topic + ", state:" + state + ") -> deleteWallet() & Exit")
			err = deleteWallet()
			if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }

			// Send exit signal
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		}

	case "basicmessages":
	case "revocation_registry":
	case "problem_report":
	case "issuer_cred_rev":

	default:
		log.Warn().Msg("- Warning Unexpected topic:" + topic)
	}

	return
}

func createWallet() error {
	body := `{
		"wallet_name": "`+walletName+`",
		"wallet_key": "`+walletName+".key"+`",
		"wallet_type": "`+config.WalletType+`",
		"label": "`+walletName+".label"+`",
		"image_url": "`+imageUrl+`",
		"wallet_webhook_urls": ["`+config.HolderWebhookUrl+`"]
	}`
	log.Info().Msg("Create a new wallet" + utils.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		Post(config.AgentApiUrl+"/multitenancy/wallet")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())
	walletId = gjson.Get(resp.String(), `settings.wallet\.id`).String()
	jwtToken = gjson.Get(resp.String(), "token").String()

	return nil
}

func receiveInvitation() error {
	resp, err := client.R().
		Get(config.IssuerContUrl+"/invitation-url")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	invitation, err := utils.ParseInvitationUrl(resp.String())
	log.Info().Msg("invitation: "+ string(invitation))

	body := string(invitation)
	resp, err = client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/out-of-band/receive-invitation")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	return nil
}

func sendCredentialProposal(connectionId string) error {
	body := `{
		"connection_id": "`+ connectionId +`"
	}`
	log.Info().Msg(utils.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/issue-credential/send-proposal")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	return nil
}

func sendCredentialRequest(credExId string) error {
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/issue-credential/records/"+ credExId +"/send-request")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	return nil
}

func sendPresentationProposal(connectionId string) error {
	body := `{
		"connection_id": "`+ connectionId +`",
		"presentation_proposal": {
			"attributes": [],
			"predicates": []
		}
	}`
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/present-proof/send-proposal")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	return nil
}

func sendProof(presExId string, presentationRequest map[string]interface{}) error {
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Get(config.AgentApiUrl+"/present-proof/records/"+ presExId +"/credentials")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	credentials := resp.String()
	credRevIDs := gjson.Get(credentials, "#.cred_info.cred_rev_id").Array()
	credIDs := gjson.Get(credentials, "#.cred_info.referent").Array()

	var maxRevId uint64 = 0
	var credId string
	for idx, credRevID := range credRevIDs {
		if credRevID.Uint() > maxRevId {
			maxRevId = credRevID.Uint()
			credId = credIDs[idx].String()
		}
	}
	log.Info().Msg("Use latest credential in demo - credId: "+credId)

	// Make body using presentationRequest
	presRequestBytes, _ := json.Marshal(presentationRequest)

	var newReqAttrs string
	reqAttrs := gjson.Get(string(presRequestBytes), "requested_attributes").Map()
	for key := range reqAttrs {
		newReqAttrs, _ = sjson.Set(newReqAttrs, key+".cred_id", credId)
		newReqAttrs, _ = sjson.Set(newReqAttrs, key+".revealed", true)
	}

	var newReqPreds string
	reqPreds := gjson.Get(string(presRequestBytes), "requested_predicates").Map()
	for key := range reqPreds {
		newReqPreds, _ = sjson.Set(newReqPreds, key+".cred_id", credId)
	}

	body := `{
		"requested_attributes": `+newReqAttrs+`,
		"requested_predicates": `+newReqPreds+`,
		"self_attested_attributes": {}
	}`
	resp, err = client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/present-proof/records/"+ presExId +"/send-presentation")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	return nil
}

func deleteWallet() error {
	// Delete wallet
	resp, err := client.R().
		Post(config.AgentApiUrl+"/multitenancy/wallet/"+ walletId +"/remove")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	return nil
}
