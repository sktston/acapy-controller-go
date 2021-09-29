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
	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sktston/acapy-controller-go/utils"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	client                          = resty.New()
	agentApiUrl, jwtToken, walletId string

	version = strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99))
	walletName = "alice." + version
	imageUrl   = "https://identicon-api.herokuapp.com/" + walletName + "/300?format=png"

	//go:embed alice-config.yaml
	config []byte
)

func main() {
	// Setting logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Read config file
	if err := utils.LoadConfig(config); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	agentApiUrl = viper.GetString("agent-api-url")

	// Set log level debug
	if strings.ToUpper(viper.GetString("log-mode")) == "DEBUG" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		gin.SetMode(gin.DebugMode)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		gin.SetMode(gin.ReleaseMode)
	}

	// Set client configuration
	client.SetTimeout(30 * time.Minute)
	client.SetHeader("Content-Type", "application/json")

	// Start web hook server
	httpServer, err := startWebHookServer()
	if err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}

	// Set exit signal
	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Start Alice
	if err := provisionController(); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}

	// Receive invitation
	log.Info().Msgf("Receive invitation from faber controller")
	if err := receiveInvitation(); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}

	// Wait exit signal
	<-exitSignal
	if err := shutdownWebHookServer(httpServer); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	close(exitSignal)

	return
}

func startWebHookServer() (*http.Server, error) {
	// Set up http router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logger.SetLogger(logger.WithWriter(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})))

	router.POST("/webhooks/topic/:topic", handleEvent)

	// Get port from HolderWebhookUrl
	urlParse, _ := url.Parse(viper.GetString("server-webhook-url"))
	_, port, _ := net.SplitHostPort(urlParse.Host)
	port = ":" + port

	httpServer := &http.Server{
		Addr:    port,
		Handler: router,
	}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Caller().Msgf("")
		}
	}()
	log.Info().Msgf("Listen on http://" + urlParse.Host)

	return httpServer, nil
}

func shutdownWebHookServer(httpServer *http.Server) error {
	// Shutdown http server gracefully
	if err := httpServer.Shutdown(context.Background()); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("Http server shutdown successfully")

	return nil
}

func provisionController() error {
	log.Info().Msgf("Create wallet")
	if err := createWallet(); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}

	log.Info().Msgf("Configuration of alice:")
	log.Info().Msgf("- wallet name: " + walletName)
	log.Info().Msgf("- webhook url: " + viper.GetString("server-webhook-url"))
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
			log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> sendProof()")

			if err := sendProof(body["presentation_exchange_id"].(string), body["presentation_request"].(map[string]interface{})); err != nil {
				log.Error().Err(err).Caller().Msgf("")
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		} else if state == "presentation_acked" {
			log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> deleteWallet() & Exit")

			if err := deleteWallet(); err != nil {
				log.Error().Err(err).Caller().Msgf("")
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
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
		"image_url": "` + imageUrl + `",
		"wallet_webhook_urls": ["` + viper.GetString("server-webhook-url") + `"]
	}`
	log.Info().Msgf("Create a new wallet" + utils.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		Post(agentApiUrl + "/multitenancy/wallet")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())
	walletId = gjson.Get(resp.String(), `settings.wallet\.id`).String()
	jwtToken = gjson.Get(resp.String(), "token").String()

	return nil
}

func receiveInvitation() error {
	resp, err := client.R().
		Get(viper.GetString("issuer-invitation-url"))
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

	invitation, err := utils.ParseInvitationUrl(resp.String())
	log.Info().Msgf("invitation: " + string(invitation))

	body := string(invitation)
	resp, err = client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/out-of-band/receive-invitation")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

	return nil
}

func sendCredentialProposal(connectionId string) error {
	body := `{
		"connection_id": "` + connectionId + `"
	}`
	log.Info().Msgf(utils.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/issue-credential/send-proposal")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

	return nil
}

func sendCredentialRequest(credExId string) error {
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/issue-credential/records/" + credExId + "/send-request")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

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
	log.Info().Msgf("response: " + resp.String())

	return nil
}

func sendProof(presExId string, presentationRequest map[string]interface{}) error {
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Get(agentApiUrl + "/present-proof/records/" + presExId + "/credentials")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

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
	log.Info().Msgf("Use latest credential in demo - credId: " + credId)

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
	log.Info().Msgf("response: " + resp.String())

	return nil
}

func deleteWallet() error {
	// Delete wallet
	resp, err := client.R().
		Post(agentApiUrl + "/multitenancy/wallet/" + walletId + "/remove")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

	return nil
}
