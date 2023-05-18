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
	"io"
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

const (
	clientTimeout  = 3 * time.Minute
	stewardSeed    = "000000000000000000000000Steward1"
	configFileName = "faber-config.yml"
)

var (
	httpClient                                         = resty.New()
	sseClient                                          *sse.Client
	did, verKey, schemaId, credDefId, walletId         string
	agentApiUrl, stewardJwtToken, jwtToken, webhookUrl string

	version = strconv.Itoa(util.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(util.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(util.GetRandomInt(1, 99))
	walletName = "faber." + version
	imageUrl   = "https://identicon-api.herokuapp.com/" + walletName + "/300?format=png"
)

func main() {
	var (
		httpServer *http.Server
		err        error
	)
	// Initialization
	if err = initialization(); err != nil {
		log.Fatal().Err(err).Caller().Msg("")
	}

	// Start web hook server
	httpServer, err = startWebHookServer()
	if err != nil {
		log.Fatal().Err(err).Caller().Msg("")
	}

	// Start Faber
	if err = provisionController(); err != nil {
		log.Fatal().Err(err).Caller().Msg("")
	}

	if viper.GetBool("server-sent-event.enable") {
		log.Info().Msgf("Waiting server sent event from data store...")
	} else {
		log.Info().Msgf("Waiting web hook event from agent...")
	}

	// Exit by pressing Ctrl-C or 'kill pid' in the shell
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)

	<-ctrlC
	log.Info().Msg("Ctrl-C detected, it may take a couple of seconds to clean up...")

	// Delete acapy agent data
	if viper.GetBool("delete-data-at-exit") == true {
		err = util.DeleteAgentData(agentApiUrl, jwtToken, walletId,
			"connection", "credential_exchange", "presentation_exchange", "wallet")
		if err != nil {
			log.Fatal().Err(err).Caller().Msg("")
		}
	}

	// Shut down web hook server
	if err = shutdownWebHookServer(httpServer); err != nil {
		log.Fatal().Err(err).Caller().Msg("")
	}

	log.Info().Msgf("Faber exiting")
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
		gin.DefaultWriter = os.Stdout
		gin.DefaultErrorWriter = os.Stderr
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		gin.SetMode(gin.ReleaseMode)
		gin.DefaultWriter = io.Discard
		gin.DefaultErrorWriter = io.Discard
	}

	// Set httpClient configuration
	httpClient.SetTimeout(clientTimeout)
	httpClient.SetHeader("Content-Type", "application/json")

	return nil
}

func startWebHookServer() (*http.Server, error) {
	// Set up http router
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/invitation-url", createInvitationUrl)
	router.GET("/oob-invitation-url", createOobInvitationUrl)
	router.GET("/oob-invitation-url-with-proof", createOobInvitationUrlProof)
	router.POST("/webhooks/:walletId/topic/:topic", handleWebhookEvent)

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
			log.Fatal().Err(err).Caller().Msg("")
		}
	}()
	log.Info().Msgf("Listen on http://%s", urlParse.Host)

	return httpServer, nil
}

func shutdownWebHookServer(httpServer *http.Server) error {
	// Shutdown http server gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}

	log.Info().Msgf("Http server shutdown successfully")
	return nil
}

func startSseClient() error {
	sseServerUrl := util.JoinURL(viper.GetString("server-sent-event.datastore-url"), "/sse-events")
	log.Info().Msgf("Start SSE client: %s", sseServerUrl)

	sseClient = sse.NewClient(sseServerUrl)
	sseClient.Headers = map[string]string{
		"Authorization": "Bearer " + jwtToken,
	}

	go func() {
		if err := sseClient.Subscribe(walletId, handleSseEvent); err != nil {
			log.Error().Err(err).Caller().Msg("")
		}
	}()

	return nil
}

func provisionController() error {
	webhookUrl = viper.GetString("server-webhook-url")
	if viper.GetBool("use-multitenancy") == true {
		log.Info().Msgf("Obtain jwtToken of steward")
		if err := obtainStewardJwtToken(); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}

		log.Info().Msgf("Create wallet")
		if err := createWallet(); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}

		log.Info().Msgf("Create a new did and register the did as an issuer")
		if err := createPublicDid(); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}
	}

	// SSE client starts using wallet ID
	if viper.GetBool("server-sent-event.enable") {
		if err := startSseClient(); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}
	}

	log.Info().Msgf("Create schema and credential definition")
	if err := createSchema(); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	if err := createCredentialDefinition(); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}

	log.Info().Msgf("Configuration of faber:")
	if viper.GetBool("use-multitenancy") == true {
		log.Info().Msgf("- wallet name: %s", walletName)
		log.Info().Msgf("- wallet ID: %s", walletId)
		log.Info().Msgf("- wallet type: %s", viper.GetString("wallet-type"))
		log.Info().Msgf("- jwt token: %s", jwtToken)
		log.Info().Msgf("- did: %s", did)
		log.Info().Msgf("- verification key: %s", verKey)
	}
	log.Info().Msgf("- webhook url: %s", webhookUrl)
	log.Info().Msgf("- schema ID: %s", schemaId)
	log.Info().Msgf("- credential definition ID: %s", credDefId)

	log.Info().Msgf("Initialization is done.")
	log.Info().Msgf("Run alice now.")

	return nil
}

func requestCreateInvitation(invitationType string) (*resty.Response, error) {
	switch invitationType {
	case "oob":
		body := `{
			"handshake_protocols": [ "connections/1.0" ],
			"use_public_did": ` + viper.GetString("public-invitation") + `
		}`
		return httpClient.R().
			SetBody(body).
			SetAuthToken(jwtToken).
			Post(agentApiUrl + "/out-of-band/create-invitation")
	case "connections":
		params := "?public=" + viper.GetString("public-invitation")
		return httpClient.R().
			SetAuthToken(jwtToken).
			Post(agentApiUrl + "/connections/create-invitation" + params)
	default:
		err := errors.New("unexpected invitation type: " + invitationType)
		log.Fatal().Err(err).Caller().Msg("")
		return nil, err
	}
}

func requestCreateOobInvitationWithProof(presExId string) (*resty.Response, error) {
	body := `{
			"handshake_protocols": [ "connections/1.0" ],
			"attachments": [ { "id": "` + presExId + `", "type": "present-proof" } ],
			"use_public_did": ` + viper.GetString("public-invitation") + `
		}`
	return httpClient.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/out-of-band/create-invitation")
}

func createInvitationUrl(c *gin.Context) {
	resp, err := requestCreateInvitation("connections")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	invitationUrl := gjson.Get(resp.String(), "invitation_url").String()
	log.Info().Msgf("createInvitationUrl: %s", invitationUrl)
	c.String(http.StatusOK, invitationUrl)
}

func createOobInvitationUrl(c *gin.Context) {
	resp, err := requestCreateInvitation("oob")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	invitationUrl := gjson.Get(resp.String(), "invitation_url").String()
	log.Info().Msgf("createOobInvitationUrl: %s", invitationUrl)
	c.String(http.StatusOK, invitationUrl)
}

func createOobInvitationUrlProof(c *gin.Context) {
	presExId, err := createProofRequest()
	if err != nil {
		log.Error().Err(err).Caller().Msg("")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp, err := requestCreateOobInvitationWithProof(presExId)
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	invitationUrl := gjson.Get(resp.String(), "invitation_url").String()
	log.Info().Msgf("createInvitationUrl: %s", invitationUrl)
	c.String(http.StatusOK, invitationUrl)
}

func handleWebhookEvent(c *gin.Context) {
	// walletId := c.Param("walletId")
	topic := c.Param("topic")

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		log.Error().Err(err).Caller().Msgf("invalid JSON")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid JSON: " + err.Error()})
		return
	}

	var state string
	if val, ok := body["state"]; ok {
		state = val.(string)
	}

	bodyAsBytes, _ := json.Marshal(body)
	log.Info().Msgf("handleWebhookEvent >>> topic:%s, state:%s", topic, state)
	log.Debug().Msgf("body: %s", util.PrettyJson(bodyAsBytes))

	switch topic {
	case "issue_credential":
		if state == "proposal_received" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> sendCredentialOffer()", topic, state)

			if err := sendCredentialOffer(body["credential_exchange_id"].(string)); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		} else if state == "credential_acked" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> issue credential successfully", topic, state)

			if viper.GetBool("revoke-after-issue") {
				log.Info().Msgf("- revoke-after-issue is true -> revokeCredential()")

				if err := revokeCredential(body["credential_exchange_id"].(string)); err != nil {
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
			}
		}

	case "present_proof":
		if state == "proposal_received" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> sendProofRequest()", topic, state)

			if err := sendProofRequest(body["connection_id"].(string)); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		} else if state == "verified" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> printProofResult()", topic, state)

			if err := printProofResult(body); err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}

	case "connections":
	case "basicmessages":
	case "revocation_registry":
	case "problem_report":
	case "issuer_cred_rev":
	case "out_of_band":

	default:
		log.Warn().Msgf("- Warning Unexpected topic:%s", topic)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid topic:" + topic})
		return
	}
	c.Status(http.StatusOK)
}

func handleSseEvent(event *sse.Event) {
	var sseData map[string]interface{}
	_ = json.Unmarshal(event.Data, &sseData)

	log.Debug().Msgf("handleSseEvent: %s", util.PrettyJson(&sseData))

	topic := sseData["topic"].(string)
	state := sseData["state"].(string)

	log.Info().Msgf("handleSseEvent >>> topic:%s, state:%s", topic, state)
	log.Debug().Msgf("sseData: %s", util.PrettyJson(&sseData))

	switch topic {
	case "issue_credential":
		if state == "proposal_received" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> sendCredentialOffer()", topic, state)

			if err := sendCredentialOffer(sseData["credential_exchange_id"].(string)); err != nil {
				log.Error().Err(err).Caller().Msg("")
				return
			}
		} else if state == "credential_acked" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> issue credential successfully", topic, state)

			if viper.GetBool("revoke-after-issue") {
				log.Info().Msgf("- revoke-after-issue is true -> revokeCredential()")

				if err := revokeCredential(sseData["credential_exchange_id"].(string)); err != nil {
					log.Error().Err(err).Caller().Msg("")
					return
				}
			}
		}

	case "present_proof":
		if state == "proposal_received" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> sendProofRequest()", topic, state)

			if err := sendProofRequest(sseData["connection_id"].(string)); err != nil {
				log.Error().Err(err).Caller().Msg("")
				return
			}
		} else if state == "verified" {
			log.Info().Msgf("- Case (topic:%s, state:%s) -> printProofResult()", topic, state)

			if err := printProofResult(sseData); err != nil {
				log.Error().Err(err).Caller().Msg("")
				return
			}
		}

	case "connections":
	case "basicmessages":
	case "revocation_registry":
	case "problem_report":
	case "issuer_cred_rev":
	case "out_of_band":

	default:
		log.Warn().Msgf("- Warning Unexpected topic:%s", topic)
		return
	}
}

func obtainStewardJwtToken() error {
	// check if steward wallet already exists
	stewardWallet := "steward"
	resp, err := httpClient.R().
		SetQueryParam("wallet_name", stewardWallet).
		Get(agentApiUrl + "/multitenancy/wallets")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	wallets := gjson.Get(resp.String(), "results").Array()
	if len(wallets) == 0 {
		// stewardWallet not exists -> create stewardWallet and get jwt token
		body := `{
			"wallet_name": "` + stewardWallet + `",
			"wallet_key": "` + stewardWallet + ".key" + `",
			"wallet_type": "` + viper.GetString("wallet-type") + `"
		}`
		log.Info().Msgf("Not found steward wallet - Create a new steward wallet: %s", util.PrettyJson(body))
		resp, err = httpClient.R().
			SetBody(body).
			Post(agentApiUrl + "/multitenancy/wallet")
		if err = util.CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}
		log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
		stewardJwtToken = gjson.Get(resp.String(), "token").String()

		body = `{ "seed": "` + stewardSeed + `" }`
		log.Info().Msgf("Create a steward did: %s", util.PrettyJson(body))
		resp, err = httpClient.R().
			SetBody(body).
			SetAuthToken(stewardJwtToken).
			Post(agentApiUrl + "/wallet/did/create")
		if err = util.CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}
		log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
		stewardDid := gjson.Get(resp.String(), "result.did").String()

		log.Info().Msgf("Assign the did to public:%s", stewardDid)
		resp, err = httpClient.R().
			SetQueryParam("did", stewardDid).
			SetAuthToken(stewardJwtToken).
			Post(agentApiUrl + "/wallet/did/public")
		if err = util.CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}
		log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
	} else {
		// stewardWallet exists -> get and return jwt token
		stewardWalletId := gjson.Get(wallets[0].String(), "wallet_id").String()
		log.Info().Msgf("Found steward wallet - Get jwt token with wallet id: %s", stewardWalletId)
		resp, err = httpClient.R().
			Post(agentApiUrl + "/multitenancy/wallet/" + stewardWalletId + "/token")
		if err = util.CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}
		log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
		stewardJwtToken = gjson.Get(resp.String(), "token").String()
	}
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

	if viper.GetBool("server-sent-event.enable") {
		webhookUrl = util.JoinURL(viper.GetString("server-sent-event.datastore-url"), "/webhooks", walletId)
	} else {
		webhookUrl = util.JoinURL(viper.GetString("server-webhook-url"), walletId)
	}

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

func createPublicDid() error {
	log.Info().Msgf("Create a new random local did")
	resp, err := httpClient.R().
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/wallet/did/create")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
	did = gjson.Get(resp.String(), "result.did").String()
	verKey = gjson.Get(resp.String(), "result.verkey").String()
	log.Info().Msgf("created did: %s, verkey: %s", did, verKey)

	log.Info().Msgf("Register the did to the ledger as a ENDORSER by steward")
	resp, err = httpClient.R().
		SetQueryParam("did", did).
		SetQueryParam("verkey", verKey).
		SetQueryParam("alias", walletName).
		SetQueryParam("role", "ENDORSER").
		SetAuthToken(stewardJwtToken).
		Post(agentApiUrl + "/ledger/register-nym")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	log.Info().Msgf("Assign the did to public: %s", did)
	resp, err = httpClient.R().
		SetQueryParam("did", did).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/wallet/did/public")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	return nil
}

func createSchema() error {
	body := `{
		"schema_name": "degree_schema",
		"schema_version": "` + version + `",
		"attributes": ["name", "date", "degree", "age", "photo"]
	}`
	log.Info().Msgf("Create a new schema on the ledger: %s", util.PrettyJson(body))
	resp, err := httpClient.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/schemas")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
	schemaId = gjson.Get(resp.String(), "schema_id").String()

	return nil
}

func createCredentialDefinition() error {
	body := `{
		"schema_id": "` + schemaId + `",
		"tag": "tag.` + version + `",
		"support_revocation": true,
		"revocation_registry_size": 10
	}`
	log.Info().Msgf("Create a new credential definition on the ledger: %s", util.PrettyJson(body))
	resp, err := httpClient.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/credential-definitions")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
	credDefId = gjson.Get(resp.String(), "credential_definition_id").String()

	return nil
}

func sendCredentialOffer(credExId string) error {
	encodedImage := "base64EncodedJpegImage"

	body := `{
		"counter_proposal": {
			"cred_def_id"  :"` + credDefId + `",
			"credential_proposal": {
				"attributes": [
					{ "name": "name", "value": "alice" },
					{ "name": "date", "value": "05-2018" },
					{ "name": "degree", "value": "maths" },
					{ "name": "age", "value": "25" },
					{ "name": "photo", "value": "` + encodedImage + `", "mime-type": "image/jpeg" }
				]
			}
		}
	}`
	resp, err := httpClient.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/issue-credential/records/" + credExId + "/send-offer")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	return nil
}

func createProofRequest() (string, error) {
	curUnixTime := strconv.FormatInt(time.Now().Unix(), 10)

	body := `{
		"proof_request": {
			"name": "proof_name",
			"version": "1.0",
			"requested_attributes": {
				"attr_name": {
					"name": "name",
					"non_revoked": { "from": 0, "to": ` + curUnixTime + ` },
					"restrictions": [ { "cred_def_id": "` + credDefId + `" } ]
				},
				"attr_date": {
					"name": "date",
					"non_revoked": { "from": 0, "to": ` + curUnixTime + ` },
					"restrictions": [ { "cred_def_id": "` + credDefId + `" } ]
				},
				"attr_degree": {
					"name": "degree",
					"non_revoked": { "from": 0, "to": ` + curUnixTime + ` },
					"restrictions": [ { "cred_def_id": "` + credDefId + `" } ]
				},
				"attr_photo": {
					"name": "photo",
					"non_revoked": { "from": 0, "to": ` + curUnixTime + ` },
					"restrictions": [ { "cred_def_id": "` + credDefId + `" } ]
				}
			},
			"requested_predicates": {
				"pred_age": {
					"name": "age",
					"p_type": ">=",
					"p_value": 20,
					"non_revoked": { "from": 0, "to": ` + curUnixTime + ` },
					"restrictions": [ { "cred_def_id": "` + credDefId + `" } ]
				}
			}
		}
	}`
	log.Debug().Msgf("body: %s", util.PrettyJson(body))
	resp, err := httpClient.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/present-proof/create-request")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return "", err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))
	presExId := gjson.Get(resp.String(), "presentation_exchange_id").String()

	return presExId, nil
}

func sendProofRequest(connectionId string) error {
	curUnixTime := strconv.FormatInt(time.Now().Unix(), 10)

	body := `{
		"connection_id": "` + connectionId + `",
		"proof_request": {
			"name": "proof_name",
			"version": "1.0",
			"requested_attributes": {
				"attr_name": {
					"name": "name",
					"non_revoked": { "from": 0, "to": ` + curUnixTime + ` },
					"restrictions": [ { "cred_def_id": "` + credDefId + `" } ]
				},
				"attr_date": {
					"name": "date",
					"non_revoked": { "from": 0, "to": ` + curUnixTime + ` },
					"restrictions": [ { "cred_def_id": "` + credDefId + `" } ]
				},
				"attr_degree": {
					"name": "degree",
					"non_revoked": { "from": 0, "to": ` + curUnixTime + ` },
					"restrictions": [ { "cred_def_id": "` + credDefId + `" } ]
				},
				"attr_photo": {
					"name": "photo",
					"non_revoked": { "from": 0, "to": ` + curUnixTime + ` },
					"restrictions": [ { "cred_def_id": "` + credDefId + `" } ]
				},
				"attr_address": {
					"name": "address"
				}
			},
			"requested_predicates": {
				"pred_age": {
					"name": "age",
					"p_type": ">=",
					"p_value": 20,
					"non_revoked": { "from": 0, "to": ` + curUnixTime + ` },
					"restrictions": [ { "cred_def_id": "` + credDefId + `" } ]
				}
			}
		}
	}`
	log.Debug().Msgf("body: %s", util.PrettyJson(body))
	resp, err := httpClient.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/present-proof/send-request")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	return nil
}

func revokeCredential(credExId string) error {
	body := `{
		"cred_ex_id": "` + credExId + `",
		"publish": true
	}`
	resp, err := httpClient.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/revocation/revoke")
	if err = util.CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}
	log.Debug().Msgf("response: %s", util.PrettyJson(resp.String()))

	return nil
}

/*
// body sample

	{
		"auto_present": false,
		"auto_verify": true,
		"connection_id": "514fbb03-1411-4d5f-ac5a-52b2cefa19ef",
		"created_at": "2022-11-28T06:44:09.200750Z",
		"initiator": "self",
		"presentation": {
			"identifiers": [{
				"cred_def_id": "SE7xaBWCDLN8AP54SKrUGX:3:CL:854272560:tag.56.41.85",
				"rev_reg_id": "SE7xaBWCDLN8AP54SKrUGX:4:SE7xaBWCDLN8AP54SKrUGX:3:CL:854272560:tag.56.41.85:CL_ACCUM:d7552474-fb3b-4f8b-a3f8-f0ac38a93c21",
				"schema_id": "SE7xaBWCDLN8AP54SKrUGX:2:degree_schema:56.41.85",
				"timestamp": 1669599616
			}],
			"requested_proof": {
				"predicates": {},
				"revealed_attrs": {
					"attr_date": {
						"encoded": "101085817956371643310471822530712840836446570298192279302750234554843339322886",
						"raw": "05-2018",
						"sub_proof_index": 0
					},
					"attr_degree": {
						"encoded": "78137204873448776862705240258723141940757006710839733585634143215803847410018",
						"raw": "maths",
						"sub_proof_index": 0
					},
					"attr_name": {
						"encoded": "19831138297880367962895005496563562590284654704047651305948751287370224856720",
						"raw": "alice",
						"sub_proof_index": 0
					},
					"attr_photo": {
						"encoded": "100389533357464973037169638548740508934417014514044717361399600653322420053534",
						"raw": "base64EncodedJpegImage",
						"sub_proof_index": 0
					}
				},
				"self_attested_attrs": {
					"attr_address": "my self-attested value"
				},
				"unrevealed_attrs": {}
			}
		},
		"presentation_exchange_id": "630df476-369e-4b89-9eaa-98ac0eea674f",
		"presentation_request": {
			"name": "proof_name",
			"nonce": "633058518906354959770561",
			"requested_attributes": {
				"attr_address": {
					"name": "address"
				},
				"attr_date": {
					"name": "date",
					"non_revoked": {
						"from": 0,
						"to": 1669617849
					},
					"restrictions": [{
						"cred_def_id": "SE7xaBWCDLN8AP54SKrUGX:3:CL:854272560:tag.56.41.85"
					}]
				},
				"attr_degree": {
					"name": "degree",
					"non_revoked": {
						"from": 0,
						"to": 1669617849
					},
					"restrictions": [{
						"cred_def_id": "SE7xaBWCDLN8AP54SKrUGX:3:CL:854272560:tag.56.41.85"
					}]
				},
				"attr_name": {
					"name": "name",
					"non_revoked": {
						"from": 0,
						"to": 1669617849
					},
					"restrictions": [{
						"cred_def_id": "SE7xaBWCDLN8AP54SKrUGX:3:CL:854272560:tag.56.41.85"
					}]
				},
				"attr_photo": {
					"name": "photo",
					"non_revoked": {
						"from": 0,
						"to": 1669617849
					},
					"restrictions": [{
						"cred_def_id": "SE7xaBWCDLN8AP54SKrUGX:3:CL:854272560:tag.56.41.85"
					}]
				}
			},
			"requested_predicates": {},
			"version": "1.0"
		},
		"role": "verifier",
		"state": "verified",
		"thread_id": "12c239a1-121a-4448-8ee9-e72a90f56bed",
		"trace": false,
		"updated_at": "2022-11-28T07:44:21.042791Z",
		"verified": "true",
		"verified_msgs": []
	}
*/
func printProofResult(body map[string]interface{}) error {
	if body["verified"] != "true" {
		log.Warn().Msgf("proof is not verified")
		return nil
	}

	bodyAsBytes, _ := json.Marshal(body)

	presRequest := gjson.Get(string(bodyAsBytes), "presentation_request").String()

	// add revealed value and self attested value to presRequest
	requestedAttrs := gjson.Get(presRequest, "requested_attributes").Map()
	for key := range requestedAttrs {
		value := "unrevealed"
		if gjson.Get(string(bodyAsBytes), "presentation.requested_proof.revealed_attrs."+key).Exists() {
			value = gjson.Get(string(bodyAsBytes), "presentation.requested_proof.revealed_attrs."+key+".raw").String()
		} else if gjson.Get(string(bodyAsBytes), "presentation.requested_proof.self_attested_attrs."+key).Exists() {
			value = gjson.Get(string(bodyAsBytes), "presentation.requested_proof.self_attested_attrs."+key).String()
		}
		presRequest, _ = sjson.Set(presRequest, "requested_attributes."+key+".value", value)
	}

	// Print Attributes
	requestedAttrs = gjson.Get(presRequest, "requested_attributes").Map()
	log.Info().Msgf("Requested Attributes")
	for key, val := range requestedAttrs {
		valMap := val.Map()
		name := valMap["name"].String()
		value := valMap["value"].String()
		log.Info().Msgf("- " + key + " - " + name + ": " + value)
	}

	// Print Predicates
	requestedPreds := gjson.Get(presRequest, "requested_predicates").Map()
	log.Info().Msgf("Requested Predicates")
	for key, val := range requestedPreds {
		valMap := val.Map()
		name := valMap["name"].String()
		pType := valMap["p_type"].String()
		pValue := valMap["p_value"].String()
		log.Info().Msgf("- " + key + " - " + name + ": " + pType + " " + pValue)
	}

	return nil
}
