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
	"github.com/skip2/go-qrcode"
	"github.com/sktston/acapy-controller-go/util"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	client                                     = resty.New()
	did, verKey, schemaId, credDefId, walletId string
	agentApiUrl, stewardJwtToken, jwtToken     string

	version = strconv.Itoa(util.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(util.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(util.GetRandomInt(1, 99))
	walletName  = "faber." + version
	imageUrl    = "https://identicon-api.herokuapp.com/" + walletName + "/300?format=png"
	stewardSeed = "000000000000000000000000Steward1"

	//go:embed faber-config.yaml
	config []byte
)


func main() {
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

	// Start web hook server
	httpServer, err := startWebHookServer()
	if err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}
	defer func() {
		if err := shutdownWebHookServer(httpServer); err != nil {
			log.Fatal().Err(err).Caller().Msgf("")
		}
	}()

	// Start Faber
	if err := provisionController(); err != nil {
		log.Fatal().Err(err).Caller().Msgf("")
	}

	log.Info().Msgf("Waiting web hook event from agent...")
	select {}
}

func startWebHookServer() (*http.Server, error) {
	// Set up http router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logger.SetLogger(logger.WithWriter(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})))

	router.GET("/invitation", createInvitation)
	router.GET("/invitation-url", createInvitationUrl)
	router.GET("/invitation-qr", createInvitationUrlQr)
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
	log.Info().Msgf("Obtain jwtToken of steward")

	if err := obtainStewardJwtToken(); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}

	log.Info().Msgf("Create wallet")
	if err := createWallet(); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}

	log.Info().Msgf("Create a new did and register the did as an issuer")
	if err := createPublicDid(); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}

	log.Info().Msgf("Create schema and credential definition")
	if err := createSchema(); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	if err := createCredentialDefinition(); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}

	log.Info().Msgf("Configuration of faber:")
	log.Info().Msgf("- wallet name: " + walletName)
	log.Info().Msgf("- webhook url: " + viper.GetString("server-webhook-url"))
	log.Info().Msgf("- wallet ID: " + walletId)
	log.Info().Msgf("- wallet type: " + viper.GetString("wallet-type"))
	log.Info().Msgf("- jwt token: " + jwtToken)
	log.Info().Msgf("- did: " + did)
	log.Info().Msgf("- verification key: " + verKey)
	log.Info().Msgf("- schema ID: " + schemaId)
	log.Info().Msgf("- credential definition ID: " + credDefId)

	log.Info().Msgf("Initialization is done.")
	log.Info().Msgf("Run alice now.")

	return nil
}

func requestCreateInvitation() (*resty.Response, error) {
	body := `{
			"handshake_protocols": [ "connections/1.0" ],
			"use_public_did": ` + viper.GetString("public-invitation") + `
		}`
	return client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/out-of-band/create-invitation")
}

func createInvitation(c *gin.Context) {
	resp, err := requestCreateInvitation()
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Info().Msgf("response: " + resp.String())

	invitation := gjson.Get(resp.String(), "invitation").String()
	log.Info().Msgf("createInvitation: " + invitation)
	c.String(http.StatusOK, invitation)
}

func createInvitationUrl(c *gin.Context) {
	resp, err := requestCreateInvitation()
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Info().Msgf("response: " + resp.String())

	invitationUrl := gjson.Get(resp.String(), "invitation_url").String()
	log.Info().Msgf("createInvitationUrl: " + invitationUrl)
	c.String(http.StatusOK, invitationUrl)
}

func createInvitationUrlQr(c *gin.Context) {
	resp, err := requestCreateInvitation()
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Info().Msgf("response: " + resp.String())

	invitationUrl := gjson.Get(resp.String(), "invitation_url").String()
	log.Info().Msgf("createInvitationUrlQr: " + invitationUrl)

	// Modify qrcode.Low to qrcode.Medium/High for reliable error recovery
	qrCode, _ := qrcode.New(invitationUrl, qrcode.Low)
	qrCodeString := qrCode.ToSmallString(false)
	c.String(http.StatusOK, qrCodeString)
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
	case "issue_credential":
		if state == "proposal_received" {
			log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> sendCredentialOffer()")

			if err := sendCredentialOffer(body["credential_exchange_id"].(string)); err != nil {
				log.Error().Err(err).Caller().Msgf("")
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		} else if state == "credential_acked" {
			log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> issue credential successfully")

			if viper.GetBool("revoke-after-issue") {
				log.Info().Msgf("- revoke-after-issue is true -> revokeCredential()")

				if err := revokeCredential(body["credential_exchange_id"].(string)); err != nil {
					log.Error().Err(err).Caller().Msgf("")
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
			}
		}

	case "present_proof":
		if state == "proposal_received" {
			log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> sendProofRequest()")

			if err := sendProofRequest(body["connection_id"].(string)); err != nil {
				log.Error().Err(err).Caller().Msgf("")
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		} else if state == "verified" {
			log.Info().Msgf("- Case (topic:" + topic + ", state:" + state + ") -> printProofResult()")

			if err := printProofResult(body); err != nil {
				log.Error().Err(err).Caller().Msgf("")
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}

	case "connections":
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

func obtainStewardJwtToken() error {
	// check if steward wallet already exists
	stewardWallet := "steward"
	resp, err := client.R().
		SetQueryParam("wallet_name", stewardWallet).
		Get(agentApiUrl + "/multitenancy/wallets")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

	wallets := gjson.Get(resp.String(), "results").Array()
	if len(wallets) == 0 {
		// stewardWallet not exists -> create stewardWallet and get jwt token
		body := `{
			"wallet_name": "` + stewardWallet + `",
			"wallet_key": "` + stewardWallet + ".key" + `",
			"wallet_type": "` + viper.GetString("wallet-type") + `"
		}`
		log.Info().Msgf("Not found steward wallet - Create a new steward wallet: " + util.PrettyJson(body))
		resp, err = client.R().
			SetBody(body).
			Post(agentApiUrl + "/multitenancy/wallet")
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
		log.Info().Msgf("response: " + resp.String())
		stewardJwtToken = gjson.Get(resp.String(), "token").String()

		body = `{ "seed": "` + stewardSeed + `" }`
		log.Info().Msgf("Create a steward did: " + util.PrettyJson(body))
		resp, err = client.R().
			SetBody(body).
			SetAuthToken(stewardJwtToken).
			Post(agentApiUrl + "/wallet/did/create")
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
		log.Info().Msgf("response: " + resp.String())
		stewardDid := gjson.Get(resp.String(), "result.did").String()

		log.Info().Msgf("Assign the did to public:" + stewardDid)
		resp, err = client.R().
			SetQueryParam("did", stewardDid).
			SetAuthToken(stewardJwtToken).
			Post(agentApiUrl + "/wallet/did/public")
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
		log.Info().Msgf("response: " + resp.String())
	} else {
		// stewardWallet exists -> get and return jwt token
		stewardWalletId := gjson.Get(wallets[0].String(), "wallet_id").String()
		log.Info().Msgf("Found steward wallet - Get jwt token with wallet id: " + stewardWalletId)
		resp, err = client.R().
			Post(agentApiUrl + "/multitenancy/wallet/" + stewardWalletId + "/token")
		if err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
		log.Info().Msgf("response: " + resp.String())
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
		"image_url": "` + imageUrl + `",
		"wallet_webhook_urls": ["` + viper.GetString("server-webhook-url") + `"]
	}`
	log.Info().Msgf("Create a new wallet" + util.PrettyJson(body))
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

func createPublicDid() error {
	log.Info().Msgf("Create a new random local did")
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/wallet/did/create")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())
	did = gjson.Get(resp.String(), "result.did").String()
	verKey = gjson.Get(resp.String(), "result.verkey").String()
	log.Info().Msgf("created did: " + did + ", verkey: " + verKey)

	log.Info().Msgf("Register the did to the ledger as a ENDORSER by steward")
	resp, err = client.R().
		SetQueryParam("did", did).
		SetQueryParam("verkey", verKey).
		SetQueryParam("alias", walletName).
		SetQueryParam("role", "ENDORSER").
		SetAuthToken(stewardJwtToken).
		Post(agentApiUrl + "/ledger/register-nym")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

	log.Info().Msgf("Assign the did to public: " + did)
	resp, err = client.R().
		SetQueryParam("did", did).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/wallet/did/public")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

	return nil
}

func createSchema() error {
	body := `{
		"schema_name": "degree_schema",
		"schema_version": "` + version + `",
		"attributes": ["name", "date", "degree", "age", "photo"]
	}`
	log.Info().Msgf("Create a new schema on the ledger:" + util.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/schemas")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())
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
	log.Info().Msgf("Create a new credential definition on the ledger:" + util.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/credential-definitions")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())
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
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/issue-credential/records/" + credExId + "/send-offer")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

	return nil
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
	log.Info().Msgf("body: " + body)
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/present-proof/send-request")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

	return nil
}

func revokeCredential(credExId string) error {
	body := `{
		"cred_ex_id": "` + credExId + `",
		"publish": true
	}`
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(agentApiUrl + "/revocation/revoke")
	if err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}
	log.Info().Msgf("response: " + resp.String())

	return nil
}

func printProofResult(body map[string]interface{}) error {
	if body["verified"] != "true" {
		log.Warn().Msgf("proof is not verified")
		return nil
	}

	bodyAsBytes, _ := json.Marshal(body)

	presRequest := gjson.Get(string(bodyAsBytes), "presentation_request").String()

	// add revealed value to presRequest
	requestedAttrs := gjson.Get(presRequest, "requested_attributes").Map()
	for key, _ := range requestedAttrs {
		value := "unrevealed"
		if gjson.Get(string(bodyAsBytes), "presentation.requested_proof.revealed_attrs."+key).Exists() {
			value = gjson.Get(string(bodyAsBytes), "presentation.requested_proof.revealed_attrs."+key+".raw").String()
		}
		presRequest, _ = sjson.Set(presRequest, "requested_attributes."+key+".value", value)
	}

	// print Attributes
	requestedAttrs = gjson.Get(presRequest, "requested_attributes").Map()
	log.Info().Msgf("Requested Attributes")
	for key, val := range requestedAttrs {
		valMap := val.Map()
		name := valMap["name"].String()
		value := valMap["value"].String()
		log.Info().Msgf("- " + key + " - " + name + ": " + value)
	}

	// print Predicates
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
