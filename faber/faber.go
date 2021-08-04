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
	"strconv"
	"time"

	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
	"github.com/sktston/acapy-controller-go/utils"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var (
	consoleWriter                                = zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	client                                       = resty.New()
	config                                       utils.ControllerConfig
	did, verKey, schemaID, credDefId string
	stewardJwtToken, jwtToken, walletId          string

	version = strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99))
	walletName  = "faber." + version
	imageUrl    = "https://identicon-api.herokuapp.com/" + walletName + "/300?format=png"
	stewardSeed = "000000000000000000000000Steward1"
)

func main() {
	// Setting log
	log.Logger = log.Output(consoleWriter)

	// Read faber-config.json file
	err := config.ReadConfig("./faber-config.json")
	if err != nil { log.Fatal().Err(err).Msg("") }

	// Set log level debug
	utils.SetLogLevelDebug(config.Debug)

	// Set client configuration
	client.SetTimeout(30 * time.Minute)
	client.SetHeader("Content-Type", "application/json")

	// Start web hook server
	httpServer, err := startWebHookServer()
	if err != nil { log.Fatal().Err(err).Msg("") }
	defer func() { _ = shutdownWebHookServer(httpServer) }()

	// Start Faber
	err = provisionController()
	if err != nil { log.Fatal().Err(err).Msg("") }

	log.Info().Msg("Waiting web hook event from agent...")
	select {}
}

func startWebHookServer() (*http.Server, error) {
	// Set up http router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(logger.SetLogger(logger.WithWriter(consoleWriter)))

	router.GET("/invitation", createInvitation)
	router.GET("/invitation-url", createInvitationUrl)
	router.GET("/invitation-qr", createInvitationUrlQr)
	router.POST("/webhooks/topic/:topic", handleEvent)

	// Get port from HolderWebhookUrl
	urlParse, _ := url.Parse(config.IssuerWebhookUrl)
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
	log.Info().Msg("Obtain jwtToken of steward")
	err := obtainStewardJwtToken()
	if err != nil { log.Error().Err(err).Msg(""); return err }

	log.Info().Msg("Create wallet")
	err = createWallet()
	if err != nil { log.Error().Err(err).Msg(""); return err }

	log.Info().Msg("Create a new did and register the did as an issuer")
	err = createPublicDid()
	if err != nil { log.Error().Err(err).Msg(""); return err }

	log.Info().Msg("Create schema and credential definition")
	err = createSchema()
	if err != nil { log.Error().Err(err).Msg(""); return err }
	err = createCredentialDefinition()
	if err != nil { log.Error().Err(err).Msg(""); return err }

	log.Info().Msg("Configuration of faber:")
	log.Info().Msg("- wallet name: " + walletName)
	log.Info().Msg("- webhook url: " + config.IssuerWebhookUrl)
	log.Info().Msg("- wallet ID: " + walletId)
	log.Info().Msg("- wallet type: " + config.WalletType)
	log.Info().Msg("- jwt token: " + jwtToken)
	log.Info().Msg("- did: " + did)
	log.Info().Msg("- verification key: " + verKey)
	log.Info().Msg("- schema ID: " + schemaID)
	log.Info().Msg("- credential definition ID: " + credDefId)

	log.Info().Msg("Initialization is done.")
	log.Info().Msg("Run alice now.")

	return nil
}

func requestCreateInvitation() (*resty.Response, error) {
	return client.R().
		SetQueryParam("public", strconv.FormatBool(config.PublicInvitation)).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/connections/create-invitation")
}
func createInvitation(ctx *gin.Context) {
	resp, err := requestCreateInvitation()
	if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
	log.Info().Msg("response: "+resp.String())

	invitation := gjson.Get(resp.String(), "invitation").String()
	log.Info().Msg("createInvitation: "+invitation)
	ctx.String(http.StatusOK, invitation)

	return
}

func createInvitationUrl(ctx *gin.Context) {
	resp, err := requestCreateInvitation()
	if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
	log.Info().Msg("response: "+resp.String())

	invitationUrl := gjson.Get(resp.String(), "invitation_url").String()
	log.Info().Msg("createInvitationUrl: "+invitationUrl)
	ctx.String(http.StatusOK, invitationUrl)

	return
}

func createInvitationUrlQr(ctx *gin.Context) {
	resp, err := requestCreateInvitation()
	if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
	log.Info().Msg("response: "+resp.String())

	invitationUrl := gjson.Get(resp.String(), "invitation_url").String()
	log.Info().Msg("createInvitationUrlQr: "+invitationUrl)
	// Modify qrcode.Low to qrcode.Medium/High for reliable error recovery
	qrCode, _ := qrcode.New(invitationUrl, qrcode.Low)
	qrCodeString := qrCode.ToSmallString(false)
	ctx.String(http.StatusOK, qrCodeString)

	return
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
	case "issue_credential":
		if state == "proposal_received" {
			log.Info().Msg("- Case (topic:" + topic + ", state:" + state + ") -> sendCredentialOffer()")

			err = sendCredentialOffer(body["credential_exchange_id"].(string))
			if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
		} else if state == "credential_acked" {
			log.Info().Msg("- Case (topic:" + topic + ", state:" + state + ") -> issue credential successfully")

			if config.RevokeAfterIssue {
				log.Info().Msg("- RevokeAfterIssue is true -> revokeCredential()")
				err = revokeCredential(body["credential_exchange_id"].(string))
				if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
			}
		}

	case "present_proof":
		if state == "proposal_received" {
			log.Info().Msg("- Case (topic:" + topic + ", state:" + state + ") -> sendProofRequest()")

			err = sendProofRequest(body["connection_id"].(string))
			if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
		} else if state == "verified" {
			log.Info().Msg("- Case (topic:" + topic + ", state:" + state + ") -> printProofResult()")

			err = printProofResult(body)
			if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
		}

	case "connections":
	case "basicmessages":
	case "revocation_registry":
	case "problem_report":
	case "issuer_cred_rev":

	default:
		log.Warn().Msg("- Warning Unexpected topic:" + topic)
	}

	return
}

func obtainStewardJwtToken() error {
	// check if steward wallet already exists
	stewardWallet := "steward"
	resp, err := client.R().
		SetQueryParam("wallet_name",stewardWallet).
		Get(config.AgentApiUrl+"/multitenancy/wallets")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	wallets := gjson.Get(resp.String(), "results").Array()
	if len(wallets) == 0 {
		// stewardWallet not exists -> create stewardWallet and get jwt token
		body := `{
			"wallet_name": "`+stewardWallet+`",
			"wallet_key": "`+stewardWallet+".key"+`",
			"wallet_type": "`+config.WalletType+`"
		}`
		log.Info().Msg("Not found steward wallet - Create a new steward wallet: "+utils.PrettyJson(body))
		resp, err = client.R().
			SetBody(body).
			Post(config.AgentApiUrl+"/multitenancy/wallet")
		if err != nil { log.Error().Err(err).Msg(""); return err }
		log.Info().Msg("response: "+resp.String())
		stewardJwtToken = gjson.Get(resp.String(), "token").String()

		body = `{ "seed": "`+stewardSeed+`" }`
		log.Info().Msg("Create a steward did: "+utils.PrettyJson(body))
		resp, err = client.R().
			SetBody(body).
			SetAuthToken(stewardJwtToken).
			Post(config.AgentApiUrl+"/wallet/did/create")
		if err != nil { log.Error().Err(err).Msg(""); return err }
		log.Info().Msg("response: "+resp.String())
		stewardDid := gjson.Get(resp.String(), "result.did").String()

		log.Info().Msg("Assign the did to public:"+stewardDid)
		resp, err = client.R().
			SetQueryParam("did", stewardDid).
			SetAuthToken(stewardJwtToken).
			Post(config.AgentApiUrl+"/wallet/did/public")
		if err != nil { log.Error().Err(err).Msg(""); return err }
		log.Info().Msg("response: "+resp.String())
	} else {
		// stewardWallet exists -> get and return jwt token
		stewardWalletId := gjson.Get(wallets[0].String(), "wallet_id").String()
		log.Info().Msg("Found steward wallet - Get jwt token with wallet id: "+stewardWalletId)
		resp, err = client.R().
			Post(config.AgentApiUrl+"/multitenancy/wallet/"+stewardWalletId+"/token")
		if err != nil { log.Error().Err(err).Msg(""); return err }
		log.Info().Msg("response: "+resp.String())
		stewardJwtToken = gjson.Get(resp.String(), "token").String()
	}
	return nil
}

func createWallet() error {
	body := `{
		"wallet_name": "`+walletName+`",
		"wallet_key": "`+walletName+".key"+`",
		"wallet_type": "`+config.WalletType+`",
		"label": "`+walletName+".label"+`",
		"image_url": "`+imageUrl+`",
		"wallet_webhook_urls": ["`+config.IssuerWebhookUrl+`"]
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

func createPublicDid() error {
	log.Info().Msg("Create a new random local did")
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/wallet/did/create")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())
	did = gjson.Get(resp.String(), "result.did").String()
	verKey = gjson.Get(resp.String(), "result.verkey").String()
	log.Info().Msg("created did: " + did + ", verkey: " + verKey)

	log.Info().Msg("Register the did to the ledger as a ENDORSER by steward")
	resp, err = client.R().
		SetQueryParam("did", did).
		SetQueryParam("verkey", verKey).
		SetQueryParam("alias", walletName).
		SetQueryParam("role", "ENDORSER").
		SetAuthToken(stewardJwtToken).
		Post(config.AgentApiUrl+"/ledger/register-nym")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	log.Info().Msg("Assign the did to public: "+did)
	resp, err = client.R().
		SetQueryParam("did", did).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/wallet/did/public")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	return nil
}

func createSchema() error {
	body := `{
		"schema_name": "degree_schema",
		"schema_version": "`+version+`",
		"attributes": ["name", "date", "degree", "age", "photo"]
	}`
	log.Info().Msg("Create a new schema on the ledger:" + utils.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/schemas")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())
	schemaID = gjson.Get(resp.String(), "schema_id").String()

	return nil
}

func createCredentialDefinition() error {
	body := `{
		"schema_id": "`+schemaID+`",
		"tag": "tag.`+version+`",
		"support_revocation": true,
		"revocation_registry_size": 10
	}`
	log.Info().Msg("Create a new credential definition on the ledger:" + utils.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/credential-definitions")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())
	credDefId = gjson.Get(resp.String(), "credential_definition_id").String()

	return nil
}

func sendCredentialOffer(credExId string) error {
	encodedImage := "base64EncodedJpegImage"

	body := `{
		"counter_proposal": {
			"cred_def_id"  :"`+ credDefId +`",
			"credential_proposal": {
				"attributes": [
					{ "name": "name", "value": "alice" },
					{ "name": "date", "value": "05-2018" },
					{ "name": "degree", "value": "maths" },
					{ "name": "age", "value": "25" },
					{ "name": "photo", "value": "`+encodedImage+`", "mime-type": "image/jpeg" }
				]
			}
		}
	}`
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/issue-credential/records/"+credExId+"/send-offer")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	return nil
}

func sendProofRequest(connectionId string) error {
	curUnixTime := strconv.FormatInt(time.Now().Unix(), 10)

	body := `{
		"connection_id": "`+connectionId+`",
		"proof_request": {
			"name": "proof_name",
			"version": "1.0",
			"requested_attributes": {
				"attr_name": {
					"name": "name",
					"non_revoked": { "from": 0, "to": `+curUnixTime+` },
					"restrictions": [ { "cred_def_id": "`+credDefId+`" } ]
				},
				"attr_date": {
					"name": "date",
					"non_revoked": { "from": 0, "to": `+curUnixTime+` },
					"restrictions": [ { "cred_def_id": "`+credDefId+`" } ]
				},
				"attr_degree": {
					"name": "degree",
					"non_revoked": { "from": 0, "to": `+curUnixTime+` },
					"restrictions": [ { "cred_def_id": "`+credDefId+`" } ]
				},
				"attr_photo": {
					"name": "photo",
					"non_revoked": { "from": 0, "to": `+curUnixTime+` },
					"restrictions": [ { "cred_def_id": "`+credDefId+`" } ]
				}
			},
			"requested_predicates": {
				"pred_age": {
					"name": "age",
					"p_type": ">=",
					"p_value": 20,
					"non_revoked": { "from": 0, "to": `+curUnixTime+` },
					"restrictions": [ { "cred_def_id": "`+credDefId+`" } ]
				}
			}
		}
	}`
	log.Info().Msg("body: "+body)
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/present-proof/send-request")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	return nil
}

func revokeCredential(credExId string) error {
	body := `{
		"cred_ex_id": "`+credExId+`",
		"publish": true
	}`
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/revocation/revoke")
	if err != nil { log.Error().Err(err).Msg(""); return err }
	log.Info().Msg("response: "+resp.String())

	return nil
}

func printProofResult(body map[string]interface{}) error {
	if body["verified"] != "true" {
		log.Warn().Msg("proof is not verified")
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
	log.Info().Msg("Requested Attributes")
	for key, val := range requestedAttrs {
		valMap := val.Map()
		name := valMap["name"].String()
		value := valMap["value"].String()
		log.Info().Msg("- "+key+" - "+name+": "+value)
	}

	// print Predicates
	requestedPreds := gjson.Get(presRequest, "requested_predicates").Map()
	log.Info().Msg("Requested Predicates")
	for key, val := range requestedPreds {
		valMap := val.Map()
		name := valMap["name"].String()
		pType := valMap["p_type"].String()
		pValue := valMap["p_value"].String()
		log.Info().Msg("- "+key+" - "+name+": "+pType+" "+pValue)
	}

	return nil
}
