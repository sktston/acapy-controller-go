/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Baegjae Sung (baegjae@gmail.com)     *
 * since July 28, 2020                            *
 **************************************************/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/skip2/go-qrcode"
	"github.com/sktston/acapy-controller-go/utils"
	"github.com/tidwall/gjson"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var (
	client                                       = resty.New()
	log                                          = utils.Log
	config                                       utils.ControllerConfig
	webhookUrl, did, verKey, schemaID, credDefID string
	stewardJwtToken, jwtToken, walletId          string

	version = strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99))
	walletName  = "faber." + version
	imageUrl    = "https://identicon-api.herokuapp.com/" + walletName + "/300?format=png"
	stewardSeed = "000000000000000000000000Steward1"
)

func main() {
	// Read faber-config.json file
	err := config.ReadConfig("./faber-config.json", "issuer-verifier")
	if err != nil { log.Fatal("ReadConfig() error:", err.Error()) }

	// Set debug mode
	utils.SetDebugMode(config.Debug)

	// Set client configuration
	client.SetTimeout(30 * time.Minute)
	client.SetHeader("Content-Type", "application/json")

	// Start web hook server
	httpServer, err := startWebHookServer()
	if err != nil { log.Fatal("startWebHookServer() error:", err.Error()) }
	defer func() { _ = shutdownWebHookServer(httpServer) }()

	// Start Faber
	err = provisionController()
	if err != nil { log.Fatal("provisionController() error:", err.Error()) }

	log.Info("Waiting web hook event from agent...")
	select {}
}

func startWebHookServer() (*http.Server, error) {
	// Set up http router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	router.GET("/invitation", createInvitation)
	router.GET("/invitation-url", createInvitationUrl)
	router.GET("/invitation-qr", createInvitationUrlQr)
	router.POST("/webhooks/topic/:topic", handleEvent)

	// Get port from webhookUrl
	if config.IssueOnly == true {
		webhookUrl = config.IssuerWebhookUrl
	} else if config.VerifyOnly == true {
		webhookUrl = config.VerifierWebhookUrl
	} else {
		webhookUrl = config.IssuerWebhookUrl
	}

	urlParse, _ := url.Parse(webhookUrl)
	_, port, _ := net.SplitHostPort(urlParse.Host)
	port = ":" + port

	// Start http server
	listener, err := net.Listen("tcp", port)
	if err != nil { log.Fatal("net.Listen() error:", err.Error()) }

	httpServer := &http.Server{
		Handler: router,
	}

	go func() {
		err = httpServer.Serve(listener)
		if err != nil { log.Fatal("httpServer.Serve() error:", err.Error()) }
	}()
	log.Info("Listen on http://" + utils.GetOutboundIP().String() + port)

	return httpServer, nil
}

func shutdownWebHookServer(httpServer *http.Server) error {
	// Shutdown http server gracefully
	err := httpServer.Shutdown(context.Background())
	if err != nil { log.Error("ttpServer.Shutdown() error:", err.Error()); return err }
	log.Info("Http server shutdown successfully")

	return nil
}

func provisionController() error {
	log.Info("Obtain jwtToken of steward")
	err := obtainStewardJwtToken()
	if err != nil { log.Error(err); return err }

	log.Info("Create wallet")
	err = createWallet()
	if err != nil { log.Error(err); return err }

	log.Info("Create a new did and register the did as an issuer")
	err = createPublicDid()
	if err != nil { log.Error(err); return err }

	log.Info("Create schema and credential definition")
	err = createSchema()
	if err != nil { log.Error(err); return err }
	err = createCredentialDefinition()
	if err != nil { log.Error(err); return err }

	log.Info("Configuration of faber:")
	log.Info("- wallet name: " + walletName)
	log.Info("- webhook url: " + webhookUrl)
	log.Info("- wallet ID: " + walletId)
	log.Info("- wallet type: " + config.WalletType)
	log.Info("- jwt token: " + jwtToken)
	log.Info("- did: " + did)
	log.Info("- verification key: " + verKey)
	log.Info("- schema ID: " + schemaID)
	log.Info("- credential definition ID: " + credDefID)

	log.Info("Initialization is done.")
	log.Info("Run alice now.")

	return nil
}

func createInvitation(ctx *gin.Context) {
	params := "?public="+strconv.FormatBool(config.PublicInvitation)
	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/connections/create-invitation"+params, jwtToken, []byte("{}"))
	if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
	log.Info("response: " + string(respAsBytes))

	invitation := gjson.Get(string(respAsBytes), "invitation").String()
	ctx.String(http.StatusOK, invitation)

	return
}

func createInvitationUrl(ctx *gin.Context) {
	params := "?public="+strconv.FormatBool(config.PublicInvitation)
	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/connections/create-invitation"+params, jwtToken, []byte("{}"))
	if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
	log.Info("response: " + string(respAsBytes))

	invitationUrl := gjson.Get(string(respAsBytes), "invitation_url").String()
	ctx.String(http.StatusOK, invitationUrl)

	return
}

func createInvitationUrlQr(ctx *gin.Context) {
	params := "?public="+strconv.FormatBool(config.PublicInvitation)
	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/connections/create-invitation"+params, jwtToken, []byte("{}"))
	if err != nil { utils.HttpError(ctx, http.StatusInternalServerError, err); return }
	log.Info("response: " + string(respAsBytes))

	invitationUrl := gjson.Get(string(respAsBytes), "invitation_url").String()

	// Modify qrcode.Low to qrcode.Medium/High for reliable error recovery
	qrCode, _ := qrcode.New(invitationUrl, qrcode.Low)
	qrCodeString := qrCode.ToSmallString(false)
	ctx.String(http.StatusOK, qrCodeString)

	return
}

func handleEvent(ctx *gin.Context) {
	var (
		topic, state string
		body         map[string]interface{}
		err          error
	)

	err = ctx.ShouldBindJSON(&body)
	if err != nil {
		log.Error("ShouldBindJSON() error:", err.Error())
		utils.HttpError(ctx, http.StatusBadRequest, err)
		return
	}

	topic = ctx.Param("topic")
	if val, ok := body["state"]; ok {
		state = val.(string)
	}

	switch topic {
	case "connections":
		// When connection with alice is done, send credential offer
		if state == "active" {
			if config.VerifyOnly == false {
				log.Info("- Case (topic:" + topic + ", state:" + state + ") -> sendCredentialOffer")
				err = sendCredentialOffer(body["connection_id"].(string))
				if err != nil {
					utils.HttpError(ctx, http.StatusInternalServerError, err)
					return
				}
			} else {
				log.Info("- Case (topic:" + topic + ", state:" + state + ") -> sendProofRequest")
				err = sendProofRequest(body["connection_id"].(string))
				if err != nil {
					utils.HttpError(ctx, http.StatusInternalServerError, err)
					return
				}
			}
		} else {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "issue_credential":
		// When credential is issued and acked, send proof(presentation) request
		if state == "credential_acked" {
			if config.SupportRevoke == true && config.RevokeAfterIssue == true {
				err = revokeCredential(body["revoc_reg_id"].(string), body["revocation_id"].(string))
				if err != nil {
					utils.HttpError(ctx, http.StatusInternalServerError, err)
					return
				}
			}

			if config.IssueOnly == false {
				log.Info("- Case (topic:" + topic + ", state:" + state + ") -> sendProofRequest")
				err = sendProofRequest(body["connection_id"].(string))
				if err != nil {
					utils.HttpError(ctx, http.StatusInternalServerError, err)
					return
				}
			}

		} else {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "present_proof":
		// When proof is verified, print the result
		if state == "verified" {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> Print result")
			bodyAsBytes, err := json.MarshalIndent(body, "", "")
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}
			err = validateProofResult(string(bodyAsBytes))
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}
		} else {
			log.Info("- Case (topic:topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "basicmessages":
		log.Info("- Case (topic:" + topic + ", state:" + state + ") -> Print message")
		log.Info("  - message:" + body["content"].(string))

	case "revocation_registry":
		log.Info("- Case (topic:" + topic + ", state:" + state + ") -> No action in demo")

	case "problem_report":
		bodyAsBytes, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			utils.HttpError(ctx, http.StatusInternalServerError, err)
			return
		}
		log.Warn("- Case (topic:" + topic + ") -> Print body")
		log.Warn("  - body:" + string(bodyAsBytes))

	default:
		log.Warn("- Warning Unexpected topic:" + topic)
	}

	return
}

func obtainStewardJwtToken() error {
	// check if steward wallet already exists
	stewardWallet := "steward"
	resp, err := client.R().
		SetQueryParam("wallet_name",stewardWallet).
		Get(config.AgentApiUrl+"/multitenancy/wallets")
	if err != nil { log.Error(err); return err }
	log.Info("response: ", resp)

	wallets := gjson.Get(resp.String(), "results").Array()
	if len(wallets) == 0 {
		// stewardWallet not exists -> create stewardWallet and get jwt token
		body := utils.JsonString(`{
			"wallet_name": "`+stewardWallet+`",
			"wallet_key": "`+stewardWallet+".key"+`",
			"wallet_type": "`+config.WalletType+`"
		}`)
		log.Info("Not found steward wallet - Create a new steward wallet: "+utils.PrettyJson(body))
		resp, err = client.R().
			SetBody(body).
			Post(config.AgentApiUrl+"/multitenancy/wallet")
		if err != nil { log.Error(err); return err }
		log.Info("response: ", resp)
		stewardJwtToken = gjson.Get(resp.String(), "token").String()

		body = utils.JsonString(`{ "seed": "`+stewardSeed+`" }`)
		log.Info("Create a steward did: "+utils.PrettyJson(body))
		resp, err = client.R().
			SetBody(body).
			SetAuthToken(stewardJwtToken).
			Post(config.AgentApiUrl+"/wallet/did/create")
		if err != nil { log.Error(err); return err }
		log.Info("response: ", resp)
		stewardDid := gjson.Get(resp.String(), "result.did").String()

		log.Info("Assign the did to public:"+stewardDid)
		resp, err = client.R().
			SetQueryParam("did", stewardDid).
			SetAuthToken(stewardJwtToken).
			Post(config.AgentApiUrl+"/wallet/did/public")
		if err != nil { log.Error(err); return err }
		log.Info("response: ", resp)
	} else {
		// stewardWallet exists -> get and return jwt token
		stewardWalletId := gjson.Get(wallets[0].String(), "wallet_id").String()
		log.Info("Found steward wallet - Get jwt token with wallet id: "+stewardWalletId)
		resp, err = client.R().
			Post(config.AgentApiUrl+"/multitenancy/wallet/"+stewardWalletId+"/token")
		if err != nil { log.Error(err); return err }
		log.Info("response: ", resp)
		stewardJwtToken = gjson.Get(resp.String(), "token").String()
	}
	return nil
}

func createWallet() error {
	body := utils.JsonString(`{
		"wallet_name": "`+walletName+`",
		"wallet_key": "`+walletName+".key"+`",
		"wallet_type": "`+config.WalletType+`",
		"label": "`+walletName+".label"+`",
		"image_url": "`+imageUrl+`",
		"wallet_webhook_urls": ["`+webhookUrl+`"]
	}`)
	log.Info("Create a new wallet:" + utils.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		Post(config.AgentApiUrl+"/multitenancy/wallet")
	if err != nil { log.Error(err); return err }
	log.Info("response: ", resp)
	walletId = gjson.Get(resp.String(), `settings.wallet\.id`).String()
	jwtToken = gjson.Get(resp.String(), "token").String()

	return nil
}

func createPublicDid() error {
	log.Info("Create a new random local did")
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/wallet/did/create")
	if err != nil { log.Error(err); return err }
	log.Info("response: ", resp)
	did = gjson.Get(resp.String(), "result.did").String()
	verKey = gjson.Get(resp.String(), "result.verkey").String()
	log.Info("created did: " + did + ", verkey: " + verKey)

	log.Info("Register the did to the ledger as a ENDORSER by steward")
	resp, err = client.R().
		SetQueryParam("did", did).
		SetQueryParam("verkey", verKey).
		SetQueryParam("alias", walletName).
		SetQueryParam("role", "ENDORSER").
		SetAuthToken(stewardJwtToken).
		Post(config.AgentApiUrl+"/ledger/register-nym")
	if err != nil { log.Error(err); return err }
	log.Info("response: ", resp)

	log.Info("Assign the did to public: "+did)
	resp, err = client.R().
		SetQueryParam("did", did).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/wallet/did/public")
	if err != nil { log.Error(err); return err }
	log.Info("response: ", resp)

	return nil
}

func createSchema() error {
	body := utils.JsonString(`{
		"schema_name": "degree_schema",
		"schema_version": "`+version+`",
		"attributes": ["name", "date", "degree", "age", "photo"]
	}`)
	log.Info("Create a new schema on the ledger:" + utils.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/schemas")
	if err != nil { log.Error(err); return err }
	log.Info("response: ", resp)
	schemaID = gjson.Get(resp.String(), "schema_id").String()

	return nil
}

func createCredentialDefinition() error {
	body := utils.JsonString(`{
		"schema_id": "`+schemaID+`",
		"tag": "tag.`+version+`",
		"support_revocation": `+strconv.FormatBool(config.SupportRevoke)+`,
		"revocation_registry_size": 10
	}`)
	log.Info("Create a new credential definition on the ledger:" + utils.PrettyJson(body))
	resp, err := client.R().
		SetBody(body).
		SetAuthToken(jwtToken).
		Post(config.AgentApiUrl+"/credential-definitions")
	if err != nil { log.Error(err); return err }
	log.Info("response: ", resp)
	credDefID = gjson.Get(resp.String(), "credential_definition_id").String()

	return nil
}

func sendCredentialOffer(connectionID string) error {
	log.Info("sendCredentialOffer >>> connectionID:" + connectionID)

	body := utils.PrettyJson(`{
		"connection_id":"`+connectionID+`",
		"cred_def_id"  :"`+credDefID+`",
		"credential_preview": {
			"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview",
			"attributes": [
				{ "name": "name", "value": "alice" },
				{ "name": "date", "value": "05-2018" },
				{ "name": "degree", "value": "maths" },
				{ "name": "age", "value": "25" }
			]
		}
	}`, "")

	_, err := utils.RequestPost(config.AgentApiUrl, "/issue-credential/send-offer", walletName, []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("sendCredentialOffer <<< done")
	return nil
}

func sendProofRequest(connectionID string) error {
	log.Info("sendCredentialOffer >>> connectionID:" + connectionID)

	body := utils.PrettyJson(`{
		"connection_id": "`+connectionID+`",
		"proof_request": {
			"name": "proof_name",
			"version": "1.0",
			"requested_attributes": {
				"attr_name": {
					"name": "name",
					"restrictions": [ { "schema_name": "degree_schema" } ]
				},
				"attr_date": {
					"name": "date",
					"restrictions": [ { "schema_name": "degree_schema" } ]
				},
				"attr_degree": {
					"name": "degree",
					"restrictions": [ { "schema_name": "degree_schema" } ]
				}
			},
			"requested_predicates": {
				"pred_age": {
					"name"        : "age",
					"p_type"      : ">=",
					"p_value"     : 20,
					"restrictions": [ { "schema_name": "degree_schema" } ]
				}
			}
		}
	}`, "")

	_, err := utils.RequestPost(config.AgentApiUrl, "/present-proof/send-request", walletName, []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("sendProofRequest <<< done")
	return nil
}

func revokeCredential(revRegId string, credRevId string) error {
	log.Info("revokeCredential >>> revRegId:" + revRegId + ", credRevId:" + credRevId)

	body := utils.PrettyJson(`{
		"rev_reg_id": "`+revRegId+`",
		"cred_rev_id": "`+credRevId+`",
		"publish": true
	}`, "")

	_, err := utils.RequestPost(config.AgentApiUrl, "/revocation/revoke", walletName, []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("revokeCredential <<< done")
	return nil
}

func validateProofResult(body string) error {
	log.Info("validateProofResult >>> start")

	requestedProof := gjson.Get(body, "presentation.requested_proof").String()
	if requestedProof == "" {
		return fmt.Errorf("requestedProof does not exist\nbody: %s: ", body)
	}
	log.Info("  - Proof requested:" + utils.PrettyJson(requestedProof))

	verified := gjson.Get(body, "verified").String()
	if verified == "" {
		return fmt.Errorf("verified does not exist\nbody: %s: ", body)
	}
	log.Info("  - Proof validation:" + verified)

	// Check validation result
	var (
		expected bool
	)

	result, err := strconv.ParseBool(verified)
	if err != nil {
		return fmt.Errorf("invalid boolean varified value: %s: ", verified)
	}

	if config.SupportRevoke == false {
		expected = true
	} else {
		if config.RevokeAfterIssue == true {
			expected = false
		} else {
			expected = true
		}
	}

	if expected != result {
		log.Error("\nSupportRevoke:", config.SupportRevoke,
			"\nRevokeAfterIssue:", config.RevokeAfterIssue,
			"\nExpected:", expected,
			"\nVerified:", result)
		return errors.New("verification fails")
	}

	log.Info("validateProofResult <<< done")
	return nil
}
