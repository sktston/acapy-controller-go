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
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"github.com/tidwall/gjson"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/sktston/acapy-controller-go/utils"
)

var (
	log                                          = utils.Log
	config                                       utils.ControllerConfig
	webhookUrl, did, verKey, schemaID, credDefID string

	version = strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99))
	adminWalletName = "admin"
	walletName      = "faber." + version
	imageUrl        = "https://identicon-api.herokuapp.com/" + walletName + "/300?format=png"
	seed            = strings.Replace(uuid.New().String(), "-", "", -1) // random seed 32 characters
)

func main() {
	// Read faber-config.yaml file
	err := config.ReadConfig("./faber-config.json", "issuer-verifier")
	if err != nil {
		log.Fatal(err.Error())
	}

	// Set debug mode
	utils.SetDebugMode(config.Debug)

	// Start web hook server
	httpServer, err := startWebHookServer()
	if err != nil {
		log.Fatal(err.Error())
	}
	defer func() { _ = shutdownWebHookServer(httpServer) }()

	// Start Faber
	err = initializeAfterStartup()
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Info("Waiting web hook event from agent...")
	select {}
}

func startWebHookServer() (*http.Server, error) {
	// Set up http router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	router.GET("/invitation", createInvitation)
	router.GET("/invitation-url", createInvitationUrlQr)
	router.GET("/invitation-qr", createInvitationUrlQr)
	router.POST("/webhooks/topic/:topic", handleMessage)

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
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	httpServer := &http.Server{
		Handler: router,
	}

	go func() {
		err = httpServer.Serve(listener)
		if err != nil {
			log.Fatal(err.Error())
		}
	}()
	log.Info("Listen on http://" + utils.GetOutboundIP().String() + port)

	return httpServer, nil
}

func shutdownWebHookServer(httpServer *http.Server) error {
	// Shutdown http server gracefully
	err := httpServer.Shutdown(context.Background())
	if err != nil {
		return err
	}
	log.Info("Http server shutdown successfully")

	return nil
}

func initializeAfterStartup() error {
	log.Info("Create wallet and did, register did as issuer, and register webhook url")
	err := createWalletAndDid()
	if err != nil {
		log.Error("createWalletAndDid() error:", err.Error())
		return err
	}

	if config.VerifyOnly == false {
		err = registerDidAsIssuer()
		if err != nil {
			log.Error("registerDidAsIssuer() error:", err.Error())
			return err
		}
	}

	if config.VerifyOnly == false {
		log.Info("Create schema and credential definition")
		err = createSchema()
		if err != nil {
			log.Error("createSchema() error:", err.Error())
			return err
		}

		err = createCredentialDefinition()
		if err != nil {
			log.Error("createCredDef() error:", err.Error())
			return err
		}
	}

	log.Info("Configuration of faber:")
	log.Info("- wallet name: " + walletName)
	log.Info("- seed: " + seed)
	log.Info("- did: " + did)
	log.Info("- verification key: " + verKey)
	log.Info("- webhook url: " + webhookUrl)
	log.Info("- schema ID: " + schemaID)
	log.Info("- credential definition ID: " + credDefID)

	log.Info("Initialization is done.")
	log.Info("Run alice now.")

	return nil
}

func createInvitation(ctx *gin.Context) {
	log.Info("createInvitation >>> start")

	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/connections/create-invitation", walletName, []byte("{}"))
	if err != nil {
		utils.HttpError(ctx, http.StatusInternalServerError, err)
		return
	}

	invitation := gjson.Get(string(respAsBytes), "invitation").String()
	if invitation == "" {
		utils.HttpError(ctx, http.StatusInternalServerError, errors.New("invitation is null"))
		return
	}

	log.Info("createInvitation <<< invitation:" + utils.PrettyJson(invitation))
	ctx.String(http.StatusOK, invitation)

	return
}

func createInvitationUrlQr(ctx *gin.Context) {
	log.Info("createInvitationUrl >>> start")

	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/connections/create-invitation", walletName, []byte("{}"))
	if err != nil {
		utils.HttpError(ctx, http.StatusInternalServerError, err)
		return
	}

	invitationURL := gjson.Get(string(respAsBytes), "invitation_url").String()
	if invitationURL == "" {
		utils.HttpError(ctx, http.StatusInternalServerError, errors.New("invitation is null"))
		return
	}

	// Generate QR code
	if ctx.FullPath() == "/invitation-qr" {
		// Modify qrcode.Low to qrcode.Medium/High for reliable error recovery
		qrCode, _ := qrcode.New(invitationURL, qrcode.Low)
		qrCodeString := qrCode.ToSmallString(false)
		invitationURL = qrCodeString
	}

	log.Info("createInvitationURL <<< invitationURL:\n" + invitationURL)
	ctx.String(http.StatusOK, invitationURL)

	return
}

func handleMessage(ctx *gin.Context) {
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
	if topic == "problem_report" {
		state = ""
	} else {
		state = body["state"].(string)
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
			err = printProofResult(string(bodyAsBytes))
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

func createWalletAndDid() error {
	log.Info("createWalletAndDid >>> start")

	body := utils.PrettyJson(`{
		"name": "`+walletName+`",
		"key": "`+walletName+".key"+`",
		"type": "indy",
		"label": "`+walletName+".label"+`",
		"image_url": "`+imageUrl+`",
		"webhook_urls": ["`+webhookUrl+`"]
	}`, "")

	log.Info("Create a new wallet:" + utils.PrettyJson(body))
	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/wallet", adminWalletName, []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}
	log.Info("response: " + utils.PrettyJson(string(respAsBytes), "  "))

	body = utils.PrettyJson(`{
		"seed": "`+seed+`"
	}`, "")

	log.Info("Create a new local did:" + utils.PrettyJson(body))
	respAsBytes, err = utils.RequestPost(config.AgentApiUrl, "/wallet/did/create", walletName, []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	did = gjson.Get(string(respAsBytes), "result.did").String()
	if did == "" {
		return fmt.Errorf("Did does not exist\nrespAsBytes: %s: ", string(respAsBytes))
	}

	verKey = gjson.Get(string(respAsBytes), "result.verkey").String()
	if verKey == "" {
		return fmt.Errorf("VerKey does not exist\nrespAsBytes: %s: ", string(respAsBytes))
	}
	log.Info("created did: " + did + ", verkey: " + verKey)

	log.Info("createWalletAndDid <<< done")
	return nil
}

func registerDidAsIssuer() error {
	log.Info("registerDidAsIssuer >>> start")

	params := "?did=" + did +
		"&verkey=" + verKey +
		"&alias=" + walletName +
		"&role=ENDORSER" +
		"&target_wallet=" + walletName

	log.Info("Register the did to the ledger as a ENDORSER")

	// did of admin wallet must have STEWARD role
	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/ledger/register-nym"+params, adminWalletName, []byte("{}"))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}
	log.Info("response: " + utils.PrettyJson(string(respAsBytes), "  "))

	params = "?did=" + did
	log.Info("Assign the did to public: " + did)

	respAsBytes, err = utils.RequestPost(config.AgentApiUrl, "/wallet/did/public"+params, walletName, []byte("{}"))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}
	log.Info("response: " + utils.PrettyJson(string(respAsBytes), "  "))

	log.Info("registerDidAsIssuer <<< done")
	return nil
}

func createSchema() error {
	log.Info("createSchema >>> start")

	body := utils.PrettyJson(`{
		"schema_name": "degree_schema",
		"schema_version": "`+version+`",
		"attributes": ["name", "date", "degree", "age"]
	}`, "")

	log.Info("Create a new schema on the ledger:" + utils.PrettyJson(body))
	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/schemas", walletName, []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	schemaID = gjson.Get(string(respAsBytes), "schema_id").String()
	if schemaID == "" {
		return fmt.Errorf("schemaID does not exist\nrespAsBytes: %s: ", string(respAsBytes))
	}

	log.Info("createSchema <<< done")
	return nil
}

func createCredentialDefinition() error {
	log.Info("createCredentialDefinition >>> start")

	body := utils.PrettyJson(`{
		"schema_id": "`+schemaID+`",
		"tag": "tag.`+version+`",
		"support_revocation": `+strconv.FormatBool(config.SupportRevoke)+`,
		"revocation_registry_size": 10
	}`, "")

	log.Info("Create a new credential definition on the ledger:" + utils.PrettyJson(body))
	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/credential-definitions", walletName, []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	credDefID = gjson.Get(string(respAsBytes), "credential_definition_id").String()
	if credDefID == "" {
		return fmt.Errorf("credDefID does not exist\nrespAsBytes: %s: ", string(respAsBytes))
	}

	log.Info("createCredentialDefinition <<< done")
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

	queryParam := url.Values{}
	queryParam.Add("rev_reg_id", revRegId)
	queryParam.Add("cred_rev_id", credRevId)
	queryParam.Add("publish", "true")

	URI := "/issue-credential/revoke" + "?" + queryParam.Encode()

	_, err := utils.RequestPost(config.AgentApiUrl, URI, walletName, []byte("{}"))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("revokeCredential <<< done")
	return nil
}

func printProofResult(body string) error {
	log.Info("printProofResult >>> start")

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

	log.Info("printProofResult <<< done")
	return nil
}
