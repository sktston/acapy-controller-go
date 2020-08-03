/**************************************************
 * Auther  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since July 28, 2020                            *
 **************************************************/

package main

import (
	"encoding/json"
	"fmt"
	"github.com/skip2/go-qrcode"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"

	"github.com/sktston/acapy-controller-go/utils"
)

var (
	log    = utils.Log
	config utils.ControllerConfig
	version, schemaID, credDefID string
)

func main() {
	// Read faber-config.yaml file
	err := config.ReadConfig("./faber-config.json")
	if err != nil {
		log.Fatal(err.Error())
	}

	// Set debug mode
	utils.SetDebugMode(config.Debug)

	// Set up http router
	router := setupHttpRouter()

	// Start http server
	listener, err := net.Listen("tcp", config.WebHookPort)
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
	log.Info("Listen on http://" + utils.GetOutboundIP().String() + config.WebHookPort)

	// Initialize Faber
	err = initializeAfterStartup()
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Info("Waiting web hook event from agent...")
	select {}

	return
}

func setupHttpRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	router.GET("/invitation", createInvitation)
	router.GET("/invitation-url", createInvitationURL)
	router.POST("/webhooks/topic/:topic", handleMessage)

	return router
}

func initializeAfterStartup() error {
	log.Info("initializeAfterStartup >>> start")

	respAsBytes, err := utils.RequestGet(config.AdminURL, "/credential-definitions/created", config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestGet() error:", err.Error())
		return err
	}

	credDefIDs := gjson.Get(string(respAsBytes), "credential_definition_ids")
	if len(credDefIDs.Array()) == 0 {
		log.Info("Agent does not have credential definition -> Create it")
		version = strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
			strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
			strconv.Itoa(utils.GetRandomInt(1, 99))

		err = createSchema()
		if err != nil {
			log.Error("createSchema() error:", err.Error())
			return err
		}

		err = createCredDef()
		if err != nil {
			log.Error("createCredDef() error:", err.Error())
			return err
		}
	} else {
		log.Info("Agent has credential definitions -> Use first one")
		credDefID = credDefIDs.Array()[0].String()
	}

	log.Info("Controller uses below configuration")
	log.Info("- credential definition ID:" + credDefID)

	log.Info("initializeAfterStartup <<< done")
	log.Info("Setting of schema and credential definition is done. Run alice now.")

	return nil
}

func createInvitation(ctx *gin.Context) {
	log.Info("createInvitation >>> start")

	respAsBytes, err := utils.RequestPost(config.AdminURL, "/connections/create-invitation", []byte("{}"), config.HttpTimeout)
	if err != nil {
		utils.HttpError(ctx, http.StatusInternalServerError, err)
		return
	}

	invitation := gjson.Get(string(respAsBytes), "invitation").String()
	if invitation == "" {
		utils.HttpError(ctx, http.StatusInternalServerError, err)
		return
	}

	log.Info("createInvitation <<< invitation:" + utils.PrettyJson(invitation))
	ctx.String(http.StatusOK, invitation)

	return
}

func createInvitationURL(ctx *gin.Context) {
	log.Info("createInvitationUrl >>> start")

	respAsBytes, err := utils.RequestPost(config.AdminURL, "/connections/create-invitation", []byte("{}"), config.HttpTimeout)
	if err != nil {
		utils.HttpError(ctx, http.StatusInternalServerError, err)
		return
	}

	invitationURL := gjson.Get(string(respAsBytes), "invitation_url").String()
	if invitationURL == "" {
		utils.HttpError(ctx, http.StatusInternalServerError, err)
		return
	}

	// Generate QR code
	if config.GenerateQR {
		// Modify qrcode.Low to qrcode.Medium/High for reliable error recovery
		qrCode, _ := qrcode.New(invitationURL, qrcode.Low)
		qrCodeString := qrCode.ToSmallString(false)
		invitationURL = qrCodeString + "\n" + invitationURL
	}

	log.Info("createInvitationURL <<< invitationURL:\n" + invitationURL)
	ctx.String(http.StatusOK, invitationURL)

	return
}

func handleMessage(ctx *gin.Context) {
	var (
		topic, state string
		body map[string]interface{}
		err error
	)

	err = ctx.ShouldBindJSON(&body)
	if err != nil {
		utils.HttpError(ctx, http.StatusBadRequest, err)
		return
	}

	topic = ctx.Param("topic")
	state = body["state"].(string)

	switch topic {
	case "connections":
		// When connection with alice is done, send credential offer
		if state == "active" {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> sendCredentialOffer")
			err = sendCredentialOffer(body["connection_id"].(string))
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}
		} else {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "issue_credential":
		// When credential is issued and acked, send proof(presentation) request
		if state == "credential_acked" {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> sendProofRequest")
			if config.EnableRevoke == true {
				err = revokeCredential(body["revoc_reg_id"].(string), body["revocation_id"].(string))
				if err != nil {
					utils.HttpError(ctx, http.StatusInternalServerError, err)
					return
				}
			}
			err = sendProofRequest(body["connection_id"].(string))
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
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

	default:
		log.Warn("- Warning Unexpected topic:" + topic)
	}

	return
}

func createSchema() error {
	log.Info("createSchema >>> start")

	body := utils.PrettyJson(`{
		"schema_name": "degree_schema",
		"schema_version": "` + version + `",
		"attributes": ["name", "date", "degree", "age"]
	}`, "")

	log.Info("Create a new schema on the ledger:" + utils.PrettyJson(body))
	respAsBytes, err := utils.RequestPost(config.AdminURL, "/schemas", []byte(body), config.HttpTimeout)
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

func createCredDef()  error {
	log.Info("createCredDef >>> start")

	body := utils.PrettyJson(`{
		"schema_id": "` + schemaID + `",
		"tag": "tag.` + version + `",
		"support_revocation": true,
		"revocation_registry_size": 50
	}`, "")

	log.Info("Create a new credential definition on the ledger:" + utils.PrettyJson(body))
	respAsBytes, err := utils.RequestPost(config.AdminURL, "/credential-definitions", []byte(body), config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	credDefID = gjson.Get(string(respAsBytes), "credential_definition_id").String()
	if credDefID == "" {
		return fmt.Errorf("credDefID does not exist\nrespAsBytes: %s: ", string(respAsBytes))
	}

	log.Info("createCredDef <<< done")
	return nil
}

func sendCredentialOffer(connectionID string) error {
	log.Info("sendCredentialOffer >>> connectionID:" + connectionID)

	body := utils.PrettyJson(`{
		"connection_id":"` + connectionID + `",
		"cred_def_id"  :"` + credDefID + `",
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

	_, err := utils.RequestPost(config.AdminURL, "/issue-credential/send-offer", []byte(body), config.HttpTimeout)
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
		"connection_id": "` + connectionID + `",
		"proof_request": {
			"name": "proof_name",
			"version": "1.0",
			"requested_attributes": {
				"attr_name": {
					"name": "name",
					"restrictions": [ { "cred_def_id": "` + credDefID + `" } ]
				},
				"attr_date": {
					"name": "date",
					"restrictions": [ { "cred_def_id": "` + credDefID + `" } ]
				},
				"attr_degree": {
					"name": "degree",
					"restrictions": [ { "cred_def_id": "` + credDefID + `" } ]
				}
			},
			"requested_predicates": {
				"pred_age": {
					"name"        : "age",
					"p_type"      : ">=",
					"p_value"     : 20,
					"restrictions": [ { "cred_def_id": "` + credDefID + `" } ]
				}
			}
		}
	}`, "")

	_, err := utils.RequestPost(config.AdminURL, "/present-proof/send-request", []byte(body), config.HttpTimeout)
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

	_, err := utils.RequestPost(config.AdminURL, URI, []byte("{}"), config.HttpTimeout)
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