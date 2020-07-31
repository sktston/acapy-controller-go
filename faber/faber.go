/**************************************************
 * Auther  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since July 28, 2020                            *
 **************************************************/

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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
	router *gin.Engine

	version, schemaID, credDefID, revRegID string
)

func main() {
	// Read faber-config.yaml file
	err := config.ReadConfig("./faber-config.json")
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	// Set debug mode
	utils.SetDebugMode(config.Debug)

	// Set up http router
	setupHttpRouter()

   // Start web server
	listener, err := net.Listen("tcp", config.WebHookPort)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	go func() {
		_ = http.Serve(listener, router)
	}()
	log.Info("Listen on http://" + utils.GetOutboundIP().String() + config.WebHookPort)

	// Initialize Faber
	err = initializeAfterStartup()
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	log.Info("Now, waiting web hook event from agency...")
	select {}

	return
}

func setupHttpRouter() {
	router = gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	router.GET("/invitation", createInvitation)
	router.GET("/invitation-url", createInvitationURL)
	router.POST("/webhooks/topic/:topic", handleMessage)

	return
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

	log.Info("createInvitationURL <<< invitationURL:" + invitationURL)
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
		"support_revocation": true
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

	body = utils.PrettyJson(`{
		"max_cred_num": 100,
		"credential_definition_id": "` + credDefID + `",
		"issuance_by_default": true
	}`, "")

	log.Info("Create a new revocation registry:" + utils.PrettyJson(body))
	respAsBytes, err = utils.RequestPost(config.AdminURL, "/revocation/create-registry", []byte(body), config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	revRegID = gjson.Get(string(respAsBytes), "result.revoc_reg_id").String()
	if revRegID == "" {
		return fmt.Errorf("revRegID does not exist\nrespAsBytes: %s: ", string(respAsBytes))
	}

	body = utils.PrettyJson(`{
		"tails_public_uri": "` + config.TailsServerURL + "/" + revRegID + `"
	}`, "")

	log.Info("Update tails file location of the revocation registry:" + utils.PrettyJson(body))
	_, err = utils.RequestPatch(config.AdminURL, "/revocation/registry/" + revRegID, []byte(body), config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestPatch() error:", err.Error())
		return err
	}

	log.Info("Publish the revocation registry on the ledger:")
	_, err = utils.RequestPost(config.AdminURL, "/revocation/registry/" + revRegID + "/publish", []byte("{}"), config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("Get tails file of the revocation registry:")
	tailsFileAsBytes, err := utils.RequestGETByteArray(config.AdminURL, "/revocation/registry/" + revRegID + "/tails-file", config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestGETByteArray() error:", err.Error())
		return err
	}

	log.Info("Get genesis file of the revocation registry:")
	genesisAsBytes, err :=  utils.RequestGet(config.VonNetworkURL, "/genesis", config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestGET() error:", err.Error())
		return err
	}

	log.Info("Put tails file to tails file server:")
	// make multipart form
	bodyBuffer := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyBuffer)

	// genesis field
	_ = writer.WriteField("genesis", string(genesisAsBytes))

	// tails field
	tailsWriter, _ := writer.CreateFormField("tails")
	_, _ = io.Copy(tailsWriter, bytes.NewBuffer(tailsFileAsBytes))

	_ = writer.Close()

	respAsBytes, err = utils.RequestPut(config.TailsServerURL, "/" + revRegID, bodyBuffer.Bytes(), config.HttpTimeout, "Content-Type:" + writer.FormDataContentType())
	if err != nil {
		log.Error("utils.RequestPut() error:", err.Error())
		return err
	}
	log.Info("respAsBytes:" + string(respAsBytes))

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