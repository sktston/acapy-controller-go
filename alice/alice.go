/**************************************************
 * Auther  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since July 28, 2020                            *
 **************************************************/

package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sktston/acapy-controller-go/utils"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"net"
	"net/http"
	"os"
	"time"
)

var (
	log    = utils.Log
	config utils.ControllerConfig
	router *gin.Engine

	exitFlag = make(chan bool)
)

func main() {
	// Read faber-config.yaml file
	err := config.ReadConfig("./alice-config.json")
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

	// Initialize Alice
	err = initializeAfterStartup()
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	log.Info("Waiting web hook event from agent...")
	select {
	case <-exitFlag:
		// Wait completion of sending last http response (present_proof, presentation_acked)
		time.Sleep(time.Millisecond * 500)
		break
	}

	return
}

func setupHttpRouter() {
	router = gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	router.POST("/webhooks/topic/:topic", handleMessage)

	return
}

func initializeAfterStartup() error {
	log.Info("initializeAfterStartup >>> start")

	err := receiveInvitation()
	if err != nil {
		return err
	}

	log.Info("initializeAfterStartup <<< done")
	return nil
}

func receiveInvitation() error {
	log.Info("receiveInvitation >>> start")

	inviteAsBytes, err := utils.RequestGet(config.FaberContURL, "/invitation", config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestGet() error", err.Error())
		return err
	}
	log.Info("invitation:" + string(inviteAsBytes))

	_, err = utils.RequestPost(config.AdminURL, "/connections/receive-invitation", inviteAsBytes, config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestPost() error", err.Error())
		return err
	}

	log.Info("receiveInvitation <<< done")
	return nil
}

func handleMessage(ctx *gin.Context) {
	var (
		topic, state string
		body         map[string]interface{}
		err          error
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
		log.Info("- Case (topic:" + topic + ", state:" + state + ") -> No action in demo")

	case "issue_credential":
		// When credential offer is received, send credential request
		if state == "offer_received" {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> sendCredentialRequest")
			err = sendCredentialRequest(body["credential_exchange_id"].(string))
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}
		} else {
				log.Info("- Case (topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "present_proof":
		// When proof request is received, send proof(presentation)
		if state == "request_received" {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> sendProof")
			bodyAsBytes, err := json.MarshalIndent(body, "", "")
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}

			err = sendProof(string(bodyAsBytes))
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}
		} else if state == "presentation_acked" {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> Alice exits")
			// Alice exit
			exitFlag <- true
		} else {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "basicmessages":
		log.Info("- Case (topic:" + topic + ", state:" + state + ") -> Print message")
		log.Info("  - message:" + body["content"].(string))

	default:
		log.Warn("- Warning Unexpected topic:" + topic)
	}

	return
}

func sendCredentialRequest(credExID string) error {
	log.Info("sendCredentialRequest >>> start")

	_, err := utils.RequestPost(config.AdminURL, "/issue-credential/records/"+ credExID + "/send-request", []byte("{}"), config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("sendCredentialRequest <<< done")
	return nil
}

func sendProof(reqBody string) error {
	log.Info("sendProof >>> start")

	presExID := gjson.Get(reqBody, "presentation_exchange_id").String()
	if presExID == "" {
		return fmt.Errorf("presExID does not exist\nreqBody: %s: ", reqBody)
	}

	credsAsBytes, err :=  utils.RequestGet(config.AdminURL, "/present-proof/records/" + presExID + "/credentials", config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestGET() error:", err.Error())
		return err
	}

	// Next 2-lines get array of cred_rev_id & referent
	credRevIDs := gjson.Get(string(credsAsBytes), "#.cred_info.cred_rev_id").Array()
	credIDs := gjson.Get(string(credsAsBytes), "#.cred_info.referent").Array()

	var (
		maxRevID uint64 = 0
		maxIndex = 0
	)

	// Find maxRevID and corresponding index
	for idx, credRevID := range credRevIDs {
		if  credRevID.Uint() > maxRevID {
			maxRevID = credRevID.Uint()
			maxIndex = idx
		}
	}

	// Get array element that has max RevID
	credRevID := credRevIDs[maxIndex].String()
	credID := credIDs[maxIndex].String()
	log.Info("Use latest credential in demo - credRevId:" + credRevID + ", credId:"+ credID)

	// Make body using presentation_request
	var (
		newReqAttrs, newReqPreds string
	)

	reqAttrs := gjson.Get(reqBody, "presentation_request.requested_attributes").Map()
	for key := range reqAttrs {
		newReqAttrs, _ = sjson.Set(newReqAttrs, key + ".cred_id", credID)
		newReqAttrs, _ = sjson.Set(newReqAttrs, key + ".revealed", true)
	}

	reqPreds := gjson.Get(reqBody, "presentation_request.requested_predicates").Map()
	for key := range reqPreds {
		newReqPreds, _ = sjson.Set(newReqPreds, key + ".cred_id", credID)
	}

	body := utils.PrettyJson(`{
		"requested_attributes": ` + newReqAttrs + `,
		"requested_predicates": ` + newReqPreds + `,
		"self_attested_attributes": {}
	}`, "")

	_, err = utils.RequestPost(config.AdminURL, "/present-proof/records/"+ presExID + "/send-presentation", []byte(body), config.HttpTimeout)
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}


	log.Info("sendProof <<< done")
	return nil
}