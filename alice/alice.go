/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Baegjae Sung (baegjae@gmail.com)     *
 * since July 28, 2020                            *
 **************************************************/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/sktston/acapy-controller-go/utils"
)

var (
	log         = utils.Log
	config      utils.ControllerConfig
	did, verKey string

	version = strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99))
	walletName = "alice." + version
	imageUrl   = "https://identicon-api.herokuapp.com/" + walletName + "/300?format=png"
	seed       = strings.Replace(uuid.New().String(), "-", "", -1) // random seed 32 characters
)

func main() {
	// Read alice-config.yaml file
	err := config.ReadConfig("./alice-config.json", "holder")
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

	// Start Alice
	err = initializeAfterStartup()
	if err != nil {
		log.Fatal(err.Error())
	}

	// Set exit signal
	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	log.Info("Waiting web hook event from agent...")

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
	router.Use(gin.Logger())

	router.POST("/webhooks/topic/:topic", handleMessage)

	// Get port from HolderWebhookUrl
	urlParse, _ := url.Parse(config.HolderWebhookUrl)
	_, port, _ := net.SplitHostPort(urlParse.Host)
	port = ":" + port

	// Start http server
	listener, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatal(err.Error())
	}

	httpServer := &http.Server{
		Handler: router,
	}

	go func() {
		err = httpServer.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
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
	log.Info("initializeAfterStartup >>> start")

	log.Info("Create wallet and did, and register webhook url")
	err := createWalletAndDid()
	if err != nil {
		log.Error("createWalletAndDid() error:", err.Error())
		return err
	}

	log.Info("Configuration of alice:")
	log.Info("- wallet name: " + walletName)
	log.Info("- seed: " + seed)
	log.Info("- did: " + did)
	log.Info("- verification key: " + verKey)
	log.Info("- webhook url: " + config.HolderWebhookUrl)

	log.Info("Receive invitation from faber controller")
	err = receiveInvitation(config.IssuerContURL)
	if err != nil {
		return err
	}

	log.Info("initializeAfterStartup <<< done")
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
		} else if state == "credential_acked" {
			if config.IssuerContURL != config.VerifierContURL {
				log.Info("- Case (topic:" + topic + ", state:" + state + ") -> receiveInvitation")
				err = receiveInvitation(config.VerifierContURL)
				if err != nil {
					utils.HttpError(ctx, http.StatusInternalServerError, err)
					return
				}
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
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> deleteWallet & Exit")
			err = deleteWallet()
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}

			// Send exit signal
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		} else {
			log.Info("- Case (topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "basicmessages":
		log.Info("- Case (topic:" + topic + ", state:" + state + ") -> Print message")
		log.Info("  - message:" + body["content"].(string))

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
		"webhook_urls": ["`+config.HolderWebhookUrl+`"]
	}`, "")

	log.Info("Create a new wallet:" + utils.PrettyJson(body))
	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/wallet", "", []byte(body))
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

func receiveInvitation(contURL string) error {
	log.Info("receiveInvitation >>> start")

	inviteAsBytes, err := utils.RequestGet(contURL, "/invitation", "")
	if err != nil {
		log.Error("utils.RequestGet() error", err.Error())
		return err
	}
	log.Info("invitation:" + string(inviteAsBytes))

	_, err = utils.RequestPost(config.AgentApiUrl, "/connections/receive-invitation", walletName, inviteAsBytes)
	if err != nil {
		log.Error("utils.RequestPost() error", err.Error())
		return err
	}

	log.Info("receiveInvitation <<< done")
	return nil
}

func sendCredentialRequest(credExID string) error {
	log.Info("sendCredentialRequest >>> start")

	_, err := utils.RequestPost(config.AgentApiUrl, "/issue-credential/records/"+credExID+"/send-request", walletName, []byte("{}"))
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

	credsAsBytes, err := utils.RequestGet(config.AgentApiUrl, "/present-proof/records/"+presExID+"/credentials", walletName)
	if err != nil {
		log.Error("utils.RequestGET() error:", err.Error())
		return err
	}

	// Next 2-lines get array of cred_rev_id & referent
	credRevIDs := gjson.Get(string(credsAsBytes), "#.cred_info.cred_rev_id").Array()
	credIDs := gjson.Get(string(credsAsBytes), "#.cred_info.referent").Array()

	var (
		maxRevID uint64 = 0
		maxIndex        = 0
	)

	// Find maxRevID and corresponding index
	for idx, credRevID := range credRevIDs {
		if credRevID.Uint() > maxRevID {
			maxRevID = credRevID.Uint()
			maxIndex = idx
		}
	}

	// Get array element that has max RevID
	credRevID := credRevIDs[maxIndex].String()
	credID := credIDs[maxIndex].String()
	log.Info("Use latest credential in demo - credRevId:" + credRevID + ", credId:" + credID)

	// Make body using presentation_request
	var (
		newReqAttrs, newReqPreds string
	)

	reqAttrs := gjson.Get(reqBody, "presentation_request.requested_attributes").Map()
	for key := range reqAttrs {
		newReqAttrs, _ = sjson.Set(newReqAttrs, key+".cred_id", credID)
		newReqAttrs, _ = sjson.Set(newReqAttrs, key+".revealed", true)
	}

	reqPreds := gjson.Get(reqBody, "presentation_request.requested_predicates").Map()
	for key := range reqPreds {
		newReqPreds, _ = sjson.Set(newReqPreds, key+".cred_id", credID)
	}

	body := utils.PrettyJson(`{
		"requested_attributes": `+newReqAttrs+`,
		"requested_predicates": `+newReqPreds+`,
		"self_attested_attributes": {}
	}`, "")

	_, err = utils.RequestPost(config.AgentApiUrl, "/present-proof/records/"+presExID+"/send-presentation", walletName, []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("sendProof <<< done")
	return nil
}

func deleteWallet() error {
	// Delete wallet
	log.Info("Delete my wallet - walletName: " + walletName)
	_, err := utils.RequestDelete(config.AgentApiUrl, "/wallet/me", walletName)
	if err != nil {
		log.Error("utils.RequestDelete() error:", err.Error())
		return err
	}
	return nil
}
