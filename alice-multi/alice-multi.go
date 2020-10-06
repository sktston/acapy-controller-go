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
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sktston/acapy-controller-go/utils"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type workDone struct {
	holderId string
	error    error
}

var (
	log                        = utils.Log
	config                     utils.ControllerConfig
	did, verKey, version, seed string
	adminWalletName            = "admin"
	workDoneSignal             = make(chan workDone)
)

func main() {
	// Read alice-config.yaml file
	err := config.ReadConfig("./alice-config.json")
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

	jobs := make(chan uint64, config.NumCycles)
	workDones := make(chan workDone, config.NumCycles)

	// Uses all CPUs
	fmt.Printf("\n-------   NumCPU   -------\n")
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Printf("NumCPU: %d\n", runtime.GOMAXPROCS(0))

	fmt.Printf("\n-------   Working start   -------\n")

	startTime := time.Now()

	var (
		wg              sync.WaitGroup
		workerId, jobId uint64
	)

	// Press Ctrl-C or'kill pid' in the shell to output intermediate results and exit
	exitSignal := make(chan os.Signal, 1)
	defer close(exitSignal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-exitSignal
		_ = shutdownWebHookServer(httpServer)
		printFinalReport(workDones, startTime)
		os.Exit(0)
	}()

	// Put all jobs to be performed in the job channel
	for jobId = 1; jobId <= config.NumCycles; jobId++ {
		jobs <- jobId

		// WaitGroup 1 increases, each worker decreases by 1 at the end of the job
		wg.Add(1)
	}

	// worker creation
	for workerId = 1; workerId <= config.NumHolders; workerId++ {
		go worker(workerId, &wg, jobs, workDones)
	}

	// Worker pulls job from job channel using range
	close(jobs)

	// Wait until all jobs are executed
	wg.Wait()

	_ = shutdownWebHookServer(httpServer)
	printFinalReport(workDones, startTime)
	return
}

func startWebHookServer() (*http.Server, error) {
	// Set up http router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	router.POST("/webhooks/:holderId/topic/:topic", handleMessage)

	// Get port from HolderWebhookUrl
	urlParse, _ := url.Parse(config.HolderWebhookUrl)
	_, port, _ := net.SplitHostPort(urlParse.Host)
	port = ":" + port

	// Start http server
	listener, err := net.Listen("tcp", port)
	if err != nil {
		return nil, err
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

func worker(id uint64, wg *sync.WaitGroup, jobs <-chan uint64, workDones chan<- workDone) {
	var (
		doneResult workDone
		workerId   = strconv.FormatUint(id, 10)
	)

	for jobId := range jobs {
		numDone := float64(config.NumCycles - uint64(len(jobs)))
		percent := numDone * 100.0 / float64(config.NumCycles)

		fmt.Printf("worker %03s processing job %05d (Remain:%5d | Done:%5.1f%%)\n",
			workerId, jobId, len(jobs), percent)

		// Start Alice
		err := initializeAfterStartup(workerId)
		if err != nil {
			sendWorkDoneSignal(workerId, err)
		}

		for {
			// workDoneSignal occurs in deleteWalletAndExit() or in error
			doneResult = <-workDoneSignal

			// Check if the result came to myself
			if doneResult.holderId == workerId {
				break
			} else {
				// If the result is not for me, sent back to the channel.
				workDoneSignal <- doneResult
				runtime.Gosched()
			}
		}

		workDones <- doneResult
		if doneResult.error != nil {
			fmt.Printf("[ERROR] workerId: %s, error: %v\n", workerId, err)
			// Generate kill signal to print intermediate result and exit
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		}

		// WaitGroup 1 decrease
		wg.Done()
	}
	return
}

func printFinalReport(workDones chan workDone, startTime time.Time) {
	// Close the channel to get all the values using range
	close(workDones)

	// Generate reports
	fmt.Printf("\n\n-------   Report   -------\n")

	elapsedTime := time.Since(startTime)

	var (
		okIdx   = 0
		failIdx = 0
	)
	for report := range workDones {
		if report.error != nil {
			fmt.Printf("[%5d] holderId: %s, report: %v\n", failIdx, report.holderId, report.error)
			failIdx++
		} else {
			okIdx++
		}
	}

	fmt.Printf("NUM_WORKERS: %d\n", config.NumHolders)
	fmt.Printf("NUM_JOBS: %d\n", config.NumCycles)
	fmt.Printf("  SUCCESS JOBS: %d\n", okIdx)
	fmt.Printf("  FAILURE JOBS: %d\n\n", failIdx)

	fmt.Printf("DURATION: %s\n", fmtDuration(elapsedTime))
	fmt.Printf("TPS: %.3f\n\n", float64(config.NumCycles)/elapsedTime.Seconds())
	return
}

func initializeAfterStartup(holderId string) error {
	log.Info("[" + holderId + "] initializeAfterStartup >>> start")

	version = strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99))
	seed = strings.Replace(uuid.New().String(), "-", "", -1) // random seed 32 characters

	log.Info("[" + holderId + "] Create wallet and did, and register webhook url")
	err := createWalletAndDid(holderId)
	if err != nil {
		log.Error("createWalletAndDid() error:", err.Error())
		return err
	}

	log.Info("[" + holderId + "] Configuration of alice:")
	log.Info("[" + holderId + "] - wallet name: " + getWalletName(holderId))
	log.Info("[" + holderId + "] - seed: " + seed)
	log.Info("[" + holderId + "] - did: " + did)
	log.Info("[" + holderId + "] - verification key: " + verKey)
	log.Info("[" + holderId + "] - webhook url: " + config.HolderWebhookUrl + "/" + holderId)

	log.Info("[" + holderId + "] Receive invitation from faber controller")
	err = receiveInvitation(holderId, config.IssuerContURL)
	if err != nil {
		return err
	}

	log.Info("[" + holderId + "] initializeAfterStartup <<< done")
	return nil
}

func handleMessage(ctx *gin.Context) {
	var (
		topic, state, holderId string
		body                   map[string]interface{}
		err                    error
	)

	err = ctx.ShouldBindJSON(&body)
	if err != nil {
		utils.HttpError(ctx, http.StatusBadRequest, err)
		return
	}

	topic = ctx.Param("topic")
	if topic == "problem_report" {
		state = ""
	} else {
		state = body["state"].(string)
	}

	holderId = ctx.Param("holderId")

	switch topic {
	case "connections":
		log.Info("[" + holderId + "] - Case (topic:" + topic + ", state:" + state + ") -> No action in demo")

	case "issue_credential":
		// When credential offer is received, send credential request
		if state == "offer_received" {
			log.Info("[" + holderId + "] - Case (topic:" + topic + ", state:" + state + ") -> sendCredentialRequest")
			err = sendCredentialRequest(holderId, body["credential_exchange_id"].(string))
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				sendWorkDoneSignal(holderId, err)
				return
			}
		} else if state == "credential_acked" {
			if config.IssuerContURL != config.VerifierContURL {
				log.Info("[" + holderId + "] - Case (topic:" + topic + ", state:" + state + ") -> receiveInvitation")
				err = receiveInvitation(holderId, config.VerifierContURL)
				if err != nil {
					utils.HttpError(ctx, http.StatusInternalServerError, err)
					sendWorkDoneSignal(holderId, err)
					return
				}
			}

		} else {
			log.Info("[" + holderId + "] - Case (topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "present_proof":
		// When proof request is received, send proof(presentation)
		if state == "request_received" {
			log.Info("[" + holderId + "] - Case (topic:" + topic + ", state:" + state + ") -> sendProof")
			bodyAsBytes, err := json.MarshalIndent(body, "", "")
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				sendWorkDoneSignal(holderId, err)
				return
			}

			err = sendProof(holderId, string(bodyAsBytes))
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				sendWorkDoneSignal(holderId, err)
				return
			}
		} else if state == "presentation_acked" {
			log.Info("[" + holderId + "] - Case (topic:" + topic + ", state:" + state + ") -> deleteWalletAndExit")
			err = deleteWalletAndExit(holderId)
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				sendWorkDoneSignal(holderId, err)
				return
			}
		} else {
			log.Info("[" + holderId + "] - Case (topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "basicmessages":
		log.Info("[" + holderId + "] - Case (topic:" + topic + ", state:" + state + ") -> Print message")
		log.Info("[" + holderId + "]   - message:" + body["content"].(string))

	case "problem_report":
		bodyAsBytes, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			utils.HttpError(ctx, http.StatusInternalServerError, err)
			sendWorkDoneSignal(holderId, err)
			return
		}
		log.Warn("- Case (topic:" + topic + ") -> Print body")
		log.Warn("  - body:" + string(bodyAsBytes))

	default:
		log.Warn("- Warning Unexpected topic:" + topic)
	}

	return
}

func createWalletAndDid(holderId string) error {
	log.Info("[" + holderId + "] createWalletAndDid >>> start")

	body := utils.PrettyJson(`{
		"name": "`+getWalletName(holderId)+`",
		"key": "`+getWalletName(holderId)+".key"+`",
		"type": "indy",
		"label": "`+getWalletName(holderId)+".label"+`",
		"image_url": "`+getWalletName(holderId)+`",
		"webhook_urls": ["`+config.HolderWebhookUrl+"/"+holderId+`"]
	}`, "")

	log.Info("[" + holderId + "] Create a new wallet:" + utils.PrettyJson(body))
	_, err := utils.RequestPost(config.AgentApiUrl, "/wallet", adminWalletName, []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	body = utils.PrettyJson(`{
		"seed": "`+seed+`"
	}`, "")

	log.Info("[" + holderId + "] Create a new local did:" + utils.PrettyJson(body))
	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/wallet/did/create", getWalletName(holderId), []byte(body))
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
	log.Info("[" + holderId + "] created did: " + did + ", verkey: " + verKey)

	log.Info("[" + holderId + "] createWalletAndDid <<< done")
	return nil
}

func receiveInvitation(holderId string, contURL string) error {
	log.Info("[" + holderId + "] receiveInvitation >>> start")

	inviteAsBytes, err := utils.RequestGet(contURL, "/invitation", "")
	if err != nil {
		log.Error("utils.RequestGet() error", err.Error())
		return err
	}
	log.Info("[" + holderId + "] invitation:" + string(inviteAsBytes))

	_, err = utils.RequestPost(config.AgentApiUrl, "/connections/receive-invitation", getWalletName(holderId), inviteAsBytes)
	if err != nil {
		log.Error("utils.RequestPost() error", err.Error())
		return err
	}

	log.Info("[" + holderId + "] receiveInvitation <<< done")
	return nil
}

func sendCredentialRequest(holderId string, credExID string) error {
	log.Info("[" + holderId + "] sendCredentialRequest >>> start")

	_, err := utils.RequestPost(config.AgentApiUrl, "/issue-credential/records/"+credExID+"/send-request", getWalletName(holderId), []byte("{}"))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("[" + holderId + "] sendCredentialRequest <<< done")
	return nil
}

func sendProof(holderId string, reqBody string) error {
	log.Info("[" + holderId + "] sendProof >>> start")

	presExID := gjson.Get(reqBody, "presentation_exchange_id").String()
	if presExID == "" {
		return fmt.Errorf("presExID does not exist\nreqBody: %s: ", reqBody)
	}

	credsAsBytes, err := utils.RequestGet(config.AgentApiUrl, "/present-proof/records/"+presExID+"/credentials", getWalletName(holderId))
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
	log.Info("[" + holderId + "] Use latest credential in demo - credRevId:" + credRevID + ", credId:" + credID)

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

	_, err = utils.RequestPost(config.AgentApiUrl, "/present-proof/records/"+presExID+"/send-presentation", getWalletName(holderId), []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("[" + holderId + "] sendProof <<< done")
	return nil
}

func deleteWalletAndExit(holderId string) error {
	// Delete wallet
	log.Info("[" + holderId + "] Delete my wallet - walletName: " + getWalletName(holderId))
	_, err := utils.RequestDelete(config.AgentApiUrl, "/wallet/me", getWalletName(holderId))
	if err != nil {
		log.Error("utils.RequestDelete() error:", err.Error())
		return err
	}

	// Alice exit
	sendWorkDoneSignal(holderId, nil)
	return nil
}

func getWalletName(holderId string) string {
	return "alice_" + holderId + "." + version
}

func sendWorkDoneSignal(holderId string, err error) {
	// Workers are waiting for workDoneSignal
	workDoneSignal <- workDone{holderId: holderId, error: err}
	return
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02dm:%02ds", m, s)
}
