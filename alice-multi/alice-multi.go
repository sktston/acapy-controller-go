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

type reportData struct {
	holderId string
	error    error
}

var (
	log                        = utils.Log
	config                     utils.ControllerConfig
	did, verKey, version, seed string
	adminWalletName            = "admin"

	numWorkers, numJobs uint64
	reportChannel       = make(chan reportData)
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

	numWorkers = config.NumHolders
	numJobs = config.NumCycles

	jobs := make(chan uint64, numJobs)
	results := make(chan bool, numJobs)
	reports := make(chan reportData, numJobs)

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
	ctrlC := make(chan os.Signal, 1)
	defer close(ctrlC)
	signal.Notify(ctrlC, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-ctrlC
		_ = shutdownWebHookServer(httpServer)
		printFinalReport(results, reports, startTime)
		os.Exit(0)
	}()

	// Put all jobs to be performed in the job channel
	for jobId = 1; jobId <= numJobs; jobId++ {
		jobs <- jobId

		// WaitGroup 1 increases, each worker decreases by 1 at the end of the job
		wg.Add(1)
	}

	// worker creation
	for workerId = 1; workerId <= numWorkers; workerId++ {
		go worker(strconv.FormatUint(workerId, 10), &wg, jobs, results, reports, ctrlC)
	}

	// Worker pulls job from job channel using range
	close(jobs)

	// Wait until all jobs are executed
	wg.Wait()

	_ = shutdownWebHookServer(httpServer)
	printFinalReport(results, reports, startTime)
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

func worker(workerId string, wg *sync.WaitGroup, jobs <-chan uint64, results chan<- bool, errors chan<- reportData, ctrlC chan<- os.Signal) {
	var (
		report reportData
	)

	for jobId := range jobs {
		numDone := float64(numJobs - uint64(len(jobs)))
		percent := numDone * 100.0 / float64(numJobs)
		numError := len(errors)

		fmt.Printf("worker %03s processing job %05d (Remain:%5d | Done:%5.1f%% | Err: %5d)\n",
			workerId, jobId, len(jobs), percent, numError)

		err := initializeAfterStartup(workerId)
		if err != nil {
			sendReportToChannel(workerId, err)
		}

		for {
			report = <-reportChannel

			if report.holderId == workerId {
				break
			} else {
				reportChannel <- report
			}
		}

		if report.error != nil {
			errors <- reportData{holderId: workerId, error: err}

			fmt.Printf("[ERROR] workerId: %s, error: %v\n", workerId, err)

			// Generate ctrlC signal to print intermediate result and exit
			ctrlC <- syscall.SIGTERM
		} else {
			results <- true
		}

		// WaitGroup 1 decrease
		wg.Done()
	}
	return
}

func printFinalReport(results chan bool, errors chan reportData, startTime time.Time) {
	// Close the channel to get all the values using range
	close(results)
	close(errors)

	// Generate reports
	fmt.Printf("\n\n-------   Report   -------\n")

	elapsedTime := time.Since(startTime)

	okIdx := len(results)

	var failIdx = 1
	for report := range errors {
		fmt.Printf("[%5d] holderId: %s, report: %v\n", failIdx, report.holderId, report.error)
		failIdx++
	}

	fmt.Printf("NUM_WORKERS: %d\n", numWorkers)
	fmt.Printf("NUM_JOBS: %d\n", numJobs)
	fmt.Printf("  SUCCESS JOBS: %d\n", okIdx)
	fmt.Printf("  FAILURE JOBS: %d\n\n", failIdx-1)

	fmt.Printf("DURATION: %s\n", fmtDuration(elapsedTime))
	fmt.Printf("TPS: %.3f\n\n", float64(numJobs)/elapsedTime.Seconds())
	return
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

func initializeAfterStartup(holderId string) error {
	log.Info("initializeAfterStartup >>> start")

	version = strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99)) + "." +
		strconv.Itoa(utils.GetRandomInt(1, 99))
	seed = strings.Replace(uuid.New().String(), "-", "", -1)

	log.Info("Create wallet and did, and register webhook url")
	err := createWalletAndDid(holderId)
	if err != nil {
		log.Error("createWalletAndDid() error:", err.Error())
		return err
	}

	err = registerWebhookUrl(holderId)
	if err != nil {
		log.Error("registerHolderWebhookUrl() error:", err.Error())
		return err
	}

	log.Info("Configuration of alice:")
	log.Info("- wallet name: " + getWalletName(holderId))
	log.Info("- seed: " + seed)
	log.Info("- did: " + did)
	log.Info("- verification key: " + verKey)
	log.Info("- webhook url: " + config.HolderWebhookUrl + "/" + holderId)

	log.Info("Receive invitation from faber controller")
	err = receiveInvitation(holderId, config.IssuerContURL)
	if err != nil {
		return err
	}

	log.Info("initializeAfterStartup <<< done")
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
		log.Info("- Case (Id:" + holderId + ", topic:" + topic + ", state:" + state + ") -> No action in demo")

	case "issue_credential":
		// When credential offer is received, send credential request
		if state == "offer_received" {
			log.Info("- Case (Id:" + holderId + ", topic:" + topic + ", state:" + state + ") -> sendCredentialRequest")
			err = sendCredentialRequest(holderId, body["credential_exchange_id"].(string))
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}
		} else if state == "credential_acked" {
			if config.IssuerContURL != config.VerifierContURL {
				log.Info("- Case (Id:" + holderId + ", topic:" + topic + ", state:" + state + ") -> receiveInvitation")
				err = receiveInvitation(holderId, config.VerifierContURL)
				if err != nil {
					utils.HttpError(ctx, http.StatusInternalServerError, err)
					return
				}
			}

		} else {
			log.Info("- Case (Id:" + holderId + ", topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "present_proof":
		// When proof request is received, send proof(presentation)
		if state == "request_received" {
			log.Info("- Case (Id:" + holderId + ", topic:" + topic + ", state:" + state + ") -> sendProof")
			bodyAsBytes, err := json.MarshalIndent(body, "", "")
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}

			err = sendProof(holderId, string(bodyAsBytes))
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}
		} else if state == "presentation_acked" {
			log.Info("- Case (Id:" + holderId + ", topic:" + topic + ", state:" + state + ") -> deleteWalletAndExit")
			err = deleteWalletAndExit(holderId)
			if err != nil {
				utils.HttpError(ctx, http.StatusInternalServerError, err)
				return
			}
		} else {
			log.Info("- Case (Id:" + holderId + ", topic:" + topic + ", state:" + state + ") -> No action in demo")
		}

	case "basicmessages":
		log.Info("- Case (Id:" + holderId + ", topic:" + topic + ", state:" + state + ") -> Print message")
		log.Info("  - message:" + body["content"].(string))

	case "problem_report":
		bodyAsBytes, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			utils.HttpError(ctx, http.StatusInternalServerError, err)
			return
		}
		log.Warn("- Case (Id:" + holderId + ", topic:" + topic + ") -> Print body")
		log.Warn("  - body:" + string(bodyAsBytes))

	default:
		log.Warn("- Warning Unexpected topic:" + topic)
	}

	return
}

func createWalletAndDid(holderId string) error {
	log.Info("createWalletAndDid >>> start")

	body := utils.PrettyJson(`{
		"name": "`+getWalletName(holderId)+`",
		"key": "`+getWalletName(holderId)+".key"+`",
		"type": "indy"
	}`, "")

	log.Info("Create a new wallet:" + utils.PrettyJson(body))
	_, err := utils.RequestPost(config.AgentApiUrl, "/wallet", adminWalletName, []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	body = utils.PrettyJson(`{
		"seed": "`+seed+`"
	}`, "")

	log.Info("Create a new local did:" + utils.PrettyJson(body))
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
	log.Info("created did: " + did + ", verkey: " + verKey)

	log.Info("createWalletAndDid <<< done")
	return nil
}

func registerWebhookUrl(holderId string) error {
	log.Info("registerHolderWebhookUrl >>> start")

	body := utils.PrettyJson(`{
		"target_url": "`+config.HolderWebhookUrl + "/" + holderId+`"
	}`, "")

	log.Info("Create a new webhook target:" + utils.PrettyJson(body))
	respAsBytes, err := utils.RequestPost(config.AgentApiUrl, "/webhooks", getWalletName(holderId), []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}
	log.Info("response: " + utils.PrettyJson(string(respAsBytes), "  "))

	log.Info("registerHolderWebhookUrl <<< done")
	return nil
}

func receiveInvitation(holderId string, contURL string) error {
	log.Info("receiveInvitation >>> start")

	inviteAsBytes, err := utils.RequestGet(contURL, "/invitation", "")
	if err != nil {
		log.Error("utils.RequestGet() error", err.Error())
		return err
	}
	log.Info("invitation:" + string(inviteAsBytes))

	_, err = utils.RequestPost(config.AgentApiUrl, "/connections/receive-invitation", getWalletName(holderId), inviteAsBytes)
	if err != nil {
		log.Error("utils.RequestPost() error", err.Error())
		return err
	}

	log.Info("receiveInvitation <<< done")
	return nil
}

func sendCredentialRequest(holderId string, credExID string) error {
	log.Info("sendCredentialRequest >>> start")

	_, err := utils.RequestPost(config.AgentApiUrl, "/issue-credential/records/"+credExID+"/send-request", getWalletName(holderId), []byte("{}"))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("sendCredentialRequest <<< done")
	return nil
}

func sendProof(holderId string, reqBody string) error {
	log.Info("sendProof >>> start")

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

	_, err = utils.RequestPost(config.AgentApiUrl, "/present-proof/records/"+presExID+"/send-presentation", getWalletName(holderId), []byte(body))
	if err != nil {
		log.Error("utils.RequestPost() error:", err.Error())
		return err
	}

	log.Info("sendProof <<< done")
	return nil
}

func deleteWalletAndExit(holderId string) error {
	// Delete wallet
	log.Info("Delete my wallet - walletName: " + getWalletName(holderId))
	_, err := utils.RequestDelete(config.AgentApiUrl, "/wallet/me", getWalletName(holderId))
	if err != nil {
		log.Error("utils.RequestDelete() error:", err.Error())
		return err
	}

	// Alice exit
	sendReportToChannel(holderId, nil)
	return nil
}

func getWalletName(holderId string) string {
	return "alice_" + holderId + "." + version
}

func sendReportToChannel(holderId string, err error) {
	reportChannel <- reportData{holderId: holderId, error: err}
	return
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02dm:%02ds", m, s)
}
