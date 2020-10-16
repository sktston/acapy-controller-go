/**************************************************
 * Author  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since July 28, 2020                            *
 **************************************************/

package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	goLog "github.com/withmandala/go-log"
	"gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"net"
	"os"
	"runtime"
)

type ControllerConfig struct {
	// Common from json file
	AgentApiUrl string `json:"AgentApiUrl" validate:"required,url"`
	Debug       bool   `json:"Debug"`

	// Faber only from json file
	IssuerWebhookUrl   string `json:"IssuerWebhookUrl" validate:"omitempty,url"`
	VerifierWebhookUrl string `json:"VerifierWebhookUrl" validate:"omitempty,url"`
	SupportRevoke      bool   `json:"SupportRevoke"`
	RevokeAfterIssue   bool   `json:"RevokeAfterIssue"`

	// Alice only from json file
	HolderWebhookUrl string `json:"HolderWebhookUrl" validate:"omitempty,url"`
	IssuerContURL    string `json:"IssuerContURL" validate:"omitempty,url"`
	VerifierContURL  string `json:"VerifierContURL" validate:"omitempty,url"`

	// Faber only, Command line parameters
	IssueOnly  bool
	VerifyOnly bool

	// Alice only, Command line parameters
	NumHolders    uint64 `validate:"omitempty,gte=1"`
	NumCycles     uint64 `validate:"omitempty"`
	VerifyRatio   uint64 `validate:"omitempty,gte=1"`
	StartInterval uint64 `validate:"omitempty,gte=0"`
	Infinite      bool
}

var (
	appVersion = os.Args[0] + " version 1.0.0\n" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
	Log        = goLog.New(os.Stdout).WithColor().WithoutTimestamp()
	log        = Log
	debugMode  bool
)

func (config *ControllerConfig) ReadConfig(fileName string, controllerType string) error {
	var (
		app                                                        *kingpin.Application
		configFilePtr                                              **os.File
		issueOnlyPtr, verifyOnlyPtr, infinitePtr                   *bool
		numHoldersPtr, numCyclesPtr, verifyRatioPtr, startInterval *uint64
	)

	app = kingpin.New(os.Args[0], "ACA-Py controller")
	configFilePtr = app.Flag("config-file", "Config json file").PlaceHolder("CONFIG_FILE").Default(fileName).File()

	switch controllerType {
	case "issuer-verifier":
		issueOnlyPtr = app.Flag("issue-only", "Faber does not perform verify after issue process").Short('i').Bool()
		verifyOnlyPtr = app.Flag("verify-only", "Faber performs verify without issue process").Short('v').Bool()

	case "holder":
		numHoldersPtr = app.Flag("num-holders", "Number of holders (i.e. Alice)").Short('n').Default("1").Uint64()
		numCyclesPtr = app.Flag("num-cycles", "Number of cycles").Short('c').Default("1").Uint64()
		verifyRatioPtr = app.Flag("verify-ratio", "Verify ratio by onboard and issue ->  verify / (onboard & issue)").Short('r').Default("1").Uint64()
		startInterval = app.Flag("start-interval", "Random interval before each holder starts (seconds)").Short('l').Default("0").Uint64()
		infinitePtr = app.Flag("infinite", "If specified, run infinitely ").Short('f').Bool()

	default:
		return errors.New("undefined controller type")
	}

	app.Version(appVersion)
	app.HelpFlag.Short('h')
	kingpin.MustParse(app.Parse(os.Args[1:]))

	if issueOnlyPtr != nil {
		config.IssueOnly = *issueOnlyPtr
	}

	if verifyOnlyPtr != nil {
		config.VerifyOnly = *verifyOnlyPtr
	}

	if numHoldersPtr != nil {
		config.NumHolders = *numHoldersPtr
	}

	if numCyclesPtr != nil {
		config.NumCycles = *numCyclesPtr
	}

	if verifyRatioPtr != nil {
		config.VerifyRatio = *verifyRatioPtr
	}

	if startInterval != nil {
		config.StartInterval = *startInterval
	}

	if infinitePtr != nil {
		config.Infinite = *infinitePtr
	}

	// Adjust NumCycles
	if config.NumCycles < config.NumHolders*config.VerifyRatio {
		config.NumCycles = config.NumHolders * config.VerifyRatio
	}

	jsonData, err := ioutil.ReadAll(*configFilePtr)

	if err != nil {
		return err
	}

	err = json.Unmarshal(jsonData, config)
	if err != nil {
		return err
	}

	validate := validator.New()
	err = validate.Struct(config)
	if err != nil {
		return err
	}

	// Print config data
	if config.Debug == true {
		jsonAsBytes, _ := json.MarshalIndent(*config, "", "  ")

		fmt.Println("------------------------------")
		fmt.Println("Config:\n", string(jsonAsBytes))
		fmt.Println("------------------------------\n")
	}

	return nil
}

func SetDebugMode(flag bool) {
	if flag == true {
		Log.WithDebug()
		gin.SetMode(gin.DebugMode)
		debugMode = true
	} else {
		Log.WithoutDebug()
		gin.SetMode(gin.ReleaseMode)
		debugMode = false
	}

	return
}

func GetDebugMode() bool {
	return debugMode
}

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}
