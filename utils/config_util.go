/**************************************************
 * Author  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since July 28, 2020                            *
 **************************************************/

package utils

import (
	"encoding/json"
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
	FaberContURL     string `json:"FaberContURL" validate:"omitempty,url"`

	// Faber only, Command line parameters
	IssueOnly  bool
	VerifyOnly bool
}

var (
	appVersion = os.Args[0] + " version 1.0.0\n" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
	Log        = goLog.New(os.Stdout).WithColor().WithoutTimestamp()
	log        = Log
)

func (config *ControllerConfig) ReadConfig(fileName string) error {
	var (
		app           = kingpin.New(os.Args[0], "Faber controller")
		configFilePtr = app.Flag("config-file", "Config json file").Short('c').PlaceHolder("CONFIG_FILE").Default(fileName).File()
		issueOnlyPtr  = app.Flag("issue-only", "Faber does not perform verify after issue process").Short('i').Bool()
		verifyOnlyPtr = app.Flag("verify-only", "Faber performs verify without issue process").Short('v').Bool()
	)

	app.Version(appVersion)
	app.HelpFlag.Short('h')
	kingpin.MustParse(app.Parse(os.Args[1:]))

	config.IssueOnly = *issueOnlyPtr
	config.VerifyOnly = *verifyOnlyPtr

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

func SetDebugMode(debugMode bool) {
	if debugMode == true {
		Log.WithDebug()
		gin.SetMode(gin.DebugMode)
	} else {
		Log.WithoutDebug()
		gin.SetMode(gin.ReleaseMode)
	}

	return
}

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}
