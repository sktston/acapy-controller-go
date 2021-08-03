/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Ethan Sung (baegjae@gmail.com)       *
 * since July 28, 2020                            *
 **************************************************/

package utils

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"io/ioutil"
	"net"
	"os"
	"runtime"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
	"gopkg.in/alecthomas/kingpin.v2"
)

type ControllerConfig struct {
	// Common from json file
	AgentApiUrl string `json:"AgentApiUrl" validate:"required,url"`
	WalletType  string `json:"WalletType"`
	Debug       bool   `json:"Debug"`

	// Faber only from json file
	IssuerWebhookUrl   string `json:"IssuerWebhookUrl" validate:"omitempty,url"`
	VerifierWebhookUrl string `json:"VerifierWebhookUrl" validate:"omitempty,url"`
	RevokeAfterIssue   bool   `json:"RevokeAfterIssue"`
	PublicInvitation   bool   `json:"PublicInvitation"`

	// Alice only from json file
	HolderWebhookUrl string `json:"HolderWebhookUrl" validate:"omitempty,url"`
	IssuerContUrl    string `json:"IssuerContUrl" validate:"omitempty,url"`
}

var appVersion = os.Args[0] + " version 1.0.0\n" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH

func (config *ControllerConfig) ReadConfig(fileName string) error {
	var (
		app                                                        *kingpin.Application
		configFilePtr                                              **os.File
	)

	app = kingpin.New(os.Args[0], "ACA-Py controller")
	configFilePtr = app.Flag("config-file", "Config json file").PlaceHolder("CONFIG_FILE").Default(fileName).File()

	app.Version(appVersion)
	app.HelpFlag.Short('h')
	kingpin.MustParse(app.Parse(os.Args[1:]))

	jsonData, err := ioutil.ReadAll(*configFilePtr)
	if err != nil { return err }

	err = json.Unmarshal(jsonData, config)
	if err != nil { return err }

	validate := validator.New()
	err = validate.Struct(config)
	if err != nil { return err }

	// Print config data
	jsonAsBytes, _ := json.MarshalIndent(*config, "", "  ")
	log.Info().Msg("------------------------------")
	log.Info().Msg("Config:\n"+ string(jsonAsBytes))
	log.Info().Msg("------------------------------\n")

	return nil
}

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil { log.Fatal().Err(err) }
	defer func() { _ = conn.Close() }()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func SetLogLevelDebug(debugMode bool) {
	if debugMode {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		gin.SetMode(gin.DebugMode)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		gin.SetMode(gin.ReleaseMode)
	}
}