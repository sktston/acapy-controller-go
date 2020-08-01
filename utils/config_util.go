/**************************************************
 * Auther  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since July 28, 2020                            *
 **************************************************/

package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	goLog "github.com/withmandala/go-log"
	"gopkg.in/alecthomas/kingpin.v2"
)

type ControllerConfig struct {
	// Common
	WebHookPort		string			`json:"WebHookPort" validate:"required,hostname_port"`
	AdminURL		string			`json:"AdminURL" validate:"required,url"`
	HttpTimeout		time.Duration	`json:"HttpTimeout" validate:"required,gt=0"`
	Debug        	bool    		`json:"Debug"`

	// Faber only
	EnableRevoke	bool			`json:"EnableRevoke"`
	GenerateQR		bool			`json:"GenerateQR"`

	// Alice only
	FaberContURL	string			`json:"FaberContURL"`
}

var (
	appVersion = os.Args[0] + " version 1.0.0\n" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
	Log        = goLog.New(os.Stdout).WithColor().WithoutTimestamp()
	log        = Log
)

func (config *ControllerConfig) ReadConfig(fileName string) error {
	var (
		app        = kingpin.New(os.Args[0], "Faber controller")
		configFile = app.Flag("config", "Config json file").Short('c').PlaceHolder("CONFIG_FILE").Default(fileName).File()
	)

	app.Version(appVersion)
	app.HelpFlag.Short('h')
	kingpin.MustParse(app.Parse(os.Args[1:]))

	jsonData, err := ioutil.ReadAll(*configFile)

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