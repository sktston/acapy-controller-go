/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Ethan Sung (baegjae@gmail.com)       *
 * since July 28, 2020                            *
 **************************************************/

package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/viper"
	"math/rand"
	"net"
	"path"
	"strings"
	"time"
)

func LoadConfig(configFile string) error {
	// Make the config names match the os env names
	replacer := strings.NewReplacer(".", "_", "-", "_")
	viper.SetEnvKeyReplacer(replacer)

	// Viper will check for an environment variable any time a viper.Get request is made
	// Viper precedence: explicit call to Set > flag > env > config > key/value store > default
	viper.AutomaticEnv()

	viper.SetConfigFile(configFile)
	//viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	return nil
}

func PrettyJson(v interface{}, indent ...string) string {
	var marshalIndent string

	TrimNewline := func(input string) interface{} {
		jsonString := strings.ReplaceAll(input, "\n", "")
		var stringUnmarshal interface{}
		_ = json.Unmarshal([]byte(jsonString), &stringUnmarshal)
		return stringUnmarshal
	}

	switch v.(type) {
	case []byte:
		v = string(v.([]byte))
		v = TrimNewline(v.(string))
	case string:
		v = TrimNewline(v.(string))
	}

	if len(indent) > 0 {
		marshalIndent = indent[0]
	} else {
		marshalIndent = "  "
	}

	// Notice: no error handling for easy use
	prettyJsonAsBytes, _ := json.MarshalIndent(v, "", marshalIndent)
	return string(prettyJsonAsBytes)
}

func GetRandomInt(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min+1) + min
}

func CheckHttpResult(response *resty.Response, err error) error {
	if response.IsSuccess() == false {
		if IsStringEmpty(response.String()) == false {
			return errors.New(response.String())
		}
		if err != nil && IsStringEmpty(err.Error()) == false {
			return err
		}
		return fmt.Errorf("http error code '%d' with empty message", response.StatusCode())
	}

	return nil
}

func IsStringEmpty(str string) bool {
	return len(strings.TrimSpace(str)) == 0
}

func JoinURL(base string, paths ...string) string {
	p := path.Join(paths...)
	return fmt.Sprintf("%s/%s", strings.TrimRight(base, "/"), strings.TrimLeft(p, "/"))
}

func If[T any](condition bool, trueValue, falseValue T) T {
	if condition {
		return trueValue
	}
	return falseValue
}

func GetOutboundIP() net.IP {
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	defer func() { _ = conn.Close() }()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}
