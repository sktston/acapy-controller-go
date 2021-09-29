/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Ethan Sung (baegjae@gmail.com)       *
 * since July 28, 2020                            *
 **************************************************/

package util

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

func LoadConfig(config []byte) (err error) {
	viper.SetConfigType("yaml")

	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	viper.AutomaticEnv()

	err = viper.ReadConfig(bytes.NewBuffer(config))
	if err != nil {
		return err
	}

	return
}

func PrettyJson(jsonString string) string {
	var unmarshalData interface{}

	err := json.Unmarshal([]byte(jsonString), &unmarshalData)
	if err != nil { log.Error().Err(err).Msg("") }

	prettyJsonAsBytes, err := json.MarshalIndent(unmarshalData, "", "  ")
	if err != nil { log.Error().Err(err).Msg("") }

	return string(prettyJsonAsBytes)
}

func GetRandomInt(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min+1) + min
}

func ParseInvitationUrl(invitationUrl string) ([]byte, error) {

	urlParse, _ := url.Parse(invitationUrl)
	query, _ := url.ParseQuery(urlParse.RawQuery)

	_, ok := query["oob"] // we use out-of-band invitation-url
	if !ok {
		err := errors.New("invalid invitation-url format")
		log.Error().Err(err).Msg("")
		return nil, err
	}
	invitationEncoded := query["oob"][0]
	invitation, err := base64.StdEncoding.DecodeString(invitationEncoded)
	if err != nil {
		log.Error().Err(err).Msg("")
		return nil, err
	}
	return invitation, nil
}