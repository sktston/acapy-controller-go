/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Ethan Sung (baegjae@gmail.com)       *
 * since July 28, 2020                            *
 **************************************************/

package utils

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand"
	"net/url"
	"time"

	"github.com/rs/zerolog/log"
)

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