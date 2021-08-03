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
	"io/ioutil"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func HttpError(ctx *gin.Context, status int, err error) {
	bodyAsBytes, _ := ioutil.ReadAll(ctx.Request.Body)

	body := `{
		"Method": "`+ctx.Request.Method+`",
		"RequestURI": "`+ctx.Request.RequestURI+`",
		"Content-Type": "`+ctx.Request.Header.Get("Content-Type")+`",
		"ContentLength": "`+strconv.FormatInt(ctx.Request.ContentLength, 10)+`",
		"Body": "`+string(bodyAsBytes)+`"
	}`
	log.Warn().Err(err).Msg(JsonString(body))

	errStruct := gin.H{
		"Code":    status,
		"Message": err.Error(),
	}

	ctx.JSON(status, errStruct)
	return
}

func JsonString(jsonString string) string {
	var unmarshalData interface{}

	jsonString = strings.ReplaceAll(jsonString, "\n", "")

	err := json.Unmarshal([]byte(jsonString), &unmarshalData)
	if err != nil { log.Error().Err(err).Msg("") }

	jsonStringAsBytes, err := json.Marshal(unmarshalData)
	if err != nil { log.Error().Err(err).Msg("") }

	return string(jsonStringAsBytes)
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
	token := strings.Split(invitationUrl, "?c_i=")
	if len(token) != 2 {
		err := errors.New("invalid invitation-url format")
		log.Error().Err(err).Msg("")
		return nil, err
	}

	invitation, err := base64.StdEncoding.DecodeString(token[1])
	if err != nil {
		log.Error().Err(err).Msg("")
		return nil, err
	}
	return invitation, nil
}