/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Baegjae Sung (baegjae@gmail.com)     *
 * since July 28, 2020                            *
 **************************************************/

package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const (
	exitOnHttpError = true
)

var (
	httpClient                = &http.Client{}
	HttpTimeout time.Duration = 3600 // seconds
)

func RequestGet(url string, uri string, token string, headers ...string) ([]byte, error) {
	return httpRequest(http.MethodGet, url, uri, token, []byte(""), headers...)
}

func RequestPost(url string, uri string, token string, body []byte, headers ...string) ([]byte, error) {
	appendHeaders := append(headers, "Content-Type:application/json")
	return httpRequest(http.MethodPost, url, uri, token, body, appendHeaders...)
}

func RequestDelete(url string, uri string, token string, headers ...string) ([]byte, error) {
	return httpRequest(http.MethodDelete, url, uri, token, []byte(""), headers...)
}

func RequestPatch(url string, uri string, token string, body []byte, headers ...string) ([]byte, error) {
	appendHeaders := append(headers, "Content-Type:application/json")
	return httpRequest(http.MethodPatch, url, uri, token, body, appendHeaders...)
}

func RequestPut(url string, uri string, token string, body []byte, headers ...string) ([]byte, error) {
	appendHeaders := append(headers, "Content-Type:application/json")
	return httpRequest(http.MethodPut, url, uri, token, body, appendHeaders...)
}

func httpRequest(httpMethod string, url string, uri string, token string, body []byte, headers ...string) ([]byte, error) {
	httpRequest, err := http.NewRequest(httpMethod, url+uri, bytes.NewBuffer(body))

	if err != nil {
		return []byte(""), err
	}

	// Set request headers
	for _, header := range headers {
		keyValue := strings.Split(header, ":")
		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])
		httpRequest.Header.Set(key, value)
	}

	// Add jwtToken to header
	if token != "" {
		httpRequest.Header.Add("Authorization", "Bearer "+token)
	}

	// Set request timeout
	httpClient.Timeout = HttpTimeout * time.Second

	// Do request
	httpResp, err := httpClient.Do(httpRequest)

	defer func() {
		if httpResp != nil {
			_, _ = io.Copy(ioutil.Discard, httpResp.Body)
			_ = httpResp.Body.Close()
		}
	}()

	if err != nil {
		return []byte(""), err
	}

	respBodyAsBytes, err := ioutil.ReadAll(httpResp.Body)

	if err != nil {
		return []byte(""), err
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		log.Error(PrettyJson(`{
				"httpMethod": "`+httpMethod+`",
				"url+uri": "`+url+uri+`",
				"Authorization": "`+"Bearer "+token+`",
				"StatusCode": `+strconv.Itoa(httpResp.StatusCode)+`,
				"RespBody": "`+string(respBodyAsBytes)+`"
			}`, "  "))
		httpError := http.StatusText(httpResp.StatusCode)
		return respBodyAsBytes, errors.New(httpError)
	}

	// for debug
	if gjson.Valid(string(respBodyAsBytes)) {
		log.Debug("resultsAsBytes:", PrettyJson(string(respBodyAsBytes)))
	} else {
		log.Debug("resultsAsBytes:", string(respBodyAsBytes))
	}

	return respBodyAsBytes, nil
}

func HttpError(ctx *gin.Context, status int, err error, holderId ...string) {
	var (
		logFunc func(...interface{})
	)

	if exitOnHttpError == true {
		logFunc = log.Fatal
	} else {
		logFunc = log.Error
	}

	bodyAsBytes, _ := ioutil.ReadAll(ctx.Request.Body)

	logFunc("\n\tMethod:", ctx.Request.Method,
		"\n\tRequestURI:", ctx.Request.RequestURI,
		"\n\tContent-Type:", ctx.Request.Header.Values("Content-Type"),
		"\n\tContentLength:", ctx.Request.ContentLength,
		"\n\tBody:", string(bodyAsBytes),
		"\n["+holderId[0]+"] http error:", err.Error())

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
	if err != nil {
		// Caution: no error handling for easy use
		log.Error("json.Unmarshal() error", err.Error())
		log.Error("jsonString:", jsonString)
	}
	jsonStringAsBytes, err := json.Marshal(unmarshalData)
	if err != nil {
		// Caution: no error handling for easy use
		log.Error("json.Marshal() error", err.Error())
		log.Error("jsonString:", jsonString)
	}

	return string(jsonStringAsBytes)
}

func PrettyJson(jsonString string, indent ...string) string {
	var (
		unmarshalData interface{}
		marshalIndent string
	)

	err := json.Unmarshal([]byte(jsonString), &unmarshalData)
	if err != nil {
		// Caution: no error handling for easy use
		log.Error("json.Unmarshal() error", err.Error())
		log.Error("jsonString:", jsonString)
	}

	if len(indent) == 0 {
		marshalIndent = "  "
	} else {
		marshalIndent = indent[0]
	}

	prettyJsonAsBytes, err := json.MarshalIndent(unmarshalData, "", marshalIndent)
	if err != nil {
		// Caution: no error handling for easy use
		log.Error("json.MarshalIndent() error", err.Error())
		log.Error("jsonString:", jsonString)
	}

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
		log.Error(err)
		return nil, err
	}
	invitation, err := base64.StdEncoding.DecodeString(token[1])
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return invitation, nil
}