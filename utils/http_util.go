/**************************************************
 * Auther  : Jihyuck Yun                          *
 *           dr.jhyun@gmail.com                   *
 * since July 28, 2020                            *
 **************************************************/

package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

var (
	httpClient = &http.Client{}
)

func RequestGet(url string, uri string, timeout time.Duration) ([]byte, error) {
	return httpRequest(http.MethodGet, url, uri, []byte(""), timeout, "Accept:application/json")
}

func RequestGETByteArray(url string, uri string, timeout time.Duration) ([]byte, error) {
	return httpRequest(http.MethodGet, url, uri, []byte(""), timeout)
}

func RequestPost(url string, uri string, body []byte, timeout time.Duration) ([]byte, error) {
	return httpRequest(http.MethodPost, url, uri, body, timeout, "Content-Type:application/json", "Accept:application/json")
}

func RequestPatch(url string, uri string, body []byte, timeout time.Duration) ([]byte, error) {
	return httpRequest(http.MethodPatch, url, uri, body, timeout, "Content-Type:application/json", "Accept:application/json")
}

func RequestPut(url string, uri string, body []byte, timeout time.Duration, headers ...string) ([]byte, error) {
	return httpRequest(http.MethodPut, url, uri, body, timeout, headers...)
}

func httpRequest(httpMethod string, url string, uri string, body []byte, timeout time.Duration, headers ...string) ([]byte, error) {
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

	// Set request timeout
	httpClient.Timeout = timeout * time.Second

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

func HttpError(ctx *gin.Context, status int, err error) {
	errStruct := gin.H{
		"Code"    : status,
		"Message" : err.Error(),
	}

	ctx.JSON(status, errStruct)
	return
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
	return rand.Intn(max - min + 1) + min
}