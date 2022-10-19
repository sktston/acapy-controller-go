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
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	client = resty.New()
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
	if err != nil {
		log.Error().Err(err).Msg("")
	}

	prettyJsonAsBytes, err := json.MarshalIndent(unmarshalData, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("")
	}

	return string(prettyJsonAsBytes)
}

func GetRandomInt(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min+1) + min
}

func ParseInvitationUrl(invitationUrl string) (string, error) {
	urlParse, _ := url.Parse(invitationUrl)
	query, _ := url.ParseQuery(urlParse.RawQuery)

	invitationEncoded := ""
	_, ok := query["oob"]
	if ok { // out-of-band invitation-url case
		invitationEncoded = query["oob"][0]
	}
	_, ok = query["c_i"]
	if ok { // connection invitation-url case
		invitationEncoded = query["c_i"][0]
	}
	if invitationEncoded == "" {
		err := errors.New("invalid invitation-url format")
		log.Error().Err(err).Msg("")
		return "", err
	}

	invitation, err := base64.URLEncoding.DecodeString(invitationEncoded)
	if err != nil {
		log.Error().Err(err).Msg("")
		return "", err
	}
	return string(invitation), nil
}

func CheckHttpResult(resp *resty.Response, err error) error {
	if resp.IsSuccess() != true {
		return errors.New(string(resp.Body()))
	}

	if err != nil {
		return err
	}

	return nil
}

func DeleteAcapyData(agentApiUrl string, jwtToken string, walletId string, deleteDataList ...string) error {
	for _, deleteData := range deleteDataList {
		if deleteData == "connection" {
			log.Info().Msgf("Delete connections")
			if err := deleteAllConnections(agentApiUrl, jwtToken); err != nil {
				return err
			}
		}

		if deleteData == "credential" {
			log.Info().Msgf("Delete credentials")
			if err := deleteAllCredentials(agentApiUrl, jwtToken); err != nil {
				return err
			}
		}

		if deleteData == "credential_exchange" {
			log.Info().Msgf("Delete credential exchanges")
			if err := deleteAllCredentialExchanges(agentApiUrl, jwtToken); err != nil {
				return err
			}
		}

		if deleteData == "presentation_exchange" {
			log.Info().Msgf("Delete presentation exchanges")
			if err := deleteAllPresentationExchanges(agentApiUrl, jwtToken); err != nil {
				return err
			}
		}

		if deleteData == "wallet" && viper.GetBool("use-multitenancy") == true {
			log.Info().Msgf("Delete wallet")
			if err := deleteWallet(agentApiUrl, walletId); err != nil {
				return err
			}
		}
	}

	return nil
}

func deleteWallet(agentApiUrl string, walletId string) error {
	// Delete wallet
	log.Debug().Msgf(walletId)
	resp, err := client.R().
		Post(agentApiUrl + "/multitenancy/wallet/" + walletId + "/remove")
	if err := CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}

	return nil
}

func deleteAllConnections(agentApiUrl string, jwtToken string) error {
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Get(agentApiUrl + "/connections")
	if err := CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}

	connections := gjson.Get(resp.String(), "results").Array()
	for idx, conn := range connections {
		connId := gjson.Get(conn.String(), "connection_id").String()
		log.Debug().Msgf("(%d) connId: %s", idx+1, connId)
		resp, err = client.R().
			SetAuthToken(jwtToken).
			Delete(agentApiUrl + "/connections/" + connId)
		if err := CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
	}

	return nil
}

func deleteAllCredentials(agentApiUrl string, jwtToken string) error {
	startIndex := 0
	count := 32
	for {
		resp, err := client.R().
			SetQueryParam("start", strconv.Itoa(startIndex)).
			SetQueryParam("count", strconv.Itoa(count)).
			SetQueryParam("wql", "{}").
			SetAuthToken(jwtToken).
			Get(agentApiUrl + "/credentials")
		if err := CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}

		credentials := gjson.Get(resp.String(), "results").Array()
		if len(credentials) == 0 {
			break
		}

		for idx, cred := range credentials {
			credId := gjson.Get(cred.String(), "referent").String()
			credAttrs := gjson.Get(cred.String(), "attrs").String()
			log.Debug().Msgf("(%d) %s: %s", startIndex+idx+1, credId, credAttrs)
			resp, err = client.R().
				SetAuthToken(jwtToken).
				Delete(agentApiUrl + "/credential/" + credId)
			if err := CheckHttpResult(resp, err); err != nil {
				log.Error().Err(err).Caller().Msgf("")
				return err
			}
		}
		startIndex += count
	}

	return nil
}

func deleteAllCredentialExchanges(agentApiUrl string, jwtToken string) error {
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Get(agentApiUrl + "/issue-credential/records")
	if err := CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}

	credExs := gjson.Get(resp.String(), "results").Array()
	for idx, credEx := range credExs {
		credExId := gjson.Get(credEx.String(), "credential_exchange_id").String()
		log.Debug().Msgf("(%d) credExId: %s", idx+1, credExId)
		resp, err = client.R().
			SetAuthToken(jwtToken).
			Delete(agentApiUrl + "/issue-credential/records/" + credExId)
		if err := CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
	}

	return nil
}

func deleteAllPresentationExchanges(agentApiUrl string, jwtToken string) error {
	resp, err := client.R().
		SetAuthToken(jwtToken).
		Get(agentApiUrl + "/present-proof/records")
	if err := CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msgf("")
		return err
	}

	presExs := gjson.Get(resp.String(), "results").Array()
	for idx, presEx := range presExs {
		presExId := gjson.Get(presEx.String(), "presentation_exchange_id").String()
		log.Debug().Msgf("(%d) presExId: %s", idx+1, presExId)
		resp, err = client.R().
			SetAuthToken(jwtToken).
			Delete(agentApiUrl + "/present-proof/records/" + presExId)
		if err := CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msgf("")
			return err
		}
	}

	return nil
}
