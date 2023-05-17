package util

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"net/url"
	"strconv"
)

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

func DeleteAgentData(agentApiUrl string, jwtToken string, walletId string, dataTypes ...string) error {
	client := resty.New().SetBaseURL(agentApiUrl).SetAuthToken(jwtToken)

	for _, dataType := range dataTypes {
		switch dataType {
		case "connection":
			log.Info().Msgf("Delete connections")
			if err := deleteAllConnections(client); err != nil {
				return err
			}

		case "credential":
			log.Info().Msgf("Delete credentials")
			if err := deleteAllCredentials(client); err != nil {
				return err
			}

		case "credential_exchange":
			log.Info().Msgf("Delete credential exchanges")
			if err := deleteAllCredentialExchanges(client); err != nil {
				return err
			}

		case "presentation_exchange":
			log.Info().Msgf("Delete presentation exchanges")
			if err := deleteAllPresentationExchanges(client); err != nil {
				return err
			}

		case "wallet":
			if viper.GetBool("use-multitenancy") == true {
				log.Info().Msgf("Delete wallet")
				if err := deleteWallet(client.SetAuthToken(""), walletId); err != nil {
					return err
				}
			}
			// Restore token
			client.SetAuthToken(jwtToken)

		default:
			return errors.New(fmt.Sprintf(" delete acapy data type '%s' not supported", dataType))
		}
	}

	return nil
}

func deleteAllConnections(client *resty.Client) error {
	resp, err := client.R().
		Get("/connections")
	if err = CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}

	connections := gjson.Get(resp.String(), "results").Array()
	for idx, conn := range connections {
		connId := gjson.Get(conn.String(), "connection_id").String()
		log.Debug().Msgf("(%d) connId: %s", idx+1, connId)
		resp, err = client.R().
			Delete("/connections/" + connId)
		if err = CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}
	}

	return nil
}

func deleteAllCredentials(client *resty.Client) error {
	startIndex := 0
	count := 32
	for {
		resp, err := client.R().
			SetQueryParam("start", strconv.Itoa(startIndex)).
			SetQueryParam("count", strconv.Itoa(count)).
			SetQueryParam("wql", "{}").
			Get("/credentials")
		if err = CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msg("")
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
				Delete("/credential/" + credId)
			if err = CheckHttpResult(resp, err); err != nil {
				log.Error().Err(err).Caller().Msg("")
				return err
			}
		}
		startIndex += count
	}

	return nil
}

func deleteAllCredentialExchanges(client *resty.Client) error {
	resp, err := client.R().
		Get("/issue-credential/records")
	if err = CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}

	credExs := gjson.Get(resp.String(), "results").Array()
	for idx, credEx := range credExs {
		credExId := gjson.Get(credEx.String(), "credential_exchange_id").String()
		log.Debug().Msgf("(%d) credExId: %s", idx+1, credExId)
		resp, err = client.R().
			Delete("/issue-credential/records/" + credExId)
		if err = CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}
	}

	return nil
}

func deleteAllPresentationExchanges(client *resty.Client) error {
	resp, err := client.R().
		Get("/present-proof/records")
	if err = CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}

	presExs := gjson.Get(resp.String(), "results").Array()
	for idx, presEx := range presExs {
		presExId := gjson.Get(presEx.String(), "presentation_exchange_id").String()
		log.Debug().Msgf("(%d) presExId: %s", idx+1, presExId)
		resp, err = client.R().
			Delete("/present-proof/records/" + presExId)
		if err = CheckHttpResult(resp, err); err != nil {
			log.Error().Err(err).Caller().Msg("")
			return err
		}
	}

	return nil
}

func deleteWallet(client *resty.Client, walletId string) error {
	// Delete wallet
	log.Debug().Msgf(walletId)
	resp, err := client.R().
		Post("/multitenancy/wallet/" + walletId + "/remove")
	if err = CheckHttpResult(resp, err); err != nil {
		log.Error().Err(err).Caller().Msg("")
		return err
	}

	return nil
}
