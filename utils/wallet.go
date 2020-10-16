/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Baegjae Sung (baegjae@gmail.com)     *
 * since October 12, 2020                         *
 **************************************************/

package utils

import (
	"sync"
)

type WalletPool struct {
	walletMap sync.Map
}

func NewWalletPool() *WalletPool {
	return &WalletPool{}
}

func (wp *WalletPool) SetWalletName(holderId string, version string) {
	wp.walletMap.Store(holderId, "alice_"+holderId+"."+version)
	return
}

func (wp *WalletPool) GetWalletName(holderId string) string {
	walletName, ok := wp.walletMap.Load(holderId)
	if ok == false {
		log.Fatal("[" + holderId + "] get value before setting")
	}

	return walletName.(string)
}

func (wp *WalletPool) DeleteWallet(holderId string, agentApiUrl string) error {
	// Delete wallet
	log.Info("[" + holderId + "] Delete my wallet - walletName: " + wp.GetWalletName(holderId))
	_, err := RequestDelete(agentApiUrl, "/wallet/me", wp.GetWalletName(holderId))
	if err != nil {
		log.Error("utils.RequestDelete() error:", err.Error())
		return err
	}
	log.Info("[" + holderId + "] Delete wallet done - walletName: " + wp.GetWalletName(holderId))

	return nil
}
