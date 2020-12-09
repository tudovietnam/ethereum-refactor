/**
 * Written by Vy Nguyen (2018)
 */
package proxy

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/tudo/kstore"
)

type TdNodeApi struct {
	config *TdConfig
	kstore *kstore.TdStore
	stop   chan struct{}
}

func newTdNodeApi(conf *TdConfig, stop chan struct{}) *TdNodeApi {
	return &TdNodeApi{
		config: conf,
		stop:   stop,
		kstore: kstore.NewTdStore(conf.KeyStoreDir),
	}
}

func (api *TdNodeApi) Start() error {
	log.Info("Start API service")
	return api.kstore.Load()
}

func (api *TdNodeApi) Stop() {
}

func (api *TdNodeApi) EnableService() error {
	log.Info("Enable API service")
	return nil
}

// NewWalletEntry creates a new wallet entry.
//
func (api *TdNodeApi) NewWalletEntry(acct, grp string,
	pub, priv, contact, desc string) (*kstore.WalletEntry, error) {

	account := kstore.AddrStrToAccount(acct)
	if account == nil {
		return nil, errors.New(fmt.Sprintf("Invalid address %s", acct))
	}
	entry := kstore.NewWalletEntry(account)
	entry.Update(grp, pub, priv, contact, desc)
	return entry, api.PersistEntry(entry)
}

// UpdateWalletEntry updates existing entry with new data.
//
func (api *TdNodeApi) UpdateWalletEntry(acct, grp string,
	pub, priv, contact, desc string) (*kstore.WalletEntry, error) {

	account := kstore.AddrStrToAccount(acct)
	if account == nil {
		return nil, errors.New("Invalid address")
	}
	return nil, nil
}

func (api *TdNodeApi) PersistEntry(entry *kstore.WalletEntry) error {
	return nil
}

// DeleteEntry removes wallet entry based on account.
//
func (api *TdNodeApi) DeleteEntry(acct string) error {
	account := kstore.AddrStrToAccount(acct)
	if account == nil {
		return errors.New(fmt.Sprintf("Invalid address %s", acct))
	}
	return nil
}

func (api *TdNodeApi) DeleteAccount(addr, auth string) error {
	if !common.IsHexAddress(addr) {
		return errors.New("Invalid address")
	}
	return nil
}

func (api *TdNodeApi) DeleteEntryCall(entry *kstore.WalletEntry) error {
	return nil
}

// GetAccount returns the account matching address, without private key info.
//
func (api *TdNodeApi) GetAccount(acct *accounts.Account) (*kstore.AccountEntry, error) {
	return nil, nil
}

// PayToRelay returns relay signed transaction.
//
func (api *TdNodeApi) PayToRelay(from, to *accounts.Account,
	auth string, xuAmt, chainId uint64) (*RelaySignedTx, error) {

	return &RelaySignedTx{
		From:     from.Address.Hex(),
		To:       to.Address.Hex(),
		SignedTx: types.Transaction{},
		// SignedTx: *signedTx,
	}, nil
}

func (api *TdNodeApi) PayToRelayNonce(from, to *accounts.Account,
	auth string, xuAmt, nonce, chainId uint64) (*RelaySignedTx, error) {

	return &RelaySignedTx{
		From:     from.Address.Hex(),
		To:       to.Address.Hex(),
		SignedTx: types.Transaction{},
		// SignedTx: *signedTx,
	}, nil
}

// CreateAccount creates a new account.
//
func (api *TdNodeApi) CreatAccount(pubName, privName,
	groupName, contact, desc, auth string) (*kstore.WalletEntry, error) {
	log.Info("Create account", "privName", privName, "pubName", pubName)

	return nil, nil
}

// CreateStock creates a new account with stock contract.
//
func (api *TdNodeApi) CreatStock(pubName, privName,
	groupName, contact, desc, auth string) (*kstore.WalletEntry, error) {
	log.Info("Create stock account", "privName", privName, "pubName", pubName)
	return nil, nil
}

// UpdateAccount updates existing account.
//
func (api *TdNodeApi) UpdateAccount(address, pubName, privName,
	groupName, contact, desc, auth string) (*kstore.AccountEntry, error) {
	log.Info("Update account", "address", address, "pubName", pubName)
	return nil, nil
}

// ImportAccount imports external account.
//
func (api *TdNodeApi) ImportAccount(pKey, pubName, privName,
	groupName, contact, desc, auth string) (*kstore.WalletEntry, error) {

	privKey, err := crypto.HexToECDSA(pKey)
	if err != nil {
		return nil, err
	}
	log.Info("Priv key", "key", privKey)
	return nil, nil
}

// GetAllAccounts returns all accounts in the store.
//
func (api *TdNodeApi) GetAllAccounts() ([]kstore.AccountEntry, error) {
	return nil, nil
}

// OpenAccount decrypts the key, open the account to send payment.
//
func (api *TdNodeApi) OpenAccount(acct *accounts.Account, auth string) (*keystore.Key, error) {
	log.Info("Lock account", "account", acct.Address.Hex())

	return nil, nil
}

// CloseAccount encrypts the key.
//
func (api *TdNodeApi) CloseAccount(acct *accounts.Account) error {
	return nil
}

// DeleteAccountKey removes private key from account record.
//
func (api *TdNodeApi) DeleteAccountKey(acct *accounts.Account) error {
	return nil
}
