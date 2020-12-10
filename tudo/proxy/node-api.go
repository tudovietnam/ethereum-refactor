/**
 * Written by Vy Nguyen (2018)
 */
package proxy

import (
	"errors"

	"github.com/ethereum/go-ethereum/accounts/keystore"
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
	return api.kstore.EnableService()
}

// NewWalletEntry creates a new wallet entry.
//
func (api *TdNodeApi) NewWalletEntry(acct, grp string,
	pub, priv, contact, desc string) (*kstore.WalletEntry, error) {

	account, err := kstore.GetAccount(acct)
	if account == nil || err != nil {
		return nil, errors.New("Invalid address")
	}
	entry := kstore.NewWalletEntry(account)
	entry.Update(grp, pub, priv, contact, desc)
	return entry, api.kstore.PersistEntry(entry)
}

// UpdateWalletEntry updates existing entry with new data.
//
func (api *TdNodeApi) UpdateWalletEntry(acct, grp string,
	pub, priv, contact, desc string) (*kstore.WalletEntry, error) {

	account, err := kstore.GetAccount(acct)
	if account == nil || err != nil {
		return nil, errors.New("Invalid address")
	}
	return api.kstore.UpdateWalletEntry(account, grp, pub, priv, contact, desc)
}

func (api *TdNodeApi) PersistEntry(entry *kstore.WalletEntry) error {
	return api.kstore.PersistEntry(entry)
}

// DeleteEntry removes wallet entry based on account.
//
func (api *TdNodeApi) DeleteEntry(acct string) error {
	account, err := kstore.GetAccount(acct)
	if account == nil || err != nil {
		return errors.New("Invalid address")
	}
	return api.kstore.DeleteEntry(account)
}

func (api *TdNodeApi) DeleteAccount(addr, auth string) error {
	account, err := kstore.GetAccount(addr)
	if account == nil || err != nil {
		return errors.New("Invalid account address")
	}
	return api.kstore.DeleteAccount(account, auth)
}

//
func (api *TdNodeApi) GetAccount(acct string) (*kstore.AccountEntry, error) {
	account, err := kstore.GetAccount(acct)
	if account == nil || err != nil {
		return nil, errors.New("Invalid account address")
	}
	return api.kstore.GetAccount(account)
}

func (api *TdNodeApi) PayToRelayNonce(from, to, auth string,
	xuAmt, nonce, chainId uint64) (*RelaySignedTx, error) {

	fromAcct, err := kstore.GetAccount(from)
	if fromAcct == nil || err != nil {
		return nil, errors.New("Invalid from account address")
	}
	toAcct, err := kstore.GetAccount(to)
	if toAcct == nil || err != nil {
		return nil, errors.New("Invalid to account address")
	}
	signedTx, err := api.kstore.PayToRelayNonce(fromAcct, toAcct, auth, xuAmt, nonce, chainId)
	return &RelaySignedTx{
		From:     fromAcct.Address.Hex(),
		To:       toAcct.Address.Hex(),
		SignedTx: *signedTx,
	}, err
}

// CreateAccount creates a new account.
//
func (api *TdNodeApi) CreatAccount(pubName, privName,
	groupName, contact, desc, auth string) (*kstore.WalletEntry, error) {

	log.Info("Create account", "privName", privName, "pubName", pubName)
	return api.kstore.CreateAccount(pubName, privName, groupName, contact, desc, auth, false)
}

// CreateStock creates a new account with stock contract.
//
func (api *TdNodeApi) CreatStock(pubName, privName,
	groupName, contact, desc, auth string) (*kstore.WalletEntry, error) {

	log.Info("Create stock account", "privName", privName, "pubName", pubName)
	return api.kstore.CreateAccount(pubName, privName, groupName, contact, desc, auth, true)
}

// UpdateAccount updates existing account.
//
func (api *TdNodeApi) UpdateAccount(address, pubName, privName,
	groupName, contact, desc, oldAuth, newAuth string) (*kstore.AccountEntry, error) {

	log.Info("Update account", "address", address, "pubName", pubName)
	account, err := kstore.GetAccount(address)
	if account == nil || err != nil {
		return nil, errors.New("Invalid account address")
	}
	return api.kstore.UpdateAccount(account, pubName,
		privName, groupName, contact, desc, oldAuth, newAuth)
}

// ImportAccount imports external account.
//
func (api *TdNodeApi) ImportAccount(pKey, pubName, privName,
	groupName, contact, desc, auth string, stock bool) (*kstore.WalletEntry, error) {

	privKey, err := crypto.HexToECDSA(pKey)
	if err != nil {
		return nil, err
	}
	log.Debug("Priv key", "key", privKey)
	return api.kstore.ImportAccount(privKey, pubName,
		privName, groupName, contact, desc, auth, stock)
}

// GetAllAccounts returns all accounts in the store.
//
func (api *TdNodeApi) GetAllAccounts() ([]kstore.AccountEntry, error) {
	return api.kstore.GetAllAccounts()
}

func (api *TdNodeApi) GetAddressBook() ([]kstore.WalletEntry, error) {
	return api.kstore.GetAddressBook()
}

// OpenAccount decrypts the key, open the account to send payment.
//
func (api *TdNodeApi) OpenAccount(acct, auth string) (*keystore.Key, error) {
	log.Info("Lock account", "account", acct)
	account, err := kstore.GetAccount(acct)
	if account == nil || err != nil {
		return nil, errors.New("Invalid account address")
	}
	return api.kstore.OpenAccount(account, auth)
}

// CloseAccount encrypts the key.
//
func (api *TdNodeApi) CloseAccount(acct string) error {
	account, err := kstore.GetAccount(acct)
	if account == nil || err != nil {
		return errors.New("Invalid account address")
	}
	return api.kstore.CloseAccount(account)
}

// DeleteAccountKey removes private key from account record.
//
func (api *TdNodeApi) DeleteAccountKey(acct string) error {
	account, err := kstore.GetAccount(acct)
	if account == nil || err != nil {
		return errors.New("Invalid account address")
	}
	return api.kstore.DeleteAccountKey(account)
}
