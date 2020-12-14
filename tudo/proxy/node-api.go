/**
 * Written by Vy Nguyen (2018)
 */
package proxy

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/tudo/kstore"
	"github.com/ethereum/go-ethereum/tudo/utils"
)

type TdNodeApi struct {
	config  *TdConfig
	kstore  *kstore.TdStore
	chainId uint64
	stockId uint64
	stop    chan struct{}
}

type SignedMessage struct {
	Address  []byte
	MesgHash string
	RValue   string
	SValue   string
	MesgType int
	HashType int
	Mesg     []byte
}

func newTdNodeApi(conf *TdConfig, stop chan struct{}) *TdNodeApi {
	chainId := conf.ChainId
	stockId := conf.StockId
	return &TdNodeApi{
		config:  conf,
		stop:    stop,
		chainId: chainId,
		stockId: stockId,
		kstore:  kstore.NewTdStore(conf.KeyStoreDir, chainId, stockId),
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

func (api *TdNodeApi) GetStoreApi() kstore.TdStoreApi {
	return api.kstore
}

func (api *TdNodeApi) DebugDump(auth string) {
	api.kstore.DebugDump(auth)
}

func (api *TdNodeApi) GetPublicKey(addr, auth string) ([]byte, error) {
	account, err := api.GetAccount(addr)
	if account == nil || err != nil {
		return nil, errors.New("Invalid address")
	}
	err = account.Decrypt(auth)
	if err != nil || account.Key == nil {
		return nil, err
	}
	pubKey := crypto.FromECDSAPub(&account.Key.PrivateKey.PublicKey)
	account.LockKey()
	return pubKey, nil
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

func (api *TdNodeApi) GetWalletEntry(acct string) (*kstore.WalletEntry, error) {
	account, err := kstore.GetAccount(acct)
	if account == nil || err != nil {
		return nil, errors.New("Invalid account address")
	}
	return api.kstore.GetWalletEntry(account)
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
func (api *TdNodeApi) CreateAccount(pubName, privName,
	groupName, contact, desc, auth string) (*kstore.WalletEntry, error) {

	log.Info("Create account", "privName", privName, "pubName", pubName)
	return api.kstore.CreateAccount(pubName, privName, groupName, contact, desc, auth, api.chainId)
}

// CreateStock creates a new account with stock contract.
//
func (api *TdNodeApi) CreateStock(pubName, privName,
	groupName, contact, desc, auth string) (*kstore.WalletEntry, error) {

	log.Info("Create stock account", "privName", privName, "pubName", pubName)
	return api.kstore.CreateAccount(pubName, privName, groupName, contact, desc, auth, api.stockId)
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
	groupName, contact, desc, auth string, chainId uint64) (*kstore.WalletEntry, error) {

	privKey, err := crypto.HexToECDSA(pKey)
	if err != nil {
		return nil, err
	}
	log.Debug("Priv key", "key", privKey)
	return api.kstore.ImportAccount(privKey, pubName,
		privName, groupName, contact, desc, auth, chainId)
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

type AccountKey struct {
	Address    string
	PrivateKey string
}

func (api *TdNodeApi) ToStringKey(key *keystore.Key) *AccountKey {
	return &AccountKey{
		Address:    key.Address.Hex(),
		PrivateKey: hex.EncodeToString(crypto.FromECDSA(key.PrivateKey)),
	}
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

func (api *TdNodeApi) IsEntryPersisted(acct string) bool {
	account, err := kstore.GetAccount(acct)
	if account == nil || err != nil {
		return false
	}
	return api.kstore.IsEntryPersisted(account)
}

func (api *TdNodeApi) IsAccountPersisted(acct string) bool {
	account, err := kstore.GetAccount(acct)
	if account == nil || err != nil {
		log.Error("Invalid account addr", "addr", acct)
		return false
	}
	return api.kstore.IsAccountPersisted(account)
}

func (api *TdNodeApi) getPrivKey(addr, auth string) (*keystore.Key, error) {
	account, err := api.GetAccount(addr)
	if account == nil || err != nil {
		return nil, err
	}
	err = account.Decrypt(auth)
	if err != nil || account.Key == nil {
		return nil, err
	}
	return account.Key, nil
}

func (api *TdNodeApi) SignMesg(from, auth, mesg string) (*SignedMessage, error) {
	key, err := api.getPrivKey(from, auth)
	if err != nil || key == nil {
		return nil, err
	}
	return api.seal(key, []byte(mesg))
}

func (api *TdNodeApi) seal(key *keystore.Key, mesg []byte) (*SignedMessage, error) {
	privKey := key.PrivateKey
	pubKey := crypto.FromECDSAPub(&key.PrivateKey.PublicKey)

	data := []byte(mesg)
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, err
	}
	return &SignedMessage{
		Address:  pubKey,
		MesgHash: "0x" + utils.ToHex(hash[:]),
		RValue:   r.String(),
		SValue:   s.String(),
		HashType: 256,
		MesgType: 0,
		Mesg:     data,
	}, nil
}

func (api *TdNodeApi) EncryptAndSign(from, auth, mesg, to string,
	pubKey []byte) (*SignedMessage, error) {

	key, err := api.getPrivKey(from, auth)
	if err != nil || key == nil {
		return nil, err
	}
	cipherText, err := api.encryptData([]byte(pubKey), []byte(mesg))
	if err != nil {
		return nil, err
	}
	return api.seal(key, cipherText)
}

func (api *TdNodeApi) encryptData(pubKey, mesg []byte) ([]byte, error) {
	pKey, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil || pKey == nil || mesg == nil {
		if err == nil {
			err = errors.New("Empty encrypted message")
		}
		return nil, err
	}
	encKey := ecies.ImportECDSAPublic(pKey)
	return ecies.Encrypt(rand.Reader, encKey, mesg, nil, nil)
}

func (api *TdNodeApi) EncryptMesg(fr, auth, mesg, to string, pub []byte) (*SignedMessage, error) {
	cipherText, err := api.encryptData([]byte(pub), []byte(mesg))
	if err != nil {
		return nil, err
	}
	return &SignedMessage{
		Address:  nil,
		MesgHash: "",
		RValue:   "",
		SValue:   "",
		HashType: 0,
		MesgType: 0,
		Mesg:     cipherText,
	}, nil
}

func (api *TdNodeApi) DecryptMesg(addr, auth string, cipher []byte) (string, error) {
	key, err := api.getPrivKey(addr, auth)
	if err != nil || key == nil {
		return "", err
	}
	pKey := ecies.ImportECDSA(key.PrivateKey)
	text, err := pKey.Decrypt(cipher, nil, nil)
	if text != nil {
		return string(text), nil
	}
	return "", nil
}
