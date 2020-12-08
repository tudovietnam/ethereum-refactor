/*
 *--------1---------2---------3---------4---------5---------6---------7---------8--------
 * Written by Vy Nguyen (2018)
 * Refactor from Ethereum go source.
 */
package kstore

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

const (
	// Default time to refresh wallets from keystore.
	DefaultGroup  = "Personal"
	ContractNonce = 0x8fffffffffffffff
)

var (
	NilAddress = common.Address{}
	NilAccount = accounts.Account{}
)

// AddrToAccount converts an address to account format.
//
func AddrToAccount(addr common.Address) *accounts.Account {
	return &accounts.Account{
		Address: addr,
		URL: accounts.URL{
			Scheme: "eth",
			Path:   addr.Hex(),
		},
	}
}

func AddrStrToAccount(addr string) *accounts.Account {
	if !common.IsHexAddress(addr) {
		return nil
	}
	return AddrToAccount(common.HexToAddress(addr))
}

type WalletEntryOps interface {
	saveRec(baseDir string) error
	deleteRec(baseDir string) error
	selfVerify(path string) error
	restoreRec(path string) error
	isPersisted(baseDir string) bool
	SerializeSha1() ([]byte, string)
	Deserialize(decode *json.Decoder) error
}

type WalletEntry struct {
	Account     *accounts.Account `json:"-"`
	ops         WalletEntryOps    `json:"-"`
	ETag        string            `json:"-"`
	JsonAcct    string            `json:"account"`
	GroupName   string            `json:"groupName"`
	PublicName  string            `json:"publicName"`
	PrivateName string            `json:"privateName"`
	ContactInfo string            `json:"contactInfo"`
	Description string            `json:"description"`
}

// Account from wallet entry with optional private key.
//
type AccountEntry struct {
	*keystore.Key
	WalletEntry
	EncryptKey []byte
	Balance    uint64
	Nonce      uint64
	BlkAt      uint64
	Contract   uint64
}

func (ae *AccountEntry) GetBalance() uint64 { return ae.Balance }
func (ae *AccountEntry) GetNonce() uint64   { return ae.Nonce }
func (ae *AccountEntry) ClearKey() {
	if ae.Key != nil {
		key := ae.Key.PrivateKey
		key.X.SetInt64(0)
		key.Y.SetInt64(0)
		key.D.SetInt64(0)
	}
}

// Serializes AccountEntry to JSON to save to persistent storage.
//
type AccountEntryJson struct {
	Info       WalletEntry `json:"info"`
	EncryptKey []byte      `json:"key"`
}

type StockEntryJson struct {
	AccountEntryJson
	ContractNonce uint64 `json:"nonce"`
}

type Wallet struct {
	accounts map[string]*AccountEntry
	recPath  string
	Mu       sync.Mutex
}

// NewWallet allocates base wallet.
//
func NewWallet(scryptN, scryptP int, path string) *Wallet {
	wallet := &Wallet{
		accounts: make(map[string]*AccountEntry),
		recPath:  path,
	}
	return wallet
}

func (w *Wallet) AccountMap() map[string]*AccountEntry { return w.accounts }
func (w *Wallet) Save() error                          { return errors.New("Base wallet save") }
func (w *Wallet) Load() error                          { return errors.New("Base wallet load") }

// Factory to create wallet account entries.
//
func (w *Wallet) NewAccountEntry(key *keystore.Key,
	we *WalletEntry, auth string, contract bool) *AccountEntry {
	return NewAccountEntry(key, we, auth, contract)
}

func NewAccountEntry(key *keystore.Key, we *WalletEntry,
	auth string, contract bool) *AccountEntry {

	entry := newFsAccountEntry(key, we, auth)
	if err := entry.Encrypt(auth); err != nil {
		log.Error("Failed to encrypt key", "error", err)
		return nil
	}
	if contract == true {
		entry.Contract = ContractNonce
	}
	return entry
}

func (w *Wallet) NewWalletEntry(acct *accounts.Account) *WalletEntry {
	return newFsWalletEntry(acct)
}

// GetAddress returns address from hex string.
//
func GetAddress(acct string) (*common.Address, error) {
	s := acct
	if s[0] == '0' {
		s = s[1:]
	}
	if s[0] == 'x' || s[0] == 'X' {
		s = s[1:]
	}
	adr, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	hexAddr := common.BytesToAddress(adr)
	return &hexAddr, nil
}

func GetAccount(acct string) (*accounts.Account, error) {
	addr, err := GetAddress(acct)
	if err == nil {
		return &accounts.Account{Address: *addr}, nil
	}
	return nil, err
}

func (we *WalletEntry) Copy(that *WalletEntry) {
	we.Account = that.Account
	we.ETag = that.ETag
	we.JsonAcct = that.JsonAcct
	we.GroupName = that.GroupName
	we.PublicName = that.PublicName
	we.PrivateName = that.PrivateName
	we.ContactInfo = that.ContactInfo
	we.Description = that.Description
}

func (ae *AccountEntry) IsContract() bool {
	return ae.Contract == ContractNonce
}
