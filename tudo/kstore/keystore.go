package kstore

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/tudo/utils"
)

const (
	walletDir   = "wallet"
	addrBookDir = "address"
)

type TdStore struct {
	cryptN    int
	cryptP    int
	kstoreDir string
	addrBook  map[string]*WalletEntry
	accounts  map[string]*AccountEntry
	Lock      sync.Mutex
}

func NewTdStore(dir string) *TdStore {
	return &TdStore{
		cryptN:    keystore.StandardScryptN,
		cryptP:    keystore.StandardScryptP,
		kstoreDir: dir,
		addrBook:  make(map[string]*WalletEntry),
		accounts:  make(map[string]*AccountEntry),
	}
}

func (store *TdStore) Load() error {
	bookDir := filepath.Join(store.kstoreDir, addrBookDir)
	if err := os.MkdirAll(bookDir, 0700); err != nil {
		log.Error("Failed to make dirs", "dir", bookDir)
		return err
	}
	acctDir := filepath.Join(store.kstoreDir, walletDir)
	if err := os.MkdirAll(acctDir, 0700); err != nil {
		log.Error("Failed to make dirs", "dir", acctDir)
		return err
	}
	if err := filepath.Walk(acctDir, store.loadRecords(true)); err != nil {
		log.Error("Failed to load accounts", "error", err)
		return err
	}
	if err := filepath.Walk(bookDir, store.loadRecords(false)); err != nil {
		log.Error("Failed to load addrbook", "error", err)
		return err
	}
	return nil
}

func (store *TdStore) loadRecords(acct bool) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if acct {
			entry := &AccountEntry{}
			if err := entry.restoreRec(path); err != nil {
				return nil
			}
			if entry.JsonAcct == "" {
				log.Error("Bad account entry", "file", path)
			} else {
				store.accounts[entry.AccountKey()] = entry
			}
		} else {
			entry := &WalletEntry{}
			if err := entry.restoreRec(path); err != nil {
				return nil
			}
			if entry.JsonAcct == "" {
				log.Error("Bad addrbook entry", "file", path)
			} else {
				store.addrBook[entry.AccountKey()] = entry
			}
		}
		return nil
	}
}

//////////////////    W a l l e t    A d d r e s s b o o k    //////////////////////////

func (we *WalletEntry) Update(grp, pub, priv, contact, desc string) {
	if grp != "" && we.GroupName != grp {
		we.GroupName = grp
	}
	if pub != "" && we.PublicName != pub {
		we.PublicName = pub
	}
	if priv != "" && we.PrivateName != priv {
		we.PrivateName = priv
	}
	if contact != "" && we.ContactInfo != contact {
		we.ContactInfo = contact
	}
	if desc != "" && we.Description != desc {
		we.Description = desc
	}
}

func (we *WalletEntry) restoreRec(path string) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()

	if err := we.Deserialize(json.NewDecoder(fd)); err != nil {
		log.Warn("Failed to decode entry", "file", path, "error", err)
		return err
	}
	if err := we.selfVerify(path); err != nil {
		log.Error("Wallet entry failed self-verified", "file", path, "error", err)
		return err
	}
	we.ETag = filepath.Base(path)
	return nil
}

func (we *WalletEntry) deleteRec(base string) error {
	_, hash := we.SerializeSha1()

	if we.ETag != "" && we.ETag != hash {
		log.Info("Remove old etag", "tag", we.ETag)
		os.Remove(filepath.Join(base, we.ETag))
	}
	hash = filepath.Join(base, hash)
	err := os.Remove(hash)
	log.Info("Removed wallet entry", "file", hash, "error", err)
	return err
}

func (we *WalletEntry) selfVerify(path string) error {
	_, hash := we.SerializeSha1()

	if hash != filepath.Base(path) {
		log.Warn("Corrupt wallet entry", "file", path)
		return errors.New("Corrupt entry")
	}
	return nil
}

// Key returns account key for the entry.
//
func (we *WalletEntry) AccountKey() string {
	if we.Account == nil {
		we.Account = AddrToAccount(common.HexToAddress(we.JsonAcct))
	}
	return we.Account.Address.Hex()
}

// SerializeSha1 returns sha1 hash and json byte stream of the entry.
//
func (we *WalletEntry) SerializeSha1() ([]byte, string) {
	content, err := json.Marshal(we)
	if err != nil {
		log.Error("Failed to encode json", "entry", we)
		return nil, ""
	}
	sum := sha1.Sum(content)
	return content, utils.ToHex(sum[:])
}

// Deserialize decodes the Json byte stream back to WalletEntry format.
//
func (we *WalletEntry) Deserialize(decode *json.Decoder) error {
	return decode.Decode(we)
}

func (we *WalletEntry) Print() {
	acct := "nil"
	if we.Account != nil {
		acct = fmt.Sprintf("%s %s", we.Account.Address.Hex(), we.Account.URL.String())
	}
	fmt.Printf(`Account......... %s
ETag............ %s
JsonAcct........ %s
Group Name...... %s
Pubic Name...... %s
Private Name.... %s
Contact Info.... %s
Description..... %s
`,
		acct, we.ETag, we.JsonAcct,
		we.GroupName, we.PublicName, we.PrivateName, we.ContactInfo, we.Description)
}

//////////////////    A c c o u n t    E n t r y    //////////////////////////

func (ae *AccountEntry) restoreRec(path string) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()

	if err := ae.Deserialize(json.NewDecoder(fd)); err != nil {
		log.Warn("Failed to decode entry", "file", path, "error", err)
		return err
	}
	if err := ae.selfVerify(path); err != nil {
		log.Error("Wallet entry failed self-verified", "file", path, "error", err)
		return err
	}
	ae.ETag = filepath.Base(path)
	return nil
}

func (ae *AccountEntry) deleteRec(base string) error {
	_, hash := ae.SerializeSha1()

	if ae.ETag != "" && ae.ETag != hash {
		log.Info("Remove old etag", "tag", ae.ETag)
		os.Remove(filepath.Join(base, ae.ETag))
	}
	hash = filepath.Join(base, hash)
	err := os.Remove(hash)
	log.Info("Removed wallet entry", "file", hash, "error", err)
	return err
}

func (ae *AccountEntry) selfVerify(path string) error {
	_, hash := ae.SerializeSha1()

	if hash != filepath.Base(path) {
		log.Warn("Corrupt wallet entry", "file", path)
		return errors.New("Corrupt entry")
	}
	return nil
}

// SerializeSha1 returns sha1 hash and json byte stream of the string.
//
func (ae *AccountEntry) SerializeSha1() ([]byte, string) {
	var (
		content []byte
		err     error
	)
	if ae.Contract == ContractNonce {
		jsonEntry := StockEntryJson{
			AccountEntryJson: AccountEntryJson{
				Info:       ae.WalletEntry,
				EncryptKey: ae.EncryptKey,
			},
			ContractNonce: ae.Contract,
		}
		content, err = json.Marshal(&jsonEntry)
	} else {
		jsonEntry := AccountEntryJson{
			Info:       ae.WalletEntry,
			EncryptKey: ae.EncryptKey,
		}
		content, err = json.Marshal(&jsonEntry)
	}
	if err != nil {
		log.Error("Failed to encode json", "entry", ae)
		return nil, ""
	}
	sum := sha1.Sum(content)
	return content, utils.ToHex(sum[:])
}

// Deserialize decodes the Json byte stream back to AccountEntry format.
//
func (ae *AccountEntry) Deserialize(decode *json.Decoder) error {
	jsonEntry := StockEntryJson{}
	if err := decode.Decode(&jsonEntry); err != nil {
		err = decode.Decode(&jsonEntry.AccountEntryJson)
		if err != nil {
			return err
		}
		jsonEntry.ContractNonce = 0
	}
	ae.WalletEntry = jsonEntry.Info
	ae.EncryptKey = jsonEntry.EncryptKey
	ae.Contract = jsonEntry.ContractNonce
	return nil
}

// Decrypt unlocks the encrypted key.
//
func (ae *AccountEntry) Decrypt(auth string) error {
	var err error = nil

	if ae.Key == nil {
		if ae.EncryptKey != nil {
			ae.Key, err = keystore.DecryptKey(ae.EncryptKey, auth)
		} else {
			err = errors.New("Have no encrypted key")
		}
	}
	return err
}

// Encrypt locks the key.
//
func (ae *AccountEntry) Encrypt(auth string) error {
	var err error = nil

	if ae.Key != nil {
		scryptN := keystore.LightScryptN
		scryptP := keystore.LightScryptP
		ae.EncryptKey, err = keystore.EncryptKey(ae.Key, auth, scryptN, scryptP)
	} else {
		err = errors.New("Don't have private key")
	}
	return err
}

// LockKey clears out the private key from AccountEntry.
//
func (ae *AccountEntry) LockKey() {
	if ae.Key == nil {
		return
	}
	privKey := ae.Key.PrivateKey
	b := privKey.D.Bits()
	for i := range b {
		b[i] = 0
	}
	ae.Key = nil
}

func (ae *AccountEntry) DeleteKey() {
	ae.LockKey()
	ae.EncryptKey = nil
}

// Print formats AccountEntry content to debug string.
//
func (ae *AccountEntry) Print(skipHdr bool) {
	if skipHdr == false {
		ae.WalletEntry.Print()
	}
	fmt.Printf("Balance......... %d\nNonce........... %d\n", ae.Balance, ae.Nonce)
	if ae.EncryptKey != nil {
		fmt.Printf("Encrypt key..... %s\n", string(ae.EncryptKey))
	}
	if ae.Key != nil {
		k := ae.Key
		fmt.Printf(`
ID.............. %s
Public key...... %s
Private key..... %s
`,
			k.Id.String(), hex.EncodeToString(k.Address[:]),
			hex.EncodeToString(crypto.FromECDSA(k.PrivateKey)))
	}
}
