package kstore

import (
	"crypto/sha1"
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/tudo/utils"
)

// newFsWalletEntry creates binding for file system backed entry.
//
func newFsWalletEntry(acct *accounts.Account) *WalletEntry {
	var strAcct string = ""
	if acct != nil {
		strAcct = acct.Address.Hex()
	}
	entry := &WalletEntry{
		Account:  acct,
		JsonAcct: strAcct,
	}
	// entry.ops = entry
	return entry
}

// newFsAccountEntry creates bind for file system backed account entry.
//
func newFsAccountEntry(key *keystore.Key, we *WalletEntry, auth string) *AccountEntry {
	var ae *AccountEntry = nil

	if we != nil {
		ae = &AccountEntry{Key: key, WalletEntry: *we}
	} else {
		ae = &AccountEntry{Key: key}
	}
	// ae.ops = ae
	return ae
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
	// ops is embeded inside the WalletEntry, we need to save it.
	//
	ops := ae.ops
	ae.WalletEntry = jsonEntry.Info
	ae.EncryptKey = jsonEntry.EncryptKey
	ae.Contract = jsonEntry.ContractNonce
	ae.ops = ops
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
