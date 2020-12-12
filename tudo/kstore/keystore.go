package kstore

import (
	"bytes"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/tudo/utils"
	"github.com/pborman/uuid"
)

const (
	walletDir   = "wallet"
	addrBookDir = "address"
)

var (
	s_bigOne       *big.Int = big.NewInt(1)
	s_chainId      uint64
	s_stockChainId uint64
)

type TdStore struct {
	cryptN    int
	cryptP    int
	kstoreDir string
	bookDir   string
	acctDir   string
	addrBook  map[string]*WalletEntry
	accounts  map[string]*AccountEntry
	Lock      sync.Mutex
}

func NewTdStore(dir string, chainId, stockChainId uint64) *TdStore {
	s_chainId = chainId
	s_stockChainId = stockChainId

	return &TdStore{
		cryptN:    keystore.StandardScryptN,
		cryptP:    keystore.StandardScryptP,
		kstoreDir: dir,
		addrBook:  make(map[string]*WalletEntry),
		accounts:  make(map[string]*AccountEntry),
	}
}

func (store *TdStore) Load() error {
	store.bookDir = filepath.Join(store.kstoreDir, addrBookDir)
	if err := os.MkdirAll(store.bookDir, 0700); err != nil {
		log.Error("Failed to make dirs", "dir", store.bookDir)
		return err
	}
	store.acctDir = filepath.Join(store.kstoreDir, walletDir)
	if err := os.MkdirAll(store.acctDir, 0700); err != nil {
		log.Error("Failed to make dirs", "dir", store.acctDir)
		return err
	}
	if err := filepath.Walk(store.bookDir, store.loadRecords(false)); err != nil {
		log.Error("Failed to load addrbook", "error", err)
		return err
	}
	if err := filepath.Walk(store.acctDir, store.loadRecords(true)); err != nil {
		log.Error("Failed to load accounts", "error", err)
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

func (store *TdStore) EnableService() error {
	return nil
}

func (store *TdStore) DebugDump(auth string) {
	fmt.Println("Account entries")
	for _, elm := range store.accounts {
		elm.Decrypt(auth)
		elm.Print(false)
	}
	fmt.Println("Address book entries")
	for _, elm := range store.addrBook {
		elm.Print()
	}
}

func (store *TdStore) UpdateWalletEntry(acct *accounts.Account,
	grp, pub, priv, contact, desc string) (*WalletEntry, error) {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	entry := store.addrBook[acct.Address.Hex()]
	if entry != nil {
		entry.Update(grp, pub, priv, contact, desc)
		return entry, entry.saveRec(store.bookDir)
	}
	return nil, errors.New("No record found")
}

func (store *TdStore) PersistEntry(entry *WalletEntry) error {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	if store.addrBook[entry.AccountKey()] == nil {
		store.addrBook[entry.AccountKey()] = entry
	}
	return entry.saveRec(store.bookDir)
}

func (store *TdStore) IsEntryPersisted(addr *accounts.Account) bool {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	entry := store.addrBook[addr.Address.Hex()]
	if entry != nil {
		return entry.isPersisted(store.bookDir)
	}
	return false
}

func (store *TdStore) IsAccountPersisted(addr *accounts.Account) bool {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	entry := store.accounts[addr.Address.Hex()]
	if entry != nil {
		return entry.isPersisted(store.acctDir)
	}
	return false
}

func (store *TdStore) DeleteEntry(account *accounts.Account) error {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	addr := account.Address.Hex()
	entry := store.addrBook[addr]
	if entry != nil {
		delete(store.addrBook, addr)
		return entry.deleteRec(store.bookDir)
	}
	return nil
}

func (store *TdStore) DeleteAccount(account *accounts.Account, auth string) error {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	addr := account.Address.Hex()
	entry := store.accounts[addr]
	if entry != nil {
		if err := entry.Decrypt(auth); err != nil {
			return err
		}
		delete(store.accounts, addr)
		return entry.deleteRec(store.acctDir)
	}
	return nil
}

func (store *TdStore) GetAccount(account *accounts.Account) (*AccountEntry, error) {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	return store.accounts[account.Address.Hex()], nil
}

func (store *TdStore) GetWalletEntry(account *accounts.Account) (*WalletEntry, error) {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	return store.addrBook[account.Address.Hex()], nil
}

type sendTx struct {
	From     common.Address  `json:"from"`
	To       *common.Address `json:"to"`
	GasPrice *big.Int        `json:"gasPrice"`
	Value    *big.Int        `json:"value"`
	Gas      uint64          `json:"gas"`
	Nonce    uint64          `json:"nonce"`
	Data     *[]byte         `json:"data"`
	Input    *[]byte         `json:"input"`
}

func (stx *sendTx) setDefaults() error {
	if stx.Gas == 0 {
		stx.Gas = 100000
	}
	if stx.GasPrice == nil {
		stx.GasPrice = s_bigOne
	}
	if stx.Data != nil && stx.Input != nil && !bytes.Equal(*stx.Data, *stx.Input) {
		return errors.New(`Both "data" and "input" are set and not equal`)
	}
	if stx.To == nil {
		// Contract creation.
		if stx.Data != nil {
			if len(*stx.Data) == 0 {
				return errors.New(`Missing data in contract`)
			}
		} else if stx.Input != nil {
			if len(*stx.Input) == 0 {
				return errors.New(`Missing data in contract`)
			}
		}
	}
	return nil

}

func (stx *sendTx) toTransaction() *types.Transaction {
	var input []byte
	if stx.Data != nil {
		input = *stx.Data
	} else if stx.Input != nil {
		input = *stx.Input
	}
	if stx.To == nil {
		types.NewContractCreation(stx.Nonce, stx.Value, stx.Gas, stx.GasPrice, input)
	}
	return types.NewTransaction(stx.Nonce, *stx.To, stx.Value, stx.Gas, stx.GasPrice, input)
}

func (store *TdStore) PayToRelayNonce(from, to *accounts.Account,
	auth string, xuAmt, nonce, chainId uint64) (*types.Transaction, error) {

	key, err := store.OpenAccount(from, auth)
	if key == nil || err != nil {
		log.Error("Failed to unlock account", "account", from.Address.Hex(), "error", err)
		return nil, err
	}
	sendTx := &sendTx{
		From:  from.Address,
		To:    &to.Address,
		Value: math.XuToWei(int64(xuAmt)),
		Nonce: nonce,
		Input: nil,
		Data:  nil,
	}
	if err := sendTx.setDefaults(); err != nil {
		log.Error("Failed to set default values", "error", err)
		return nil, err
	}
	tx := sendTx.toTransaction()
	chainID := big.NewInt(int64(chainId))
	return types.SignTx(tx, types.NewEIP155Signer(chainID), key.PrivateKey)
}

func fromPrivKeyECDSA(privKey *ecdsa.PrivateKey) *keystore.Key {
	return &keystore.Key{
		Id:         uuid.NewRandom(),
		Address:    crypto.PubkeyToAddress(privKey.PublicKey),
		PrivateKey: privKey,
	}
}

func (store *TdStore) newKey(rand io.Reader) (*keystore.Key, error) {
	privKey, err := ecdsa.GenerateKey(crypto.S256(), rand)
	if err != nil {
		return nil, err
	}
	return fromPrivKeyECDSA(privKey), nil
}

func (store *TdStore) CreateAccount(pub, priv, group, contact, desc, auth string,
	chainId uint64) (*WalletEntry, error) {
	key, err := store.newKey(crand.Reader)
	if err != nil {
		return nil, err
	}
	return store.ImportAccount(key.PrivateKey, pub, priv, group, contact, desc, auth, chainId)
}

func (store *TdStore) UpdateAccount(account *accounts.Account,
	pub, priv, group, contact, desc, oldAuth, newAuth string) (*AccountEntry, error) {

	store.Lock.Lock()
	entry := store.accounts[account.Address.Hex()]
	store.Lock.Unlock()

	if entry != nil {
		if oldAuth != "" && oldAuth != newAuth {
			err := entry.Decrypt(oldAuth)
			if err != nil {
				return nil, err
			}
			if err = entry.Encrypt(newAuth); err != nil {
				return nil, err
			}
			entry.LockKey()
		}
		entry.Update(group, pub, priv, contact, desc)
		if err := entry.saveRec(store.acctDir); err != nil {
			return nil, err
		}
		return entry, nil
	}
	return nil, errors.New("No matching account")
}

func importPrivateKey(keyHex []byte, auth string) (*keystore.Key, error) {
	key := keystore.Key{}
	err := key.UnmarshalJSON(keyHex)

	if err != nil {
		keyPtr, err := keystore.DecryptKey(keyHex, auth)
		if keyPtr == nil || err != nil {
			return nil, err
		}
		key.Id = keyPtr.Id
		key.Address = keyPtr.Address
		key.PrivateKey = keyPtr.PrivateKey
	}
	return &key, err
}

func (store *TdStore) Import(json []byte, auth string, chainId uint64) (*WalletEntry, error) {
	key, err := importPrivateKey(json, auth)
	if err != nil || key.PrivateKey == nil {
		return nil, errors.New("Invalid json key")
	}
	return store.ImportAccount(key.PrivateKey, "", "", "", "", "", auth, chainId)
}

func (store *TdStore) ImportAccount(privKey *ecdsa.PrivateKey,
	pub, priv, group, contact, desc, auth string, chainId uint64) (*WalletEntry, error) {
	address := crypto.PubkeyToAddress(privKey.PublicKey)

	store.Lock.Lock()
	defer store.Lock.Unlock()

	key := fromPrivKeyECDSA(privKey)
	addrHex := address.Hex()
	account := store.accounts[addrHex]
	if account == nil {
		account = &AccountEntry{
			Key: key,
			WalletEntry: WalletEntry{
				Account:     &accounts.Account{Address: address},
				JsonAcct:    addrHex,
				GroupName:   group,
				PublicName:  pub,
				PrivateName: priv,
				ContactInfo: contact,
				Description: desc,
			},
			EncryptKey: nil,
			Balance:    0,
			Nonce:      0,
			BlkAt:      0,
			ChainId:    chainId,
		}
		if err := account.Encrypt(auth); err != nil {
			return nil, err
		}
		store.accounts[addrHex] = account
	} else {
		if account.Key == nil && account.EncryptKey != nil {
			if err := account.Decrypt(auth); err != nil {
				log.Error("Failed to decrypt account", "address", addrHex)
				return nil, err
			}
		}
		if account.Key != nil {
			if account.Key.PrivateKey.D.Cmp(key.PrivateKey.D) != 0 &&
				bytes.Compare(account.Key.Address[:], key.Address[:]) != 0 {
				return nil, errors.New("Account has different key")
			}
		} else {
			account.Key = key
			if err := account.Encrypt(auth); err != nil {
				return nil, err
			}
		}
		account.Update(group, pub, priv, contact, desc)
	}
	if err := account.saveRec(store.acctDir); err != nil {
		return nil, err
	}
	return &account.WalletEntry, nil
}

func (store *TdStore) GetAllAccounts() ([]AccountEntry, error) {
	out := make([]AccountEntry, 0, len(store.accounts))

	store.Lock.Lock()
	defer store.Lock.Unlock()

	for _, entry := range store.accounts {
		out = append(out, *entry)
	}
	return out, nil
}

func (store *TdStore) GetAddressBook() ([]WalletEntry, error) {
	out := make([]WalletEntry, 0, len(store.addrBook))

	store.Lock.Lock()
	defer store.Lock.Unlock()

	for _, entry := range store.addrBook {
		out = append(out, *entry)
	}
	return out, nil
}

func (store *TdStore) OpenAccount(acct *accounts.Account, auth string) (*keystore.Key, error) {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	account := store.accounts[acct.Address.Hex()]
	if account != nil {
		err := account.Decrypt(auth)
		if err != nil {
			return nil, err
		}
		return account.Key, nil
	}
	return nil, nil
}

func (store *TdStore) CloseAccount(acct *accounts.Account) error {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	account := store.accounts[acct.Address.Hex()]
	if account != nil {
		account.LockKey()
		return nil
	}
	return errors.New("No matching account")
}

func (store *TdStore) DeleteAccountKey(acct *accounts.Account) error {
	store.Lock.Lock()
	defer store.Lock.Unlock()

	account := store.accounts[acct.Address.Hex()]
	if account != nil {
		return account.DeleteKey(store.acctDir)
	}
	return errors.New("No matching account")
}

//////////////////    W a l l e t    A d d r e s s b o o k    //////////////////////////

// saveRec saves address book entry to file system.
//
func (we *WalletEntry) saveRec(baseDir string) error {
	content, hash := we.SerializeSha1()
	if content == nil {
		return errors.New("Failed to save " + we.JsonAcct)
	}
	return we.saveRecContent(baseDir, hash, content)
}

func (we *WalletEntry) saveRecContent(baseDir, hash string, content []byte) error {
	if we.ETag == hash {
		log.Info("Identical etag save, no-op", "etag", we.ETag)
		return nil
	}
	name := filepath.Join(baseDir, hash)
	fd, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0755)
	defer fd.Close()

	if err != nil {
		return err
	}
	l, err := fd.Write(content)
	if l == len(content) && err == nil {
		if we.ETag != "" && we.ETag != hash {
			os.Remove(filepath.Join(baseDir, we.ETag))
		}
		we.ETag = hash
	}
	log.Info("Saved record entry", "file", name, "len", l)
	return err
}

// isPersisted returns true if the account is saved on disk.
//
func (we *WalletEntry) isPersisted(baseDir string) bool {
	if we.ETag == "" {
		return false
	}
	path := filepath.Join(baseDir, we.ETag)
	fd, err := os.Open(path)
	defer fd.Close()

	return err == nil
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

	return we.deleteRecHash(base, hash)
}

func (we *WalletEntry) deleteRecHash(base, hash string) error {
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
		we.Account = &accounts.Account{Address: common.HexToAddress(we.JsonAcct)}
	}
	return we.Account.Address.Hex()
}

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
	fmt.Printf(`...........................................
Account......... %s
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

// saveRec saves address book entry to file system.
//
func (ae *AccountEntry) saveRec(baseDir string) error {
	content, hash := ae.SerializeSha1()
	if content == nil {
		return errors.New("Failed to save " + ae.JsonAcct)
	}
	return ae.WalletEntry.saveRecContent(baseDir, hash, content)
}

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
	ae.LockKey()
	_, hash := ae.SerializeSha1()
	return ae.WalletEntry.deleteRecHash(base, hash)
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
	if ae.ChainId == s_stockChainId {
		jsonEntry := StockEntryJson{
			AccountEntryJson: AccountEntryJson{
				Info:       ae.WalletEntry,
				EncryptKey: ae.EncryptKey,
			},
			ChainId: ae.ChainId,
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
		jsonEntry.ChainId = 0
	}
	ae.WalletEntry = jsonEntry.Info
	ae.EncryptKey = jsonEntry.EncryptKey
	ae.ChainId = jsonEntry.ChainId
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
	ae.ClearKey()
	ae.Key = nil
}

func (ae *AccountEntry) DeleteKey(base string) error {
	ae.LockKey()
	err := ae.deleteRec(base)

	if err != nil {
		return err
	}
	ae.EncryptKey = nil
	return ae.saveRec(base)
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
	fmt.Println("--------------------------------------------------------")
}

func (ae *AccountEntry) IsContract() bool {
	return ae.ChainId == s_stockChainId
}
