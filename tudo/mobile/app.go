/*
 * Written by Vy Nguyen (2018)
 */
package mobile

import (
	"errors"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/tudo/kstore"
	"github.com/ethereum/go-ethereum/tudo/proxy"
)

type MobileApp struct {
	app      *proxy.TdApp
	pendTx   string
	pendFrom string
	pendTo   string
	started  bool
	mutex    sync.Mutex
}

var (
	instMutex  sync.Mutex
	singleInst *MobileApp = nil
)

type AccountEntry struct {
	Address     string
	ETag        string
	GroupName   string
	PublicName  string
	PrivateName string
	ContactInfo string
	Description string
	Balance     int64
	Nonce       int64
	Contract    int64
}

type AccountKey struct {
	Address    string
	PrivateKey string
}

type RelayTransaction struct {
	From   string
	To     string
	JsonTx []byte
}

/**
 * AccountEntryArr array of account entries.
 */
type AccountEntryArr struct {
	Array []*AccountEntry
}

func (a *AccountEntryArr) Size() int              { return len(a.Array) }
func (a *AccountEntryArr) Append(e *AccountEntry) { a.Array = append(a.Array, e) }

func (a *AccountEntryArr) Get(index int) *AccountEntry {
	if index < 0 || index >= len(a.Array) {
		return nil
	}
	return a.Array[index]
}

func (a *AccountEntryArr) Set(index int, entry *AccountEntry) {
	if 0 <= index && index < len(a.Array) {
		a.Array[index] = entry
	}
}

/**
 * MobileApp interfaces
 */
func NewMobileApp() *MobileApp {
	instMutex.Lock()
	if singleInst == nil {
		singleInst = &MobileApp{
			app:     proxy.NewTdApp(),
			started: false,
		}
	}
	instMutex.Unlock()
	return singleInst
}

func (m *MobileApp) Stop() {
	m.Stop()
}

func (m *MobileApp) Pause() {
	m.Pause()
}

func (m *MobileApp) Resume() {
	m.Resume()
}

func (m *MobileApp) MobileRun(base, level, config string) {
	run := false

	instMutex.Lock()
	if m.started == false {
		run = true
		m.started = true
	}
	instMutex.Unlock()

	if run {
		os.Args = []string{os.Args[0], "--verbosity", level, "--basedir", base}
		go m.app.Run(os.Args, config)
	}
}

func (m *MobileApp) MobileRunArgs(args *Strings) {
	osArgs := []string{os.Args[0]}
	for _, s := range args.strs {
		osArgs = append(osArgs, s)
	}
	os.Args = osArgs
	go m.app.Run(os.Args, "")
}

// GetMyAccounts returns the current account list.
//
func (m *MobileApp) GetMyAccounts(out *AccountEntryArr, stock *AccountEntryArr) error {
	api := m.app.GetApi()
	entries, err := api.GetAllAccounts()
	if err != nil {
		return err
	}
	for idx, _ := range entries {
		entry := &entries[idx]
		if entry.IsContract() {
			stock.Array = append(stock.Array, fromAccountEntry(entry))
		} else {
			out.Array = append(out.Array, fromAccountEntry(entry))
		}
	}
	return nil
}

// fromWalletEntry converts a wallet entry to mobile software interface.
//
func fromWalletEntry(w *kstore.WalletEntry) *AccountEntry {
	account := &accounts.Account{}
	if w.Account != nil {
		account = w.Account
	}
	return &AccountEntry{
		Address:     account.Address.Hex(),
		GroupName:   w.GroupName,
		PublicName:  w.PublicName,
		PrivateName: w.PrivateName,
		ContactInfo: w.ContactInfo,
		Description: w.Description,
		Balance:     0,
		Nonce:       0,
	}
}

// fromAccountEntry converts a full account entry to mobile software interface.
//
func fromAccountEntry(a *kstore.AccountEntry) *AccountEntry {
	if a != nil {
		entry := fromWalletEntry(&a.WalletEntry)
		entry.Balance = int64(a.Balance)
		entry.Nonce = int64(a.Nonce)
		entry.Contract = int64(a.Contract)
		return entry
	}
	return nil
}

// GetAddressBook returns all addressbook entries.
//
func (m *MobileApp) GetAddressBook(out *AccountEntryArr) {
	/*
		api := m.app.GetApi()
		entries := api.EntryByGroup("")
		for idx, _ := range entries {
			out.Array = append(out.Array, fromWalletEntry(entries[idx]))
		}
	*/
}

// CreatAccount creates a new account.
//
func (m *MobileApp) CreatAccount(pub, priv string,
	gr, ct, desc, auth string) (*AccountEntry, error) {

	api := m.app.GetApi()
	entry, err := api.CreatAccount(pub, priv, gr, ct, desc, auth)
	if err != nil {
		return nil, err
	}
	return fromWalletEntry(entry), nil
}

func (m *MobileApp) CreatStock(pub, priv string,
	gr, ct, desc, auth string) (*AccountEntry, error) {

	api := m.app.GetApi()
	entry, err := api.CreatStock(pub, priv, gr, ct, desc, auth)
	if err != nil {
		return nil, err
	}
	return fromWalletEntry(entry), nil
}

func (m *MobileApp) UpdateAccount(address, pub, priv string,
	gr, ct, desc, auth string) (*AccountEntry, error) {
	api := m.app.GetApi()
	entry, err := api.UpdateAccount(address, pub, priv, gr, ct, desc, auth)
	return fromAccountEntry(entry), err
}

// ImportAccount imports full account info to the wallet.
//
func (m *MobileApp) ImportAccount(pkey string,
	pub, priv, gr, ct, desc, auth string) (*AccountEntry, error) {

	api := m.app.GetApi()
	entry, err := api.ImportAccount(pkey, pub, priv, gr, ct, desc, auth)
	if err != nil {
		return nil, err
	}
	return fromWalletEntry(entry), nil
}

// ImportPrivateKey imports private key to existing account in the wallet.
//
func (m *MobileApp) ImportPrivateKey(pkey, auth string) (*AccountEntry, error) {
	api := m.app.GetApi()
	entry, err := api.ImportAccount(pkey, "", "", "", "", "", auth)
	if err != nil {
		return nil, err
	}
	return fromWalletEntry(entry), nil
}

// OpenAccount decrypts the key, returns the key.
//
func (m *MobileApp) OpenAccount(acct, auth string) (*AccountKey, error) {
	api := m.app.GetApi()
	addr, err := kstore.GetAccount(acct)
	if err != nil {
		return nil, err
	}
	key, err := api.OpenAccount(addr, auth)
	if err != nil || key == nil {
		log.Info("Failed to open account", "account", acct)
		return nil, err
	}
	return nil, nil
	// return fromPrivKey(key), nil
}

// GetAccount returns the account matching address.
//
func (m *MobileApp) GetAccount(acct string) (*AccountEntry, error) {
	api := m.app.GetApi()
	addr, err := kstore.GetAccount(acct)
	if err != nil {
		return nil, err
	}
	entry, err := api.GetAccount(addr)
	if err != nil || entry == nil {
		log.Info("Failed to locate account", "account", acct)
		return nil, err
	}
	return fromAccountEntry(entry), nil
}

// CloseAccount encrypts the key for the account.
//
func (m *MobileApp) CloseAccount(acct string) error {
	api := m.app.GetApi()
	addr, err := kstore.GetAccount(acct)
	if err != nil {
		return err
	}
	return api.CloseAccount(addr)
}

// DeleteAccountKey deletes the key, assumes user saved a hard-copy.  There's no way
// to recover back a deleted key.
//
func (m *MobileApp) DeleteAccountKey(acct string) error {
	api := m.app.GetApi()
	addr, err := kstore.GetAccount(acct)
	if err != nil {
		return err
	}
	return api.DeleteAccountKey(addr)
}

func (m *MobileApp) DeleteAccount(addr, auth string) error {
	api := m.app.GetApi()
	return api.DeleteAccount(addr, auth)
}

func (m *MobileApp) PayToRelay(from, to, auth string,
	xuAmt, chainId int64) (*RelayTransaction, error) {
	toAcct, err := kstore.GetAccount(to)
	if toAcct == nil || err != nil {
		log.Info("Invalid to account", "to", to, "err", err)
		return nil, err
	}
	fromAcct, err := kstore.GetAccount(from)
	if fromAcct == nil || err != nil {
		log.Info("Invalid from account", "from", from, "err", err)
		return nil, err
	}
	m.app.Lock.Lock()
	if m.pendFrom != "" || to == "" {
		m.app.Lock.Unlock()
		log.Info("Pending trans", "from", m.pendFrom, "to", to)
		return nil, errors.New("A transaction is pending")
	}
	m.pendFrom = from
	m.pendTo = to
	m.app.Lock.Unlock()

	api := m.app.GetApi()
	tx, err := api.PayToRelay(fromAcct, toAcct, auth, uint64(xuAmt), uint64(chainId))
	if err != nil {
		return nil, err
	}
	json, err := tx.SignedTx.MarshalJSON()
	return &RelayTransaction{
		From:   tx.From,
		To:     tx.To,
		JsonTx: json,
	}, err
}

func (m *MobileApp) PayToRelayNonce(from, to, auth string,
	xuAmt, nonce, chainId int64) (*RelayTransaction, error) {
	toAcct, err := kstore.GetAccount(to)
	if toAcct == nil || err != nil {
		log.Info("Invalid to account", "to", to, "err", err)
		return nil, err
	}
	fromAcct, err := kstore.GetAccount(from)
	if fromAcct == nil || err != nil {
		log.Info("Invalid from account", "from", from, "err", err)
		return nil, err
	}
	m.app.Lock.Lock()
	if m.pendFrom != "" || to == "" {
		m.app.Lock.Unlock()
		log.Info("Pending trans", "from", m.pendFrom, "to", to)
		return nil, errors.New("A transaction is pending")
	}
	m.pendFrom = from
	m.pendTo = to
	m.app.Lock.Unlock()

	api := m.app.GetApi()
	tx, err := api.PayToRelayNonce(fromAcct, toAcct, auth,
		uint64(xuAmt), uint64(nonce), uint64(chainId))
	if err != nil {
		return nil, err
	}
	json, err := tx.SignedTx.MarshalJSON()
	return &RelayTransaction{
		From:   tx.From,
		To:     tx.To,
		JsonTx: json,
	}, err
}

func (m *MobileApp) PaymentCompletion(txHash string) {
	m.pendTo = ""
	m.pendTx = ""
	m.pendFrom = ""
}
