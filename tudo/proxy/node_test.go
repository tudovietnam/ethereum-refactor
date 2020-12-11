package proxy

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/tudo/kstore"
	"github.com/stretchr/testify/assert"
)

const (
	gcStockA   = "StockA"
	gcStockB   = "StockB"
	gcStockC   = "StockC"
	gcAccountA = "accountA"
	gcAccountB = "accountB"
	gcAccountC = "accountC"
	gcAuthStr  = "abc123"
)

var (
	_instMutex sync.Mutex
	_testApp   *TdApp
	_accounts  map[string]string
)

func getApp() *TdApp {
	_instMutex.Lock()
	defer _instMutex.Unlock()

	if _testApp == nil {
		_testApp = NewTdApp()
		_accounts = make(map[string]string)
		os.Args = []string{os.Args[0], "--basedir", "/tmp/gotest"}
		go _testApp.Run(os.Args, "")
	}
	return _testApp
}

func getApi() *TdNodeApi {
	return getApp().GetApi()
}

func TestAppApi(t *testing.T) {
	fmt.Println("Test TD APP keystore lib")
	app := getApp()

	t.Run("Cleanup keystore", cleanupTests)
	t.Run("Create accounts", createTests)
	t.Run("Sign transactions", signTests)
	t.Run("Update accounts", updateTests)
	t.Run("Import accounts", importTests)
	t.Run("Cleanup keystore", cleanupTests)
	app.Stop()
}

func verifyNoErr(assert *assert.Assertions, err error, cond bool, header string) {
	assert.Condition(func() bool { return err == nil && cond }, header)
}

func cleanupTests(t *testing.T) {
	fmt.Println("Clean up keystore")

	api := getApi()
	assert := assert.New(t)
	accounts, err := api.GetAllAccounts()
	assert.Nil(err, "Get all accounts", err)

	for idx, _ := range accounts {
		key := accounts[idx].AccountKey()
		err := api.DeleteAccount(key, "")
		assert.Nil(err, "Failed to delete account", key, err)
	}
	entries, err := api.GetAddressBook()
	assert.Nil(err, "Get all address book", err)

	for idx, _ := range entries {
		key := entries[idx].AccountKey()
		err := api.DeleteEntry(key)
		assert.Nil(err, "Failed to delete addrbook entry", key, err)
	}
	// Verify keystore is empty.
	accounts, err = api.GetAllAccounts()
	verifyNoErr(assert, err, len(accounts) == 0, "Failed to remove accounts")

	entries, err = api.GetAddressBook()
	verifyNoErr(assert, err, len(entries) == 0, "Failed to remove addr book")
}

func createAccountTest(t *testing.T, api *TdNodeApi, name string, stock bool) {
	var (
		ac  *kstore.WalletEntry
		err error
	)
	if stock {
		ac, err = api.CreateStock(name, name, name, "abc@abc.com", "Test Stock", gcAuthStr)
	} else {
		ac, err = api.CreateAccount(name, name, name, "abc@abc.com", "Test Account", gcAuthStr)
	}
	assert := assert.New(t)
	verifyNoErr(assert, err, ac != nil, "Failed to create account")

	_accounts[name] = ac.JsonAcct
}

func createWalletEntry(t *testing.T, api *TdNodeApi, name string) {
	assert := assert.New(t)
	addr := _accounts[name]
	account, err := api.GetAccount(addr)
	verifyNoErr(assert, err, account != nil, "Failed to create account entry")

	we, err := api.NewWalletEntry(addr, account.PublicName,
		account.PrivateName, account.GroupName, account.ContactInfo, account.Description)

	verifyNoErr(assert, err, we != nil, "Failed to create wallet entry")
}

func verifyEntry(assert *assert.Assertions, api *TdNodeApi, name string) {
	acct := _accounts[name]
	entry, err := api.GetWalletEntry(acct)

	verifyNoErr(assert, err, entry != nil, "Failed to create wallet entry")
	assert.Condition(func() bool { return api.IsEntryPersisted(entry) }, acct, "Not on disk")
}

func createTests(t *testing.T) {
	api := getApi()
	assert := assert.New(t)
	fmt.Println("Test create accounts")

	createAccountTest(t, api, gcAccountA, false)
	createAccountTest(t, api, gcStockA, true)

	createAccountTest(t, api, gcAccountB, false)
	createAccountTest(t, api, gcStockB, true)

	createAccountTest(t, api, gcAccountC, false)
	createAccountTest(t, api, gcStockC, true)

	fmt.Println("Test create address book entries")
	createWalletEntry(t, api, gcAccountA)
	createWalletEntry(t, api, gcAccountB)
	createWalletEntry(t, api, gcAccountC)

	verifyEntry(assert, api, gcAccountA)
	verifyEntry(assert, api, gcAccountB)
	verifyEntry(assert, api, gcAccountC)
}

func updateTests(t *testing.T) {
	fmt.Println("Test update accounts")
	api := getApi()
	api.Stop()

}

func importTests(t *testing.T) {
	fmt.Println("Test import API")
	api := getApi()
	assert := assert.New(t)

	acct := _accounts[gcAccountC]
	key, err := api.OpenAccount(acct, gcAuthStr)
	verifyNoErr(assert, err, key != nil, "Failed to lock account")

	keyStr := api.ToStringKey(key)
	err = api.CloseAccount(acct)
	verifyNoErr(assert, err, keyStr != nil, "Failed to unlock account")

	key, err = api.OpenAccount(acct, "wrong")
	assert.Nil(key, "Must not be able to decode key")
	assert.NotNil(err, "Must have error")
	fmt.Println("Expected error:", err)

	account, err := api.GetAccount(acct)
	verifyNoErr(assert, err, account != nil, "Failed to get account")
	assert.Condition(func() bool { return api.IsAccountPersisted(account) }, acct, "Not on disk")

	err = api.DeleteAccountKey(acct)
	assert.Nil(err, "Failed to delete key")
	assert.Condition(func() bool { return api.IsAccountPersisted(account) }, acct, "Not on disk")

	entry, err := api.ImportAccount(keyStr.PrivateKey,
		"", "", "", "", "", gcAuthStr, account.ChainId)

	fmt.Printf("account %p, entry %p, err %s\n", account, entry, err)
	/*
		verifyNoErr(assert, err, entry != nil, "Failed to import key")
		assert.Equal(entry.JsonAcct, account.JsonAcct, "Account must be the same")
		assert.Equal(entry.ETag, account.ETag, "ETag must be the same")
	*/
	api.DebugDump(gcAuthStr)
}

func signTests(t *testing.T) {
	fmt.Println("Test sign transactions")
	api := getApi()
	assert := assert.New(t)

	to := _accounts[gcAccountB]
	from := _accounts[gcAccountA]

	relay, err := api.PayToRelayNonce(from, to, gcAuthStr, 100, 200, 1973)
	verifyNoErr(assert, err, relay != nil, "Failed to sign tx")
	relay.Print()
}
