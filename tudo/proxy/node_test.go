package proxy

import (
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
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
	t.Run("Encrypt/decrypt tests", encryptTests)
	t.Run("Update accounts", updateTests)
	t.Run("Import accounts", importTests)
	t.Run("Cleanup keystore", cleanupTests)
	app.Stop()
}

func verifyNoErr(assert *assert.Assertions, err error, cond bool, header string) {
	assert.Condition(func() bool { return err == nil && cond }, header)
	if err != nil {
		fmt.Println(">>> Error", err)
	}
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
	assert.Condition(func() bool { return api.IsEntryPersisted(acct) }, acct, "Not on disk")
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
	assert := assert.New(t)

	acct := _accounts[gcAccountB]
	account, err := api.GetAccount(acct)
	verifyNoErr(assert, err, account != nil, "Failed to locate account")

	orig := *account
	change, err := api.UpdateAccount(acct, "New Public B", "New Private B", "New Group",
		"New Contact", "New Description", gcAuthStr, "welcome")
	verifyNoErr(assert, err, change != nil, "Failed to update account")

	str := "Must be the same"
	assert.Equal(account.JsonAcct, change.JsonAcct, str)
	assert.Equal(account.ChainId, change.ChainId, str)

	key, err := api.OpenAccount(acct, gcAuthStr)
	assert.Nil(key, "Changed passcode")
	fmt.Println("Expected error:", err)

	key, err = api.OpenAccount(acct, "welcome")
	verifyNoErr(assert, err, key != nil, "Match passcode account")

	change, err = api.UpdateAccount(acct, orig.PublicName, orig.PrivateName,
		orig.GroupName, orig.ContactInfo, orig.Description, "welcome", gcAuthStr)
	verifyNoErr(assert, err, change != nil, "Failed to update account")

	assert.Equal(orig.PublicName, change.PublicName, str)
	assert.Equal(orig.PrivateName, change.PrivateName, str)
	assert.Equal(orig.GroupName, change.GroupName, str)
}

func importTests(t *testing.T) {
	fmt.Println("Test import API")
	api := getApi()
	assert := assert.New(t)

	fmt.Println("\tAPI to unlock account key")
	acct := _accounts[gcAccountC]
	key, err := api.OpenAccount(acct, gcAuthStr)
	verifyNoErr(assert, err, key != nil, "Failed to unlock account")

	keyStr := api.ToStringKey(key)
	err = api.CloseAccount(acct)
	verifyNoErr(assert, err, keyStr != nil, "Failed to unlock account")

	fmt.Println("\tAPI to unlock account key with wrong passcode")
	key, err = api.OpenAccount(acct, "wrong")
	assert.Nil(key, "Must not be able to decode key")
	assert.NotNil(err, "Must have error")
	fmt.Println("Expected error:", err)

	assertAccount := func(err error, account *kstore.AccountEntry) {
		verifyNoErr(assert, err, account != nil, "Failed to get account")
		assert.Condition(func() bool { return api.IsAccountPersisted(acct) }, acct, "Not on disk")
	}
	assertEntries := func(err error, entry *kstore.WalletEntry, account *kstore.AccountEntry) {
		verifyNoErr(assert, err, entry != nil, "Failed to import key")
		assert.Equal(entry.JsonAcct, account.JsonAcct, "Account must be the same")
		assert.Equal(entry.PublicName, account.PublicName, "Public name must be the same")
		assert.Equal(entry.PrivateName, account.PrivateName, "Public name must be the same")
	}

	account, err := api.GetAccount(acct)
	assertAccount(err, account)

	fmt.Println("\tAPI to delete account key")
	err = api.DeleteAccountKey(acct)
	assertAccount(err, account)

	// Import account not having private key.
	fmt.Println("\tAPI to import the key back to account")
	entry, err := api.ImportAccount(keyStr.PrivateKey,
		"", "", "", "", "", gcAuthStr, account.ChainId)
	assertEntries(err, entry, account)

	// Import the same account now has the same private key.
	fmt.Println("\tAPI to import same key to account")
	entry, err = api.ImportAccount(keyStr.PrivateKey,
		entry.PublicName, entry.PrivateName, "", "", "", gcAuthStr, account.ChainId)
	assertEntries(err, entry, account)

	// Delete the account.
	fmt.Println("\tAPI to delete the account")
	err = api.DeleteAccount(acct, gcAuthStr)
	assert.Nil(err, "Must not have delete error", err)
	assert.Condition(func() bool { return !api.IsAccountPersisted(acct) }, acct, "Still on disk")

	// Restore the same account.
	fmt.Println("\tAPI to import the account from key")
	entry, err = api.ImportAccount(keyStr.PrivateKey,
		entry.PublicName, entry.PrivateName, entry.GroupName, entry.ContactInfo,
		entry.Description, gcAuthStr, account.ChainId)
	assertEntries(err, entry, account)

	// Verify keys
	nKey, err := api.OpenAccount(acct, gcAuthStr)
	verifyNoErr(assert, err, nKey != nil, "Failed to unlock account")

	nKeyStr := api.ToStringKey(nKey)
	assert.Equal(keyStr, nKeyStr, "Keys must be the same")

	fmt.Println("\tAPI to import wrong key to the account")
	actb := _accounts[gcAccountB]
	bKey, err := api.OpenAccount(actb, gcAuthStr)
	verifyNoErr(assert, err, bKey != nil, "Failed to unlock account")

	bKeyStr := api.ToStringKey(bKey)
	assert.NotEqual(keyStr, bKeyStr, "Not same key")
}

func verifyTx(assert *assert.Assertions, tx1, tx2 *types.Transaction) {
	str := "Tx transaction must be identical"
	assert.Equal(tx1.Hash(), tx2.Hash(), str)
	if tx1.To() != nil {
		assert.Equal(*tx1.To(), *tx2.To(), str)
	} else {
		assert.Equal(tx1.To(), tx2.To(), str)
	}
}

func signTests(t *testing.T) {
	fmt.Println("Test sign transactions")
	api := getApi()
	assert := assert.New(t)

	to := _accounts[gcAccountB]
	from := _accounts[gcAccountA]

	r1, err := api.PayToRelayNonce(from, to, gcAuthStr, 100, 200, 1973)
	verifyNoErr(assert, err, r1 != nil, "Failed to sign tx")
	r1.Print()

	r2, err := api.PayToRelayNonce(from, to, gcAuthStr, 100, 200, 1973)
	verifyNoErr(assert, err, r1 != nil, "Failed to sign tx")
	verifyTx(assert, &r1.SignedTx, &r2.SignedTx)
}

func signTx(api *TdNodeApi, from, to string, nonce, amt uint64) {
	tx, err := api.PayToRelayNonce(from, to, gcAuthStr, nonce, amt, 1973)
	if tx == nil || err != nil {
		fmt.Println("Failed to sign tx", err)
	}
}

func encryptTests(t *testing.T) {
	fmt.Println("Encrypt/decrypt test")
	data := "This is the original text"
	api := getApi()
	assert := assert.New(t)

	to := _accounts[gcAccountB]
	pubKey, err := api.GetPublicKey(to, gcAuthStr)
	verifyNoErr(assert, err, pubKey != nil, "Failed to get public key")

	sign, err := api.EncryptMesg(_accounts[gcAccountA], gcAuthStr, data, to, pubKey)
	verifyNoErr(assert, err, sign != nil, "Failed to encrypt data")

	if sign != nil {
		decrypt, err := api.DecryptMesg(to, gcAuthStr, sign.Mesg)
		verifyNoErr(assert, err, decrypt != "", "Failed to decrypt data")
		assert.Equal(data, decrypt, "Must be the same as original")

		fmt.Println("Encrypt hexdump")
		fmt.Println(hex.Dump(sign.Mesg))
		fmt.Println("Decode data:", decrypt)
	}
}

/*
func BenchmarkTxSign(b *testing.B) {
	to := _accounts[gcAccountB]
	from := _accounts[gcAccountA]

	api := getApi()
	for i := 0; i < b.N; i++ {
		signTx(api, from, to, uint64(i), 1000)
	}
}
*/
