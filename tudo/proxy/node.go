/*
 * Written by Vy Nguyen (2018)
 */
package proxy

import (
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	cli "gopkg.in/urfave/cli.v1"
)

type RelaySignedTx struct {
	From     string
	To       string
	SignedTx types.Transaction
}

type NodeIf interface {
	Start() error
	Stop() error
	EnableService() error
	Wait()
}

type ProxyNode struct {
	cliCtx *cli.Context
	config *TdConfig
	accman *accounts.Manager
	stop   chan struct{}
	mutex  sync.Mutex
}

// AccountConfig returns parameters to create account manager.
//
func AccountConfig(conf *TdConfig) (int, int, string) {
	return keystore.StandardScryptN, keystore.StandardScryptP, conf.KeyStoreDir
}

// NewNode returns a new proxy node.
//
func newNode(conf *TdConfig, ctx *cli.Context) *ProxyNode {
	out := &ProxyNode{
		cliCtx: ctx,
		config: conf,
		stop:   make(chan struct{}),
	}
	out.makeAccountManager()
	return out
}

// makeAccountManager creates account manager for the node.
//
func (pxNode *ProxyNode) makeAccountManager() {
	scryptN, scryptP, keydir := AccountConfig(pxNode.config)

	log.Info("Make account manager", "keydir", keydir, "N", scryptN, "P", scryptP)

	/*
		ks := tdk.NewTdKeyStore(scryptN, scryptP, keydir, pxNode)
		pxNode.ksiface = ks.Interface()
		pxNode.ksWalletIf = ks.KsWalletIf()
		backends := []accounts.Backend{ks}
		pxNode.RegAccountBackends(backends...)
	*/
}

func (pxNode *ProxyNode) Start() error {
	// Start the base node service.
	//
	log.Info("Td node start....")
	return nil
}

func (pxNode *ProxyNode) EnableService() error {
	log.Info("Td node enable service")
	return nil
}

func (pxNode *ProxyNode) Wait() {
	log.Info("Wait on node")
}

func (pxNode *ProxyNode) Stop() error {
	return nil
}

/////////////////////////    S t a r t u p    A p p    /////////////////////////////////

type TdApp struct {
	waitApi int
	Node    NodeIf
	api     *TdNodeApi
	App     *cli.App
	Cond    *sync.Cond
	Lock    sync.Mutex
}

func NewTdApp() *TdApp {
	app := &TdApp{
		App: cli.NewApp(),
		api: newTdNodeApi(),
	}
	app.Cond = sync.NewCond(&app.Lock)
	return app
}

func (m *TdApp) Run(arguments []string, cfgData string) {
	AppHelpFlagGroups.Init()

	app := m.App
	app.Usage = "TVNTD Phone Terminal"
	app.Flags = []cli.Flag{
		BaseDirFlag,
		DataDirFlag,
		VerbosityFlag,
	}
	app.Before = func(ctx *cli.Context) error {
		AppConfig.Init(ctx)
		err := AppConfig.LoadConfigStr(ctx, cfgData)
		if err != nil {
			log.Error("Error loading config", "error", err)
			return err
		}
		return nil
	}
	app.Action = func(ctx *cli.Context) error {
		node := makeNode(ctx)
		m.Node = node

		if err := node.Start(); err != nil {
			return err
		}
		m.Lock.Lock()
		// m.api = m.TdSvc.api
		if m.waitApi > 0 {
			m.Cond.Broadcast()
		}
		m.Lock.Unlock()

		node.Wait()
		return nil
	}
	if err := app.Run(os.Args); err != nil {
		log.Error("Runtime error", "error", err)
		os.Exit(1)
	}
}

func (m *TdApp) Start() {
	log.Info("Start node status")
}

func (m *TdApp) Stop() {
	log.Info("Stop node status")
}

func (m *TdApp) GetApi() *TdNodeApi {
	if m.api != nil {
		return m.api
	}
	m.Lock.Lock()
	for m.api == nil {
		m.waitApi++
		m.Cond.Wait()
		m.waitApi--
	}
	m.Lock.Unlock()
	return m.api
}

// makeNode constructs the local node service from configuration.
//
func makeNode(ctx *cli.Context) *ProxyNode {
	AppConfig.FixupConfig(ctx)
	self := newNode(AppConfig, ctx)
	return self
}
