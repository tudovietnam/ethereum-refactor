/*
 * Written by Vy Nguyen (2018)
 */
package proxy

import (
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	cli "gopkg.in/urfave/cli.v1"
)

type RelaySignedTx struct {
	From     string
	To       string
	SignedTx types.Transaction
}

/////////////////////////    S t a r t u p    A p p    /////////////////////////////////

type TdApp struct {
	waitApi int
	cliCtx  *cli.Context
	config  *TdConfig
	api     *TdNodeApi
	App     *cli.App
	Cond    *sync.Cond
	stop    chan struct{}
	Lock    sync.Mutex
}

func NewTdApp() *TdApp {
	app := &TdApp{
		App:    cli.NewApp(),
		config: AppConfig,
		stop:   make(chan struct{}),
	}
	app.Cond = sync.NewCond(&app.Lock)
	return app
}

func (m *TdApp) configApp(ctx *cli.Context) error {
	m.config.FixupConfig(ctx)
	m.cliCtx = ctx

	api := newTdNodeApi(m.config, m.stop)
	if err := api.Start(); err != nil {
		return err
	}
	if err := api.EnableService(); err != nil {
		return err
	}
	m.Lock.Lock()
	m.api = api
	if m.waitApi > 0 {
		m.Cond.Broadcast()
	}
	m.Lock.Unlock()
	return nil
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
		if err := m.configApp(ctx); err != nil {
			return err
		}
		m.wait()
		return nil
	}
	if err := app.Run(os.Args); err != nil {
		log.Error("Runtime error", "error", err)
		os.Exit(1)
	}
}

func (m *TdApp) wait() {
	<-m.stop
}

func (m *TdApp) Stop() {
	if m.api != nil {
		m.api.Stop()
	}
	close(m.stop)
}

func (m *TdApp) Pause() {
}

func (m *TdApp) Resume() {
}
