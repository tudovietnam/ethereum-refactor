/**
 * Written by Vy Nguyen (2018)
 */
package proxy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/tudo/config"
	"github.com/naoina/toml"
	cli "gopkg.in/urfave/cli.v1"
)

type TdConfig struct {
	BaseDir     string
	DataDir     string
	KeyStoreDir string
	GasPrice    int
}

const (
	defaultDataDir     = "data"
	defaultKeyStoreDir = "keystore"
)

var (
	AppHelpFlagGroups = config.FlagCategory{}
	AppConfig         = &TdConfig{}

	defaultConfig = `
DataDir = "data"
GasPrice = 1
`

	// These settings ensure that TOML keys use the same names as Go struct fields.
	tomlSettings = toml.Config{
		NormFieldName: func(rt reflect.Type, key string) string {
			return key
		},
		FieldToKey: func(rt reflect.Type, field string) string {
			return field
		},
		MissingField: func(rt reflect.Type, field string) error {
			return fmt.Errorf("field '%s' is not defined in %s", field, rt.String())
		},
	}
	DataDirFlag = config.DirectoryFlag{
		Name:  "datadir",
		Usage: "Data directory for the database",
		Value: config.DirectoryString{defaultDataDir},
	}
	BaseDirFlag = config.DirectoryFlag{
		Name:  "basedir",
		Usage: "Base data directory",
	}
	VerbosityFlag = cli.IntFlag{
		Name:  "verbosity",
		Usage: "Set verbosity log level",
		Value: 1,
	}
)

func (cfg *TdConfig) Init(ctx *cli.Context) {
	baseDir := ctx.GlobalString(BaseDirFlag.Name)
	if baseDir == "" || baseDir == "." {
		baseDir, _ = os.Getwd()
	}
	cfg.BaseDir = baseDir
}

// LoadConfig overrides loading config
//
func (cfg *TdConfig) LoadConfigStr(ctx *cli.Context, cfgData string) error {
	if cfgData == "" {
		cfgData = defaultConfig
		log.Info("Load default td config")
	}
	err := cfg.ParseConfig(ctx, strings.NewReader(cfgData))
	if err != nil {
		log.Info("Parse config error", "error", err)
	}
	return err
}

func (cfg *TdConfig) ParseConfig(ctx *cli.Context, reader io.Reader) error {
	err := tomlSettings.NewDecoder(reader).Decode(cfg)
	if _, ok := err.(*toml.LineError); ok {
		err = errors.New(err.Error())
	}
	return err
}

func (cfg *TdConfig) MakeNode(ctx *cli.Context) error {
	return nil
}

func (cfg *TdConfig) DumpConfig(ctx *cli.Context) error {
	out, err := tomlSettings.Marshal(cfg)
	if err != nil {
		return err
	}
	os.Stdout.Write(out)
	return nil
}

// FixupConfig setups default config from command line options.
//
func (cfg *TdConfig) FixupConfig(ctx *cli.Context) error {
	logLvl := log.Lvl(ctx.Int(VerbosityFlag.Name))
	logger := log.NewGlogHandler(log.StreamHandler(os.Stdout, log.TerminalFormat(true)))

	logger.Verbosity(logLvl)
	log.Root().SetHandler(logger)

	dir, err := resolveAbsPath(cfg.DataDir, cfg.BaseDir, defaultDataDir)
	cfg.DataDir = dir
	cfg.KeyStoreDir = filepath.Join(dir, defaultKeyStoreDir)

	if err := os.MkdirAll(cfg.KeyStoreDir, 0700); err != nil {
		log.Error("Failed to make keydir", "keydir", cfg.KeyStoreDir, "err", err)
		panic("Failed in mkdir")
	}
	log.Info("Config", "datadir", dir, "keystore", cfg.KeyStoreDir, "verbosity", logLvl.String())
	return err
}

func resolveAbsPath(path, base, def string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		path = filepath.Join(base, def)
	}
	absDir, err := filepath.Abs(path)
	if err == nil {
		return absDir, nil
	}
	return path, err
}
