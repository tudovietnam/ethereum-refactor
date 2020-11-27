Build steps:

make geth
make td
make android


=======================================================================
Config files:

+ config
    + common.toml
    + conf-main.toml
    + private-genesis.json

common.toml
-----------
GcMode = "archive"

BootstrapNodes = [
  "enode://a610c4b3617f6967cf68f6062ae8e2ef4197dc95df6c16ef26dd7e1bb18c5bde05267519cb879ba671d8d6ff836fd5d8cbe1e1e46d675cf5530a9179ef50027f@127.0.0.1:40002",
]

StaticNodes = [
]

TrustedNodes = [
  "enode://a610c4b3617f6967cf68f6062ae8e2ef4197dc95df6c16ef26dd7e1bb18c5bde05267519cb879ba671d8d6ff836fd5d8cbe1e1e46d675cf5530a9179ef50027f@127.0.0.1:40002",
]

conf-main.toml
--------------
ShareCfg = "common.toml"

[Eth]
NetworkId = 1973202011012023
SyncMode = "full"
DatabaseCache = 768
EnablePreimageRecording = false

[Eth.Miner]
GasPrice = 1
Etherbase = "0x4702058fe8468ab5a6985ff366a6bd64d165566b"

[Eth.Ethash]
CacheDir = "ethash"
CachesInMem = 2
CachesOnDisk = 3
DatasetDir = "master"
DatasetsInMem = 1
DatasetsOnDisk = 2
PowMode = 0

[Eth.TxPool]
NoLocals = false
Journal = "transactions.rlp"
Rejournal = 3600000000000
PriceLimit = 100000000
PriceBump = 1
AccountSlots = 10000
GlobalSlots = 40960
AccountQueue = 64
GlobalQueue = 10000
Lifetime = 10800000000000

[Eth.GPO]
Blocks = 20
Percentile = 60

[Node]
DataDir = "master"
IPCPath = "geth.ipc"
HTTPPort = 7541
HTTPHost = "0.0.0.0"
HTTPModules = ["net", "web3", "eth"]

[Node.P2P]
MaxPeers = 10000
NoDiscovery = false

ListenAddr = "0.0.0.0:40002"
EnableMsgEvents = false

private-genesis.json
--------------------
100000000000000000000000 = 100K tokens
{
    "config": {
        "chainId": 1973202011012023,
        "homesteadBlock": 0,
        "daoForkBlock": 0,
        "eip150Block": 0,
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "muirGlacierBlock": 0,
        "yoloV2Block": 0,
        "ethash": {}
    },
    "alloc": {
        "4702058fe8468ab5a6985ff366a6bd64d165566b": {
            "nonce": "1",
            "balance": "100000000000000000000000"
        }
    },
    "number": "0x0",
    "nonce": "0x88992e0",
    "difficulty": "400",
    "mixhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0x4702058fe8468ab5a6985ff366a6bd64d165566b",
    "timestamp": "0x00",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "extraData": "0xcafedabeefcafeda",
    "gasLimit": "100000"
}

==========================================================

Setup
./geth init config/private-genesis.json --datadir master

Run 1 node:
./geth --config config/conf-main.toml --verbosity 3

Attach web3:
./geth --datadir master attach
