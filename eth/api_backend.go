// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/gasprice"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// EthAPIBackend implements ethapi.Backend for full nodes
type EthAPIBackend struct {
	extRPCEnabled bool
	eth           *Ethereum
	gpo           *gasprice.Oracle
}

// ChainConfig returns the active chain configuration.
func (b *EthAPIBackend) ChainConfig() *params.ChainConfig {
	return b.eth.blockchain.Config()
}

func (b *EthAPIBackend) CurrentBlock() *types.Block {
	return b.eth.blockchain.CurrentBlock()
}

func (b *EthAPIBackend) SetHead(number uint64) {
	b.eth.protocolManager.downloader.Cancel()
	b.eth.blockchain.SetHead(number)
}

func (b *EthAPIBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	if number == rpc.PendingBlockNumber {
		block := b.eth.miner.PendingBlock()
		return block.Header(), nil
	}
	// Otherwise resolve and return the block
	if number == rpc.LatestBlockNumber {
		return b.eth.blockchain.CurrentBlock().Header(), nil
	}
	return b.eth.blockchain.GetHeaderByNumber(uint64(number)), nil
}

func (b *EthAPIBackend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.HeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.eth.blockchain.GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.eth.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		return header, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *EthAPIBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return b.eth.blockchain.GetHeaderByHash(hash), nil
}

func (b *EthAPIBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	// Pending block is only known by the miner
	if number == rpc.PendingBlockNumber {
		block := b.eth.miner.PendingBlock()
		return block, nil
	}
	// Otherwise resolve and return the block
	if number == rpc.LatestBlockNumber {
		return b.eth.blockchain.CurrentBlock(), nil
	}
	return b.eth.blockchain.GetBlockByNumber(uint64(number)), nil
}

func (b *EthAPIBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.eth.blockchain.GetBlockByHash(hash), nil
}

func (b *EthAPIBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.BlockByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header := b.eth.blockchain.GetHeaderByHash(hash)
		if header == nil {
			return nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.eth.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, errors.New("hash is not currently canonical")
		}
		block := b.eth.blockchain.GetBlock(hash, header.Number.Uint64())
		if block == nil {
			return nil, errors.New("header found, but block body is missing")
		}
		return block, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *EthAPIBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if number == rpc.PendingBlockNumber {
		block, state := b.eth.miner.Pending()
		return state, block.Header(), nil
	}
	// Otherwise resolve the block number and return its state
	header, err := b.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	stateDb, err := b.eth.BlockChain().StateAt(header.Root)
	return stateDb, header, err
}

func (b *EthAPIBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.StateAndHeaderByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		header, err := b.HeaderByHash(ctx, hash)
		if err != nil {
			return nil, nil, err
		}
		if header == nil {
			return nil, nil, errors.New("header for hash not found")
		}
		if blockNrOrHash.RequireCanonical && b.eth.blockchain.GetCanonicalHash(header.Number.Uint64()) != hash {
			return nil, nil, errors.New("hash is not currently canonical")
		}
		stateDb, err := b.eth.BlockChain().StateAt(header.Root)
		return stateDb, header, err
	}
	return nil, nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *EthAPIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	return b.eth.blockchain.GetReceiptsByHash(hash), nil
}

func (b *EthAPIBackend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	receipts := b.eth.blockchain.GetReceiptsByHash(hash)
	if receipts == nil {
		return nil, nil
	}
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (b *EthAPIBackend) GetTd(ctx context.Context, hash common.Hash) *big.Int {
	return b.eth.blockchain.GetTdByHash(hash)
}

func (b *EthAPIBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header) (*vm.EVM, func() error, error) {
	vmError := func() error { return nil }

	context := core.NewEVMContext(msg, header, b.eth.BlockChain(), nil)
	return vm.NewEVM(context, state, b.eth.blockchain.Config(), *b.eth.blockchain.GetVMConfig()), vmError, nil
}

func (b *EthAPIBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (b *EthAPIBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.eth.miner.SubscribePendingLogs(ch)
}

func (b *EthAPIBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeChainEvent(ch)
}

func (b *EthAPIBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeChainHeadEvent(ch)
}

func (b *EthAPIBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	return b.eth.BlockChain().SubscribeChainSideEvent(ch)
}

func (b *EthAPIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.eth.BlockChain().SubscribeLogsEvent(ch)
}

func (b *EthAPIBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	return b.eth.txPool.AddLocal(signedTx)
}

func (b *EthAPIBackend) GetPoolTransactions() (types.Transactions, error) {
	pending, err := b.eth.txPool.Pending()
	if err != nil {
		return nil, err
	}
	var txs types.Transactions
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	return txs, nil
}

func (b *EthAPIBackend) GetPoolTransaction(hash common.Hash) *types.Transaction {
	return b.eth.txPool.Get(hash)
}

func (b *EthAPIBackend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(b.eth.ChainDb(), txHash)
	return tx, blockHash, blockNumber, index, nil
}

func (b *EthAPIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return b.eth.txPool.Nonce(addr), nil
}

func (b *EthAPIBackend) Stats() (pending int, queued int) {
	return b.eth.txPool.Stats()
}

func (b *EthAPIBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return b.eth.TxPool().Content()
}

func (b *EthAPIBackend) TxPool() *core.TxPool {
	return b.eth.TxPool()
}

func (b *EthAPIBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return b.eth.TxPool().SubscribeNewTxsEvent(ch)
}

func (b *EthAPIBackend) Downloader() *downloader.Downloader {
	return b.eth.Downloader()
}

func (b *EthAPIBackend) ProtocolVersion() int {
	return b.eth.EthVersion()
}

func (b *EthAPIBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return b.gpo.SuggestPrice(ctx)
}

func (b *EthAPIBackend) ChainDb() ethdb.Database {
	return b.eth.ChainDb()
}

func (b *EthAPIBackend) EventMux() *event.TypeMux {
	return b.eth.EventMux()
}

func (b *EthAPIBackend) AccountManager() *accounts.Manager {
	return b.eth.AccountManager()
}

func (b *EthAPIBackend) ExtRPCEnabled() bool {
	return b.extRPCEnabled
}

func (b *EthAPIBackend) RPCGasCap() uint64 {
	return b.eth.config.RPCGasCap
}

func (b *EthAPIBackend) RPCTxFeeCap() float64 {
	return b.eth.config.RPCTxFeeCap
}

func (b *EthAPIBackend) BloomStatus() (uint64, uint64) {
	sections, _, _ := b.eth.bloomIndexer.Sections()
	return params.BloomBitsBlocks, sections
}

func (b *EthAPIBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < bloomFilterThreads; i++ {
		go session.Multiplex(bloomRetrievalBatch, bloomRetrievalWait, b.eth.bloomRequests)
	}
}

func (b *EthAPIBackend) Engine() consensus.Engine {
	return b.eth.engine
}

func (b *EthAPIBackend) CurrentHeader() *types.Header {
	return b.eth.blockchain.CurrentHeader()
}

func (b *EthAPIBackend) Miner() *miner.Miner {
	return b.eth.Miner()
}

func (b *EthAPIBackend) StartMining(threads int) error {
	return b.eth.StartMining(threads)
}

func (b *EthAPIBackend) PayToRelay(ctx context.Context, from, to, signedTx string) map[string]interface{} {
	log.Info("EthAPI payToRelay", "from", from, "to", to, "json", signedTx)
	out := make(map[string]interface{})

	rawTx := []byte(signedTx)
	tx := types.NewTransaction(0, common.Address{}, nil, 0, nil, nil)
	if err := tx.UnmarshalJSON(rawTx); err != nil {
		out["Error"] = err.Error()
		out["Cause"] = "Invalid JSON signed Tx"
		return out
	}
	if err := b.SendTx(ctx, tx); err != nil {
		log.Info("Known tx", "tx", tx.Hash().Hex(), "err", err)
		out["Error"] = err.Error()
		out["Cause"] = "Known Tx"
		return out
	}
	res, _ := b.getTransDetail(ctx, from, tx.Hash().Hex(), true)
	out["Error"] = res.Error
	out["Tx"] = res
	return out
}

func (b *EthAPIBackend) PollTransaction(ctx context.Context, from, txHex string) map[string]interface{} {
	out := make(map[string]interface{})
	out["Tx"], _ = b.getTransDetail(ctx, from, txHex, true)
	return out
}

type txbasic struct {
	From             string
	To               string
	Hash             string
	Error            string
	BlockHash        string
	BlockNumber      uint64
	Nonce            uint64
	XuValue          uint64
	FromXuBal        uint64
	ToXuBal          uint64
	Time             uint64
	TransactionIndex uint64
}

func (b *EthAPIBackend) ListTransactions(ctx context.Context, trans []string) map[string]interface{} {
	type transout struct {
		txbasic
		Gas      uint64
		GasPrice uint64
		Input    hexutil.Bytes
		V        string
		R        string
		S        string
	}
	txOut := make([]transout, 0)
	err := make([]string, 0)
	out := make(map[string]interface{})

	for _, txHash := range trans {
		res, tx := b.getTransDetail(ctx, "", txHash, false)
		if tx != nil {
			v, r, s := tx.RawSignatureValues()
			txOut = append(txOut, transout{
				txbasic:  *res,
				Gas:      uint64(tx.Gas()),
				GasPrice: uint64(tx.GasPrice().Int64()),
				Input:    hexutil.Bytes(tx.Data()),
				V:        fmt.Sprintf("%x", v),
				R:        fmt.Sprintf("%x", r),
				S:        fmt.Sprintf("%x", s),
			})
		} else if res.Error != "" {
			err = append(err, res.Error)
		}
	}
	out["Error"] = err
	out["Tx"] = txOut
	return out
}

func (b *EthAPIBackend) getTransDetail(ctx context.Context, from, txHex string, poll bool) (*txbasic, *types.Transaction) {
	var pollLoop int = 1
	if poll {
		pollLoop = 20
	}
	txHash := common.HexToHash(txHex)
	out := txbasic{
		Error:       "",
		To:          "",
		From:        from,
		BlockHash:   "0x0",
		Hash:        txHex,
		BlockNumber: 0,
		Nonce:       0,
		XuValue:     0,
		FromXuBal:   0,
		ToXuBal:     0,
		Time:        0,
	}
	for i := 0; i < pollLoop; i++ {
		nTx, blockHash, blockNo, index := rawdb.ReadTransaction(b.eth.ChainDb(), txHash)
		if nTx == nil || blockNo == 0 {
			if out.Error == "" {
				out.Error = fmt.Sprintf("%s: can't find transaction", txHex)
			}
			time.Sleep(300 * time.Millisecond)
			continue
		}
		out.Error = ""
		out.TransactionIndex = index
		out.BlockNumber = blockNo
		out.BlockHash = blockHash.Hex()

		bc := b.eth.BlockChain()
		header := bc.GetHeaderByNumber(blockNo)
		if header == nil {
			out.Error = fmt.Sprintf("%s: no header, block %x", txHex, blockNo)
			return &out, nil
		}
		stateDb, err := bc.StateAt(header.Root)
		if err != nil || stateDb == nil {
			out.Error = fmt.Sprintf("%s: %s", txHex, err.Error())
			return &out, nil
		}
		var fromAddr common.Address
		if from == "" {
			var signer types.Signer = types.FrontierSigner{}
			if nTx.Protected() {
				signer = types.NewEIP155Signer(nTx.ChainId())
			}
			fromAddr, _ = types.Sender(signer, nTx)
		} else {
			fromAddr = common.HexToAddress(from)
		}
		out.To = nTx.To().Hex()
		out.From = fromAddr.Hex()
		out.Nonce = uint64(nTx.Nonce())
		out.XuValue = math.FromWeiToXu(nTx.Value())
		out.ToXuBal = math.FromWeiToXu(stateDb.GetBalance(*nTx.To()))
		out.FromXuBal = math.FromWeiToXu(stateDb.GetBalance(fromAddr))
		out.Time = header.Time
		return &out, nTx
	}
	return &out, nil
}

func (b *EthAPIBackend) ListAccounts(ctx context.Context, accounts []string) map[string]interface{} {
	type accountInfo struct {
		Account   string
		Type      string
		XuBalance uint64
		Nonce     uint64
		BlockNo   uint64
	}
	result := make([]accountInfo, 0)
	out := make(map[string]interface{})
	netID := fmt.Sprintf("%x", b.eth.NetVersion())

	state, header, err := b.StateAndHeaderByNumber(ctx, -1)
	if err != nil || header == nil || state == nil {
		out["Accounts"] = result
		out["Error"] = fmt.Sprintf("Unable to get current block, try again")
		return out
	}
	blkNo := uint64(header.Number.Int64())
	for _, addr := range accounts {
		actKey := common.HexToAddress(addr)
		balance := state.GetBalance(actKey)
		result = append(result, accountInfo{
			Account:   addr,
			Type:      netID,
			XuBalance: math.FromWeiToXu(balance),
			Nonce:     state.GetNonce(actKey),
			BlockNo:   blkNo,
		})
	}
	out["Error"] = ""
	out["Accounts"] = result
	return out
}

func (b *EthAPIBackend) DumpAccounts(ctx context.Context) map[string]interface{} {
	out := make(map[string]interface{})
	eth := b.eth
	bc := eth.BlockChain()
	latest := bc.CurrentBlock()
	log.Info("EthAPI dumpAccounts", "latest block", latest)

	if latest == nil {
		return out
	}
	stateDb, err := bc.StateAt(latest.Root())
	if err == nil {
		accounts := stateDb.RawDump(true, true, true)
		out["Error"] = ""
		out["Accounts"] = accounts.Accounts
	} else {
		out["Error"] = err.Error()
		out["Accounts"] = make([]string, 0)
	}
	return out
}
