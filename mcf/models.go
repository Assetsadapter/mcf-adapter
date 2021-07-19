/*
 * Copyright 2018 The openwallet Authors
 * This file is part of the openwallet library.
 *
 * The openwallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The openwallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */
package mcf

import (
	"github.com/blocktree/openwallet/v2/openwallet"
	"github.com/tidwall/gjson"
	"strings"
)

const BATCH_CHARGE_TO_TAG = "batch_charge"

//
//"last_added_block_info": {
//   "hash": "8313a81942c21ebbec80a6e0d3c26af242e0ac86fdae150f406af54ce66ebcae",
//   "timestamp": "2021-04-14T11:38:33.344Z",
//   "era_id": 166,
//   "height": 18193,
//   "state_root_hash": "4914622c35cabaf631b19b8eb9e4e851593d4d50bd6143476d10bd903861dc7c",
//   "creator": "011117189c666f81c5160cd610ee383dc9b2d0361f004934754d39752eedc64957"
// }

type Status struct {
	Hash          string `json:"hash"`
	EraId         uint64 `json:"era_id"`
	Height        uint64 `json:"height"`
	StateRootHash string `json:"state_root_hash"`
}
type Block struct {
	Hash          string         `json:"hash"`
	PrevBlockHash string         `json:"previousHash"`
	Timestamp     uint64         `json:"timestamp"`
	Height        uint64         `json:"height"`
	Transactions  []*Transaction `json:"transactions"`
}

type Transaction struct {
	TxID            string
	Fee             uint64
	TimeStamp       uint64
	FromAccountHash string
	From            string
	To              string
	Amount          string
	BlockHeight     uint64
	BlockHash       string
	Status          string
	ToArr           []string //@required 格式："地址":"数量"
	ToDecArr        []string //@required 格式："地址":"数量(带小数)"
}

func GetTransactionInBlock(txJson *gjson.Result, blockHash string) []*Transaction {
	transferArray := txJson.Array()
	transactions := make([]*Transaction, 0)
	for _, transfer := range transferArray {
		txType := transfer.Get("type").String()
		if txType != "PAYMENT" {
			continue
		}

		transaction := Transaction{}
		transaction.BlockHash = blockHash
		transaction.BlockHeight = transfer.Get("blockHeight").Uint()
		transaction.TxID = transfer.Get("signature").String()
		transaction.Amount = transfer.Get("amount").String()
		transaction.From = transfer.Get("creatorAddress").String()
		transaction.To = transfer.Get("recipient").String()
		transactions = append(transactions, &transaction)
	}
	return transactions
}

// 从"account-hash-b383c7cc23d18bc1b42406a1b2d29fc8dba86425197b6f553d7fd61375b5e446" 格式中提取 hash
func GetHashFromAccountHash(accountHash string) string {
	if accountHash == "" {
		return ""
	}
	dataArray := strings.Split(accountHash, "-")
	if len(dataArray) != 3 {
		return ""
	}
	return dataArray[2]
}

func NewBlock(json *gjson.Result) *Block {
	obj := &Block{}
	obj.Hash = json.Get("signature").String()
	obj.PrevBlockHash = json.Get("reference").String()
	obj.Height = json.Get("height").Uint()
	return obj
}

//BlockHeader 区块链头
func (b *Block) BlockHeader() *openwallet.BlockHeader {

	obj := openwallet.BlockHeader{}
	//解析json
	obj.Hash = b.Hash
	//obj.Confirmations = b.Confirmations
	obj.Previousblockhash = b.PrevBlockHash
	obj.Height = b.Height
	//obj.Symbol = Symbol

	return &obj
}

type AddrBalance struct {
	Address string
	Balance string
}

type TxArtifacts struct {
	Hash        string
	Height      int64
	GenesisHash string
	SpecVersion uint32
	Metadata    string
	TxVersion   uint32
	ChainName   string
}

func GetTxArtifacts(json *gjson.Result) *TxArtifacts {
	obj := &TxArtifacts{}

	obj.Hash = gjson.Get(json.Raw, "at").Get("hash").String()
	obj.Height = gjson.Get(json.Raw, "at").Get("height").Int()
	obj.GenesisHash = gjson.Get(json.Raw, "genesisHash").String()
	obj.SpecVersion = uint32(gjson.Get(json.Raw, "specVersion").Uint())
	obj.Metadata = gjson.Get(json.Raw, "metadata").String()
	obj.TxVersion = uint32(gjson.Get(json.Raw, "txVersion").Uint())
	obj.ChainName = gjson.Get(json.Raw, "chainName").String()

	return obj
}
