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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Assetsadapter/mcf-adapter/mcftransaction"
	"github.com/Assetsadapter/mcf-adapter/txsigner"
	"github.com/blocktree/go-owcrypt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/prometheus/common/log"
	"github.com/shopspring/decimal"
	"math/big"
	"sort"
	"time"

	"github.com/blocktree/openwallet/v2/openwallet"
)

type TransactionDecoder struct {
	openwallet.TransactionDecoderBase
	openwallet.AddressDecoderV2
	wm *WalletManager //钱包管理者
}

//NewTransactionDecoder 交易单解析器
func NewTransactionDecoder(wm *WalletManager) *TransactionDecoder {
	decoder := TransactionDecoder{}
	decoder.wm = wm
	return &decoder
}

//CreateRawTransaction 创建交易单
func (decoder *TransactionDecoder) CreateRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {
	return decoder.CreateMcfRawTransaction(wrapper, rawTx)
}

//SignRawTransaction 签名交易单
func (decoder *TransactionDecoder) SignRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {

	if rawTx.Signatures == nil || len(rawTx.Signatures) == 0 {
		return openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "transaction signature is empty")
	}
	key, err := wrapper.HDKey()
	if err != nil {
		return err
	}

	keySignatures := rawTx.Signatures[rawTx.Account.AccountID]
	if keySignatures != nil {
		for _, keySignature := range keySignatures {

			childKey, err := key.DerivedKeyWithPath(keySignature.Address.HDPath, keySignature.EccType)
			keyBytes, err := childKey.GetPrivateKeyBytes()
			if err != nil {
				return err
			}

			publicKey, _ := hex.DecodeString(keySignature.Address.PublicKey)

			msg, err := hex.DecodeString(keySignature.Message)
			if err != nil {
				return openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "decoder transaction hash failed, unexpected err: %v", err)
			}

			sig, err := txsigner.Default.SignTransactionHash(msg, keyBytes, keySignature.EccType)
			if err != nil {
				return openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "sign transaction hash failed, unexpected err: %v", err)
			}

			rawTxHex, err := hex.DecodeString(rawTx.RawHex)
			if err != nil {
				return err
			}
			tx := mcftransaction.PaymentTransaction{}
			if err := json.Unmarshal(rawTxHex, &tx); err != nil {
				return openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "sign transaction hash failed, unexpected err: %v", err)
			}
			tx.SetSignature(sig)
			if err != nil {
				return err
			}
			rawTx.RawHex = hex.EncodeToString(tx.ToBytes())
			if err != nil {
				return openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "raw tx Unmarshal failed=%s", err)
			}
			decoder.wm.Log.Debugf("message: %s", hex.EncodeToString(msg))
			decoder.wm.Log.Debugf("publicKey: %s", hex.EncodeToString(publicKey))
			decoder.wm.Log.Debug("publicKey: ", publicKey)

			decoder.wm.Log.Debugf("signature: %s", hex.EncodeToString(sig))

			keySignature.Signature = hex.EncodeToString(sig)
		}
	}

	decoder.wm.Log.Info("transaction hash sign success")

	rawTx.Signatures[rawTx.Account.AccountID] = keySignatures

	return nil
}

//VerifyRawTransaction 验证交易单，验证交易单并返回加入签名后的交易单
func (decoder *TransactionDecoder) VerifyRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {
	return decoder.VerifyMcfRawTransaction(wrapper, rawTx)
}

func (decoder *TransactionDecoder) SubmitRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) (*openwallet.Transaction, error) {
	if len(rawTx.RawHex) == 0 {
		return nil, fmt.Errorf("transaction hex is empty")
	}

	if !rawTx.IsCompleted {
		return nil, fmt.Errorf("transaction is not completed validation")
	}

	rawTxBytes, err := hex.DecodeString(rawTx.RawHex)
	if err != nil {
		return nil, openwallet.Errorf(openwallet.ErrSubmitRawSmartContractTransactionFailed, "raw tx Unmarshal failed=%s", err)
	}
	rawTxBase58 := base58.Encode(rawTxBytes)
	txId := base58.Encode(rawTxBytes[len(rawTxBytes)-64:])

	log.Info("txId: ", rawTxBase58)
	log.Info("txBase58: ", rawTxBase58)
	err = decoder.wm.SendRawTransaction(rawTxBase58)
	if err != nil {
		return nil, err
	}

	rawTx.TxID = txId
	rawTx.IsSubmit = true

	decimals := int32(6)

	tx := openwallet.Transaction{
		From:       rawTx.TxFrom,
		To:         rawTx.TxTo,
		Amount:     rawTx.TxAmount,
		Coin:       rawTx.Coin,
		TxID:       rawTx.TxID,
		Decimal:    decimals,
		AccountID:  rawTx.Account.AccountID,
		Fees:       rawTx.Fees,
		SubmitTime: time.Now().Unix(),
	}

	tx.WxID = openwallet.GenTransactionWxID(&tx)

	return &tx, nil
}

func (decoder *TransactionDecoder) CreateMcfRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {

	addresses, err := wrapper.GetAddressList(0, -1, "AccountID", rawTx.Account.AccountID)

	if err != nil {
		return err
	}

	if len(addresses) == 0 {
		return openwallet.Errorf(openwallet.ErrAccountNotAddress, "[%s] have not addresses", rawTx.Account.AccountID)
	}

	addressesBalanceList := make([]AddrBalance, 0, len(addresses))

	for _, addr := range addresses {
		balance, err := decoder.wm.ApiClient.getBalance(addr.Address)
		if err != nil {
			return err
		}
		//nonce := decoder.wm.GetAddressNonce(wrapper, balance)
		addressesBalanceList = append(addressesBalanceList, *balance)
	}

	sort.Slice(addressesBalanceList, func(i int, j int) bool {
		return addressesBalanceList[i].Balance > addressesBalanceList[j].Balance
	})

	feeStr := ""
	fee := uint64(0)
	if len(rawTx.FeeRate) > 0 {
		feeStr = rawTx.FeeRate
		fee = uint64(int64(convertFromAmount(feeStr, decoder.wm.Decimal())))
		if err != nil {
			return err
		}
	} else {
		feeStr = decoder.wm.Config.FixedFee
	}
	fee = uint64(int64(convertFromAmount(feeStr, decoder.wm.Decimal())))

	var amountStr, to string
	for k, v := range rawTx.To {
		to = k
		amountStr = v
		break
	}

	from := ""
	amount := uint64(int64(convertFromAmount(amountStr, decoder.wm.Decimal())))
	for _, a := range addressesBalanceList {
		addrBalance := uint64(int64(convertFromAmount(a.Balance, decoder.wm.Decimal())))
		if addrBalance < (amount + fee) {
			continue
		}
		from = a.Address

	}

	if from == "" {
		return openwallet.Errorf(openwallet.ErrInsufficientBalanceOfAccount, "the balance: %s is not enough", amountStr)
	}

	rawTx.TxFrom = []string{from}
	rawTx.TxTo = []string{to}
	rawTx.TxAmount = amountStr
	rawTx.FeeRate = convertToAmount(fee, decoder.wm.Decimal())
	addrFrom, err := wrapper.GetAddress(from)
	if err != nil {
		return err
	}
	tx, message, err := decoder.CreateEmptyRawTransactionAndMessage(from, addrFrom.PublicKey, to, amountStr, feeStr)
	if err != nil {
		return err
	}
	txBytes, err := json.Marshal(tx)
	if err != nil {
		return err
	}

	rawTx.RawHex = hex.EncodeToString(txBytes)

	if rawTx.Signatures == nil {
		rawTx.Signatures = make(map[string][]*openwallet.KeySignature)
	}

	keySigs := make([]*openwallet.KeySignature, 0)

	signature := openwallet.KeySignature{
		EccType: decoder.wm.Config.CurveType,
		Address: addrFrom,
		Message: message,
	}

	keySigs = append(keySigs, &signature)

	rawTx.Signatures[rawTx.Account.AccountID] = keySigs

	rawTx.FeeRate = big.NewInt(int64(fee)).String()

	rawTx.IsBuilt = true

	return nil
}

func (decoder *TransactionDecoder) VerifyMcfRawTransaction(wrapper openwallet.WalletDAI, rawTx *openwallet.RawTransaction) error {

	if rawTx.Signatures == nil || len(rawTx.Signatures) == 0 {
		return openwallet.Errorf(openwallet.ErrVerifyRawTransactionFailed, "transaction signature is empty")
	}

	//支持多重签名
	for accountID, keySignatures := range rawTx.Signatures {
		decoder.wm.Log.Debug("accountID Signatures:", accountID)
		for _, keySignature := range keySignatures {

			messsage, _ := hex.DecodeString(keySignature.Message)
			signature, _ := hex.DecodeString(keySignature.Signature)
			publicKey, _ := hex.DecodeString(keySignature.Address.PublicKey)

			// 验证签名
			//ret := owcrypt.Verify(publicKey, nil, 0, messsage, uint16(len(messsage)), signature, keySignature.EccType)
			if owcrypt.SUCCESS != owcrypt.Verify(publicKey, nil, messsage, signature, owcrypt.ECC_CURVE_ED25519) {
				return openwallet.Errorf(openwallet.ErrVerifyRawTransactionFailed, "transaction verify failed")

			}

			break

		}
	}

	rawTx.IsCompleted = true

	return nil
}

func (decoder *TransactionDecoder) GetRawTransactionFeeRate() (feeRate string, unit string, err error) {
	//rate := uint64(decoder.wm.Config.FixedFee)
	//return convertToAmount(rate, decoder.wm.Decimal()), "TX", nil
	return "0", "0", nil
}

//CreateSummaryRawTransaction 创建汇总交易，返回原始交易单数组
func (decoder *TransactionDecoder) CreateSummaryRawTransaction(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransaction, error) {
	if sumRawTx.Coin.IsContract {
		return nil, nil
	} else {
		return decoder.CreateSimpleSummaryRawTransaction(wrapper, sumRawTx)
	}
}

func (decoder *TransactionDecoder) CreateSimpleSummaryRawTransaction(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransaction, error) {

	var (
		rawTxArray      = make([]*openwallet.RawTransaction, 0)
		accountID       = sumRawTx.Account.AccountID
		retainedBalance = big.NewInt(int64(convertFromAmount(sumRawTx.RetainedBalance, decoder.wm.Decimal())))
	)
	minTransferDec, err := decimal.NewFromString(sumRawTx.MinTransfer)
	if err != nil {
		return nil, err
	}
	minTransfer := big.NewInt(minTransferDec.IntPart())
	if minTransfer.Cmp(retainedBalance) < 0 {
		return nil, fmt.Errorf("mini transfer amount must be greater than address retained balance")
	}

	//获取wallet
	addresses, err := wrapper.GetAddressList(sumRawTx.AddressStartIndex, sumRawTx.AddressLimit,
		"AccountID", sumRawTx.Account.AccountID)
	if err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("[%s] have not addresses", accountID)
	}

	searchAddrs := make([]string, 0)
	for _, address := range addresses {
		searchAddrs = append(searchAddrs, address.Address)
	}

	addrBalanceArray, err := decoder.wm.Blockscanner.GetBalanceByAddress(searchAddrs...)
	if err != nil {
		return nil, err
	}
	fee := new(big.Int)
	if len(sumRawTx.FeeRate) > 0 {
		feeGet, err := decimal.NewFromString(sumRawTx.FeeRate)
		if err != nil {
			return nil, err
		}
		fee = big.NewInt(feeGet.IntPart())
	} else {
		//fee = big.NewInt(decoder.wm.Config.FixedFee)
	}

	for _, addrBalance := range addrBalanceArray {

		//检查余额是否超过最低转账
		addrBalance_BI := big.NewInt(int64(convertFromAmount(addrBalance.Balance, decoder.wm.Decimal())))

		addrBalance_BI_Fee := new(big.Int)
		addrBalance_BI_Fee.Sub(addrBalance_BI, fee)
		if addrBalance_BI_Fee.Cmp(minTransfer) < 0 {
			continue
		}
		//计算汇总数量 = 余额 - 保留余额
		sumAmount_BI := new(big.Int)
		sumAmount_BI.Sub(addrBalance_BI, retainedBalance)

		//this.wm.Log.Debug("sumAmount:", sumAmount)
		//计算手续费

		//减去手续费
		sumAmount_BI.Sub(sumAmount_BI, fee)
		if sumAmount_BI.Cmp(big.NewInt(0)) <= 0 {
			continue
		}
		//if sumAmount_BI.Cmp(big.NewInt(decoder.wm.Config.ReserveAmount)) < 0 {
		//	return nil, errors.New("The summary address [" + sumRawTx.SummaryAddress + "] 保留余额不足!")
		//}

		sumAmount := convertToAmount(sumAmount_BI.Uint64(), decoder.wm.Decimal())
		fees := convertToAmount(fee.Uint64(), decoder.wm.Decimal())

		decoder.wm.Log.Debug(
			"address : ", addrBalance.Address,
			" balance : ", addrBalance.Balance,
			" fees : ", fees,
			" sumAmount : ", sumAmount)

		//创建一笔交易单
		rawTx := &openwallet.RawTransaction{
			Coin:     sumRawTx.Coin,
			Account:  sumRawTx.Account,
			ExtParam: sumRawTx.ExtParam,
			TxAmount: sumAmount,
			To: map[string]string{
				sumRawTx.SummaryAddress: sumAmount,
			},
			Required: 1,
			FeeRate:  sumRawTx.FeeRate,
		}

		//createErr := decoder.createRawTransaction(
		//	wrapper,
		//	rawTx,
		//	addrBalance)
		//if createErr != nil {
		//	return nil, createErr
		//}

		//deploy, message, err := decoder.CreateEmptyRawTransactionAndMessage(addrBalance.Address, sumRawTx.SummaryAddress, sumAmount_BI.Uint64(), fee.Uint64())
		if err != nil {
			return nil, openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "Serialization error ")
		}
		//deployBytes, err := json.Marshal(deploy)
		if err != nil {
			return nil, openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "json marshal tx error")
		}

		//rawTx.RawHex = hex.EncodeToString(deployBytes)

		if rawTx.Signatures == nil {
			rawTx.Signatures = make(map[string][]*openwallet.KeySignature)
		}
		keySigs := make([]*openwallet.KeySignature, 0)

		addr, err := wrapper.GetAddress(addrBalance.Address)
		if err != nil {
			return nil, openwallet.Errorf(openwallet.ErrCreateRawTransactionFailed, "find address error")

		}
		signature := openwallet.KeySignature{
			EccType: decoder.wm.Config.CurveType,
			Address: addr,
			Message: "",
		}
		keySigs = append(keySigs, &signature)
		rawTx.Signatures[rawTx.Account.AccountID] = keySigs

		//创建成功，添加到队列
		rawTxArray = append(rawTxArray, rawTx)
	}
	return rawTxArray, nil
}

//CreateSummaryRawTransactionWithError 创建汇总交易，返回能原始交易单数组（包含带错误的原始交易单）
func (decoder *TransactionDecoder) CreateSummaryRawTransactionWithError(wrapper openwallet.WalletDAI, sumRawTx *openwallet.SummaryRawTransaction) ([]*openwallet.RawTransactionWithError, error) {
	raTxWithErr := make([]*openwallet.RawTransactionWithError, 0)
	rawTxs, err := decoder.CreateSummaryRawTransaction(wrapper, sumRawTx)
	if err != nil {
		return nil, err
	}
	for _, tx := range rawTxs {
		raTxWithErr = append(raTxWithErr, &openwallet.RawTransactionWithError{
			RawTx: tx,
			Error: nil,
		})
	}
	return raTxWithErr, nil
}

func (decoder *TransactionDecoder) CreateEmptyRawTransactionAndMessage(fromAddr, fromPubKey, toAddr, transferAmount, payFeeAmount string) (*mcftransaction.PaymentTransaction, string, error) {
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)
	//create public key
	bytes, err := hex.DecodeString(fromPubKey)
	if err != nil {
		return nil, "", err
	}
	fromAddrPubKeyBase58 := base58.Encode(bytes)
	//Reference 引用txid
	lastTxId, err := decoder.wm.ApiClient.Client.getAddressLastTxHash(fromAddr)
	log.Info("llllllastId:", lastTxId)
	if err != nil {
		return nil, "", err
	}
	payFeeAmount = "0.00001"
	tx := mcftransaction.NewTransaction(uint64(timestamp), lastTxId, fromAddrPubKeyBase58, toAddr, transferAmount, payFeeAmount)

	return tx, hex.EncodeToString(tx.ToBytes()), nil
}
