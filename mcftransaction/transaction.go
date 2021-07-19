package mcftransaction

import (
	"github.com/btcsuite/btcutil/base58"
)

type PaymentTransaction struct {
	SenderPublicKey string
	Recipient       string
	Amount          string
	Fee             string
	Timestamp       uint64
	Reference       string
	Signature       []byte
}

func NewTransaction(timestamp uint64, reference, createPubKey, recipient, amount, fee string) *PaymentTransaction {
	tx := &PaymentTransaction{
		SenderPublicKey: createPubKey,
		Recipient:       recipient,
		Amount:          amount,
		Timestamp:       timestamp,
		Reference:       reference,
		Fee:             fee,
		Signature:       nil,
	}
	return tx
}

func (tx *PaymentTransaction) ToJson() (map[string]interface{}, error) {
	deployHeaderMap := make(map[string]interface{})
	return deployHeaderMap, nil

}
func (tx *PaymentTransaction) SetSignature(sig []byte) {
	tx.Signature = sig
}

// payment 序列化
func (tx *PaymentTransaction) ToBytes() []byte {
	var bytesData []byte
	//payment type 2
	bytesData = append(bytesData, uint32ToBigEndianBytes(2)...)
	// timestamp
	bytesData = append(bytesData, uint64ToBigEndianBytes(tx.Timestamp)...)
	//group id 默认为0
	bytesData = append(bytesData, uint32ToBigEndianBytes(0)...)
	//Reference 引用txid
	bytesData = append(bytesData, base58.Decode(tx.Reference)...)
	//Creator public key
	bytesData = append(bytesData, base58.Decode(tx.SenderPublicKey)...)
	//Recipient
	bytesData = append(bytesData, base58.Decode(tx.Recipient)...)
	//Amount
	// java version
	///MCF/src/main/java/org/qora/utils/Serialization.java  serializeBigDecimal
	bytesData = append(bytesData, decimalToBytes(tx.Amount)...)
	//fee
	bytesData = append(bytesData, decimalToBytes(tx.Fee)...)
	//signature
	if len(tx.Signature) > 0 {
		bytesData = append(bytesData, tx.Signature...)
	}
	return bytesData
}
