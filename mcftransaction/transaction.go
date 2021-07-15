package mcftransaction

import (
	"github.com/btcsuite/btcutil/base58"
)

type PaymentTransaction struct {
	SenderPublicKey string
	Recipient       string
	Amount          string
	Timestamp       uint64
	Reference       string
	Fee             uint64
	Signature       string
}

func (tx *PaymentTransaction) ToJson() (map[string]interface{}, error) {
	deployHeaderMap := make(map[string]interface{})
	return deployHeaderMap, nil

}

// payment 序列化
func (tx *PaymentTransaction) toBytes() ([]byte, error) {
	var bytesData []byte
	//payment type 2
	bytesData = append(bytesData, byte(2))
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
	//signature
	if tx.Signature != "" {
		bytesData = append(bytesData, base58.Decode(tx.Signature)...)
	}
	return bytesData, nil
}
