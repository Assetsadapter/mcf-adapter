package caspertransaction

import (
	"encoding/hex"
	"github.com/blocktree/go-owcrypt"
	"strconv"
	"strings"
	"time"
)

//https://docs.casperlabs.io/en/latest/implementation/serialization-standard.html 有些细节不全
//https://github.com/casper-ecosystem/casper-client-sdk.git 参考JavaScript sdk的实现
type Deploy struct {
	Approvals Approvals
	Header    DeployHeader
	Hash      []byte
	Payment   Payment
	Session   Transfer
}

type DeployHeader struct {
	Account      string
	Timestamp    uint64
	Ttl          uint64
	GasPrice     uint64
	BodyHash     []byte
	Dependencies []byte
	ChainName    string
}

type Approvals struct {
	Signer    string
	Signature string
}
type Payment struct {
	Amount uint64
}
type Transfer struct {
	Amount     uint64
	To         string //public key hex
	SourceUref string
	TransferId uint64
}

func NewDeploy(payAmount, transAmount, timeStamp, gasPrice, ttl uint64, fromAccount, toAccount, chainName string) (*Deploy, error) {
	payment := Payment{Amount: payAmount}
	paymentBytes, err := payment.toBytes()
	if err != nil {
		return nil, err
	}
	trans := Transfer{To: toAccount, Amount: transAmount}
	transBytes, err := trans.toBytes()
	if err != nil {
		return nil, err
	}
	var deployBodyBytes []byte
	deployBodyBytes = append(deployBodyBytes, paymentBytes...)
	deployBodyBytes = append(deployBodyBytes, transBytes...)
	deployBodyHash := owcrypt.Hash(deployBodyBytes, 32, owcrypt.HASH_ALG_BLAKE2B)

	deployHeader := DeployHeader{Account: fromAccount, Timestamp: timeStamp, Ttl: ttl, GasPrice: gasPrice, BodyHash: deployBodyHash, ChainName: chainName, Dependencies: []byte{}}
	deployHeaderBytes, err := deployHeader.toBytes()
	if err != nil {
		return nil, err
	}
	deployHeaderHash := owcrypt.Hash(deployHeaderBytes, 32, owcrypt.HASH_ALG_BLAKE2B)
	deploy := &Deploy{Header: deployHeader, Session: trans, Payment: payment, Hash: deployHeaderHash}
	return deploy, nil
}

func (deploy *Deploy) ToJson() (map[string]interface{}, error) {
	deployMap := make(map[string]interface{})
	deployBodyMap := make(map[string]interface{})
	deployMap["deploy"] = deployBodyMap
	if deploy.Approvals.Signature != "" {
		var array []map[string]string
		approvalsMap := make(map[string]string)
		approvalsMap["signature"] = "01" + deploy.Approvals.Signature
		approvalsMap["signer"] = deploy.Approvals.Signer
		array = append(array, approvalsMap)
		deployBodyMap["approvals"] = array
	}
	header, _ := deploy.Header.ToJson()
	session, _ := deploy.Session.toJson()
	payment, _ := deploy.Payment.ToJson()
	deployBodyMap["hash"] = hex.EncodeToString(deploy.Hash)
	deployBodyMap["header"] = header
	deployBodyMap["payment"] = payment
	deployBodyMap["session"] = session

	return deployBodyMap, nil
}

//deployHeader 序列化
func (deployHeader *DeployHeader) toBytes() ([]byte, error) {
	var bytesData []byte
	//tag is 1
	bytesData = append(bytesData, byte(1))
	//public key bytes
	acountPublicKeyBytes, err := hex.DecodeString(deployHeader.Account[2:])
	if err != nil {
		return nil, err
	}
	bytesData = append(bytesData, acountPublicKeyBytes...)

	//timestamp
	bytesData = append(bytesData, uint64ToLittleEndianBytes(deployHeader.Timestamp)...)

	//ttl
	bytesData = append(bytesData, uint64ToLittleEndianBytes(deployHeader.Ttl)...)

	//gasPrice
	bytesData = append(bytesData, uint64ToLittleEndianBytes(deployHeader.GasPrice)...)

	//body hash
	bytesData = append(bytesData, deployHeader.BodyHash...)

	//dependencies
	bytesData = append(bytesData, []byte{0, 0, 0, 0}...)

	//length of chainName String
	bytesData = append(bytesData, uint32ToLittleEndianBytes(uint32(len(deployHeader.ChainName)))...)
	//Amount string
	bytesData = append(bytesData, []byte(deployHeader.ChainName)...)

	return bytesData, nil
}

func (deployHeader *DeployHeader) ToJson() (map[string]interface{}, error) {
	deployHeaderMap := make(map[string]interface{})

	deployHeaderMap["account"] = deployHeader.Account
	deployHeaderMap["body_hash"] = hex.EncodeToString(deployHeader.BodyHash)
	deployHeaderMap["gas_price"] = deployHeader.GasPrice
	deployHeaderMap["dependencies"] = []interface{}{}
	deployHeaderMap["chain_name"] = deployHeader.ChainName
	date := time.Unix(int64(deployHeader.Timestamp/1000), int64(deployHeader.Timestamp%1000)*int64(time.Millisecond))
	deployHeaderMap["timestamp"] = date.UTC().Format(time.RFC3339Nano)
	ttlMin := strconv.Itoa(int(deployHeader.Ttl))
	deployHeaderMap["ttl"] = ttlMin + "ms"
	return deployHeaderMap, nil

}

// payment 序列化
func (payment *Payment) toBytes() ([]byte, error) {
	var bytesData []byte
	//tag
	bytesData = append(bytesData, byte(0))

	//modoule bytes
	bytesData = append(bytesData, []byte{0, 0, 0, 0}...)
	//length of args 只有1个参数可用
	bytesData = append(bytesData, uint32ToLittleEndianBytes(1)...)
	//Amount
	//length of "Amount" String
	bytesData = append(bytesData, uint32ToLittleEndianBytes(6)...)
	//Amount string
	bytesData = append(bytesData, []byte("amount")...)
	//Amount number 512 bit little endian Byte
	amountBytes := uintToShortByte(payment.Amount)
	bytesData = append(bytesData, uint32ToLittleEndianBytes(uint32(len(amountBytes)))...)
	bytesData = append(bytesData, amountBytes...)
	//Amount u512 tag = 8
	bytesData = append(bytesData, byte(8))

	return bytesData, nil
}

func (payment *Payment) ToJson() (map[string]interface{}, error) {
	paymentJson := make(map[string]interface{})
	moduleByteJson := make(map[string]interface{})

	paymentJson["ModuleBytes"] = moduleByteJson
	args := make([]interface{}, 0)
	var amountArray []interface{}
	amountArray = append(amountArray, "amount")
	amountJson := make(map[string]interface{})
	amountBytes := uintToShortByte(payment.Amount)
	amountJson["bytes"] = hex.EncodeToString(amountBytes)
	amountJson["cl_type"] = "U512"
	amountStr := strconv.FormatUint(payment.Amount, 10)
	amountJson["parsed"] = amountStr
	amountArray = append(amountArray, amountJson)
	args = append(args, amountArray)

	moduleByteJson["args"] = args
	moduleByteJson["module_bytes"] = ""
	return paymentJson, nil

}

// transfer 序列化
func (transfer *Transfer) toBytes() ([]byte, error) {
	var bytesData []byte

	//tag
	bytesData = append(bytesData, byte(5))

	//length of args 只有3个参数可用
	bytesData = append(bytesData, uint32ToLittleEndianBytes(3)...)

	//length of "Amount" String
	bytesData = append(bytesData, uint32ToLittleEndianBytes(6)...)
	//Amount string
	bytesData = append(bytesData, []byte("amount")...)
	//Amount number 512 bit little endian Byte
	amountBytes := uintToShortByte(transfer.Amount)
	bytesData = append(bytesData, uint32ToLittleEndianBytes(uint32(len(amountBytes)))...)
	bytesData = append(bytesData, amountBytes...)
	//Amount u512 tag = 8
	bytesData = append(bytesData, byte(8))

	//target

	//length of "target" String
	bytesData = append(bytesData, uint32ToLittleEndianBytes(6)...)
	//target string
	bytesData = append(bytesData, []byte("target")...)
	//accountHash string len
	bytesData = append(bytesData, uint32ToLittleEndianBytes(32)...)
	accountHashBytes, err := convertPublicToAccountHashBytes(transfer.To)
	if err != nil {
		return nil, err
	}
	//account hash bytes
	bytesData = append(bytesData, accountHashBytes...)
	//public key tag  =  15
	bytesData = append(bytesData, byte(15))
	//public key size 32
	bytesData = append(bytesData, uint32ToLittleEndianBytes(32)...)

	//length of "id" String
	bytesData = append(bytesData, uint32ToLittleEndianBytes(2)...)
	//id string
	bytesData = append(bytesData, []byte("id")...)
	// left bytes fixed
	bytesData = append(bytesData, []byte{1, 0, 0, 0, 0, 13, 5}...)

	return bytesData, nil

}

//转化为json
func (transfer *Transfer) toJson() (map[string]interface{}, error) {
	sessionJson := make(map[string]interface{})
	transferJson := make(map[string]interface{})

	sessionJson["Transfer"] = transferJson
	args := make([]interface{}, 0)
	var amountArray []interface{}
	amountArray = append(amountArray, "amount")
	amountJson := make(map[string]string)
	amountBytes := uintToShortByte(transfer.Amount)
	amountJson["bytes"] = hex.EncodeToString(amountBytes)
	amountJson["cl_type"] = "U512"
	amountStr := strconv.FormatUint(transfer.Amount, 10)
	amountJson["parsed"] = amountStr
	amountArray = append(amountArray, amountJson)

	args = append(args, amountArray)

	//target 目标需要转化成account-hash
	var targetArray []interface{}
	targetArray = append(targetArray, "target")

	targetJson := make(map[string]interface{})
	accountHashBytes, err := convertPublicToAccountHashBytes(transfer.To)
	if err != nil {
		return nil, err
	}
	targetJson["bytes"] = hex.EncodeToString(accountHashBytes)
	targetJson["cl_type"] = map[string]interface{}{"ByteArray": 32}
	targetJson["parsed"] = hex.EncodeToString(accountHashBytes)
	targetArray = append(targetArray, targetJson)
	args = append(args, targetArray)

	//id
	var idArray []interface{}
	idArray = append(idArray, "id")

	idJson := make(map[string]interface{})
	idJson["bytes"] = "00"
	idJson["cl_type"] = map[string]interface{}{"Option": "U64"}
	idJson["parsed"] = nil
	idArray = append(idArray, idJson)
	args = append(args, idArray)
	transferJson["args"] = args
	return sessionJson, nil

}

func convertPublicToAccountHashBytes(pubKeyHex string) ([]byte, error) {
	if len(pubKeyHex) == 66 && strings.HasPrefix(pubKeyHex, "01") {
		pubKeyHex = pubKeyHex[2:]
	}
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, nil
	}
	split, _ := hex.DecodeString("00")
	prefix := append([]byte("ed25519"), split...)
	pubKeyBytesAll := append(prefix, pubKeyBytes...)
	pkHash := owcrypt.Hash(pubKeyBytesAll, 32, owcrypt.HASH_ALG_BLAKE2B)
	return pkHash, nil
}
