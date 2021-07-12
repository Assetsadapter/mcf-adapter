package mcf

import (
	"encoding/hex"
	"github.com/blocktree/go-owcdrivers/addressEncoder"
	"github.com/blocktree/go-owcrypt"
	"github.com/blocktree/openwallet/v2/openwallet"
	"strings"
)

var (
	Default = AddressDecoderV2{}
)

//AddressDecoderV2
type AddressDecoderV2 struct {
	*openwallet.AddressDecoderV2Base
	wm *WalletManager
}

//NewAddressDecoder 地址解析器
func NewAddressDecoderV2(wm *WalletManager) *AddressDecoderV2 {
	decoder := AddressDecoderV2{}
	decoder.wm = wm
	return &decoder
}

//AddressDecode 地址解析
func (dec *AddressDecoderV2) AddressDecode(addr string, opts ...interface{}) ([]byte, error) {

	return nil, nil
}

var MainNetAddressP2PKH = addressEncoder.AddressType{"base58", addressEncoder.BTCAlphabet, "doubleSHA256", "h160", 20, []byte{0x3A}, nil}

//AddressEncode 地址编码
func (dec *AddressDecoderV2) AddressEncode(pub []byte, opts ...interface{}) (string, error) {
	if len(pub) != 32 {
		pub, _ = owcrypt.CURVE25519_convert_Ed_to_X(pub)
	}
	cfg := MainNetAddressP2PKH

	pkHash := owcrypt.Hash(pub, 0, owcrypt.HASH_ALG_HASH160)

	address := addressEncoder.AddressEncode(pkHash, cfg)

	return address, nil

}

// AddressVerify 地址校验
func (dec *AddressDecoderV2) AddressVerify(address string, opts ...interface{}) bool {
	if len(address) == 66 && strings.HasPrefix(address, "01") {
		_, err := hex.DecodeString(address)
		if err != nil {
			return false
		}
		return true
	}
	return false
}
