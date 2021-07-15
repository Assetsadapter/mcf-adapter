package mcftransaction

import (
	"encoding/hex"
	"github.com/prometheus/common/log"
	"testing"
)

//{
//"0": 3,
//"1": 199,
//"2": 149,
//"3": 3
//}
func Test_uint32(t *testing.T) {
	bytes := decimalToBytes("22221.223423")
	log.Info(bytes)
	log.Info(hex.EncodeToString(bytes))
	//a:= new(big.Int)
	//n:= new(big.Int)
	//n.SetUint64(100000000)
	//
	//log.Info(a.Bytes())
	//
	//a.Mul(a,n)
	//log.Info(a.Bytes())
	//a.SetUint64(120000000)
	//log.Info(a.Bytes())
}
