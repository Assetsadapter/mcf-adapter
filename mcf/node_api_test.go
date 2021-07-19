package mcf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/blocktree/openwallet/v2/log"
	"github.com/btcsuite/btcutil/base58"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

const (
	testNodeAPIHttp = "http://3.208.91.63:8888"
	testNodeAPIRpc  = "http://1.wallet.info"
)

func PrintJsonLog(t *testing.T, logCont string) {
	if strings.HasPrefix(logCont, "{") {
		var str bytes.Buffer
		_ = json.Indent(&str, []byte(logCont), "", "    ")
		t.Logf("Get Call Result return: \n\t%+v\n", str.String())
	} else {
		t.Logf("Get Call Result return: \n\t%+v\n", logCont)
	}
}

func TestGetCall(t *testing.T) {
	tw := NewClient(testNodeAPIRpc, true)

	if r, err := tw.GetCall("/metadata/"); err != nil {
		t.Errorf("Get Call Result failed: %v\n", err)
	} else {
		PrintJsonLog(t, r.String())
	}
}

func Test_getAddrBalance(t *testing.T) {

	c := NewClient(testNodeAPIHttp, true)

	r, err := c.getBalance("QYqmSCw73QYAvCmkZCfpCm55XDk8W18fWW")

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("balance:", r)
	}

}

func Test_getBlockByHeight(t *testing.T) {
	c := NewClient(testNodeAPIRpc, true)
	r, err := c.getBlockByHeight(1830393)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}
}
func Test_clientRpc(t *testing.T) {
	c := NewClient(testNodeAPIRpc, true)
	data := make([]interface{}, 0)
	dataResp, err := c.RpcCall("info_get_status", data)
	if err != nil {
		t.Fatal(err)
		return
	}
	log.Info(dataResp.String())

}

func Test_getBlockRpc(t *testing.T) {
	c := NewClient(testNodeAPIRpc, true)
	dataResp, err := c.getBlockByHeight(5210)
	if err != nil {
		t.Fatal(err)
		return
	}
	log.Info(dataResp)
}

func Test_getBalance(t *testing.T) {

	c := NewClient(testNodeAPIRpc, true)
	address := "QYqmSCw73QYAvCmkZCfpCm55XDk8W18fWW"
	r, err := c.getBalance(address)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}

}
func Test_getLastTx(t *testing.T) {

	c := NewClient(testNodeAPIRpc, true)
	address := "QYqmSCw73QYAvCmkZCfpCm55XDk8W18fWW"
	r, err := c.getAddressLastTxHash(address)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(r)
	}

}

func Test_sendTransaction(t *testing.T) {
	b := "111FDmMyRw9zzfbkskARoJ5bs3z4auestAi3P31YpAv7ZmrvMEu6p2hoHVRPE4PA1kJbrnrK5cPzdbckDsEjoHiSyp5nabEYPUoD68JT9xZiuTMNCTFRnrapRPcPQXtWZzmXCWdirdb17d41qf1quzHKsBVzmi8iToEfRkreLU8gsY8YTHcnioPJTMxtFvmhf4W6X2NVAinQZU3"
	c := base58.Decode(b)
	log.Info(c)
}
func Test_rpc(t *testing.T) {
	// test (POST http://3.208.91.63:7777/rpc)
	//	Content-Length: 67
	//Accept: application/json
	//	Content-Type: application/json
	//	Accept-Encoding: gzip

	//{"id":1,"jsonrpc":"2.0","method":"info_get_status","params":[null]}
	json := []byte(`{"jsonrpc": "2.0","id": 123123,"method": "info_get_status","params": []}`)
	body := bytes.NewBuffer(json)

	// Create client
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("POST", "http://3.208.91.63:7777/rpc", body)

	// Headers
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	// Fetch Request
	resp, err := client.Do(req)

	if err != nil {
		fmt.Println("Failure : ", err)
	}

	// Read Response Body
	respBody, _ := ioutil.ReadAll(resp.Body)

	// Display Results
	fmt.Println("response Status : ", resp.Status)
	fmt.Println("response Headers : ", resp.Header)
	fmt.Println("response Body : ", string(respBody))

}
