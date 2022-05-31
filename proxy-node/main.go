package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/elazarl/goproxy"
)

func createBody(currBody []byte, privateKey *rsa.PrivateKey) []byte {
	hasher := sha256.New()
	hasher.Write(currBody)
	bodySHA := hex.EncodeToString(hasher.Sum(nil))
	jObj := map[string]interface{}{
		"body":             currBody,
		"bodySignature":    "plain body signature",
		"lastObjSignature": "last obj signature",
		"lastBodyHash":     bodySHA,
		"node-connection":  privateKey.PublicKey,
	} // TODO: add a body hash
	res, _ := json.Marshal(jObj)
	hasher.Write(res)
	newBodySHA := hex.EncodeToString(hasher.Sum(nil))
	rawNewBodySHA := hasher.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, rawNewBodySHA, nil)
	if err != nil {
		panic(err)
	}
	jObj["bodySignature"] = hex.EncodeToString(signature)
	jObj["currentBodyHash"] = newBodySHA
	res, _ = json.Marshal(jObj)
	return []byte(res)
}

func main() {
	log.Println("Starting proxy server on port 8080")
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	requestHandleFunc := func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		log.Println(req.Header["Content-Length"])
		bs, _ := ioutil.ReadAll(req.Body)
		req.Body.Close()
		bs = createBody(bs, pk)
		req.Body = ioutil.NopCloser(bytes.NewReader(bs))
		//ctx.Req.Header.Set("Content-Length", strconv.Itoa(len(bs)))
		req.ContentLength = int64(len(bs))
		return req, nil
	}
	proxy.OnRequest().DoFunc(requestHandleFunc)
	log.Fatal(http.ListenAndServe(":8080", proxy))
}
