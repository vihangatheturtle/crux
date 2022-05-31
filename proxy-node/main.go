package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/elazarl/goproxy"
)

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func createBody(currBody []byte, privateKey *rsa.PrivateKey) []byte {
	hasher := sha256.New()
	jObj := map[string]interface{}{
		"body":            currBody,
		"bodySignature":   "plain body signature",
		"node-connection": privateKey.PublicKey,
	} // TODO: add a body hash
	hasher.Write(currBody)
	bodySHA := hex.EncodeToString(hasher.Sum(nil))
	if json.Valid(currBody) {
		var oldBodyData map[string]interface{}
		json.Unmarshal(currBody, &oldBodyData)
		k := make([]string, len(oldBodyData))
		i := 0
		for s := range oldBodyData {
			k[i] = s
			i++
		}
		if contains(k, "body") && contains(k, "bodySignature") && contains(k, "node-connection") && contains(k, "lastBodyHash") {
			bd, _ := b64.StdEncoding.DecodeString(oldBodyData["body"].(string))
			hasher.Write(bd)
			bodySHA = hex.EncodeToString(hasher.Sum(nil))
		}
	}
	jObj["lastBodyHash"] = bodySHA
	res, _ := json.Marshal(jObj)
	hasher.Write(res)
	rawNewBodySHA := hasher.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, rawNewBodySHA, nil)
	if err != nil {
		panic(err)
	}
	jObj["bodySignature"] = hex.EncodeToString(signature)
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
		bs, _ := ioutil.ReadAll(req.Body)
		req.Body.Close()
		if json.Valid(bs) {
			var oldBodyData map[string]interface{}
			json.Unmarshal(bs, &oldBodyData)
			k := make([]string, len(oldBodyData))
			i := 0
			for s := range oldBodyData {
				k[i] = s
				i++
			}
			if contains(k, "_crux_request_encrypted") {
				// Decrypt layer
			}
		}
		bs = createBody(bs, pk)
		req.Body = ioutil.NopCloser(bytes.NewReader(bs))
		//ctx.Req.Header.Set("Content-Length", strconv.Itoa(len(bs)))
		req.ContentLength = int64(len(bs))
		return req, nil
	}
	proxy.OnRequest().DoFunc(requestHandleFunc)
	log.Fatal(http.ListenAndServe(":8080", proxy))
}