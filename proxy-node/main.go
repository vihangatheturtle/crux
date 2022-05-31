package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	"github.com/elazarl/goproxy"
)

func createBody(currBody []byte) []byte {
	jObj := map[string]interface{}{
		"body":             currBody,
		"bodySignature":    "plain body signature",
		"lastObjSignature": "last obj signature",
		"lastBodyHash":     "last body hash",
	} // TODO: add a body hash
	res, _ := json.Marshal(jObj)
	return []byte(res)
}

func main() {
	log.Println("Starting proxy server on port 8080")
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	requestHandleFunc := func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		log.Println(req.Header["Content-Length"])
		bs, _ := ioutil.ReadAll(req.Body)
		req.Body.Close()
		bs = createBody(bs)
		req.Body = ioutil.NopCloser(bytes.NewReader(bs))
		req.Header.Set("Content-Length", strconv.Itoa(len(bs)))
		return req, nil
	}
	proxy.OnRequest().DoFunc(requestHandleFunc)
	log.Fatal(http.ListenAndServe(":8080", proxy))
}
