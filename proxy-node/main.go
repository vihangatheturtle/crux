package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"

	"github.com/elazarl/goproxy"
)

func main() {
	log.Println("Starting proxy server on port 8080")
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.AlwaysMitm)
	requestHandleFunc := func(request *http.Request, ctx *goproxy.ProxyCtx) (req *http.Request, resp *http.Response) {
		req = request
		bs, _ := ioutil.ReadAll(req.Body)
		log.Println("BODY", string(bs))
		// TODO: modify bs
		req.Body = ioutil.NopCloser(bytes.NewReader(bs))
		return
	}
	proxy.OnRequest().DoFunc(requestHandleFunc)
	log.Fatal(http.ListenAndServe(":8080", proxy))
}
