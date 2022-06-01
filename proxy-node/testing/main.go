package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
)

var nodesList = make(map[string]interface{})
var privateKey *rsa.PrivateKey
var publicKey string
var stype string
var port string
var killServer bool
var proxySrv *http.Server
var tcpSrv *net.TCPListener

func saveRSAKey(key *rsa.PrivateKey) []byte {
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	return pemdata
}

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

func getPublicAddressFromPrivate(privateKey *rsa.PrivateKey) string {
	pub := privateKey.PublicKey
	hasher := sha256.New()
	hasher.Write(x509.MarshalPKCS1PublicKey(&pub))
	return hex.EncodeToString(hasher.Sum(nil))
}

func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return plaintext
}

func isRequestBodyCruxNetForwardRequest(body map[string]interface{}) bool {
	k := make([]string, len(body))
	i := 0
	for s := range body {
		k[i] = s
		i++
	}
	return contains(k, "_crux_request_encrypted")
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

func getConn(addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", addr)
	return conn, err
}

func propagateCommand(text string) {
	known := nodesList

	log.Println("Propagating command "+strings.Split(text, "::")[0]+" to", len(nodesList), "nodes")

	for _, validator := range known {
		data, _ := validator.(map[string]interface{})
		conn, err := net.Dial("tcp", data["IP"].(string)+":"+data["PORT"].(string))
		if err != nil {
			log.Fatal("Couldnt propagate command to validator: "+data["PUBKEY"].(string)+",", err)
		}
		log.Println("Sending to " + data["IP"].(string) + ":" + data["PORT"].(string))
		fmt.Fprintf(conn, text+"\n")
		raw, _ := bufio.NewReader(conn).ReadString('\n')
		message := strings.Split(raw, "\n")[0]
		if message != "OK" {
			log.Println(data["IP"].(string) + ":" + data["PORT"].(string) + " responded with string NEQ \"OK\"")
			log.Println(message)
		}
	}
}

func signMessage(message string, privateKey *rsa.PrivateKey) string {
	hash := sha256.New()
	hash.Write([]byte(message))
	raw := hash.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, raw, nil)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(signature)
}

func shutDownProxy() {
	log.Println("Stopping proxy server")
	proxySrv.Shutdown(context.Background())
}

func main() {
	log.Println("Loading environment variables")
	killServer = false
	stype = os.Getenv("TYPE")
	port = os.Getenv("PORT")
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	pkFromFile, err := ioutil.ReadFile("private.pem")
	if err != nil {
		log.Println("No existing private key found, creating a new one")
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		privateKey = pk
		b := saveRSAKey(pk)
		err = ioutil.WriteFile("private.pem", b, 0644)
		if err != nil {
			panic(err)
		}
	} else {
		block, _ := pem.Decode(pkFromFile)
		if block == nil {
			panic("failed to parse PEM block containing the key")
		}
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
	}
	publicKey = getPublicAddressFromPrivate(privateKey)

	requestHandleFunc := func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if req.Method == "POST" {
			bs, _ := ioutil.ReadAll(req.Body)
			req.Body.Close()
			if req.Host == "cruxnet.main.pnet.tunnel" {
				if json.Valid(bs) {
					var oldBodyData map[string]interface{}
					json.Unmarshal(bs, &oldBodyData)
					if isRequestBodyCruxNetForwardRequest(oldBodyData) {
						ciphertext, _ := b64.StdEncoding.DecodeString(oldBodyData["_crux_request_encrypted"].(string))
						d := strings.Split(string(DecryptWithPrivateKey(ciphertext, privateKey)), "||")
						log.Println("DECRYPT DATA", d[0])
						log.Println("DECRYPT META", d[1])
					}
				} else {
					responseObj := map[string]interface{}{
						"error":   true,
						"message": "Invalid request body",
					}
					json, _ := json.Marshal(responseObj)
					newReq := goproxy.NewResponse(req,
						goproxy.ContentTypeText,
						400,
						string(json),
					)
					newReq.Header.Set("Content-Type", "application/json")
					newReq.Header.Set("Access-Control-Allow-Origin", "*")
					return req, newReq
				}
			}
		} else if req.Method == "GET" {
			pubkey := privateKey.PublicKey
			pubKeyMarshal, _ := ExportRsaPublicKeyAsPemStr(&pubkey)
			//pubKeyMarshal := x509.MarshalPKCS1PublicKey(&pubkey)
			hasher := sha256.New()
			hasher.Write([]byte(pubKeyMarshal))
			pubKeyHash := hasher.Sum(nil)
			PKMarshalSignature, _ := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, pubKeyHash, nil)
			responseObj := map[string]interface{}{
				"publicKey":          pubKeyMarshal,
				"publicKeySignature": PKMarshalSignature,
				"publicViewKey":      publicKey,
			}
			json, _ := json.Marshal(responseObj)
			newReq := goproxy.NewResponse(req,
				goproxy.ContentTypeText,
				200,
				string(json),
			)
			newReq.Header.Set("Content-Type", "application/json")
			newReq.Header.Set("Access-Control-Allow-Origin", "*")
			if req.Host == "cruxnet.main.pnet.node-data" {
				return req, newReq
			}
		}
		//bs, _ := ioutil.ReadAll(req.Body)
		//req.Body.Close()
		// if json.Valid(bs) {
		// 	var oldBodyData map[string]interface{}
		// 	json.Unmarshal(bs, &oldBodyData)
		// 	k := make([]string, len(oldBodyData))
		// 	i := 0
		// 	for s := range oldBodyData {
		// 		k[i] = s
		// 		i++
		// 	}
		// 	log.Println(req.Host)
		// 	if req.Host == "cruxnet.main.pnet.tunnel" {
		// 		if contains(k, "_crux_request_encrypted") {
		// 			d := DecryptWithPrivateKey([]byte(oldBodyData["_crux_request_encrypted"].(string)), privateKey)
		// 			log.Println("DECRYPT", d)
		// 		}
		// 	} else if req.Host == "cruxnet.main.pnet.node-data" {
		// 		log.Println(req)
		// 	}
		// }
		//bs = createBody(bs, privateKey)
		//req.Body = ioutil.NopCloser(bytes.NewReader(bs))
		//ctx.Req.Header.Set("Content-Length", strconv.Itoa(len(bs)))
		//req.ContentLength = int64(len(bs))
		return req, nil
	}
	proxy.OnRequest().DoFunc(requestHandleFunc)
	if port == "" || port == "0" {
		port = "8080"
	}
	log.Println("Starting proxy server on port " + port)
	go (func() {
		for {
			if !killServer {
				time.Sleep(time.Second)
			} else {
				shutDownProxy()
				break
			}
		}
	})()
	time.Sleep(time.Second)
	go startTCPServer()
	go registerWithPeers()
	proxySrv = &http.Server{Addr: ":" + port, Handler: proxy}
	proxySrv.ListenAndServe()
}

func shutDownTCP() {
	if tcpSrv != nil {
		log.Println("Stopping TCP server")
		tcpSrv.Close()
	}
}

func startTCPServer() {
	// start TCP and serve TCP server
	p2pPort, _ := strconv.Atoi(port)
	p2pPort += 1
	p2pPortStr := strconv.Itoa(p2pPort)
	tcpSrv, err := net.Listen("tcp", ":"+p2pPortStr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TCP Server Listening on port", p2pPortStr)
	defer (func() {
		shutDownTCP()
	})()

	for {
		if tcpSrv != nil {
			conn, err := tcpSrv.Accept()
			if err != nil {
				log.Fatal(err)
			}
			log.Println(conn)
			//go handleConn(conn)
		} else {
			break
		}
	}
}

func registerWithPeers() {
	log.Println("Registering with peer nodes")
	originAddr := "localhost:8081"

	c, err := getConn(originAddr)

	if err != nil {
		log.Fatal("INITIAL NODE OFFLINE:", err)
	} else {
		fmt.Fprintf(c, "REGISTER_NODE::0.0.0.0::"+port+"::"+publicKey+"::"+signMessage(publicKey, privateKey)+"\n")

		raw, _ := bufio.NewReader(c).ReadString('\n')
		message := strings.Split(raw, "\n")[0]
		if message == "NODE_REGISTERED" {
			fmt.Fprintf(c, "GET_PUBKEY\n")
			raw, _ := bufio.NewReader(c).ReadString('\n')
			message := strings.Split(raw, "\n")[0]
			nodesList[message] = map[string]interface{}{
				"IP":     strings.Split(originAddr, ":")[0],
				"PORT":   strings.Split(originAddr, ":")[1],
				"PUBKEY": message,
			}
			log.Println("Validator registered with initial node")
			log.Println("Network propagation is in progress this may take up to an hour")
		} else {
			if stype != "origin" {
				log.Println("Error registering node")
				shutDownTCP()
				killServer = true
				return
			} else {
				log.Println("Error registering node ignored: this is an origin node")
			}
		}
	}
}
