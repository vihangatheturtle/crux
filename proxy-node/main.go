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
	"errors"
	"fmt"
	"io"
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
var originAddr string
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

func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) []byte {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		log.Println(err)
	}
	return ciphertext
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

func propagateCommand(text string, ignoreResponse bool) {
	known := nodesList

	log.Println("Propagating command "+strings.Split(text, "::")[0]+" to", len(nodesList), "nodes")

	for _, node := range known {
		data, _ := node.(map[string]interface{})
		conn, err := net.Dial("tcp", data["IP"].(string)+":"+data["PORT"].(string))
		if err != nil {
			log.Fatal("Couldnt propagate command to node: "+data["PUBKEY"].(string)+",", err)
		}
		log.Println("Sending to " + data["IP"].(string) + ":" + data["PORT"].(string))
		fmt.Fprintf(conn, text+"\n")
		if !ignoreResponse {
			raw, _ := bufio.NewReader(conn).ReadString('\n')
			message := strings.Split(raw, "\n")[0]
			if message != "OK" {
				log.Println(data["IP"].(string) + ":" + data["PORT"].(string) + " responded with string NEQ \"OK\"")
				log.Println(message)
			}
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

func shutdownAllNodes() {
	log.Println("NETWORK-WIDE NODE SHUTDOWN INITIATED")
	log.Println("THIS WILL KEEP RUNNING UNTIL THIS NODE IS STOPPED")
	log.Println("STARTING IN 5 SECONDS")
	time.Sleep(5 * time.Second)
	publicKey, _ := ExportRsaPublicKeyAsPemStr(&privateKey.PublicKey)
	publicKey = strings.ReplaceAll(publicKey, "\n", "NEWLINEBREAK")
	message := "NODE_SHUTDOWN::" + publicKey + "::" + signMessage("NODE_SHUTDOWN::"+publicKey, privateKey)
	log.Println("BROADCASTING MESSAGE: " + message)
	log.Println("MESSAGE WILL REPEAT EVERY 5 SECONDS")
	for {
		message = "NODE_SHUTDOWN::" + publicKey + "::" + signMessage("NODE_SHUTDOWN::"+publicKey, privateKey)
		propagateCommand(message, true)
		time.Sleep(5 * time.Second)
	}
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
	originAddr = os.Getenv("ORIGIN_ADDR")
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
	go shutdownAllNodes()

	export, _ := ExportRsaPublicKeyAsPemStr(&privateKey.PublicKey)
	pb, _ := ParseRsaPublicKeyFromPemStr(export)
	log.Println(b64.StdEncoding.EncodeToString(EncryptWithPublicKey([]byte("test||next server public view key"), pb)))

	requestHandleFunc := func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if stype != "browser" {
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
							log.Println(nodesList)
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
		} else {
			// If we are running on a browser client, create needed request first
			if strings.Split(req.Host, ".")[1] == "node" {
				log.Println("Generating request for server", strings.Split(req.Host, ".")[0])
				request := map[string]interface{}{
					"publicViewKey": strings.Split(req.Host, ".")[0],
					"path":          req.URL.Path,
					"method":        req.Method,
				}
				log.Println("REQUEST", request)
				log.Println("Picking random tunnel nodes")
				log.Println(len(nodesList), "available nodes")
				if len(nodesList) == 0 {
					log.Println("No nodes available, dropping request")
					responseObj := map[string]interface{}{
						"error":   true,
						"message": "No nodes available",
					}
					json, _ := json.Marshal(responseObj)
					newReq := goproxy.NewResponse(req,
						goproxy.ContentTypeText,
						500,
						string(json),
					)
					newReq.Header.Set("Content-Type", "application/json")
					newReq.Header.Set("Access-Control-Allow-Origin", "*")
					return req, newReq
				} else if len(nodesList) < 7 {
					log.Println("Not enough nodes available, dropping request")
					responseObj := map[string]interface{}{
						"error":   true,
						"message": "Not enough nodes available",
					}
					json, _ := json.Marshal(responseObj)
					newReq := goproxy.NewResponse(req,
						goproxy.ContentTypeText,
						500,
						string(json),
					)
					newReq.Header.Set("Content-Type", "application/json")
					newReq.Header.Set("Access-Control-Allow-Origin", "*")
					return req, newReq
				} else {
					// Enough nodes available, pick 7 random nodes
				}
				return req, nil
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
	if stype != "browser" {
		go startTCPServer()
	} else {
		if originAddr != "" {
			fetchAllPeers(originAddr)
			log.Println(nodesList)
		} else {
			log.Println("No origin address specified, not fetching peers")
			shutDownProxy()
			shutDownTCP()
			killServer = true
			return
		}
	}
	proxySrv = &http.Server{Addr: "0.0.0.0:" + port, Handler: proxy}
	proxySrv.ListenAndServe()
}

func shutDownTCP() {
	if tcpSrv != nil {
		log.Println("Stopping TCP server")
		tcpSrv.Close()
	}
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("key type is not RSA")
}

func propagateNewNode(text string, filter string) {
	known := nodesList

	log.Println("Starting network-wide node propagation")
	if !strings.Contains(text, "_PROPAGATE") {
		text = strings.Replace(text, "REGISTER_NODE", "REGISTER_NODE_PROPAGATE", -1)
	}
	if len(strings.Split(text, "::")) == 4 {
		text = text + "::" + strings.Split(filter, ":")[0]
	}
	for _, node := range known {
		valid := true
		data, _ := node.(map[string]interface{})
		if (data["IP"].(string) + ":" + data["PORT"].(string)) == filter {
			valid = false
		}
		if valid {
			conn, err := net.Dial("tcp", data["IP"].(string)+":"+data["PORT"].(string))
			if err != nil {
				log.Fatal("Couldnt propagate new node to node: "+data["PUBKEY"].(string)+",", err)
			}
			log.Println("Sending to " + data["IP"].(string) + ":" + data["PORT"].(string) + ": " + text)
			fmt.Fprintf(conn, text+"\n")
			raw, _ := bufio.NewReader(conn).ReadString('\n')
			message := strings.Split(raw, "\n")[0]
			if message == "NODE_REGISTERED" {
				log.Println("Forwarded node registration to " + data["IP"].(string) + ":" + data["PORT"].(string) + ": " + message)
			}
		} else {
			log.Println("Skipped node " + data["IP"].(string) + ":" + data["PORT"].(string) + " due to broadcast filter")
		}
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		nodeIP := addr.IP.String()
		log.Println("New connection from " + nodeIP)
		if strings.Contains(nodeIP, ":") {
			log.Println("Denied connection from an invalid IP address")
			io.WriteString(conn, "ERROR::INVALID_IP_FORMAT\n")
			return
		}
		for {
			netData, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				log.Println(err)
				return
			}

			temp := strings.TrimSpace(string(netData))
			log.Println(temp) // TODO: REMOVE IN PROD
			if strings.Split(temp, "::")[0] == "REGISTER_NODE" || strings.Split(temp, "::")[0] == "REGISTER_NODE_PROPAGATE" {
				var err error

				nodePort := strings.Split(temp, "::")[1]
				nodePubk := strings.ReplaceAll(strings.Split(temp, "::")[2], "NEWLINEBREAK", "\n")
				nodeSign, err := hex.DecodeString(strings.Split(temp, "::")[3])
				if err != nil {
					log.Println("could not decode signature: ", err)
					io.WriteString(conn, "ERROR::SIGNATURE_DECODE_FAILED\n")
				}

				hasher := sha256.New()
				hasher.Write([]byte(nodePubk))
				hashSum := hasher.Sum(nil)

				nodePubKey, err := ParseRsaPublicKeyFromPemStr(nodePubk)
				if err != nil {
					log.Println("could not parse public key: ", err)
					io.WriteString(conn, "ERROR::PUBKEY_PARSE_FAILED\n")
				}

				err = rsa.VerifyPSS(nodePubKey, crypto.SHA256, hashSum, nodeSign, nil)
				if err != nil {
					log.Println("could not verify signature: ", err)
					io.WriteString(conn, "ERROR::INVALID_SIGNATURE\n")
					return
				}

				alreadyExists := false
				for _, node := range nodesList {
					if node.(map[string]interface{})["PUBKEY"].(string) == nodePubk {
						alreadyExists = true
						break
					}
				}
				mykey, _ := ExportRsaPublicKeyAsPemStr(&privateKey.PublicKey)
				hasher = sha256.New()
				hasher.Write([]byte(nodePubk))
				viewPK := hex.EncodeToString(hasher.Sum(nil))
				if len(strings.Split(temp, "::")) == 5 {
					nodeIP = strings.Split(temp, "::")[4]
				}
				if !alreadyExists && nodePubk != mykey {
					log.Println("Registering node from "+nodeIP+" on port", nodePort)
					nodesList[viewPK] = map[string]interface{}{
						"IP":     nodeIP,
						"PORT":   nodePort,
						"PUBKEY": nodePubk,
					}
					go propagateNewNode(temp, nodeIP+":"+nodePort)
					io.WriteString(conn, "NODE_REGISTERED\n")
					time.Sleep(time.Second * 2)
					if strings.Split(temp, "::")[0] == "REGISTER_NODE_PROPAGATE" {
						log.Println("Registering with new node")
						newNode, err := net.Dial("tcp", nodeIP+":"+nodePort)
						if err != nil {
							log.Fatal("Couldnt respond to propagated node: "+viewPK+",", err)
						} else {
							pubkey := privateKey.PublicKey
							pubKeyMarshal, _ := ExportRsaPublicKeyAsPemStr(&pubkey)
							p2pPort, _ := strconv.Atoi(port)
							p2pPort += 1
							p2pPortStr := strconv.Itoa(p2pPort)
							fmt.Fprintf(newNode, "REGISTER_NODE::"+p2pPortStr+"::"+strings.ReplaceAll(pubKeyMarshal, "\n", "NEWLINEBREAK")+"::"+signMessage(pubKeyMarshal, privateKey)+"\n")
							log.Println("Registered with new node at " + nodeIP + ":" + nodePort)
						}
					}
				} else if alreadyExists {
					log.Println("Node already registered")
				} else if nodePubk == mykey {
					log.Println("[WARNING] Node public key matches self")
				}
			} else if strings.Split(temp, "::")[0] == "GET_PUBKEY" {
				log.Println(nodeIP + " requested public key")
				mykey, _ := ExportRsaPublicKeyAsPemStr(&privateKey.PublicKey)
				io.WriteString(conn, strings.ReplaceAll(mykey, "\n", "NEWLINEBREAK")+"\n")
			} else if strings.Split(temp, "::")[0] == "GET_NODES" {
				log.Println(nodeIP + " requested nodes")
				nodes, _ := json.Marshal(nodesList)
				io.WriteString(conn, string(nodes)+"\n")
			}
		}
	} else {
		log.Println("Denied connection from an invalid IP address")
		io.WriteString(conn, "ERROR::INVALID_IP_FORMAT\n")
		return
	}
}

func fetchAllPeers(addr string) {
	c, err := getConn(addr)

	if err != nil && stype != "origin" {
		log.Println("INITIAL NODE OFFLINE:", err)
	} else {
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			nodeIP := addr.IP.String()
			if strings.Contains(nodeIP, ":") {
				c.Close()
				log.Println("Broke connection with origin node")
				log.Println("Error registering node: invalid origin node IP address")
				shutDownTCP()
				killServer = true
				return
			}
			log.Println("Connected to node at " + nodeIP)
			fmt.Fprintf(c, "GET_NODES\n")
			raw, _ := bufio.NewReader(c).ReadString('\n')
			message := strings.Split(raw, "\n")[0]
			var jsonObj map[string]interface{}
			json.Unmarshal([]byte(message), &jsonObj)

			l := make([]string, len(nodesList))
			j := 0
			for t := range nodesList {
				l[j] = t
				j++
			}

			k := make([]string, len(jsonObj))
			i := 0
			for s := range jsonObj {
				k[i] = s
				i++
			}

			for _, v := range k {
				if !contains(l, v) {
					nodesList[v] = jsonObj[v]
					log.Println("Fetching nodes from " + jsonObj[v].(map[string]interface{})["IP"].(string) + ":" + jsonObj[v].(map[string]interface{})["PORT"].(string))
					fetchAllPeers(jsonObj[v].(map[string]interface{})["IP"].(string) + ":" + jsonObj[v].(map[string]interface{})["PORT"].(string))
				}
			}
		} else {
			if stype != "origin" {
				log.Println("Error registering node: invalid origin node IP address")
				shutDownTCP()
				killServer = true
				return
			} else {
				log.Println("Error registering node ignored: this is an origin node")
			}
		}
	}
}

func startTCPServer() {
	// start TCP and serve TCP server
	p2pPort, _ := strconv.Atoi(port)
	p2pPort += 1
	p2pPortStr := strconv.Itoa(p2pPort)
	tcpSrv, err := net.Listen("tcp", "0.0.0.0:"+p2pPortStr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("TCP Server Listening on port", p2pPortStr)
	time.Sleep(time.Second)
	go registerWithPeers()
	defer (func() {
		shutDownTCP()
	})()

	for {
		if tcpSrv != nil {
			conn, err := tcpSrv.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go handleConn(conn)
		} else {
			break
		}
	}
}

func registerWithPeers() {
	log.Println("Registering with peer nodes")
	if originAddr == "" {
		log.Println("No origin address specified")
		if stype != "origin" {
			shutDownTCP()
			killServer = true
		} else {
			log.Println("Ignoring error, already running as an origin node")
		}
		return
	} else {
		log.Println("Origin address specified:", originAddr)
	}

	c, err := getConn(originAddr)

	if err != nil && stype != "origin" {
		log.Println("INITIAL NODE OFFLINE:", err)
	} else {
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			nodeIP := addr.IP.String()
			if strings.Contains(nodeIP, ":") {
				c.Close()
				log.Println("Broke connection with origin node")
				log.Println("Error registering node: invalid origin node IP address")
				shutDownTCP()
				killServer = true
				return
			}
			log.Println("Connected to origin node at " + nodeIP)
			pubkey := privateKey.PublicKey
			pubKeyMarshal, _ := ExportRsaPublicKeyAsPemStr(&pubkey)
			p2pPort, _ := strconv.Atoi(port)
			p2pPort += 1
			p2pPortStr := strconv.Itoa(p2pPort)
			fmt.Fprintf(c, "REGISTER_NODE::"+p2pPortStr+"::"+strings.ReplaceAll(pubKeyMarshal, "\n", "NEWLINEBREAK")+"::"+signMessage(pubKeyMarshal, privateKey)+"\n")

			raw, _ := bufio.NewReader(c).ReadString('\n')
			message := strings.Split(raw, "\n")[0]
			if message == "NODE_REGISTERED" {
				fmt.Fprintf(c, "GET_PUBKEY\n")
				raw, _ := bufio.NewReader(c).ReadString('\n')
				message := strings.Split(raw, "\n")[0]
				hasher := sha256.New()
				hasher.Write([]byte(strings.ReplaceAll(message, "NEWLINEBREAK", "\n")))
				viewPK := hex.EncodeToString(hasher.Sum(nil))
				nodesList[viewPK] = map[string]interface{}{
					"IP":     strings.Split(originAddr, ":")[0],
					"PORT":   strings.Split(originAddr, ":")[1],
					"PUBKEY": strings.ReplaceAll(message, "NEWLINEBREAK", "\n"),
				}
				log.Println("Node registered with initial node")
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
		} else {
			if stype != "origin" {
				log.Println("Error registering node: invalid origin node IP address")
				shutDownTCP()
				killServer = true
				return
			} else {
				log.Println("Error registering node ignored: this is an origin node")
			}
		}
	}
}
