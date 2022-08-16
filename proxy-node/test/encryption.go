package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

type CruxNetworkPacket struct {
	Version        int
	Method         string
	Key            []byte
	Data           []byte
	Hash           []byte
	DHashSignature []byte
	KeySignature   []byte
	SenderPubkey   string
	Nonce          []byte
}

func DecryptGCMCipher(ciphertext []byte, key []byte, nonce []byte) []byte {
	// Create a new cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// Create a new GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return plaintext
}

func CreateCruxNetworkPacket(pub *rsa.PublicKey, priv *rsa.PrivateKey, inputData []byte, meth string) CruxNetworkPacket {
	// Generate random number for key generation
	nk := make([]byte, 1024)
	_, err := rand.Read(nk)
	if err != nil {
		panic(err)
	}
	key32 := sha256.Sum256(nk)
	key := key32[:]
	// Create a new cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// Create a new GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	// Create a new nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	// Create a new ciphertext
	ciphertext := gcm.Seal(nil, nonce, inputData, nil)
	// Encrypt the key with the public key
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, nil)
	if err != nil {
		panic(err)
	}
	// Hash data
	h := sha256.New()
	h.Write(inputData)
	dataHash := h.Sum(nil)
	// Sign the data
	DHashSignature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, dataHash)
	if err != nil {
		panic(err)
	}
	// Sign the key
	KeyHash32 := sha256.Sum256(encryptedKey)
	KeyHash := KeyHash32[:]
	KeySignature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, KeyHash)
	if err != nil {
		panic(err)
	}
	pempub, _ := ExportRsaPublicKeyAsPemStr(&priv.PublicKey)
	packet := CruxNetworkPacket{
		Version:        1,
		Method:         meth,
		Key:            encryptedKey,
		Data:           ciphertext,
		Hash:           dataHash,
		DHashSignature: DHashSignature,
		KeySignature:   KeySignature,
		SenderPubkey:   pempub,
		Nonce:          nonce,
	}
	return packet
}
