package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/fxtlabs/primes"
)

func test() {

	fmt.Println("\n\nPrime Number")

	// gen prime
	primeNumber := generatePrime()

	fmt.Println(primeNumber)
	fmt.Println(len(primeNumber.String()))
	fmt.Println(primeNumber.BitLen())

	fmt.Println("BigInt as int64:", primeNumber.Int64())

	if primes.IsPrime(int(primeNumber.Int64())) {
		fmt.Printf("%d is prime\n", primeNumber)
	} else {
		fmt.Printf("%d is composite\n", primeNumber)
	}

	// =================================================

	fmt.Println("\n\nECDH")

	serverPrivKey, serverPubKey := generateKeyPair()

	fmt.Println(serverPubKey.Bytes())
	serverHexString := hex.EncodeToString(serverPubKey.Bytes())
	fmt.Printf("serverHexString (share to client) %v \n", serverHexString)

	// Fix client public key (for test)
	publicKeyClientHexString := "04236c081a68c0f77f2dcca648a41d344c19248553e21b82af007e3178459567731036b1469e367a43627e64b1f427f0b3496eb8c77deedee6bea1c1868c8b0692"

	byteArray, err := hex.DecodeString(publicKeyClientHexString)
	if err != nil {
		log.Fatalf("Error decoding hex string: %v", err)
	}

	fmt.Printf("Client Hex String: %s\n", publicKeyClientHexString)
	fmt.Printf("Decoded Byte Array: %v\n", byteArray)
	fmt.Printf("Decoded String: %s\n", string(byteArray))
	fmt.Printf("Decoded Byte Array [length]: %v\n", len(byteArray))

	curve := ecdh.P256()
	clientPubKey, err := curve.NewPublicKey(byteArray)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Compute shared key
	serverSecretKey := deriveSharedSecret(serverPrivKey, clientPubKey)

	fmt.Println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	fmt.Printf("serverSecretKey %v \n", serverSecretKey)
	// fmt.Printf("%x\n", serverSecretKey)

	// clientSecretKey := deriveSharedSecret(clientPrivKey, serverPubKey)
	// serverSecretKey := deriveSharedSecret(serverPrivKey, clientPubKey)

	// if !bytes.Equal(clientSecretKey, serverSecretKey) {
	// 	log.Fatalf("The secrets do not match")
	// } else {
	// 	log.Printf("The secrets match")
	// }

	// println(len(clientSecretKey))
	// println(len(serverSecretKey))

	// fmt.Println(clientSecretKey)
	// fmt.Println(serverSecretKey)

	// fmt.Printf("%x\n", clientSecretKey)
	// fmt.Printf("%x\n", serverSecretKey)

	// // =================================================

	// fmt.Println("\n\nAES")

	// plaintext := []byte("This is a secret message")

	// // AES
	// // encryptedData := aesEncrypt(plaintext, clientSecretKey)
	// // message := aesDecrypt(encryptedData, serverSecretKey)

	// // AES/GCM mode
	// base64CipherText := aesGcmModeEncrypt(plaintext, clientSecretKey)
	// message := aesGcmModeDecrypt(base64CipherText, serverSecretKey)

	// fmt.Println(message)
}
