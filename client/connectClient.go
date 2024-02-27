package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
)

var (
	key = []byte("my32digitkey12345678901234567890") // 32 bytes for AES-256
	iv  = []byte("my16digitIvKey12")                  // 16 bytes for AES
)

// GetAESEncrypted encrypts given text in AES 256 CBC
func GetAESEncrypted(plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	
	//Convert plain text to bytes

	plaintextBytes := []byte(plaintext)
	plaintextBytes = PKCS5Padding(plaintextBytes, aes.BlockSize)

	//Encrypt using AES and encode using base64

	ciphertext := make([]byte, len(plaintextBytes))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintextBytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// PKCS5Padding pads a certain blob of data with necessary data to be used in AES block cipher
func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src) % blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port.")
		return
	}

	CONNECT := arguments[1]
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer c.Close()

	for {

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter text: ")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)

		if text == "STOP" {
			fmt.Println("TCP client exiting...")
			return
		}

		encrypted, err := GetAESEncrypted(text)
		if err != nil {
			fmt.Println("Error during encryption:", err)
			continue
		}

		fmt.Fprintf(c, encrypted+"\n")

		message, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println("Error reading from server:", err)
			return
		}
		fmt.Print("Received from server: " + message)
	}
}
