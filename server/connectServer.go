package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)


var (
    count = 0
        key = []byte("my32digitkey12345678901234567890") // 32 bytes for AES-256
        iv  = []byte("my16digitIvKey12")                  // 16 bytes for AES
)

func handleConnection(c net.Conn) {
        fmt.Println("Connection Found")
        for {
                netData, err := bufio.NewReader(c).ReadString('\n')
                if err != nil {
                        fmt.Println(err)
                        return
                }

                temp := strings.TrimSpace(string(netData))
                if temp == "STOP" {
                        break
                }
                Decrypt(temp)

                // Return number of connected devices to client
                counter := strconv.Itoa(count) + "\n"

                c.Write([]byte(string(counter)))
        }
        c.Close()
}

func PKCS5UnPadding(src []byte) []byte {
        length := len(src)
        unpadding := int(src[length-1])

        return src[:(length - unpadding)]
}

func Decrypt(s string) {

        // Decode from base64
        cipherText, err := base64.StdEncoding.DecodeString(s)
        if err != nil {
                log.Fatal("Error decoding string")
        }
        
        //Create AES block to decrypt

        block, err := aes.NewCipher(key)
        if err != nil {
                log.Fatal("Error creating block cipher")
        }
        
        // Apply Block and remove padding

        mode := cipher.NewCBCDecrypter(block, iv)
        mode.CryptBlocks(cipherText, cipherText)
        cipherText = PKCS5UnPadding(cipherText)
        decodedMessage := string(cipherText[:])
        fmt.Printf("Encrypted Message: %v | Decrypted Message: %v\n", s, decodedMessage)
}

func main() {
        arguments := os.Args
        if len(arguments) == 1 {
                fmt.Println("Please provide a port number!")
                return
        }

        PORT := ":" + arguments[1]
        l, err := net.Listen("tcp4", PORT)
        if err != nil {
                fmt.Println(err)
                return
        }
        defer l.Close()

        for {
                // Accept all incoming connections
                c, err := l.Accept()
                if err != nil {
                        fmt.Println(err)
                        return
                }
                // Read the size of the public key
                publicKeySizeBuf := make([]byte, 4)
                _, err = io.ReadFull(c, publicKeySizeBuf)
                if err != nil {
                fmt.Println("Error reading public key size:", err)
                c.Close()
                continue
                }

                publicKeySize := binary.BigEndian.Uint32(publicKeySizeBuf)

                // Read the public key
                publicKey := make([]byte, publicKeySize)
                _, err = io.ReadFull(c, publicKey)
                if err != nil {
                fmt.Println("Error reading public key:", err)
                c.Close()
                continue
                }
                fmt.Println("Received public key:", string(publicKey))

                if err != nil {
                        fmt.Println(err)
                        return
                }
                go handleConnection(c)
                count++
        }
}
      

