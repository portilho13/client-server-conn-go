package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
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
        key []byte
        iv []byte
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

func GenerateKeyAndIv() ([]byte, []byte) {
        key := make([]byte, 32) // 32 Bits for AES-256
        iv := make([]byte, 16) // 16 bits for AES

        _, err := rand.Read(key)
        if err != nil {
                log.Fatal("Error creating AES Key")
                return nil, nil
        }
        _, err = rand.Read(iv)
        if err != nil {
                log.Fatal("Error creating AES Key")
                return nil, nil
        }

        return key, iv
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
                publicKeyPEM := make([]byte, publicKeySize)
                _, err = io.ReadFull(c, publicKeyPEM)
                if err != nil {
                        fmt.Println("Error reading public key:", err)
                        c.Close()
                        continue
                }
                fmt.Println("Received public key:", string(publicKeyPEM))
                
                block, _ := pem.Decode(publicKeyPEM)

                publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
                if err != nil {
                        log.Fatal(err)
                }

                rsaPublicKey, ok := publicKey.(*rsa.PublicKey)

                if !ok {
                        log.Fatal("Not an RSA Key")
                }
                key, iv := GenerateKeyAndIv()

                encryptedAESKey, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, key)
                if err != nil {
                        log.Fatal(err)
                }

                encryptedAESIv, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, iv)
                if err != nil {
                        log.Fatal(err)
                }
                fmt.Println("------")
                fmt.Println(encryptedAESKey)
                fmt.Println("------")
                fmt.Println(encryptedAESIv)

                encryptedAESKeySize := make([]byte, 4)
                encryptedAESIvSize := make([]byte, 4)

                binary.BigEndian.PutUint32(encryptedAESKeySize, uint32(len(encryptedAESKey)))
                binary.BigEndian.PutUint32(encryptedAESIvSize, uint32(len(encryptedAESIv)))

                _, err = c.Write(encryptedAESKeySize)
                if err != nil {
                        log.Fatal(err)
                }

                _, err = c.Write(encryptedAESKey)
                if err != nil {
                        log.Fatal(err)
                }

                _, err = c.Write(encryptedAESIvSize)
                if err != nil {
                        log.Fatal(err)
                }

                _, err = c.Write(encryptedAESIv)
                if err != nil {
                        log.Fatal(err)
                }
                




                go handleConnection(c)
                count++
        }
}
      

