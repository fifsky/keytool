package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

func ParseCertificate(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("certificate failed to load")
	}

	csr, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

// GetCertSerialNumber 从证书中获取证书序列号
// openssl x509 -in cert.pem -text -noout -serial
func GetCertSerialNumber(certificate *x509.Certificate) string {
	return fmt.Sprintf("%X", certificate.SerialNumber.Bytes())
}

// PKCS82PKCS1 converts a PKCS8 key to PKCS1
func PKCS82PKCS1(pkcs8Key []byte) ([]byte, error) {
	block, _ := pem.Decode(pkcs8Key)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing PKCS8 key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("found non-RSA key in PKCS8 encoding")
	}

	pkcs1Key := x509.MarshalPKCS1PrivateKey(rsaKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkcs1Key,
	}), nil
}

// PKCS12PKCS8 converts a PKCS1 key to PKCS8
func PKCS12PKCS8(pkcs1Key []byte) ([]byte, error) {
	block, _ := pem.Decode(pkcs1Key)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing PKCS1 key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Key,
	}), nil
}

type keyFormat string

const (
	PKCS1 keyFormat = "PKCS1"
	PKCS8 keyFormat = "PKCS8"
)

// split the string by the specified size.
func stringSplit(s string, n int) string {
	substr, str := "", ""
	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		substr = substr + string(r)
		if (i+1)%n == 0 {
			str = str + substr + "\n"
			substr = ""
		} else if (i + 1) == l {
			str = str + substr + "\n"
		}
	}
	return str
}

func getPrivateKeyFormat(key []byte) keyFormat {
	if isPKCS1(key) {
		return PKCS1
	}
	if isPKCS8(key) {
		return PKCS8
	}
	return "unknown"
}

func isPublicKey(key []byte) bool {
	block, _ := pem.Decode(key)
	if block == nil {
		return false
	}

	_, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return false
	}
	return true
}

func isPKCS1(pkcs1Key []byte) bool {
	block, _ := pem.Decode(pkcs1Key)
	if block == nil {
		return false
	}

	_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return false
	}
	return true
}

func isPKCS8(pkcs8Key []byte) bool {
	block, _ := pem.Decode(pkcs8Key)
	if block == nil {
		return false
	}

	_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return false
	}
	return true
}

// FormatPublicKey formats public key, adds header, tail and newline character.
func FormatPublicKey(pkcs keyFormat, publicKey []byte) []byte {
	if bytes.HasPrefix(publicKey, []byte("-----BEGIN")) {
		return publicKey
	}

	keyHeader, keyTail := "", ""
	if pkcs == PKCS1 {
		keyHeader = "-----BEGIN RSA PUBLIC KEY-----\n"
		keyTail = "-----END RSA PUBLIC KEY-----\n"
	}
	if pkcs == PKCS8 {
		keyHeader = "-----BEGIN PUBLIC KEY-----\n"
		keyTail = "-----END PUBLIC KEY-----\n"
	}
	keyBody := stringSplit(strings.Replace(string(publicKey), "\n", "", -1), 64)
	return []byte(keyHeader + keyBody + keyTail)
}

// FormatPrivateKey formats private key, adds header, tail and newline character
func FormatPrivateKey(pkcs keyFormat, privateKey []byte) []byte {
	if bytes.HasPrefix(privateKey, []byte("-----BEGIN")) {
		return privateKey
	}

	keyHeader, keyTail := "", ""
	if pkcs == PKCS1 {
		keyHeader = "-----BEGIN RSA PRIVATE KEY-----\n"
		keyTail = "-----END RSA PRIVATE KEY-----\n"
	}
	if pkcs == PKCS8 {
		keyHeader = "-----BEGIN PRIVATE KEY-----\n"
		keyTail = "-----END PRIVATE KEY-----\n"
	}
	keyBody := stringSplit(strings.Replace(string(privateKey), "\n", "", -1), 64)
	return []byte(keyHeader + keyBody + keyTail)
}
