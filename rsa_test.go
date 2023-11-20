package main

import (
	"os"
	"testing"
)

func TestGetCertSerialNumber(t *testing.T) {
	cert, err := os.ReadFile("testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	x, err := ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	sn := GetCertSerialNumber(x)

	if sn != "10C764E9D560384212D9C08FD10E373FDD0FB396" {
		t.Fatal("sn error")
	}
}

func TestFormatPublicKey(t *testing.T) {
	publicKey, err := os.ReadFile("testdata/no_format_public_key.txt")
	if err != nil {
		t.Fatal(err)
	}

	publicKeyPem, err := os.ReadFile("testdata/public_key.pem")
	if err != nil {
		t.Fatal(err)
	}

	formatted := FormatPublicKey(PKCS8, publicKey)

	if string(formatted) != string(publicKeyPem) {
		t.Fatal("format error")
	}
}

func TestFormatPrivateKey(t *testing.T) {
	privateKey, err := os.ReadFile("testdata/no_format_pkcs8.txt")
	if err != nil {
		t.Fatal(err)
	}

	privateKeyPem, err := os.ReadFile("testdata/pkcs8.pem")
	if err != nil {
		t.Fatal(err)
	}

	formatted := FormatPrivateKey(PKCS8, privateKey)

	if string(formatted) != string(privateKeyPem) {
		t.Fatal("format error")
	}
}

func TestPKCS82PKCS1(t *testing.T) {
	pkcs8Key, err := os.ReadFile("testdata/pkcs8.pem")
	if err != nil {
		t.Fatal(err)
	}
	pkcs1Key, err := PKCS82PKCS1(pkcs8Key)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPem, err := os.ReadFile("testdata/pkcs1.pem")
	if err != nil {
		t.Fatal(err)
	}

	if string(pkcs1Key) != string(privateKeyPem) {
		t.Fatal("convert error")
	}
}

func TestPKCS12PKCS8(t *testing.T) {
	pkcs1Key, err := os.ReadFile("testdata/pkcs1.pem")
	if err != nil {
		t.Fatal(err)
	}
	pkcs8Key, err := PKCS12PKCS8(pkcs1Key)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPem, err := os.ReadFile("testdata/pkcs8.pem")
	if err != nil {
		t.Fatal(err)
	}

	if string(pkcs8Key) != string(privateKeyPem) {
		t.Fatal("convert error")
	}
}
