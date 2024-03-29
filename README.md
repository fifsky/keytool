# RSA Key Tools

[![Go](https://github.com/fifsky/ktool/actions/workflows/go.yml/badge.svg)](https://github.com/fifsky/ktool/actions/workflows/go.yml)

## Tools
 - format rsa key
 - pkcs1 to pkcs8
 - pkcs8 to pkcs1
 - get cert serial number

## Usage

```text
go install github.com/fifsky/ktool
```

Get certificate serial number
```bash
ktool serial -f=./testdata/cert.pem
```

Format pkcs8 private key
```bash
ktool format -f=./testdata/no_format_pkcs8.txt
```

Format pkcs1 private key
```bash
ktool format -f=./testdata/no_format_pkcs1.txt
```

Format public key
```bash
ktool format -f=./testdata/no_format_public_key.txt -m=public -t=pkcs1
```

Convert private key to pkcs1, suppert pem and der
```bash
ktool convert -f=./testdata/pkcs8.pem -t=pkcs1
```

Convert private key to pkcs8, suppert pem and der
```bash
ktool convert -f=./testdata/pkcs1.pem -t=pkcs8
```

Show private key format:
```bash
ktool info -f=./testdata/pkcs1.pem
// Output: file ./testdata/pkcs1.pem format is: PKCS1
```


## PS

public key pkcs8 to pkcs1
```bash
openssl rsa -pubin -in public_key_pkcs1.pem -RSAPublicKey_out
```

private pem to der
```bash
openssl rsa -outform der -in pkcs8.pem | base64
```

public pem to der
```bash
openssl rsa -pubin -outform DER -in public_key.pem | base64
```

rsa der public key to pem
```bash
cat public_key | base64 --decode | openssl rsa -pubin -inform DER -outform PEM -out public_key.pem
```

rsa der private key to pem
```bash
cat pkcs8_private_key | base64 --decode | openssl rsa -inform DER -outform PEM -out pkcs8.pem
```
