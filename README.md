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
ktool format -f=./testdata/no_format_pkcs8.txt -m=private -t=pkcs8
```

Format pkcs1 private key
```bash
ktool format -f=./testdata/no_format_pkcs1.txt -m=private -t=pkcs1
```

Format public key
```bash
ktool format -f=./testdata/no_format_public_key.txt -m=public -t=pkcs1
```

Convert public key to pkcs1
```bash
ktool convert -f=./testdata/pkcs8.pem -t=pkcs1
```

Convert public key to pkcs8
```bash
ktool convert -f=./testdata/pkcs1.pem -t=pkcs8
```

Show private key format:
```bash
ktool info -f=./testdata/pkcs1.pem
// Output: file ./testdata/pkcs1.pem format is: PKCS1
```
