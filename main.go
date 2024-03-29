package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
)

func main() {
	if len(os.Args) < 2 || !slices.Contains([]string{"format", "serial", "convert", "info"}, os.Args[1]) {
		fmt.Println("Usage: ktool <tool> [options]")
		fmt.Println("Tools: format, serial, convert")
		os.Exit(1)
	}

	var file string
	var to string

	fg := flag.NewFlagSet("ktool", flag.ExitOnError)
	fg.StringVar(&file, "f", "", "file path")

	tool := os.Args[1]
	switch tool {
	case "convert":
		fg.StringVar(&to, "t", "", "convert to pkcs1 or pkcs8, example: ktool convert -t=pkcs1 -f=private.pem")
	}

	err := fg.Parse(os.Args[2:])
	if err != nil {
		fmt.Printf("parse flag err: %s\n", err.Error())
		os.Exit(1)
	}

	switch tool {
	case "format":
		if file == "" {
			fmt.Println("Usage: ktool format -m=public -f=ccc.pem")
			os.Exit(1)
		}

		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("read file err: %s\n", err.Error())
			os.Exit(1)
		}

		if isPublicKey(content) {
			fmt.Println(string(FormatPublicKey(PKCS1, content)))
		} else {
			format := getPrivateKeyFormat(content)
			fmt.Println(string(FormatPrivateKey(format, content)))
		}

	case "serial":
		if file == "" {
			fmt.Println("Usage: ktool serial -f=cert.pem")
			os.Exit(1)
		}
		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("read file err: %s %s\n", err.Error(), file)
			os.Exit(1)
		}

		cert, err := ParseCertificate(content)
		if err != nil {
			fmt.Printf("parse certificate err: %s\n", err.Error())
			os.Exit(1)
		}

		fmt.Println(GetCertSerialNumber(cert))
	case "convert":
		if to == "" || file == "" {
			fmt.Println("Usage: ktool convert -t=pkcs1 -f=private.pem")
			os.Exit(1)
		}

		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("read file err: %s\n", err.Error())
			os.Exit(1)
		}

		to = strings.ToUpper(to)
		if to == "PKCS1" {
			ret, err := PKCS82PKCS1(content)
			if err != nil {
				fmt.Printf("convert err: %s\n", err.Error())
				os.Exit(1)
			}
			fmt.Println(string(ret))
		} else if to == "PKCS8" {
			ret, err := PKCS12PKCS8(content)
			if err != nil {
				fmt.Printf("convert err: %s\n", err.Error())
				os.Exit(1)
			}
			fmt.Println(string(ret))
		}
	case "info":
		if file == "" {
			fmt.Println("Usage: ktool info -f=private.pem")
			os.Exit(1)
		}

		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("read file err: %s\n", err.Error())
			os.Exit(1)
		}
		ret := getPrivateKeyFormat(content)
		fmt.Printf("file %s format is: %s\n", file, ret)
	}

}
