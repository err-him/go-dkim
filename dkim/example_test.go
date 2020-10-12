package dkim_test

import (
	"crypto"
	"log"
	"strings"

	"github.com/err-him/go-dkim/dkim"
)

var (
	mailString string
	privateKey crypto.Signer
)

func ExampleSign() {
	r := strings.NewReader(mailString)

	options := &dkim.SignOptions{
		Domain:   "example.org",
		Selector: "brisbane",
		Signer:   privateKey,
	}
	if _, err := dkim.Sign(r, options); err != nil {
		log.Fatal(err)
	}
}

func ExampleVerify() {
	r := strings.NewReader(mailString)

	verifications, err := dkim.Verify(r)
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range verifications {
		if v.Err == nil {
			log.Println("Valid signature for:", v.Domain)
		} else {
			log.Println("Invalid signature for:", v.Domain, v.Err)
		}
	}
}
