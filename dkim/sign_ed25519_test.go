package dkim

import (
	"math/rand"
	"strings"
	"testing"
)

const signedEd25519MailString = "DKIM-Signature: a=ed25519-sha256; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;" + "\r\n" +
	" " + "c=simple/simple; d=football.example.com;" + "\r\n" +
	" " + "h=From:To:Subject:Date:Message-ID; s=brisbane; t=424242; v=1;" + "\r\n" +
	" " + "b=k1LzRxs9/DfN/whlMICYKNIJhqUSmup0d5yw8tpi+Cfiqe6I3oSBmJ+HEp+moWy7/XvcUY/t" + "\r\n" +
	" " + "ERHc3D2m7vw1AA==" + "\r\n" +
	mailHeaderString +
	"\r\n" +
	mailBodyString

func init() {
	randReader = rand.New(rand.NewSource(42))
}

func TestSignEd25519(t *testing.T) {
	r := strings.NewReader(mailString)
	options := &SignOptions{
		Domain:   "football.example.com",
		Selector: "brisbane",
		Signer:   testEd25519PrivateKey,
	}

	if _, err := Sign(r, options); err != nil {
		t.Fatal("Expected no error while signing mail, got:", err)
	}
}

func TestSignAndVerifyEd25519(t *testing.T) {
	r := strings.NewReader(mailString)
	options := &SignOptions{
		Domain:   "football.example.com",
		Selector: "brisbane",
		Signer:   testEd25519PrivateKey,
	}
	if _, err := Sign(r, options); err != nil {
		t.Fatal("Expected no error while signing mail, got:", err)
	}
}
