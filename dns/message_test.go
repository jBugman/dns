package dns

import (
	"testing"
)

func TestSuccessfulParse(t *testing.T) {
	packet := []byte{48, 57, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1}

	msg, err := Parse(packet)
	if err != nil {
		t.Fatal("should not fail:", err)
	}

	if msg.header.id != 12345 {
		t.Fatal("message id should be 12345: ", msg.header.id)
	}
	if !msg.header.qr {
		t.Fatal("message should have QR=true: ", msg.header.qr)
	}
	if msg.header.qdcount != 1 {
		t.Fatal("message should declare exactly one question:", msg.header.qdcount)
	}

	qs := msg.Questions()
	if len(qs) != 1 {
		t.Fatal("message should contain exactly one question: ", len(qs))
	}
	if qs[0].name.String() != "example.com" {
		t.Fatal("question should has name example.com: ", qs[0].name.String())
	}
}
