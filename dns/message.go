// Package dns implements https://tools.ietf.org/html/rfc1035
package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Message is a single format for all communications inside of the domain protocol
type Message struct {
	header    header
	questions []question
}

type header struct {
	// id is a 16 bit identifier assigned by the program that
	// generates any kind of query. This identifier is copied
	// the corresponding reply and can be used by the requester
	// to match up replies to outstanding queries.
	id uint16
	// qr is a one bit field that specifies whether this message is a
	// query (0), or a response (1).
	qr bool
	// opcode is a four bit field that specifies kind of query in this
	// message. This value is set by the originator of a query
	// and copied into the response.
	opcode uint8

	aa bool
	tc bool

	// rd represents Recursion Desired - this bit may be set in a query and
	// is copied into the response. If RD is set, it directs
	// the name server to pursue the query recursively.
	// Recursive query support is optional.
	rd bool
	// ra represents Recursion Available - this be is set or cleared in a
	// response, and denotes whether recursive query support is
	// available in the name server.
	ra bool

	// qdcount is an unsigned 16 bit integer specifying the number of
	// entries in the question section.
	qdcount uint16
}

// question implements 4.1.2. Question section format
type question struct {
	name   qname
	qtype  uint16
	qclass uint16
}

type qname [][]byte

// Parse decodes Message from the binary representation
func Parse(packet []byte) (Message, error) {
	h := header{
		// bytes 0-1
		id: binary.BigEndian.Uint16(packet[0:2]),
		// byte 2
		qr:     (packet[2] & 0b10000000) > 0,
		opcode: (packet[2] & 0b01111000),
		// TC
		rd: (packet[2] & 0b00000001) > 0,
		// byte 3
		ra: (packet[3] & 0b10000000) > 0,
		// Z
		// RCODE
		// bytes 4-5
		qdcount: binary.BigEndian.Uint16(packet[4:6]),
		// bytes 6-7
		// ANCOUNT: binary.BigEndian.Uint16(packet[6:8]),
		// bytes 8-9
		// NSCOUNT: binary.BigEndian.Uint16(packet[8:10]),
		// bytes 10-11
		// ARCOUNT: binary.BigEndian.Uint16(packet[10:12]),
	}

	var questions []question
	var offset int
	for len(questions) < int(h.qdcount) {
		q, n, err := parseQuestion(packet[12+offset:])
		if err != nil {
			return Message{}, fmt.Errorf("failed to parse question: %w", err)
		}
		offset += n
		questions = append(questions, q)
	}

	return Message{
		header:    h,
		questions: questions,
	}, nil
}

func parseQuestion(data []byte) (question, int, error) {
	var n int
	var name qname
	for {
		ll := int(data[n])
		if ll == 0 {
			break
		}
		name = append(name, data[n+1:n+1+ll])
		n += ll + 1
	}

	if data[n] != 0 {
		return question{}, 0, errors.New("null-terminator expected")
	}
	n++

	return question{
		name:   name,
		qtype:  binary.BigEndian.Uint16(data[n : n+2]),
		qclass: binary.BigEndian.Uint16(data[n+2 : n+4]),
	}, n, nil
}

func (m Message) Questions() []question {
	return m.questions
}

func (n qname) String() string {
	return string(bytes.Join(n, []byte(".")))
}

func (q question) String() string {
	return q.name.String()
}
