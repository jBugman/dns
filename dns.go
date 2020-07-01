package main

import (
	"log"
	"net"

	"dns/dns"
)

func main() {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 512) // UDP messages    512 octets or less
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("request from %+v", addr)
		log.Printf("%d: %+v", n, buf[:n])
		m, _ := dns.Parse(buf[:n])
		log.Printf("%+v", m)
		log.Println(m.Questions())
	}
}
