package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	nats "github.com/nats-io/go-nats"
)

func TestSSLping(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	req := request{
		Hostname: "sslping.com",
		Host:     "195.154.227.44",
		Port:     443,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("get.CERTPUMP.US", bytes, time.Second*100)
	if err != nil {
		fmt.Println(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if res.Error != "" {
		t.Fatal("Error not nil", res.Error)
	}
}

func TestPlacenames(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	req := request{
		Hostname: "www.placenames.com",
		Host:     "104.28.13.117",
		Port:     443,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("get.CERTPUMP.US", bytes, time.Second*100)
	if err != nil {
		fmt.Println(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if res.Error != "" {
		t.Fatal("Error not nil", res.Error)
	}
}

func TestFail1(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	req := request{
		Hostname: "ems.med.unsw.edu.au",
		Host:     "149.171.203.11",
		Port:     443,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("get.CERTPUMP.US", bytes, time.Second*100)
	if err != nil {
		fmt.Println(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if len(res.Cert.Chain) != 1 {
		t.Fatal("Not one cert in chain")
	}
	if res.Error != ErrIncompleteCertChain.Error() {
		t.Fatal("Error not detected", res.Error)
	}
}
func TestFail2(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	req := request{
		Hostname: "mail.farelogix.com",
		Host:     "72.46.248.210",
		Port:     995,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("get.CERTPUMP.US", bytes, time.Second*100)
	if err != nil {
		fmt.Println(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if len(res.Cert.Chain) != 1 {
		t.Fatal("Not one cert in chain")
	}
	if res.Error != ErrSelfSigned.Error() {
		t.Fatal("Error not detected", res.Error)
	}
}

func TestFail3(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	req := request{
		Hostname: "clickholdings.co.uk",
		Host:     "77.72.203.173",
		Port:     443,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("get.CERTPUMP.US", bytes, time.Second*100)
	if err != nil {
		fmt.Println(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if len(res.Cert.Chain) != 1 {
		t.Fatal("Not one cert in chain")
	}
	if res.Error != ErrSelfSigned.Error() {
		t.Fatal("Error not detected", res.Error)
	}
}

func TestFail4(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	req := request{
		Hostname: "incorrecthostname.com",
		Host:     "195.154.227.44",
		Port:     443,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("get.CERTPUMP.US", bytes, time.Second*100)
	if err != nil {
		fmt.Println(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if res.Error != ErrInvalidCertHostname.Error() {
		t.Fatal("Error not detected", res.Error)
	}
}

func TestFail5(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	req := request{
		Hostname: "sslping.com",
		Host:     "195.154.227.44",
		Port:     4000,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("get.CERTPUMP.US", bytes, time.Second*50)
	if err != nil {
		t.Fatal(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if res.Error != ErrIOTimeout.Error() {
		t.Fatal("Error not detected", res.Error)
	}
}
