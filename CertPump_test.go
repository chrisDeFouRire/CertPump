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
	msg, err := nc.Request("get.CERT.US", bytes, time.Second*100)
	if err != nil {
		fmt.Println(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)
	fmt.Println(string(msg.Data))
	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if res.Error != nil {
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
	msg, err := nc.Request("get.CERT.US", bytes, time.Second*100)
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
	if res.Error != nil {
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
	msg, err := nc.Request("get.CERT.US", bytes, time.Second*100)
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
	if len(res.Certs) != 1 {
		t.Fatal("Not one cert chain but ", len(res.Certs))
	}
	if res.Error.Code != ErrIncompleteCertChain.Code {
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
	msg, err := nc.Request("get.CERT.US", bytes, time.Second*100)
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
	if len(res.Certs) != 1 {
		t.Fatal("Not one cert chain")
	}
	if res.Error.Code != ErrSelfSigned.Code {
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
	msg, err := nc.Request("get.CERT.US", bytes, time.Second*100)
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
	if len(res.Certs) != 1 {
		t.Fatal("Not one cert chain")
	}
	if res.Error.Code != ErrSelfSigned.Code {
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
	msg, err := nc.Request("get.CERT.US", bytes, time.Second*100)
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
	if res.Error.Code != ErrInvalidCertHostname.Code {
		t.Fatal("Error not detected", res.Error)
	}
}

func TestFail5(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	req := request{
		Hostname:   "sslping.com",
		Host:       "195.154.227.44",
		Port:       4000,
		TimeoutSec: 2,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("get.CERT.US", bytes, time.Second*50)
	if err != nil {
		t.Fatal(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)
	fmt.Println(string(msg.Data))
	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if res.Error.Code != ErrIOTimeout.Code {
		t.Fatal("Error not detected", res.Error)
	}
}
func TestFail6(t *testing.T) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	req := request{
		Hostname:   "www.efficioconsulting.com",
		Host:       "176.58.127.96",
		Port:       443,
		TimeoutSec: 10,
	}
	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("get.CERT.US", bytes, time.Second*50)
	if err != nil {
		t.Fatal(err)
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)
	t.Fatal(string(msg.Data))
	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
	if res.Error != nil {
		t.Fatal("Error detected", res.Error)
	}
}
