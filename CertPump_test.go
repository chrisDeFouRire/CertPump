package main

import (
	"encoding/json"
	"testing"
	"time"

	nats "github.com/nats-io/go-nats"
)

func ensureServiceInvariant(t *testing.T, req request, res response) {
	if res.Host != req.Host {
		t.Fatal("Host changed")
	}
	if res.Port != req.Port {
		t.Fatal("Port changed")
	}
	if res.Hostname != req.Hostname {
		t.Fatal("Hostname changed")
	}
}

func send(t *testing.T, req request) (*response, error) {
	var nc *nats.Conn
	nc, _ = nats.Connect("nats://localhost:4222")

	bytes, _ := json.Marshal(req)
	msg, err := nc.Request("get.CERT.US", bytes, time.Second*100)
	if err != nil {
		return nil, err
	}
	res := response{}
	json.Unmarshal(msg.Data, &res)

	ensureServiceInvariant(t, req, res)

	return &res, nil
}

func sendRequest(t *testing.T, hostname string, host string, port int32) (*response, error) {
	req := request{
		Hostname: hostname,
		Host:     host,
		Port:     port,
	}
	return send(t, req)
}

func TestSSLping(t *testing.T) {
	res, err := sendRequest(t, "sslping.com", "195.154.227.44", 443)

	if err != nil {
		t.Fatal(err)
	}

	if res.Error != nil {
		t.Error("Error not nil", res.Error)
	}
}

func TestPlacenames(t *testing.T) {
	res, err := sendRequest(t, "www.placenames.com", "104.28.13.117", 443)

	if err != nil {
		t.Fatal(err)
	}

	if res.Error != nil {
		t.Fatal("Error not nil", res.Error)
	}
}

func TestFail1(t *testing.T) {
	res, err := sendRequest(t, "monitoring.meshwith.me", "64.140.158.156", 443)

	if err != nil {
		t.Fatal(err)
	}

	if len(res.Certs) != 1 {
		t.Fatal("Not one cert chain but ", len(res.Certs))
	}
	if res.Error.Code != ErrIncompleteCertChain.Code {
		t.Fatal("Error not detected", res.Error)
	}
}
func TestFail2(t *testing.T) {
	res, err := sendRequest(t, "mail.farelogix.com", "72.46.248.210", 995)

	if err != nil {
		t.Fatal(err)
	}

	if len(res.Certs) != 1 {
		t.Fatal("Not one cert chain")
	}
	if res.Error.Code != ErrSelfSigned.Code {
		t.Fatal("Error not detected", res.Error)
	}
}

func TestFail3(t *testing.T) {
	res, err := sendRequest(t, "clickholdings.co.uk", "77.72.203.173", 443)

	if err != nil {
		t.Fatal(err)
	}

	if len(res.Certs) != 1 {
		t.Fatal("Not one cert chain")
	}
	if res.Error.Code != ErrSelfSigned.Code {
		t.Fatal("Error not detected", res.Error)
	}
}

func TestFail4(t *testing.T) {
	res, err := sendRequest(t, "incorrecthostname.com", "195.154.227.44", 443)
	if err != nil {
		t.Fatal(err)
	}

	if res.Error.Code != ErrInvalidCertHostname.Code {
		t.Fatal("Error not detected", res.Error)
	}
}

func TestFail5(t *testing.T) {

	res, err := send(t, request{"sslping.com", "195.154.227.44", 4000, 2})
	if err != nil {
		t.Fatal(err)
	}

	if res.Error.Code != ErrIOTimeout.Code {
		t.Fatal("Error not detected", res.Error)
	}
}

func TestFail6(t *testing.T) {
	res, err := send(t, request{"telefoot-01.xtralife.me", "188.166.85.124", 443, 10})
	if err != nil {
		t.Fatal(err)
	}

	if res.Error != nil {
		t.Fatal("Error detected", res.Error)
	}
}

func TestFail7(t *testing.T) {
	res, err := send(t, request{"www.efficioconsulting.com", "176.58.127.96", 443, 10})
	if err != nil {
		t.Fatal(err)
	}

	if res.Error != nil {
		t.Fatal("Error detected", res.Error)
	}
}
