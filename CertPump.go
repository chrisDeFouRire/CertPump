package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	nats "github.com/nats-io/go-nats"
)

type cert struct {
	Issuer             string   `json:"issuer"`
	DNSnames           []string `json:"altNames"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	NotBefore          string   `json:"notBefore"`
	NotAfter           string   `json:"notAfter"`
	SerialNumber       string   `json:"serialNumber"`
	Chain              []string `json:"chain"`
}

type request struct {
	Hostname string `json:"hostname"`
	Host     string `json:"host"`
	Port     int32  `json:"port"`
}

type response struct {
	Hostname string `json:"hostname"`
	Host     string `json:"host"`
	Port     int32  `json:"port"`
	Cert     cert   `json:"cert"`
	Error    string `json:"error,omitempty"`
}

func getCert(hostname string, ip string, port int32) (*cert, error) {

	address := fmt.Sprintf("%s:%d", ip, port)
	conf := &tls.Config{
		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         hostname,
	}

	conn, err := tls.Dial("tcp", address, conf)
	if err != nil {
		return nil, err
	}

	tlsState := conn.ConnectionState()
	if len(tlsState.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	_c := tlsState.PeerCertificates[0]

	names := _c.DNSNames
	if len(names) == 0 {
		names = append(names, _c.Subject.CommonName)
	}

	c := &cert{
		DNSnames:           names,
		Issuer:             _c.Issuer.CommonName,
		NotBefore:          _c.NotBefore.Format(time.RFC1123Z),
		NotAfter:           _c.NotAfter.Format(time.RFC1123Z),
		SerialNumber:       _c.SerialNumber.Text(16),
		SignatureAlgorithm: _c.SignatureAlgorithm.String(),
		Chain:              nil,
	}

	opts := x509.VerifyOptions{
		Roots:         conf.RootCAs,
		CurrentTime:   time.Now(),
		DNSName:       conf.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for i, cert := range tlsState.PeerCertificates {
		c.Chain = append(c.Chain, cert.Subject.CommonName)
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}

	_, certerr := tlsState.PeerCertificates[0].Verify(opts)

	if certerr != nil && len(tlsState.PeerCertificates) == 1 {
		if tlsState.PeerCertificates[0].Issuer.CommonName == tlsState.PeerCertificates[0].Subject.CommonName {
			certerr = fmt.Errorf("x509: self signed cert")
		} else {
			certerr = fmt.Errorf("x509: incomplete cert chain")
		}
	}

	conn.Close()
	return c, certerr
}

func handleRequest(nc *nats.Conn, msg []byte, reply string) {
	// don't let a panic crash the app or we'll crash all concurrent requests
	/* Use DEV env var
	defer func() {
		if r := recover(); r != nil {
			log.Println("Error recovered: ", r)
		}
	}() */

	req := request{}
	jierr := json.Unmarshal(msg, &req)
	if jierr != nil {
		log.Println("JSON request unmarshal Error: ", jierr.Error())
	}

	res := response{
		Hostname: req.Hostname,
		Host:     req.Host,
		Port:     req.Port,
	}

	cert, err := getCert(req.Hostname, req.Host, req.Port)
	if err != nil {
		res.Error = err.Error()
	}
	if cert != nil {
		res.Cert = *cert
	}

	bytes, joerr := json.Marshal(res)
	if joerr != nil {
		log.Println("JSON response marshal Error: ", jierr.Error())
	}
	fmt.Println(string(bytes))
	nc.Publish(reply, bytes)
}

func main() {

	log.SetFlags(log.LstdFlags | log.LUTC)

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://127.0.0.1:4222"
	}

	natsChannel := os.Getenv("NATS_CHANNEL")
	if natsChannel == "" {
		natsChannel = "get.CERTPUMP.*"
	}

	var nc *nats.Conn
	var err error
	nc, err = nats.Connect(
		natsURL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(1*time.Second),
		nats.DisconnectHandler(func(*nats.Conn) {
			log.Println("Got disconnected from nats!")
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Printf("Got reconnected to %v!\n", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			log.Printf("Connection closed. Reason: %q\n", nc.LastError())
		}))
	if err != nil {
		log.Println("Error: Can't connect to nats (", natsURL, ")")
		log.Fatalln(err.Error())
	}

	log.Println("CertPump Connected to Nats (", natsURL, ")")

	// subscribe and spawn a goroutine for each message
	_, err = nc.QueueSubscribe(natsChannel, "certpump_group", func(msg *nats.Msg) {
		go handleRequest(nc, msg.Data, msg.Reply)
	})

	if err != nil {
		log.Println("Error: Can't subscribe to nats")
		log.Fatalln(err.Error())
	}
	runtime.Goexit()
}
