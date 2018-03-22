package main

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	nats "github.com/nats-io/go-nats"
)

type cert struct {
	Issuer             string   `json:"issuer"`
	DNSnames           []string `json:"altNames"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	NotBefore          string   `json:"notBefore"`
	NotAfter           string   `json:"notAfter"`
	SHA1               string   `json:"sha1"`
}

func newCert(_c *x509.Certificate) *cert {
	names := _c.DNSNames
	if len(names) == 0 {
		names = append(names, _c.Subject.CommonName)
	}

	res := &cert{
		DNSnames:           names,
		Issuer:             _c.Issuer.CommonName,
		NotBefore:          _c.NotBefore.Format(time.RFC1123Z),
		NotAfter:           _c.NotAfter.Format(time.RFC1123Z),
		SignatureAlgorithm: _c.SignatureAlgorithm.String(),
		SHA1:               fmt.Sprintf("%x", sha1.Sum(_c.Raw)),
	}
	return res
}

type request struct {
	Hostname   string `json:"hostname"`
	Host       string `json:"host"`
	Port       int32  `json:"port"`
	TimeoutSec int32  `json:"timeout"`
}

type response struct {
	Hostname string         `json:"hostname"`
	Host     string         `json:"host"`
	Port     int32          `json:"port"`
	Certs    [][]cert       `json:"cert"`
	Error    *ExternalError `json:"error,omitempty"`
	Duration float64        `json:"duration"`
}

func (r *response) failed(err ExternalError) *response {
	r.Error = &err
	return r
}

// ExternalError reprents an error as sent in json
type ExternalError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func (e ExternalError) Error() string {
	return e.Message
}

var (
	// ErrIOTimeout if a timeout occurs
	ErrIOTimeout = ExternalError{Code: "ETIMEOUT", Message: "IO timeout"}
	//ErrNoCertFound if no cert is found with TLS
	ErrNoCertFound = ExternalError{Code: "NOCERT", Message: "no cert found"}
	// ErrSelfSigned if cert is self signed
	ErrSelfSigned = ExternalError{Code: "SELFSIGNED", Message: "x509: self signed cert"}
	// ErrIncompleteCertChain if some certs are missing
	ErrIncompleteCertChain = ExternalError{Code: "INCOMPLETECERTCHAIN", Message: "x509: incomplete cert chain"}
	// ErrInvalidCertHostname if the host name doesn't match
	ErrInvalidCertHostname = ExternalError{Code: "INVALIDHOSTNAME", Message: "x509: invalid cert for hostname"}
)

func pumpCert(req request) *response {

	res := &response{
		Hostname: req.Hostname,
		Host:     req.Host,
		Port:     req.Port,
	}

	address := fmt.Sprintf("%s:%d", req.Host, req.Port)
	conf := &tls.Config{

		MinVersion:         tls.VersionSSL30,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         req.Hostname,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: time.Duration(req.TimeoutSec) * time.Second,
	}, "tcp", address, conf)
	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			return res.failed(ErrIOTimeout)
		}
		return res.failed(ExternalError{Code: "CONNECTERROR", Message: err.Error()})
	}

	tlsState := conn.ConnectionState()
	if len(tlsState.PeerCertificates) == 0 {
		return res.failed(ErrNoCertFound)
	}

	opts := x509.VerifyOptions{
		Roots:         conf.RootCAs,
		CurrentTime:   time.Now(),
		DNSName:       conf.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	var allcerts []cert
	for i, cert := range tlsState.PeerCertificates {
		c := newCert(cert)
		allcerts = append(allcerts, *c)

		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}

	verified, certerr := tlsState.PeerCertificates[0].Verify(opts)

	if certerr != nil {
		var result [][]cert
		result = append(result, allcerts)
		res.Certs = result

		if len(tlsState.PeerCertificates) == 1 {
			if tlsState.PeerCertificates[0].Issuer.CommonName == tlsState.PeerCertificates[0].Subject.CommonName {
				return res.failed(ErrSelfSigned)
			}
			return res.failed(ErrIncompleteCertChain)

		}
		if strings.Contains(certerr.Error(), "x509: certificate is valid for ") {
			return res.failed(ErrInvalidCertHostname)
		}
		return res.failed(ExternalError{Code: "CERTERROR", Message: certerr.Error()})
	}

	for _, each := range verified {
		var chain []cert
		for _, _c := range each {
			c := newCert(_c)
			chain = append(chain, *c)
		}
		res.Certs = append(res.Certs, chain)
	}

	/*
		CODE TO PERFORM HTTP HEAD
		if certerr == nil {
			tr := &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) {
					return conn, nil
				},
			}
			client := &http.Client{Transport: tr}
			url := fmt.Sprintf("https://%s:%d/", hostname, port)
			resp, err := client.Head(url)
			if err != nil {
				fmt.Println("http error", err.Error())
			}
			fmt.Println("response code: ", hostname, resp.StatusCode)
		}*/

	conn.Close()
	return res
}

func handleRequest(nc *nats.Conn, msg []byte, reply string) {

	before := time.Now()
	req := request{}
	jierr := json.Unmarshal(msg, &req)
	if jierr != nil {
		log.Println("JSON request unmarshal: ", jierr.Error())
	}
	if req.TimeoutSec <= 0 {
		req.TimeoutSec = 10
	}
	res := pumpCert(req)
	if res.Error != nil {
		log.Printf("%s:%d (%s) Error:%s (%s)\n", res.Hostname, res.Port, res.Host, res.Error.Message, res.Error.Code)
	}
	res.Duration = time.Now().Sub(before).Seconds()
	bytes, joerr := json.Marshal(res)
	if joerr != nil {
		log.Println("JSON response marshal Error: ", jierr.Error())
	}
	puberr := nc.Publish(reply, bytes)
	if puberr != nil {
		log.Println("pub: ", puberr)
	}
}

func main() {

	log.SetFlags(log.LstdFlags | log.LUTC)

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://127.0.0.1:4222"
	}

	natsChannel := os.Getenv("NATS_CHANNEL")
	if natsChannel == "" {
		natsChannel = "get.CERT.*"
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

	log.Println("Connected to Nats (", natsURL, ")")

	// subscribe and spawn a goroutine for each message
	_, err = nc.QueueSubscribe(natsChannel, "certpump_group", func(msg *nats.Msg) {
		go handleRequest(nc, msg.Data, msg.Reply)
	})

	if err != nil {
		log.Println("Error: Can't subscribe to ", natsChannel)
		log.Fatalln(err.Error())
	}
	runtime.Goexit()
}
