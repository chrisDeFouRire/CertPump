package main

import (
	"encoding/json"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/chrisDeFouRire/Heartbleed/heartbleed"
	nats "github.com/nats-io/go-nats"
)

type request struct {
	Hostname string `json:"hostname"`
	Host     string `json:"host"`
	Port     int32  `json:"port"`
}

type response struct {
	Hostname   string `json:"hostname"`
	Host       string `json:"host"`
	Port       int32  `json:"port"`
	Vulnerable bool   `json:"vulnerable"`
	Error      string `json:"error,omitifempty"`
}

func handleRequest(nc *nats.Conn, msg []byte, reply string) {
	// don't let a panic crash the app or we'll crash all concurrent requests
	defer func() {
		if r := recover(); r != nil {
			log.Println("Error recovered")
		}
	}()

	req := request{}
	jierr := json.Unmarshal(msg, &req)
	if jierr != nil {
		log.Println("JSON request unmarshal Error: ", jierr.Error())
	}

	tgt := &heartbleed.Target{
		Service:  "https",
		HostIp:   req.Host,
		Hostname: req.Hostname,
		Port:     req.Port,
	}

	_, err := heartbleed.Heartbleed(tgt,
		[]byte("github.com/FiloSottile/Heartbleed"), true)

	res := response{
		Hostname: req.Hostname,
		Host:     req.Host,
		Port:     req.Port,
	}

	if err == heartbleed.Safe {
		res.Vulnerable = false
		log.Printf("%s (%s:%d): %#v\n", req.Hostname, req.Host, req.Port, res.Vulnerable)
	} else if err != nil {
		log.Printf("ERROR: %s (%s:%d): %s\n", req.Hostname, req.Host, req.Port, res.Error)
		res.Error = err.Error()
	} else {
		res.Vulnerable = true
		log.Printf("%s (%s:%d): %#v\n", req.Hostname, req.Host, req.Port, res.Vulnerable)
	}

	bytes, joerr := json.Marshal(res)
	if joerr != nil {
		log.Println("JSON response marshal Error: ", jierr.Error())
	}
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
		natsChannel = "vuln.HEARTBLEED.*"
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
	_, err = nc.QueueSubscribe(natsChannel, "heartbleed_group", func(msg *nats.Msg) {
		go handleRequest(nc, msg.Data, msg.Reply)
	})

	if err != nil {
		log.Println("Error: Can't subscribe to nats")
		log.Fatalln(err.Error())
	}
	runtime.Goexit()
}
