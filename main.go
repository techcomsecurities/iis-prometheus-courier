package main

import (
	"flag"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/techcomsecurities/iis-prometheus-courier/iisexporter"
	"log"
	"net/http"
	"strings"
)

var (
	user     = flag.String("user", "sangnv", "User name")
	pass     = flag.String("pass", "Tcbs123", "Password")
	iisAddr     = flag.String("addr", "https://10.7.2.4:55539", "Address of one or more iis nodes, comma separated")
	token     = flag.String("token", "Kqr8MiKWkbJ_MwEwNKktVJl-4Vod-f9uxTL1bZVaR0nwf5F8Qp0Y5g", "Token of one or more iis nodes, comma separated")
	namespace     = flag.String("namespace", "iis", "Namespace for metrics")
	port = flag.String("port", ":9121", "Address to listen on for web interface and telemetry.")
)
func main() {
	flag.Parse()

	addrs := strings.Split(*iisAddr, ",")
	if len(addrs) == 0 || len(addrs[0]) == 0 {
		log.Fatal("Invalid parameter --addr")
	}

	tokens := strings.Split(*token, ",")
	if len(addrs) == 0 || len(addrs[0]) == 0 {
		log.Fatal("Invalid parameter --token")
	}

	e := iisexporter.NewIISExporter(*user,*pass,addrs, tokens, *namespace)
	prometheus.MustRegister(e)


	http.Handle("/metrics", promhttp.Handler())

	log.Printf("Connecting to iss administration api url: %s", addrs)
	log.Printf("Connecting to iss administration api token: %s", tokens)

	log.Printf("Metrics path is http://localhost%s/metrics", *port)
	log.Fatal(http.ListenAndServe(*port, nil))
}