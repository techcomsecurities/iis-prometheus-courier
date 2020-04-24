package iisexporter

import (
	"github.com/sirupsen/logrus"
	"github.com/techcomsecurities/iis-prometheus-courier/iisapi"
	"regexp"

	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Exporter struct {
	user      string
	pass      string
	addrs     []string
	tokens    []string
	namespace string
	duration  prometheus.Gauge
	metrics   map[string]*prometheus.GaugeVec
	sync.RWMutex
}

type scrapeResult struct {
	Name  string
	Value float64
	Addr  string
	Index string
}
type iisApisChan struct {
	AppName string
	Path    string
	User    string
	Pass    string
	Addr    string
	Token   string
}

func (e *Exporter) initGauges() {
	e.metrics = map[string]*prometheus.GaugeVec{}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {

	for _, m := range e.metrics {
		m.Describe(ch)
	}
	ch <- e.duration.Desc()
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	scrapes := make(chan scrapeResult)

	e.Lock()
	defer e.Unlock()

	e.initGauges()
	go e.scrape(scrapes)
	e.setMetrics(scrapes)

	ch <- e.duration
	e.collectMetrics(ch)
}

func extractMetrics(iisMetrics *iisapi.IISMetrics, scrapes chan<- scrapeResult) {
	logrus.Infof("Begin extract metrics from AppName:%s", iisMetrics.AppName)
	if iisMetrics.HttpRequestMetrics != nil {
		index := "HttpRequest"
		prfix := iisMetrics.AppName + "http_request_"
		scrapes <- scrapeResult{Name: prfix + "http_request_", Addr: iisMetrics.HttpRequestMetrics.Url, Index: index, Value: iisMetrics.HttpRequestMetrics.TimeElapsed}
	}else if iisMetrics.Network != nil {
		// Network
		index := "Network"
		prfix := iisMetrics.AppName + "network_"
		scrapes <- scrapeResult{Name: prfix + "bytes_sent_sec", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Network.BytesSentSec}
		scrapes <- scrapeResult{Name: prfix + "bytes_recv_sec", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Network.BytesRecvSec}
		scrapes <- scrapeResult{Name: prfix + "connection_attempts_sec", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Network.ConnectionAttemptsSec}
		scrapes <- scrapeResult{Name: prfix + "total_bytes_sent", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Network.TotalBytesSent}
		scrapes <- scrapeResult{Name: prfix + "total_bytes_recv", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Network.TotalBytesRecv}
		scrapes <- scrapeResult{Name: prfix + "total_connection_attempts", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Network.TotalConnectionAttempts}
		scrapes <- scrapeResult{Name: prfix + "current_connections", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Network.CurrentConnections}
	} else {

		// Requests
		index := "Requests"
		prfix := iisMetrics.AppName + "requests_"
		scrapes <- scrapeResult{Name: prfix + "active", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Requests.Active}
		scrapes <- scrapeResult{Name: prfix + "per_sec", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Requests.PerSec}
		scrapes <- scrapeResult{Name: prfix + "total", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Requests.Total}

		// Memory
		index = "Memory"
		prfix = iisMetrics.AppName + "memory_"
		scrapes <- scrapeResult{Name: prfix + "handles", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Memory.Handles}
		scrapes <- scrapeResult{Name: prfix + "private_bytes", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Memory.PrivateBytes}
		scrapes <- scrapeResult{Name: prfix + "private_working_set", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Memory.PrivateWorkingSet}
		scrapes <- scrapeResult{Name: prfix + "system_in_use", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Memory.SystemInUse}
		scrapes <- scrapeResult{Name: prfix + "installed", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Memory.Installed}

		// Cpu
		index = "Cpu"
		prfix = iisMetrics.AppName + "cpu_"
		scrapes <- scrapeResult{Name: prfix + "threads", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cpu.Threads}
		scrapes <- scrapeResult{Name: prfix + "processes", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cpu.Processes}
		scrapes <- scrapeResult{Name: prfix + "percent_usage", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cpu.PercentUsage}
		scrapes <- scrapeResult{Name: prfix + "system_percent_usage", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cpu.SystemPercentUsage}

		// Disk
		index = "Disk"
		prfix = iisMetrics.AppName + "disk_"
		scrapes <- scrapeResult{Name: prfix + "io_write_operations_sec", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Disk.IoWriteOperationsSec}
		scrapes <- scrapeResult{Name: prfix + "io_read_operations_sec", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Disk.IoReadOperationsSec}
		scrapes <- scrapeResult{Name: prfix + "page_faults_sec", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Disk.PageFaultsSec}

		// Cache
		index = "Cache"
		prfix = iisMetrics.AppName + "cache_"
		scrapes <- scrapeResult{Name: prfix + "file_cache_count", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.FileCacheCount}
		scrapes <- scrapeResult{Name: prfix + "file_cache_memory_usage", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.FileCacheMemoryUsage}
		scrapes <- scrapeResult{Name: prfix + "file_cache_hits", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.FileCacheHits}
		scrapes <- scrapeResult{Name: prfix + "file_cache_misses", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.FileCacheMisses}
		scrapes <- scrapeResult{Name: prfix + "total_files_cached", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.TotalFilesCached}
		scrapes <- scrapeResult{Name: prfix + "output_cache_count", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.OutputCacheCount}
		scrapes <- scrapeResult{Name: prfix + "output_cache_memory_usage", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.OutputCacheMemoryUsage}
		scrapes <- scrapeResult{Name: prfix + "output_cache_hits", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.OutputCacheHits}
		scrapes <- scrapeResult{Name: prfix + "output_cache_misses", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.OutputCacheMisses}
		scrapes <- scrapeResult{Name: prfix + "uri_cache_count", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.UriCacheCount}
		scrapes <- scrapeResult{Name: prfix + "uri_cache_hits", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.UriCacheHits}
		scrapes <- scrapeResult{Name: prfix + "uri_cache_misses", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.UriCacheMisses}
		scrapes <- scrapeResult{Name: prfix + "total_uris_cached", Addr: iisMetrics.Addr, Index: index, Value: iisMetrics.Cache.TotalUrisCached}
	}
	logrus.Infof("End extract metrics from AppName:%s", iisMetrics.AppName)
}

func (e *Exporter) scrape(scrapes chan<- scrapeResult) {
	in := []iisApisChan{}
	defer close(scrapes)
	now := time.Now().UnixNano()

	for i, addr := range e.addrs {
		path := "/api/webserver/monitoring"

		in = append(in, iisApisChan{"", path, e.user, e.pass, addr, e.tokens[i]})

		appPoolResp, err := iisapi.GetApplicationPool(e.user, e.pass, addr, e.tokens[i])
		if err != nil {
			logrus.WithField("err", err).Errorf("Get app pool from address %s has an error", addr)
			// @todo error counter
			continue
		}

		for _, appPool := range appPoolResp.AppPools {
			appPoolDetailResp, err := iisapi.GetApplicationPoolDetail(appPool, e.user, e.pass, addr, e.tokens[i])
			if err != nil {
				logrus.WithField("err", err).Errorf("Get application pool from address %s has an error", addr)
				// @todo error counter
				continue
			}
			logrus.Infof("Name %s Monitoring href: %s", appPoolDetailResp.Name, appPoolDetailResp.Links.Monitoring.Href)

			appName, err := removeAllSpecialCharacter(appPoolDetailResp.Name)

			in = append(in, iisApisChan{*appName, appPoolDetailResp.Links.Monitoring.Href, e.user, e.pass, addr, e.tokens[i]})
		}
	}

	total := len(in) + len(e.addrs)
	var wg sync.WaitGroup
	wg.Add(total)
	for _, api := range in {
		go func() {
			// Call Done() using defer as it's be easiest way to guarantee it's called at every exit
			defer wg.Done()
			iisMetrics, err := iisapi.GetMetrics(api.Path, api.User, api.Pass, api.Addr, api.Token)
			if err != nil {
				logrus.WithField("err", err).Errorf("Get metrics from address %s has an error", api.Addr)
				// error counter
			} else {
				iisMetrics.AppName = api.AppName
				extractMetrics(iisMetrics, scrapes)
			}
		}()
	}

	// /api/webserver/http-request-monitor/requests
	for j, a := range e.addrs {
		go func() {
			// Call Done() using defer as it's be easiest way to guarantee it's called at every exit
			defer wg.Done()
			httpMxRes, err := iisapi.GetHttpRequestMetrics(e.user, e.pass, a, e.tokens[j])

			if err != nil {
				logrus.WithField("err", err).Errorf("Get metrics from address %s has an error", a)
				// error counter
			} else {
				//httpMxRes
				for _, h := range httpMxRes.Requests {
					mx := iisapi.IISMetrics{AppName: "IIS", HttpRequestMetrics: &h}
					extractMetrics(&mx, scrapes)
				}
			}
		}()
	}

	// wait all threads is done
	wg.Wait()
	logrus.Info("Done get metrics")
	e.duration.Set(float64(time.Now().UnixNano()-now) / 1000000000)
	logrus.Info("Done scrape")
}
func removeAllSpecialCharacter(s string) (*string, error) {
	// Make a Regex to say we only want letters and numbers
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		logrus.WithField("err", err).Error("Regexp compile remove special character has an error")
		return nil, err
	}
	processedString := string(reg.ReplaceAllString(s, ""))
	return &processedString, nil
}

func (e *Exporter) setMetrics(scrapes <-chan scrapeResult) {

	for scr := range scrapes {
		name := scr.Name
		if _, ok := e.metrics[name]; !ok {
			e.metrics[name] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: e.namespace,
				Name:      name,
			}, []string{"addr", "index"})
		}
		var labels prometheus.Labels = map[string]string{"addr": scr.Addr, "index": scr.Index}

		e.metrics[name].With(labels).Set(scr.Value)
	}
}

func (e *Exporter) collectMetrics(metrics chan<- prometheus.Metric) {
	for _, m := range e.metrics {
		m.Collect(metrics)
	}
}

func NewIISExporter(user, pass string, addrs, tokens []string, namespace string) *Exporter {
	e := Exporter{
		user:      user,
		pass:      pass,
		addrs:     addrs,
		tokens:    tokens,
		namespace: namespace,

		duration: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "exporter_last_scrape_duration_seconds",
			Help:      "The last scrape duration.",
		}),
	}

	e.initGauges()
	return &e
}
