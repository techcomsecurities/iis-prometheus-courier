package iisapi

import (
	"crypto/tls"
	"encoding/json"
	"github.com/sirupsen/logrus"
	httpntlm "github.com/vadimi/go-http-ntlm"
	"io/ioutil"
	"net/http"
	"strings"
)

type Network struct {
	BytesSentSec            float64 `json:"bytes_sent_sec"`
	BytesRecvSec            float64 `json:"bytes_recv_sec"`
	ConnectionAttemptsSec   float64 `json:"connection_attempts_sec"`
	TotalBytesSent          float64 `json:"total_bytes_sent"`
	TotalBytesRecv          float64 `json:"total_bytes_recv"`
	TotalConnectionAttempts float64 `json:"total_connection_attempts"`
	CurrentConnections      float64 `json:"current_connections"`
}
type Requests struct {
	Active float64 `json:"active"`
	PerSec float64 `json:"per_sec"`
	Total  float64 `json:"total"`
}
type Memory struct {
	Handles           float64 `json:"handles"`
	PrivateBytes      float64 `json:"private_bytes"`
	PrivateWorkingSet float64 `json:"private_working_set"`
	SystemInUse       float64 `json:"system_in_use"`
	Installed         float64 `json:"installed"`
}
type Cpu struct {
	Threads            float64 `json:"threads"`
	Processes          float64 `json:"processes"`
	PercentUsage       float64 `json:"percent_usage"`
	SystemPercentUsage float64 `json:"system_percent_usage"`
}
type Disk struct {
	IoWriteOperationsSec float64 `json:"io_write_operations_sec"`
	IoReadOperationsSec  float64 `json:"io_read_operations_sec"`
	PageFaultsSec        float64 `json:"page_faults_sec"`
}
type Cache struct {
	FileCacheCount         float64 `json:"file_cache_count"`
	FileCacheMemoryUsage   float64 `json:"file_cache_memory_usage"`
	FileCacheHits          float64 `json:"file_cache_hits"`
	FileCacheMisses        float64 `json:"file_cache_misses"`
	TotalFilesCached       float64 `json:"total_files_cached"`
	OutputCacheCount       float64 `json:"output_cache_count"`
	OutputCacheMemoryUsage float64 `json:"output_cache_memory_usage"`
	OutputCacheHits        float64 `json:"output_cache_hits"`
	OutputCacheMisses      float64 `json:"output_cache_misses"`
	UriCacheCount          float64 `json:"uri_cache_count"`
	UriCacheHits           float64 `json:"uri_cache_hits"`
	UriCacheMisses         float64 `json:"uri_cache_misses"`
	TotalUrisCached        float64 `json:"total_uris_cached"`
}
type IISMetrics struct {
	Id       string   `json:"id"`
	AppName	 string   `json:"appName"`
	Addr	 string   `json:"addr"`
	Network  *Network  `json:"network"`
	Requests *Requests `json:"requests"`
	Memory   *Memory   `json:"memory"`
	Cpu      *Cpu      `json:"cpu"`
	Disk     *Disk     `json:"disk"`
	Cache    *Cache    `json:"cache"`
	HttpRequestMetrics *HttpRequestMetrics `json:"http_request"`
}

func GetMetrics(path, user,pass,addr, token string) (*IISMetrics, error) {
	url := addr + path
	logrus.Infof("connecting to api %s", url)
	// configure http client
	client := http.Client{
		Transport: &httpntlm.NtlmTransport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			//Domain:   "mydomain",
			User:     user,
			Password: pass,
		},
	}

	req, err := http.NewRequest("GET", url, strings.NewReader(""))
	if err != nil {
		logrus.WithField("err", err).Error("New request has an error")
		return nil, err
	}
	req.Header.Add("Access-Token", "Bearer "+token)
	req.Header.Add("Accept", "application/hal+json")
	req.Header.Add("Connection", "keep-alive")
	resp, err := client.Do(req)
	if err != nil {
		logrus.WithField("err", err).Error("Do request has an error")
		return nil, err
	}

	if resp.StatusCode != 200 {
		logrus.WithField("err", err).Error("Http code get time server error")
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.WithField("err", err).Error("Read body from response has an error")
		return nil, err
	}

	logrus.Infof("Path %s response Status: %v", path, resp.Status)

	//s, _ := strconv.Unquote(string(body))
	//logrus.Infof("Unquote response Body:%v", s)

	var iisMetrics IISMetrics
	err = json.Unmarshal(body, &iisMetrics)
	if err != nil {
		logrus.WithField("err", err).Error("Unmarshal response has an error")
		return nil, err
	}
	iisMetrics.Addr = addr
	return &iisMetrics, nil
}
