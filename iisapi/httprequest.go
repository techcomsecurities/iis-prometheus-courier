
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

// /api/webserver/http-request-monitor/requests
/*
{
    "requests": [
        {
            "url": "/TCPrice/signalr/connect?transport=webSockets&clientProtocol=1.5&connectionToken=JyDxORJfH2wEw7v3ADi%2BRUCybGprkBZ16C4bkwDEajEFcAxO%2B29bHPvEQwz9hgNbbz6eYvChIcGdlb6rRgpAjHWe0Bi0HgKZbBYUGMtg2%2FlUxcIeLNJgT7gLgdFkyfrx&connectionData=%5B%7B%22name%22%3A%22pbhub%22%7D%5D&tid=0",
            "id": "FKoIkWSQ_M6LPjQvL3slnfCXR1HkyzodSvcFexjcEbE",
            "time_elapsed": "24214484",
            "_links": {
                "self": {
                    "href": "/api/webserver/http-request-monitor/requests/FKoIkWSQ_M6LPjQvL3slnfCXR1HkyzodSvcFexjcEbE"
                }
            }
        }
    ]
}
*/
type HttpRequestMetrics struct {
	Url string `json:"url"`
	Id  string `json:"id"`
	TimeElapsed float64 `json:"time_elapsed"`
}
type HttpRequestMetricsRes struct {
	Requests []HttpRequestMetrics `json:"requests"`
}
func GetHttpRequestMetrics(user,pass,addr, token string)  (*HttpRequestMetricsRes, error){
	url := addr + "/api/webserver/http-request-monitor/requests"
	logrus.Infof("Connecting to api %s ", url)
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

	logrus.Infof("response Status: %v", resp.Status)

	var ap HttpRequestMetricsRes
	json.Unmarshal(body, &ap)
	return &ap, nil
}

