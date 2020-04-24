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

type Href struct {
	Href string `json:"href"`
}
type Links struct {
	Self Href `json:"self"`

}
type ApplicationPool struct {
	Name string `json:"name"`
	Id string `json:"id"`
	Status string `json:"status"`
	Links Links `json:"_links"`
}
type ApplicationPoolResp struct {
	AppPools []ApplicationPool `json:"app_pools"`
}

type CpuApplicationPool struct {
	Limit float64 `json:"limit"`
	LimitInterval float64 `json:"limit_interval"`
}

type LinkApplicationPool struct {
	Monitoring Href `json:"monitoring"`
	WorkerProcesses Href `json:"worker_processes"`
}
type ApplicationPoolDetailResp struct {
	Name string `json:"name"`
	Id string `json:"id"`
	Status string `json:"status"`
	QueueLength float64 `json:"queue_length"`
	Cpu CpuApplicationPool `json:"cpu"`
	Links LinkApplicationPool `json:"_links"`
}

// Path: /api/webserver/application-pools
/**
{
    "app_pools": [
        {
            "name": "DefaultAppPool",
            "id": "HxxfhsjqAbqPv_JvPwV-cw",
            "status": "started",
            "_links": {
                "self": {
                    "href": "/api/webserver/application-pools/HxxfhsjqAbqPv_JvPwV-cw"
                }
            }
        },
        {
            "name": "Classic .NET AppPool",
            "id": "WNTXbNJ8wuo2kAzl-NzaxoP9mIDGDydSkAmsMiTTI4w",
            "status": "started",
            "_links": {
                "self": {
                    "href": "/api/webserver/application-pools/WNTXbNJ8wuo2kAzl-NzaxoP9mIDGDydSkAmsMiTTI4w"
                }
            }
        }
 	]
}
 */
func GetApplicationPool(user,pass,addr, token string) (*ApplicationPoolResp, error) {
	url := addr + "/api/webserver/application-pools"
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

	var ap ApplicationPoolResp
	json.Unmarshal(body, &ap)
	return &ap, nil
}
// Path: /api/webserver/application-pools/HxxfhsjqAbqPv_JvPwV-cw
/*
{
    "name": "DefaultAppPool",
    "id": "HxxfhsjqAbqPv_JvPwV-cw",
    "status": "started",
    "auto_start": "true",
    "pipeline_mode": "integrated",
    "managed_runtime_version": "v4.0",
    "enable_32bit_win64": "false",
    "queue_length": "1000",
    "cpu": {
        "limit": "0",
        "limit_interval": "5",
        "action": "NoAction",
        "processor_affinity_enabled": "false",
        "processor_affinity_mask32": "0xFFFFFFFF",
        "processor_affinity_mask64": "0xFFFFFFFF"
    },
    "process_model": {
        "idle_timeout": "20",
        "max_processes": "1",
        "pinging_enabled": "true",
        "ping_interval": "30",
        "ping_response_time": "90",
        "shutdown_time_limit": "90",
        "startup_time_limit": "90",
        "idle_timeout_action": "Terminate"
    },
    "identity": {
        "identity_type": "ApplicationPoolIdentity",
        "username": "",
        "load_user_profile": "false"
    },
    "recycling": {
        "disable_overlapped_recycle": "false",
        "disable_recycle_on_config_change": "false",
        "log_events": {
            "time": "true",
            "requests": "false",
            "schedule": "false",
            "memory": "true",
            "isapi_unhealthy": "false",
            "on_demand": "false",
            "config_change": "false",
            "private_memory": "true"
        },
        "periodic_restart": {
            "time_interval": "1740",
            "private_memory": "0",
            "request_limit": "0",
            "virtual_memory": "0",
            "schedule": []
        }
    },
    "rapid_fail_protection": {
        "enabled": "true",
        "load_balancer_capabilities": "HttpLevel",
        "interval": "5",
        "max_crashes": "5",
        "auto_shutdown_exe": "",
        "auto_shutdown_params": ""
    },
    "process_orphaning": {
        "enabled": "false",
        "orphan_action_exe": "",
        "orphan_action_params": ""
    },
    "_links": {
        "monitoring": {
            "href": "/api/webserver/application-pools/monitoring/HxxfhsjqAbqPv_JvPwV-cw"
        },
        "self": {
            "href": "/api/webserver/application-pools/HxxfhsjqAbqPv_JvPwV-cw"
        },
        "webapps": {
            "href": "/api/webserver/webapps?application_pool.id=HxxfhsjqAbqPv_JvPwV-cw"
        },
        "websites": {
            "href": "/api/webserver/websites?application_pool.id=HxxfhsjqAbqPv_JvPwV-cw"
        },
        "worker_processes": {
            "href": "/api/webserver/worker-processes?application_pool.id=HxxfhsjqAbqPv_JvPwV-cw"
        }
    }
}
*/
func GetApplicationPoolDetail(appPool ApplicationPool, user,pass,addr, token string) (*ApplicationPoolDetailResp, error) {
	url := addr + appPool.Links.Self.Href
	logrus.Infof("AppName %s connecting to api %s ", appPool.Name, url)
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

	var ap ApplicationPoolDetailResp
	json.Unmarshal(body, &ap)
	return &ap, nil
}
