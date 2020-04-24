package iisapi

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
	"testing"
)

func TestGetMetrics(t *testing.T) {
	r,err := GetMetrics("/api/webserver/monitoring","sangnv","Tcbs123","https://10.7.2.4:55539","gYke24iXNg8JmNR_SbsLmWgfVef-SnqLqhIOZdv8F8qaTXW0gNCg9g")
	if err != nil{
		t.Fatalf("Unexpected error: %s", err)
	}
	rjson,_:= json.Marshal(r)
	logrus.Infof("rjson %s", string(rjson))
}
