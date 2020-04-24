package iisapi

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
	"testing"
)

func TestGetApplicationPool(t *testing.T) {
	appPoolResp,err := GetApplicationPool("sangnv","Tcbs123","https://10.7.2.4:55539","gYke24iXNg8JmNR_SbsLmWgfVef-SnqLqhIOZdv8F8qaTXW0gNCg9g")
	if err != nil{
		t.Fatalf("Unexpected error: %s", err)
	}
	rjson,_:= json.Marshal(appPoolResp)
	logrus.Infof("appPoolResp %s", string(rjson))

	for _, appPool := range appPoolResp.AppPools {
		appPoolDetailResp, err := GetApplicationPoolDetail(appPool,"sangnv","Tcbs123","https://10.7.2.4:55539","gYke24iXNg8JmNR_SbsLmWgfVef-SnqLqhIOZdv8F8qaTXW0gNCg9g")
		if err != nil{
			t.Fatalf("Unexpected error: %s", err)
			continue
		}
		logrus.Infof("Name %s Monitoring href: %s", appPoolDetailResp.Name, appPoolDetailResp.Links.Monitoring.Href)
	}
}