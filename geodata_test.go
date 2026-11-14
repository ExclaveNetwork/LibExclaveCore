package libexclavecore

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/exclavenetwork/exclave-core/v5/app/router/routercommon"
)

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.dat")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateGeoData(t *testing.T) {
	geoip, err := proto.Marshal(&routercommon.GeoIPList{Entry: []*routercommon.GeoIP{
		{CountryCode: "CN", Cidr: []*routercommon.CIDR{{Ip: []byte{10, 0, 0, 0}, Prefix: 8}}},
		{CountryCode: "PRIVATE"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	geosite, err := proto.Marshal(&routercommon.GeoSiteList{Entry: []*routercommon.GeoSite{
		{CountryCode: "GOOGLE", Domain: []*routercommon.Domain{{Type: routercommon.Domain_RootDomain, Value: "google.com"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	noCode, err := proto.Marshal(&routercommon.GeoIPList{Entry: []*routercommon.GeoIP{{}}})
	if err != nil {
		t.Fatal(err)
	}

	// Valid files are accepted by their own validator and by ValidateGeoDataFile.
	if err := ValidateGeoIPFile(writeTemp(t, geoip)); err != nil {
		t.Errorf("geoip: %v", err)
	}
	if err := ValidateGeoSiteFile(writeTemp(t, geosite)); err != nil {
		t.Errorf("geosite: %v", err)
	}
	if err := ValidateGeoDataFile(writeTemp(t, geoip)); err != nil {
		t.Errorf("geoip (any): %v", err)
	}
	if err := ValidateGeoDataFile(writeTemp(t, geosite)); err != nil {
		t.Errorf("geosite (any): %v", err)
	}

	// A GeoIPList is not a GeoSiteList and vice versa.
	if ValidateGeoSiteFile(writeTemp(t, geoip)) == nil {
		t.Error("geoip accepted as geosite")
	}
	if ValidateGeoIPFile(writeTemp(t, geosite)) == nil {
		t.Error("geosite accepted as geoip")
	}

	// Broken files are rejected by every validator.
	bad := map[string][]byte{
		"truncated":            geoip[:len(geoip)-3],
		"html":                 []byte("<!DOCTYPE html><html><body>Sign in to the network</body></html>"),
		"empty":                {},
		"missing country code": noCode,
	}
	for name, data := range bad {
		path := writeTemp(t, data)
		if ValidateGeoIPFile(path) == nil {
			t.Errorf("%s: ValidateGeoIPFile accepted a bad file", name)
		}
		if ValidateGeoSiteFile(path) == nil {
			t.Errorf("%s: ValidateGeoSiteFile accepted a bad file", name)
		}
		if ValidateGeoDataFile(path) == nil {
			t.Errorf("%s: ValidateGeoDataFile accepted a bad file", name)
		}
	}
	if ValidateGeoDataFile(filepath.Join(t.TempDir(), "missing.dat")) == nil {
		t.Error("missing file must fail")
	}
}
