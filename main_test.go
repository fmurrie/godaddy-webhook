//go:build integration

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/test/acme"
)

var (
	zone      = os.Getenv("TEST_ZONE_NAME")
	dnsServer = os.Getenv("TEST_DNS_SERVER")
)

func TestRunsSuite(t *testing.T) {
	testToken := os.Getenv("GODADDY_TEST_TOKEN")
	if testToken == "" {
		t.Skip("set GODADDY_TEST_TOKEN to run the GoDaddy DNS conformance suite")
	}
	if zone == "" {
		t.Fatal("set TEST_ZONE_NAME to run the GoDaddy DNS conformance suite")
	}

	fixturePath := t.TempDir()
	config, err := os.ReadFile("testdata/godaddy/config.json")
	if err != nil {
		t.Fatalf("read webhook test config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixturePath, "config.json"), config, 0o600); err != nil {
		t.Fatalf("write webhook test config: %v", err)
	}

	secretManifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: godaddy-credentials
type: Opaque
data:
  token: %s
`, base64.StdEncoding.EncodeToString([]byte(testToken)))
	if err := os.WriteFile(filepath.Join(fixturePath, "godaddy-credentials.yaml"), []byte(secretManifest), 0o600); err != nil {
		t.Fatalf("write temporary GoDaddy credential fixture: %v", err)
	}

	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.

	pollTime, _ := time.ParseDuration("5s")
	timeOut, _ := time.ParseDuration("3m")

	if dnsServer == "" {
		dnsServer = "1.1.1.1:53"
	}

	fixture := dns.NewFixture(&godaddyDNSSolver{},
		dns.SetResolvedZone(zone),
		dns.SetAllowAmbientCredentials(false),
		dns.SetManifestPath(fixturePath),
		dns.SetDNSServer(dnsServer),
		dns.SetUseAuthoritative(false),

		// Disable the extended test as godaddy do not support to create several records for the same Record DNS Name !!
		dns.SetStrict(false),

		// Increase the poll interval to 10s
		dns.SetPollInterval(pollTime),
		// Increase the limit from 2 min to 5 min
		dns.SetPropagationLimit(timeOut),
	)

	fixture.RunConformance(t)
}
