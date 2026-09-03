package main

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestExtractPATFromSecretRejectsEmptyToken(t *testing.T) {
	t.Parallel()

	solver := &godaddyDNSSolver{
		client: fake.NewSimpleClientset(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "godaddy-credentials",
				Namespace: "cert-manager",
			},
			Data: map[string][]byte{"token": []byte(" \n\t ")},
		}),
	}
	cfg := &godaddyDNSProviderConfig{
		APIKeySecretRef: certmanagerv1.SecretKeySelector{
			LocalObjectReference: certmanagerv1.LocalObjectReference{Name: "godaddy-credentials"},
			Key:                  "token",
		},
	}

	err := solver.extractPATFromSecret(cfg, &v1alpha1.ChallengeRequest{
		ResourceNamespace: "cert-manager",
	})
	if err == nil || !strings.Contains(err.Error(), "must contain a non-empty GoDaddy personal access token") {
		t.Fatalf("expected malformed token error, got %v", err)
	}
}

func TestExtractPATFromSecretTrimsWhitespace(t *testing.T) {
	t.Parallel()

	solver := &godaddyDNSSolver{
		client: fake.NewSimpleClientset(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "godaddy-credentials",
				Namespace: "cert-manager",
			},
			Data: map[string][]byte{"token": []byte("  godaddy-pat-value  \n")},
		}),
	}
	cfg := &godaddyDNSProviderConfig{
		APIKeySecretRef: certmanagerv1.SecretKeySelector{
			LocalObjectReference: certmanagerv1.LocalObjectReference{Name: "godaddy-credentials"},
			Key:                  "token",
		},
	}

	if err := solver.extractPATFromSecret(cfg, &v1alpha1.ChallengeRequest{
		ResourceNamespace: "cert-manager",
	}); err != nil {
		t.Fatalf("extract API token: %v", err)
	}

	if cfg.AuthToken != "godaddy-pat-value" {
		t.Fatalf("unexpected personal access token")
	}
}

func TestUpdateRecordsCreatesTXTRecordWithPOST(t *testing.T) {
	originalTransport := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", req.Method)
		}
		if req.URL.String() != "https://api.godaddy.com/v3/domains/zones/ownsuall.com/dns-records" {
			t.Fatalf("unexpected request URL: %s", req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Status:     "201 Created",
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})

	solver := &godaddyDNSSolver{}
	err := solver.UpdateRecords(&godaddyDNSProviderConfig{
		AuthToken:  "test-token",
		Production: true,
	}, []DNSRecord{{
		Type: "TXT",
		Name: "_acme-challenge",
		Data: "challenge-value",
		TTL:  600,
	}}, "ownsuall.com", "_acme-challenge")
	if err != nil {
		t.Fatalf("create TXT record: %v", err)
	}
}
