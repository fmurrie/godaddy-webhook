package main

import (
	"strings"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestExtractAPITokenFromSecretRejectsMalformedToken(t *testing.T) {
	t.Parallel()

	solver := &godaddyDNSSolver{
		client: fake.NewSimpleClientset(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "godaddy-credentials",
				Namespace: "cert-manager",
			},
			Data: map[string][]byte{"token": []byte("missing-separator")},
		}),
	}
	cfg := &godaddyDNSProviderConfig{
		APIKeySecretRef: certmanagerv1.SecretKeySelector{
			LocalObjectReference: certmanagerv1.LocalObjectReference{Name: "godaddy-credentials"},
			Key:                  "token",
		},
	}

	err := solver.extractApiTokenFromSecret(cfg, &v1alpha1.ChallengeRequest{
		ResourceNamespace: "cert-manager",
	})
	if err == nil || !strings.Contains(err.Error(), "must contain a non-empty GoDaddy API key") {
		t.Fatalf("expected malformed token error, got %v", err)
	}
}

func TestExtractAPITokenFromSecretPreservesColonInSecret(t *testing.T) {
	t.Parallel()

	solver := &godaddyDNSSolver{
		client: fake.NewSimpleClientset(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "godaddy-credentials",
				Namespace: "cert-manager",
			},
			Data: map[string][]byte{"token": []byte("api-key:api-secret:with-colon")},
		}),
	}
	cfg := &godaddyDNSProviderConfig{
		APIKeySecretRef: certmanagerv1.SecretKeySelector{
			LocalObjectReference: certmanagerv1.LocalObjectReference{Name: "godaddy-credentials"},
			Key:                  "token",
		},
	}

	if err := solver.extractApiTokenFromSecret(cfg, &v1alpha1.ChallengeRequest{
		ResourceNamespace: "cert-manager",
	}); err != nil {
		t.Fatalf("extract API token: %v", err)
	}

	if cfg.AuthAPIKey != "api-key" || cfg.AuthAPISecret != "api-secret:with-colon" {
		t.Fatalf("unexpected parsed credential components")
	}
}
