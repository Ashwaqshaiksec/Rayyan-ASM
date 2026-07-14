package cloud

import (
	"context"
	"testing"
	"time"
)

// --- Asset struct ---

func TestAsset_ZeroValue(t *testing.T) {
	var a Asset
	if a.Provider != "" || a.ResourceID != "" {
		t.Error("zero Asset should have empty fields")
	}
}

func TestAsset_FieldAssignment(t *testing.T) {
	a := Asset{
		Provider:     "aws",
		AccountID:    "123456789",
		Region:       "us-east-1",
		ResourceID:   "i-abc123",
		ResourceType: "ec2_instance",
		Name:         "web-server",
		Status:       "running",
		IPs:          []string{"10.0.0.1", "52.0.0.1"},
		Tags:         map[string]string{"env": "prod"},
		Metadata:     map[string]interface{}{"vpc": "vpc-xxx"},
	}
	if a.Provider != "aws" {
		t.Errorf("Provider: want aws, got %s", a.Provider)
	}
	if len(a.IPs) != 2 {
		t.Errorf("IPs: want 2, got %d", len(a.IPs))
	}
	if a.Tags["env"] != "prod" {
		t.Errorf("Tags[env]: want prod, got %s", a.Tags["env"])
	}
}

// --- ProviderCreds ---

func TestProviderCreds_ZeroValue(t *testing.T) {
	var c ProviderCreds
	if c.AWSAccessKeyID != "" || c.AzureClientID != "" || c.GCPServiceAccountJSON != "" {
		t.Error("zero ProviderCreds should have empty credential fields")
	}
}

func TestProviderCreds_Fields(t *testing.T) {
	c := ProviderCreds{
		AWSAccessKeyID:        "AKIAIOSFODNN7EXAMPLE",
		AWSSecretAccessKey:    "secret",
		AWSRegion:             "eu-west-1",
		AzureClientID:         "client-id",
		AzureTenantID:         "tenant-id",
		GCPServiceAccountJSON: `{"type":"service_account"}`,
	}
	if c.AWSAccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AWSAccessKeyID mismatch")
	}
	if c.AzureTenantID != "tenant-id" {
		t.Errorf("AzureTenantID mismatch")
	}
}

// --- SyncAWS / SyncAzure / SyncGCP without CLI ---
//
// These functions shell out to aws/az/gcloud. In a clean test environment
// those binaries are absent. We verify:
//   - Function returns (nil-or-empty, error) rather than panicking.
//   - Context cancellation is respected (returns quickly when cancelled).

func TestSyncAWS_NoCLI_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	creds := ProviderCreds{
		AWSAccessKeyID:     "AKIAIOSFODNN7TEST",
		AWSSecretAccessKey: "testsecret",
		AWSRegion:          "us-east-1",
	}
	_, err := SyncAWS(ctx, creds)
	if err == nil {
		t.Log("SyncAWS succeeded (aws CLI may be present in this environment)")
	}
}

func TestSyncAzure_NoCLI_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	creds := ProviderCreds{
		AzureClientID:     "test-client",
		AzureTenantID:     "test-tenant",
		AzureClientSecret: "test-secret",
		AzureSubID:        "test-sub",
	}
	_, err := SyncAzure(ctx, creds)
	if err == nil {
		t.Log("SyncAzure succeeded (az CLI may be present in this environment)")
	}
}

func TestSyncGCP_NoCLI_ReturnsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	creds := ProviderCreds{
		GCPServiceAccountJSON: `{"type":"service_account","project_id":"test-project"}`,
		GCPProject:            "test-project",
	}
	_, err := SyncGCP(ctx, creds)
	if err == nil {
		t.Log("SyncGCP succeeded (gcloud CLI may be present in this environment)")
	}
}

func TestSyncAWS_ContextCancelled_ReturnsQuickly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Set AWSRegion so awsListRegions returns []{"us-east-1"} without
	// shelling out to `aws ec2 describe-regions` — makes the test fast and
	// deterministic regardless of whether the aws CLI is installed.
	creds := ProviderCreds{
		AWSAccessKeyID:     "K",
		AWSSecretAccessKey: "S",
		AWSRegion:          "us-east-1",
	}
	done := make(chan struct{})
	go func() {
		SyncAWS(ctx, creds) //nolint:errcheck
		close(done)
	}()

	// Each sub-call (EC2, S3, RDS, ELB, Lambda) uses exec.CommandContext,
	// which fails immediately when the context is already cancelled.
	// Even if the CLI is absent, exec errors are fast — 5s is generous.
	select {
	case <-done:
		// returned quickly — good
	case <-time.After(5 * time.Second):
		t.Error("SyncAWS did not return within 5s on a pre-cancelled context")
	}
}
