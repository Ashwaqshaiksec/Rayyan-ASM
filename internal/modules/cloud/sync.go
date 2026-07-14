// Package cloud provides cloud provider asset enumeration via CLI tools.
// It uses aws, az, and gcloud CLIs rather than SDKs so no extra Go
// dependencies are required — only the binaries need to be installed.
package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Asset is a normalised cloud resource record, provider-agnostic.
type Asset struct {
	Provider     string // aws | azure | gcp
	AccountID    string // AWS account ID / Azure subscription / GCP project
	Region       string
	ResourceID   string // ARN / Azure resource ID / GCP self-link
	ResourceType string // e.g. ec2_instance, s3_bucket, vm, gke_cluster
	Name         string
	IPs          []string
	Tags         map[string]string
	Metadata     map[string]interface{}
	Status       string
}

// ProviderCreds holds credentials needed to configure the respective CLI.
type ProviderCreds struct {
	// AWS
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSSessionToken    string
	AWSRegion          string

	// Azure
	AzureClientID     string
	AzureClientSecret string
	AzureTenantID     string
	AzureSubID        string

	// GCP
	GCPServiceAccountJSON string // path to JSON key file OR raw JSON content
	GCPProject            string
}

// SyncAWS enumerates EC2 instances, S3 buckets, RDS instances, ELBs, and
// Lambda functions across all regions (or just the configured region if set).
func SyncAWS(ctx context.Context, creds ProviderCreds) ([]Asset, error) {
	env := awsEnv(creds)
	regions, err := awsListRegions(ctx, env, creds.AWSRegion)
	if err != nil {
		return nil, fmt.Errorf("aws list regions: %w", err)
	}

	accountID, _ := awsAccountID(ctx, env)

	var all []Asset
	for _, region := range regions {
		regionEnv := append(env, "AWS_DEFAULT_REGION="+region)

		// EC2 Instances
		ec2, err := awsEC2(ctx, regionEnv, accountID, region)
		if err == nil {
			all = append(all, ec2...)
		}

		// S3 Buckets (global, only enumerate once from the first region)
		if region == regions[0] {
			s3, err := awsS3(ctx, regionEnv, accountID)
			if err == nil {
				all = append(all, s3...)
			}
		}

		// RDS Instances
		rds, err := awsRDS(ctx, regionEnv, accountID, region)
		if err == nil {
			all = append(all, rds...)
		}

		// ELBv2 Load Balancers
		elb, err := awsELB(ctx, regionEnv, accountID, region)
		if err == nil {
			all = append(all, elb...)
		}

		// Lambda Functions
		lambda, err := awsLambda(ctx, regionEnv, accountID, region)
		if err == nil {
			all = append(all, lambda...)
		}
	}
	return all, nil
}

// SyncAzure enumerates VMs, Storage Accounts, SQL Servers, App Services,
// and AKS clusters across all resource groups in the subscription.
func SyncAzure(ctx context.Context, creds ProviderCreds) ([]Asset, error) {
	env := azureEnv(creds)

	// Login with service principal
	if creds.AzureClientID != "" {
		loginArgs := []string{
			"login", "--service-principal",
			"-u", creds.AzureClientID,
			"-p", creds.AzureClientSecret,
			"--tenant", creds.AzureTenantID,
			"--output", "none",
		}
		if err := runCLI(ctx, "az", loginArgs, env, 60*time.Second); err != nil {
			return nil, fmt.Errorf("az login: %w", err)
		}
	}

	subID := creds.AzureSubID
	if subID == "" {
		// Attempt to detect current subscription
		out, err := runCLIOut(ctx, "az", []string{"account", "show", "--query", "id", "-o", "tsv"}, env, 30*time.Second)
		if err == nil {
			subID = strings.TrimSpace(out)
		}
	}

	var all []Asset

	// VMs
	vms, err := azureVMs(ctx, env, subID)
	if err == nil {
		all = append(all, vms...)
	}

	// Storage Accounts
	sa, err := azureStorageAccounts(ctx, env, subID)
	if err == nil {
		all = append(all, sa...)
	}

	// App Services (Web Apps)
	apps, err := azureAppServices(ctx, env, subID)
	if err == nil {
		all = append(all, apps...)
	}

	// SQL Servers
	sql, err := azureSQLServers(ctx, env, subID)
	if err == nil {
		all = append(all, sql...)
	}

	// AKS Clusters
	aks, err := azureAKS(ctx, env, subID)
	if err == nil {
		all = append(all, aks...)
	}

	return all, nil
}

// SyncGCP enumerates Compute Engine VMs, GCS buckets, GKE clusters, Cloud SQL
// instances, and Cloud Run services in the given project.
func SyncGCP(ctx context.Context, creds ProviderCreds) ([]Asset, error) {
	env := gcpEnv(creds)

	project := creds.GCPProject
	if project == "" {
		out, err := runCLIOut(ctx, "gcloud", []string{"config", "get-value", "project"}, env, 30*time.Second)
		if err == nil {
			project = strings.TrimSpace(out)
		}
	}
	if project == "" {
		return nil, fmt.Errorf("gcp: no project configured")
	}

	var all []Asset

	// Compute Engine VMs
	vms, err := gcpComputeVMs(ctx, env, project)
	if err == nil {
		all = append(all, vms...)
	}

	// GCS Buckets
	buckets, err := gcpStorageBuckets(ctx, env, project)
	if err == nil {
		all = append(all, buckets...)
	}

	// GKE Clusters
	gke, err := gcpGKEClusters(ctx, env, project)
	if err == nil {
		all = append(all, gke...)
	}

	// Cloud SQL
	sql, err := gcpCloudSQL(ctx, env, project)
	if err == nil {
		all = append(all, sql...)
	}

	// Cloud Run
	run, err := gcpCloudRun(ctx, env, project)
	if err == nil {
		all = append(all, run...)
	}

	return all, nil
}

// ─── AWS helpers ─────────────────────────────────────────────────────────────

func awsEnv(c ProviderCreds) []string {
	env := []string{}
	if c.AWSAccessKeyID != "" {
		env = append(env, "AWS_ACCESS_KEY_ID="+c.AWSAccessKeyID)
	}
	if c.AWSSecretAccessKey != "" {
		env = append(env, "AWS_SECRET_ACCESS_KEY="+c.AWSSecretAccessKey)
	}
	if c.AWSSessionToken != "" {
		env = append(env, "AWS_SESSION_TOKEN="+c.AWSSessionToken)
	}
	if c.AWSRegion != "" {
		env = append(env, "AWS_DEFAULT_REGION="+c.AWSRegion)
	}
	return env
}

func awsAccountID(ctx context.Context, env []string) (string, error) {
	out, err := runCLIOut(ctx, "aws", []string{"sts", "get-caller-identity", "--query", "Account", "--output", "text"}, env, 30*time.Second)
	return strings.TrimSpace(out), err
}

func awsListRegions(ctx context.Context, env []string, override string) ([]string, error) {
	if override != "" {
		return []string{override}, nil
	}
	out, err := runCLIOut(ctx, "aws", []string{
		"ec2", "describe-regions",
		"--query", "Regions[].RegionName",
		"--output", "json",
	}, env, 30*time.Second)
	if err != nil {
		return []string{"us-east-1"}, nil // fallback
	}
	var regions []string
	if err := json.Unmarshal([]byte(out), &regions); err != nil {
		return []string{"us-east-1"}, nil
	}
	return regions, nil
}

func awsEC2(ctx context.Context, env []string, accountID, region string) ([]Asset, error) {
	out, err := runCLIOut(ctx, "aws", []string{
		"ec2", "describe-instances",
		"--query", "Reservations[].Instances[]",
		"--output", "json",
	}, env, 120*time.Second)
	if err != nil {
		return nil, err
	}
	var instances []struct {
		InstanceID       string                `json:"InstanceId"`
		InstanceType     string                `json:"InstanceType"`
		State            struct{ Name string } `json:"State"`
		PrivateIPAddress string                `json:"PrivateIpAddress"`
		PublicIPAddress  string                `json:"PublicIpAddress"`
		Tags             []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
	}
	if err := json.Unmarshal([]byte(out), &instances); err != nil {
		return nil, err
	}

	var assets []Asset
	for _, i := range instances {
		name := tagValue(i.Tags, "Name", i.InstanceID)
		tags := tagsToMap(i.Tags)
		ips := filterEmpty(i.PrivateIPAddress, i.PublicIPAddress)
		assets = append(assets, Asset{
			Provider:     "aws",
			AccountID:    accountID,
			Region:       region,
			ResourceID:   fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, i.InstanceID),
			ResourceType: "ec2_instance",
			Name:         name,
			IPs:          ips,
			Tags:         tags,
			Status:       i.State.Name,
			Metadata:     map[string]interface{}{"instance_type": i.InstanceType},
		})
	}
	return assets, nil
}

func awsS3(ctx context.Context, env []string, accountID string) ([]Asset, error) {
	out, err := runCLIOut(ctx, "aws", []string{
		"s3api", "list-buckets",
		"--query", "Buckets",
		"--output", "json",
	}, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var buckets []struct {
		Name         string `json:"Name"`
		CreationDate string `json:"CreationDate"`
	}
	if err := json.Unmarshal([]byte(out), &buckets); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, b := range buckets {
		assets = append(assets, Asset{
			Provider:     "aws",
			AccountID:    accountID,
			Region:       "global",
			ResourceID:   fmt.Sprintf("arn:aws:s3:::%s", b.Name),
			ResourceType: "s3_bucket",
			Name:         b.Name,
			Status:       "active",
			Metadata:     map[string]interface{}{"creation_date": b.CreationDate},
		})
	}
	return assets, nil
}

func awsRDS(ctx context.Context, env []string, accountID, region string) ([]Asset, error) {
	out, err := runCLIOut(ctx, "aws", []string{
		"rds", "describe-db-instances",
		"--query", "DBInstances",
		"--output", "json",
	}, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var dbs []struct {
		DBInstanceIdentifier string `json:"DBInstanceIdentifier"`
		DBInstanceStatus     string `json:"DBInstanceStatus"`
		Engine               string `json:"Engine"`
		EngineVersion        string `json:"EngineVersion"`
		Endpoint             struct {
			Address string `json:"Address"`
			Port    int    `json:"Port"`
		} `json:"Endpoint"`
	}
	if err := json.Unmarshal([]byte(out), &dbs); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, db := range dbs {
		ips := filterEmpty(db.Endpoint.Address)
		assets = append(assets, Asset{
			Provider:     "aws",
			AccountID:    accountID,
			Region:       region,
			ResourceID:   fmt.Sprintf("arn:aws:rds:%s:%s:db:%s", region, accountID, db.DBInstanceIdentifier),
			ResourceType: "rds_instance",
			Name:         db.DBInstanceIdentifier,
			IPs:          ips,
			Status:       db.DBInstanceStatus,
			Metadata:     map[string]interface{}{"engine": db.Engine, "engine_version": db.EngineVersion},
		})
	}
	return assets, nil
}

func awsELB(ctx context.Context, env []string, accountID, region string) ([]Asset, error) {
	out, err := runCLIOut(ctx, "aws", []string{
		"elbv2", "describe-load-balancers",
		"--query", "LoadBalancers",
		"--output", "json",
	}, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var lbs []struct {
		LoadBalancerArn  string                `json:"LoadBalancerArn"`
		LoadBalancerName string                `json:"LoadBalancerName"`
		DNSName          string                `json:"DNSName"`
		State            struct{ Code string } `json:"State"`
		Type             string                `json:"Type"`
	}
	if err := json.Unmarshal([]byte(out), &lbs); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, lb := range lbs {
		assets = append(assets, Asset{
			Provider:     "aws",
			AccountID:    accountID,
			Region:       region,
			ResourceID:   lb.LoadBalancerArn,
			ResourceType: "elb_" + strings.ToLower(lb.Type),
			Name:         lb.LoadBalancerName,
			IPs:          filterEmpty(lb.DNSName),
			Status:       lb.State.Code,
		})
	}
	return assets, nil
}

func awsLambda(ctx context.Context, env []string, accountID, region string) ([]Asset, error) {
	out, err := runCLIOut(ctx, "aws", []string{
		"lambda", "list-functions",
		"--query", "Functions",
		"--output", "json",
	}, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var fns []struct {
		FunctionArn  string `json:"FunctionArn"`
		FunctionName string `json:"FunctionName"`
		Runtime      string `json:"Runtime"`
	}
	if err := json.Unmarshal([]byte(out), &fns); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, fn := range fns {
		assets = append(assets, Asset{
			Provider:     "aws",
			AccountID:    accountID,
			Region:       region,
			ResourceID:   fn.FunctionArn,
			ResourceType: "lambda_function",
			Name:         fn.FunctionName,
			Status:       "active",
			Metadata:     map[string]interface{}{"runtime": fn.Runtime},
		})
	}
	return assets, nil
}

// ─── Azure helpers ────────────────────────────────────────────────────────────

func azureEnv(c ProviderCreds) []string {
	env := []string{}
	if c.AzureTenantID != "" {
		env = append(env, "AZURE_TENANT_ID="+c.AzureTenantID)
	}
	if c.AzureClientID != "" {
		env = append(env, "AZURE_CLIENT_ID="+c.AzureClientID)
	}
	if c.AzureClientSecret != "" {
		env = append(env, "AZURE_CLIENT_SECRET="+c.AzureClientSecret)
	}
	return env
}

func azureVMs(ctx context.Context, env []string, subID string) ([]Asset, error) {
	args := []string{"vm", "list", "--subscription", subID, "--show-details", "--output", "json"}
	out, err := runCLIOut(ctx, "az", args, env, 120*time.Second)
	if err != nil {
		return nil, err
	}
	var vms []struct {
		ID         string            `json:"id"`
		Name       string            `json:"name"`
		Location   string            `json:"location"`
		Tags       map[string]string `json:"tags"`
		PowerState string            `json:"powerState"`
		PublicIPs  string            `json:"publicIps"`
		PrivateIPs string            `json:"privateIps"`
	}
	if err := json.Unmarshal([]byte(out), &vms); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, vm := range vms {
		ips := parseCSV(vm.PublicIPs, vm.PrivateIPs)
		assets = append(assets, Asset{
			Provider:     "azure",
			AccountID:    subID,
			Region:       vm.Location,
			ResourceID:   vm.ID,
			ResourceType: "vm",
			Name:         vm.Name,
			IPs:          ips,
			Tags:         vm.Tags,
			Status:       vm.PowerState,
		})
	}
	return assets, nil
}

func azureStorageAccounts(ctx context.Context, env []string, subID string) ([]Asset, error) {
	args := []string{"storage", "account", "list", "--subscription", subID, "--output", "json"}
	out, err := runCLIOut(ctx, "az", args, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var accts []struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		Location         string            `json:"location"`
		Kind             string            `json:"kind"`
		Tags             map[string]string `json:"tags"`
		PrimaryEndpoints struct {
			Blob string `json:"blob"`
		} `json:"primaryEndpoints"`
	}
	if err := json.Unmarshal([]byte(out), &accts); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, a := range accts {
		assets = append(assets, Asset{
			Provider:     "azure",
			AccountID:    subID,
			Region:       a.Location,
			ResourceID:   a.ID,
			ResourceType: "storage_account",
			Name:         a.Name,
			Tags:         a.Tags,
			Status:       "active",
			Metadata:     map[string]interface{}{"kind": a.Kind, "blob_endpoint": a.PrimaryEndpoints.Blob},
		})
	}
	return assets, nil
}

func azureAppServices(ctx context.Context, env []string, subID string) ([]Asset, error) {
	args := []string{"webapp", "list", "--subscription", subID, "--output", "json"}
	out, err := runCLIOut(ctx, "az", args, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var apps []struct {
		ID              string            `json:"id"`
		Name            string            `json:"name"`
		Location        string            `json:"location"`
		State           string            `json:"state"`
		DefaultHostName string            `json:"defaultHostName"`
		Tags            map[string]string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(out), &apps); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, a := range apps {
		assets = append(assets, Asset{
			Provider:     "azure",
			AccountID:    subID,
			Region:       a.Location,
			ResourceID:   a.ID,
			ResourceType: "app_service",
			Name:         a.Name,
			IPs:          filterEmpty(a.DefaultHostName),
			Tags:         a.Tags,
			Status:       strings.ToLower(a.State),
		})
	}
	return assets, nil
}

func azureSQLServers(ctx context.Context, env []string, subID string) ([]Asset, error) {
	args := []string{"sql", "server", "list", "--subscription", subID, "--output", "json"}
	out, err := runCLIOut(ctx, "az", args, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var servers []struct {
		ID                       string            `json:"id"`
		Name                     string            `json:"name"`
		Location                 string            `json:"location"`
		FullyQualifiedDomainName string            `json:"fullyQualifiedDomainName"`
		State                    string            `json:"state"`
		Tags                     map[string]string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(out), &servers); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, s := range servers {
		assets = append(assets, Asset{
			Provider:     "azure",
			AccountID:    subID,
			Region:       s.Location,
			ResourceID:   s.ID,
			ResourceType: "sql_server",
			Name:         s.Name,
			IPs:          filterEmpty(s.FullyQualifiedDomainName),
			Tags:         s.Tags,
			Status:       strings.ToLower(s.State),
		})
	}
	return assets, nil
}

func azureAKS(ctx context.Context, env []string, subID string) ([]Asset, error) {
	args := []string{"aks", "list", "--subscription", subID, "--output", "json"}
	out, err := runCLIOut(ctx, "az", args, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var clusters []struct {
		ID                string            `json:"id"`
		Name              string            `json:"name"`
		Location          string            `json:"location"`
		ProvisioningState string            `json:"provisioningState"`
		Tags              map[string]string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(out), &clusters); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, cl := range clusters {
		assets = append(assets, Asset{
			Provider:     "azure",
			AccountID:    subID,
			Region:       cl.Location,
			ResourceID:   cl.ID,
			ResourceType: "aks_cluster",
			Name:         cl.Name,
			Tags:         cl.Tags,
			Status:       strings.ToLower(cl.ProvisioningState),
		})
	}
	return assets, nil
}

// ─── GCP helpers ─────────────────────────────────────────────────────────────

func gcpEnv(c ProviderCreds) []string {
	env := []string{}
	if c.GCPServiceAccountJSON != "" {
		env = append(env, "GOOGLE_APPLICATION_CREDENTIALS="+c.GCPServiceAccountJSON)
	}
	return env
}

func gcpComputeVMs(ctx context.Context, env []string, project string) ([]Asset, error) {
	out, err := runCLIOut(ctx, "gcloud", []string{
		"compute", "instances", "list",
		"--project", project,
		"--format", "json",
	}, env, 120*time.Second)
	if err != nil {
		return nil, err
	}
	var vms []struct {
		ID                string `json:"id"`
		Name              string `json:"name"`
		Zone              string `json:"zone"`
		Status            string `json:"status"`
		SelfLink          string `json:"selfLink"`
		MachineType       string `json:"machineType"`
		NetworkInterfaces []struct {
			NetworkIP     string `json:"networkIP"`
			AccessConfigs []struct {
				NatIP string `json:"natIP"`
			} `json:"accessConfigs"`
		} `json:"networkInterfaces"`
		Labels map[string]string `json:"labels"`
	}
	if err := json.Unmarshal([]byte(out), &vms); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, vm := range vms {
		zone := zoneShort(vm.Zone)
		var ips []string
		for _, ni := range vm.NetworkInterfaces {
			if ni.NetworkIP != "" {
				ips = append(ips, ni.NetworkIP)
			}
			for _, ac := range ni.AccessConfigs {
				if ac.NatIP != "" {
					ips = append(ips, ac.NatIP)
				}
			}
		}
		assets = append(assets, Asset{
			Provider:     "gcp",
			AccountID:    project,
			Region:       zone,
			ResourceID:   vm.SelfLink,
			ResourceType: "compute_instance",
			Name:         vm.Name,
			IPs:          ips,
			Tags:         vm.Labels,
			Status:       strings.ToLower(vm.Status),
			Metadata:     map[string]interface{}{"machine_type": machineTypeShort(vm.MachineType)},
		})
	}
	return assets, nil
}

func gcpStorageBuckets(ctx context.Context, env []string, project string) ([]Asset, error) {
	out, err := runCLIOut(ctx, "gcloud", []string{
		"storage", "buckets", "list",
		"--project", project,
		"--format", "json(name,location,storageClass,selfLink)",
	}, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var buckets []struct {
		Name         string `json:"name"`
		Location     string `json:"location"`
		StorageClass string `json:"storageClass"`
		SelfLink     string `json:"selfLink"`
	}
	if err := json.Unmarshal([]byte(out), &buckets); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, b := range buckets {
		assets = append(assets, Asset{
			Provider:     "gcp",
			AccountID:    project,
			Region:       strings.ToLower(b.Location),
			ResourceID:   b.SelfLink,
			ResourceType: "gcs_bucket",
			Name:         b.Name,
			Status:       "active",
			Metadata:     map[string]interface{}{"storage_class": b.StorageClass},
		})
	}
	return assets, nil
}

func gcpGKEClusters(ctx context.Context, env []string, project string) ([]Asset, error) {
	out, err := runCLIOut(ctx, "gcloud", []string{
		"container", "clusters", "list",
		"--project", project,
		"--format", "json",
	}, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var clusters []struct {
		Name     string `json:"name"`
		Location string `json:"location"`
		Status   string `json:"status"`
		SelfLink string `json:"selfLink"`
		Endpoint string `json:"endpoint"`
	}
	if err := json.Unmarshal([]byte(out), &clusters); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, cl := range clusters {
		assets = append(assets, Asset{
			Provider:     "gcp",
			AccountID:    project,
			Region:       cl.Location,
			ResourceID:   cl.SelfLink,
			ResourceType: "gke_cluster",
			Name:         cl.Name,
			IPs:          filterEmpty(cl.Endpoint),
			Status:       strings.ToLower(cl.Status),
		})
	}
	return assets, nil
}

func gcpCloudSQL(ctx context.Context, env []string, project string) ([]Asset, error) {
	out, err := runCLIOut(ctx, "gcloud", []string{
		"sql", "instances", "list",
		"--project", project,
		"--format", "json",
	}, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var instances []struct {
		Name            string `json:"name"`
		Region          string `json:"region"`
		State           string `json:"state"`
		SelfLink        string `json:"selfLink"`
		DatabaseVersion string `json:"databaseVersion"`
		IPAddresses     []struct {
			IPAddress string `json:"ipAddress"`
		} `json:"ipAddresses"`
	}
	if err := json.Unmarshal([]byte(out), &instances); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, i := range instances {
		var ips []string
		for _, ip := range i.IPAddresses {
			ips = append(ips, ip.IPAddress)
		}
		assets = append(assets, Asset{
			Provider:     "gcp",
			AccountID:    project,
			Region:       i.Region,
			ResourceID:   i.SelfLink,
			ResourceType: "cloud_sql",
			Name:         i.Name,
			IPs:          ips,
			Status:       strings.ToLower(i.State),
			Metadata:     map[string]interface{}{"database_version": i.DatabaseVersion},
		})
	}
	return assets, nil
}

func gcpCloudRun(ctx context.Context, env []string, project string) ([]Asset, error) {
	out, err := runCLIOut(ctx, "gcloud", []string{
		"run", "services", "list",
		"--project", project,
		"--format", "json",
		"--platform", "managed",
	}, env, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var services []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Status struct {
			URL        string `json:"url"`
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &services); err != nil {
		return nil, err
	}
	var assets []Asset
	for _, svc := range services {
		status := "unknown"
		for _, cond := range svc.Status.Conditions {
			if cond.Type == "Ready" {
				status = strings.ToLower(cond.Status)
			}
		}
		assets = append(assets, Asset{
			Provider:     "gcp",
			AccountID:    project,
			Region:       "global",
			ResourceID:   fmt.Sprintf("//run.googleapis.com/projects/%s/services/%s", project, svc.Metadata.Name),
			ResourceType: "cloud_run_service",
			Name:         svc.Metadata.Name,
			IPs:          filterEmpty(svc.Status.URL),
			Status:       status,
		})
	}
	return assets, nil
}

// ─── Shared CLI helpers ───────────────────────────────────────────────────────

// runCLI runs a CLI command and discards output, returning only the error.
func runCLI(ctx context.Context, binary string, args []string, extraEnv []string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204
	if len(extraEnv) > 0 {
		cmd.Env = append(cmd.Environ(), extraEnv...)
	}
	return cmd.Run()
}

// runCLIOut runs a CLI command and returns stdout as a string.
func runCLIOut(ctx context.Context, binary string, args []string, extraEnv []string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204
	if len(extraEnv) > 0 {
		cmd.Env = append(cmd.Environ(), extraEnv...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// ─── Utility ─────────────────────────────────────────────────────────────────

func filterEmpty(vals ...string) []string {
	var out []string
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseCSV(vals ...string) []string {
	var out []string
	for _, v := range vals {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func tagValue(tags []struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}, key, fallback string) string {
	for _, t := range tags {
		if t.Key == key {
			return t.Value
		}
	}
	return fallback
}

func tagsToMap(tags []struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}) map[string]string {
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[t.Key] = t.Value
	}
	return m
}

// zoneShort trims the GCP zone URL to just the zone name, e.g.
// "https://…/zones/us-central1-a" → "us-central1-a".
func zoneShort(zone string) string {
	parts := strings.Split(zone, "/")
	return parts[len(parts)-1]
}

// machineTypeShort trims the GCP machine type URL to just the type name.
func machineTypeShort(mt string) string {
	parts := strings.Split(mt, "/")
	return parts[len(parts)-1]
}
