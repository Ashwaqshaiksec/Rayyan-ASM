package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// CloudAssetResult holds a single resource discovered via a cloud CLI tool.
type CloudAssetResult struct {
	Provider     string                 `json:"provider"`
	ResourceID   string                 `json:"resource_id"`
	ResourceType string                 `json:"resource_type"`
	Name         string                 `json:"name"`
	Region       string                 `json:"region"`
	AccountID    string                 `json:"account_id"`
	IPs          []string               `json:"ips,omitempty"`
	Tags         map[string]string      `json:"tags,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// RunAWSEnum enumerates EC2 instances, S3 buckets, RDS instances, and ELBs
// using the AWS CLI. Credentials are picked up from the environment (AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION) or an IAM role — callers must
// ensure they are set before invoking.
func RunAWSEnum(region string, timeout time.Duration) ([]CloudAssetResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("aws")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("aws")
	}

	var results []CloudAssetResult
	var firstErr error

	// EC2 instances
	ec2Args := []string{"ec2", "describe-instances", "--output", "json"}
	if region != "" {
		ec2Args = append(ec2Args, "--region", region)
	}
	ec2Result := trtypes.Run(info.BinaryPath, ec2Args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("aws", ec2Result.Error == nil)
	if ec2Result.Error == nil {
		results = append(results, parseAWSEC2(ec2Result.Stdout, region)...)
	} else if firstErr == nil {
		firstErr = fmt.Errorf("aws ec2: %w", ec2Result.Error)
	}

	// S3 buckets
	s3Args := []string{"s3api", "list-buckets", "--output", "json"}
	s3Result := trtypes.Run(info.BinaryPath, s3Args, trtypes.RunOptions{Timeout: timeout})
	if s3Result.Error == nil {
		results = append(results, parseAWSS3(s3Result.Stdout)...)
	} else if firstErr == nil {
		firstErr = fmt.Errorf("aws s3api: %w", s3Result.Error)
	}

	// RDS instances
	rdsArgs := []string{"rds", "describe-db-instances", "--output", "json"}
	if region != "" {
		rdsArgs = append(rdsArgs, "--region", region)
	}
	rdsResult := trtypes.Run(info.BinaryPath, rdsArgs, trtypes.RunOptions{Timeout: timeout})
	if rdsResult.Error == nil {
		results = append(results, parseAWSRDS(rdsResult.Stdout, region)...)
	}

	// ELBv2 load balancers
	elbArgs := []string{"elbv2", "describe-load-balancers", "--output", "json"}
	if region != "" {
		elbArgs = append(elbArgs, "--region", region)
	}
	elbResult := trtypes.Run(info.BinaryPath, elbArgs, trtypes.RunOptions{Timeout: timeout})
	if elbResult.Error == nil {
		results = append(results, parseAWSELB(elbResult.Stdout, region)...)
	}

	if len(results) == 0 {
		return nil, firstErr
	}
	return results, nil
}

// RunAzureEnum enumerates Azure VMs and storage accounts using the Azure CLI.
// Callers must ensure `az login` has been run or a service principal is configured.
func RunAzureEnum(subscriptionID string, timeout time.Duration) ([]CloudAssetResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("az")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("az")
	}

	var results []CloudAssetResult
	var firstErr error

	// VMs
	vmArgs := []string{"vm", "list", "--output", "json"}
	if subscriptionID != "" {
		vmArgs = append(vmArgs, "--subscription", subscriptionID)
	}
	vmResult := trtypes.Run(info.BinaryPath, vmArgs, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("az", vmResult.Error == nil)
	if vmResult.Error == nil {
		results = append(results, parseAzureVMs(vmResult.Stdout, subscriptionID)...)
	} else if firstErr == nil {
		firstErr = fmt.Errorf("az vm list: %w", vmResult.Error)
	}

	// Storage accounts
	storageArgs := []string{"storage", "account", "list", "--output", "json"}
	if subscriptionID != "" {
		storageArgs = append(storageArgs, "--subscription", subscriptionID)
	}
	storageResult := trtypes.Run(info.BinaryPath, storageArgs, trtypes.RunOptions{Timeout: timeout})
	if storageResult.Error == nil {
		results = append(results, parseAzureStorage(storageResult.Stdout, subscriptionID)...)
	}

	if len(results) == 0 {
		return nil, firstErr
	}
	return results, nil
}

// RunGCPEnum enumerates GCP compute instances and Cloud Storage buckets using
// the gcloud CLI. Callers must ensure `gcloud auth application-default login`
// has been run or a service account key is active.
func RunGCPEnum(project string, timeout time.Duration) ([]CloudAssetResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("gcloud")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("gcloud")
	}

	var results []CloudAssetResult
	var firstErr error

	// Compute instances
	computeArgs := []string{"compute", "instances", "list", "--format=json"}
	if project != "" {
		computeArgs = append(computeArgs, "--project", project)
	}
	computeResult := trtypes.Run(info.BinaryPath, computeArgs, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("gcloud", computeResult.Error == nil)
	if computeResult.Error == nil {
		results = append(results, parseGCPInstances(computeResult.Stdout, project)...)
	} else if firstErr == nil {
		firstErr = fmt.Errorf("gcloud compute instances: %w", computeResult.Error)
	}

	// Cloud Storage buckets
	bucketsArgs := []string{"storage", "buckets", "list", "--format=json"}
	if project != "" {
		bucketsArgs = append(bucketsArgs, "--project", project)
	}
	bucketsResult := trtypes.Run(info.BinaryPath, bucketsArgs, trtypes.RunOptions{Timeout: timeout})
	if bucketsResult.Error == nil {
		results = append(results, parseGCPBuckets(bucketsResult.Stdout, project)...)
	}

	if len(results) == 0 {
		return nil, firstErr
	}
	return results, nil
}

// --- AWS parsers ---

func parseAWSEC2(stdout, region string) []CloudAssetResult {
	var response struct {
		Reservations []struct {
			Instances []struct {
				InstanceID string `json:"InstanceId"`
				State      struct {
					Name string `json:"Name"`
				} `json:"State"`
				Tags []struct {
					Key   string `json:"Key"`
					Value string `json:"Value"`
				} `json:"Tags"`
				PublicIPAddress  string `json:"PublicIpAddress"`
				PrivateIPAddress string `json:"PrivateIpAddress"`
				Placement        struct {
					AvailabilityZone string `json:"AvailabilityZone"`
				} `json:"Placement"`
			} `json:"Instances"`
		} `json:"Reservations"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		return nil
	}
	var out []CloudAssetResult
	for _, res := range response.Reservations {
		for _, inst := range res.Instances {
			tags := make(map[string]string)
			name := inst.InstanceID
			for _, t := range inst.Tags {
				tags[t.Key] = t.Value
				if t.Key == "Name" {
					name = t.Value
				}
			}
			var ips []string
			if inst.PublicIPAddress != "" {
				ips = append(ips, inst.PublicIPAddress)
			}
			if inst.PrivateIPAddress != "" {
				ips = append(ips, inst.PrivateIPAddress)
			}
			r := region
			if r == "" {
				r = strings.TrimRight(inst.Placement.AvailabilityZone, "abcde")
			}
			out = append(out, CloudAssetResult{
				Provider:     "aws",
				ResourceID:   inst.InstanceID,
				ResourceType: "ec2",
				Name:         name,
				Region:       r,
				IPs:          ips,
				Tags:         tags,
				Metadata:     map[string]interface{}{"state": inst.State.Name},
			})
		}
	}
	return out
}

func parseAWSS3(stdout string) []CloudAssetResult {
	var response struct {
		Buckets []struct {
			Name         string `json:"Name"`
			CreationDate string `json:"CreationDate"`
		} `json:"Buckets"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		return nil
	}
	var out []CloudAssetResult
	for _, b := range response.Buckets {
		out = append(out, CloudAssetResult{
			Provider:     "aws",
			ResourceID:   b.Name,
			ResourceType: "s3",
			Name:         b.Name,
			Metadata:     map[string]interface{}{"creation_date": b.CreationDate},
		})
	}
	return out
}

func parseAWSRDS(stdout, region string) []CloudAssetResult {
	var response struct {
		DBInstances []struct {
			DBInstanceIdentifier string `json:"DBInstanceIdentifier"`
			DBInstanceClass      string `json:"DBInstanceClass"`
			Engine               string `json:"Engine"`
			AvailabilityZone     string `json:"AvailabilityZone"`
			Endpoint             struct {
				Address string `json:"Address"`
				Port    int    `json:"Port"`
			} `json:"Endpoint"`
		} `json:"DBInstances"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		return nil
	}
	var out []CloudAssetResult
	for _, db := range response.DBInstances {
		r := region
		if r == "" {
			r = strings.TrimRight(db.AvailabilityZone, "abcde")
		}
		var ips []string
		if db.Endpoint.Address != "" {
			ips = append(ips, db.Endpoint.Address)
		}
		out = append(out, CloudAssetResult{
			Provider:     "aws",
			ResourceID:   db.DBInstanceIdentifier,
			ResourceType: "rds",
			Name:         db.DBInstanceIdentifier,
			Region:       r,
			IPs:          ips,
			Metadata:     map[string]interface{}{"engine": db.Engine, "class": db.DBInstanceClass},
		})
	}
	return out
}

func parseAWSELB(stdout, region string) []CloudAssetResult {
	var response struct {
		LoadBalancers []struct {
			LoadBalancerArn  string `json:"LoadBalancerArn"`
			LoadBalancerName string `json:"LoadBalancerName"`
			Type             string `json:"Type"`
			DNSName          string `json:"DNSName"`
		} `json:"LoadBalancers"`
	}
	if err := json.Unmarshal([]byte(stdout), &response); err != nil {
		return nil
	}
	var out []CloudAssetResult
	for _, lb := range response.LoadBalancers {
		var ips []string
		if lb.DNSName != "" {
			ips = append(ips, lb.DNSName)
		}
		out = append(out, CloudAssetResult{
			Provider:     "aws",
			ResourceID:   lb.LoadBalancerArn,
			ResourceType: "elb",
			Name:         lb.LoadBalancerName,
			Region:       region,
			IPs:          ips,
			Metadata:     map[string]interface{}{"type": lb.Type},
		})
	}
	return out
}

// --- Azure parsers ---

func parseAzureVMs(stdout, subscriptionID string) []CloudAssetResult {
	var vms []struct {
		Name     string            `json:"name"`
		ID       string            `json:"id"`
		Location string            `json:"location"`
		Tags     map[string]string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(stdout), &vms); err != nil {
		return nil
	}
	var out []CloudAssetResult
	for _, vm := range vms {
		out = append(out, CloudAssetResult{
			Provider:     "azure",
			ResourceID:   vm.ID,
			ResourceType: "vm",
			Name:         vm.Name,
			Region:       vm.Location,
			AccountID:    subscriptionID,
			Tags:         vm.Tags,
		})
	}
	return out
}

func parseAzureStorage(stdout, subscriptionID string) []CloudAssetResult {
	var accounts []struct {
		Name     string            `json:"name"`
		ID       string            `json:"id"`
		Location string            `json:"location"`
		Tags     map[string]string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(stdout), &accounts); err != nil {
		return nil
	}
	var out []CloudAssetResult
	for _, a := range accounts {
		out = append(out, CloudAssetResult{
			Provider:     "azure",
			ResourceID:   a.ID,
			ResourceType: "storage_account",
			Name:         a.Name,
			Region:       a.Location,
			AccountID:    subscriptionID,
			Tags:         a.Tags,
		})
	}
	return out
}

// --- GCP parsers ---

func parseGCPInstances(stdout, project string) []CloudAssetResult {
	var instances []struct {
		Name              string            `json:"name"`
		ID                string            `json:"id"`
		Zone              string            `json:"zone"`
		Status            string            `json:"status"`
		Labels            map[string]string `json:"labels"`
		NetworkInterfaces []struct {
			NetworkIP     string `json:"networkIP"`
			AccessConfigs []struct {
				NatIP string `json:"natIP"`
			} `json:"accessConfigs"`
		} `json:"networkInterfaces"`
	}
	if err := json.Unmarshal([]byte(stdout), &instances); err != nil {
		return nil
	}
	var out []CloudAssetResult
	for _, inst := range instances {
		zone := inst.Zone
		if idx := strings.LastIndex(zone, "/"); idx >= 0 {
			zone = zone[idx+1:]
		}
		region := zone
		if len(zone) > 2 {
			region = zone[:len(zone)-2]
		}
		var ips []string
		for _, ni := range inst.NetworkInterfaces {
			if ni.NetworkIP != "" {
				ips = append(ips, ni.NetworkIP)
			}
			for _, ac := range ni.AccessConfigs {
				if ac.NatIP != "" {
					ips = append(ips, ac.NatIP)
				}
			}
		}
		out = append(out, CloudAssetResult{
			Provider:     "gcp",
			ResourceID:   inst.ID,
			ResourceType: "compute_instance",
			Name:         inst.Name,
			Region:       region,
			AccountID:    project,
			IPs:          ips,
			Tags:         inst.Labels,
			Metadata:     map[string]interface{}{"status": inst.Status},
		})
	}
	return out
}

func parseGCPBuckets(stdout, project string) []CloudAssetResult {
	var buckets []struct {
		Name     string            `json:"name"`
		Location string            `json:"location"`
		Labels   map[string]string `json:"labels"`
	}
	if err := json.Unmarshal([]byte(stdout), &buckets); err != nil {
		return nil
	}
	var out []CloudAssetResult
	for _, b := range buckets {
		out = append(out, CloudAssetResult{
			Provider:     "gcp",
			ResourceID:   b.Name,
			ResourceType: "gcs_bucket",
			Name:         b.Name,
			Region:       strings.ToLower(b.Location),
			AccountID:    project,
			Tags:         b.Labels,
		})
	}
	return out
}
