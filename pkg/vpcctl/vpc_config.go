/*******************************************************************************
* IBM Cloud Kubernetes Service, 5737-D43
* (C) Copyright IBM Corp. 2021, 2023 All Rights Reserved.
*
* SPDX-License-Identifier: Apache2.0
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

package vpcctl

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"cloud.ibm.com/cloud-provider-ibm/pkg/klog"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"gopkg.in/gcfg.v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultPoolMemberQuota = 8 // Max pool member nodes / zone when externalTrafficPolicy:Cluster

	// envVarAPIKey is an environmental variable used to specify the API key to use for VPC operations
	envVarAPIKey = "VPCCTL_API_KEY" // #nosec G101 API key environment variable

	healthCheckDelayDefault = 5
	healthCheckDelayMin     = 2
	healthCheckDelayMax     = 60

	healthCheckRetriesDefault = 2
	healthCheckRetriesMin     = 1
	healthCheckRetriesMax     = 10

	healthCheckTimeoutDefault = 2
	healthCheckTimeoutMin     = 1
	healthCheckTimeoutMax     = 59

	idleConnTimeoutDefault = 50
	idleConnTimeoutMin     = 50
	idleConnTimeoutMax     = 7200

	// IAM Token Exchange URLs
	iamPrivateTokenExchangeURL         = "https://private.iam.cloud.ibm.com"      // #nosec G101 IBM Cloud iam prod private URL
	iamPublicTokenExchangeURL          = "https://iam.cloud.ibm.com"              // #nosec G101 IBM Cloud iam prod public URL
	iamStagePrivateTokenExchangeURL    = "https://private.iam.test.cloud.ibm.com" // #nosec G101 IBM Cloud iam stage private URL
	iamStageTestPublicTokenExchangeURL = "https://iam.stage1.bluemix.net"         // #nosec G101 IBM Cloud iam stage public URL

	// VpcEndpointIaaSBaseURL - baseURL for constructing the VPC infrastructure API Endpoint URL
	vpcEndpointIaaSProdURL  = "iaas.cloud.ibm.com"
	vpcEndpointIaaSStageURL = "iaasdev.cloud.ibm.com"

	nodeLabelDedicated     = "dedicated"
	nodeLabelInstanceID    = "ibm-cloud.kubernetes.io/instance-id"
	nodeLabelIpiInstanceID = "ibm-cloud.kubernetes.io/vpc-instance-id"
	nodeLabelZone          = "topology.kubernetes.io/zone"
	nodeLabelValueEdge     = "edge"
	nodeLabelInternalIP    = "ibm-cloud.kubernetes.io/internal-ip"

	serviceAnnotationEnableFeatures      = "service.kubernetes.io/ibm-load-balancer-cloud-provider-enable-features"
	serviceAnnotationIPType              = "service.kubernetes.io/ibm-load-balancer-cloud-provider-ip-type"
	serviceAnnotationHealthCheckDelay    = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-health-check-delay"
	serviceAnnotationHealthCheckPath     = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-health-check-path"
	serviceAnnotationHealthCheckPort     = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-health-check-port"
	serviceAnnotationHealthCheckProtocol = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-health-check-protocol"
	serviceAnnotationHealthCheckRetries  = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-health-check-retries"
	serviceAnnotationHealthCheckTimeout  = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-health-check-timeout"
	serviceAnnotationHealthCheckUDP      = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-health-check-udp"
	serviceAnnotationIdleConnTimeout     = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-idle-connection-timeout"
	serviceAnnotationLbName              = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-lb-name"
	serviceAnnotationMemberQuota         = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-member-quota"
	serviceAnnotationNodeSelector        = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-node-selector"
	serviceAnnotationPortRange           = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-port-range"
	serviceAnnotationSubnets             = "service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-subnets"
	serviceAnnotationZone                = "service.kubernetes.io/ibm-load-balancer-cloud-provider-zone"
	servicePrivateLB                     = "private"
	servicePublicLB                      = "public"

	// VpcCloudProviderNamespace - Namespace where config map is located that contains cluster VPC subnets
	VpcCloudProviderNamespace = "kube-system"
	// VpcCloudProviderConfigMap - Name of the config map that contains cluster VPC subnets
	VpcCloudProviderConfigMap = "ibm-cloud-provider-data"
	// VpcCloudProviderSubnetsKey - Data field in the config map that contains cluster VPC subnets
	VpcCloudProviderSubnetsKey = "vpc_subnet_ids"
	// VpcCloudProviderVpcIDKey - Data field in the config map that contains cluster VPC id
	VpcCloudProviderVpcIDKey = "vpc_id"

	// VpcProviderTypeFake - Fake SDK interface for VPC
	VpcProviderTypeFake = "fake"
	// VpcProviderTypeGen2 - IKS provider type for VPC Gen2
	VpcProviderTypeGen2 = "g2"
	// VpcProviderTypeSecret - IKS provider type - use value from storage-secret-store
	VpcProviderTypeSecret = "secret"

	// VpcSecretNamespace - Namespace where the secret is stored
	VpcSecretNamespace = "kube-system"
	// VpcSecretFileName - Name of the secret
	VpcSecretFileName = "storage-secret-store"
	// VpcClientDataKey - Key in the secret data where information can be found
	VpcClientDataKey = "slclient.toml"
)

// Global variables
var (
	// VpcGoRoutinesAllowed - Are GO routines allowed?  Can't use if called from CLI
	VpcGoRoutinesAllowed = false

	// vpcMapAsyncUpdates - Map of async update calls that are in progress, key=LB ID
	vpcMapAsyncUpdates = map[string]chan (string){} // Map/channel created by async update routine

	// vpcMapUpdateMutex - Map of sync.Mutex to prevent two update LBs from occurring at the same time, key=LB ID
	vpcMapUpdateMutex = map[string]*sync.Mutex{}
)

// InformerConfigMap is called to process the add/delete/update of a Kubernetes config map
func InformerConfigMap(configMap *v1.ConfigMap, action string) {
	// If the VPC environment has not been initialized, simply return
	vpc := GetCloudVpc()
	if vpc == nil {
		return
	}
	// Check the config map name to determine if the config map data needs to be refreshed
	if configMap.ObjectMeta.Namespace == VpcCloudProviderNamespace && configMap.ObjectMeta.Name == VpcCloudProviderConfigMap {
		klog.Infof("Config map %s/%s had been %s. Refresh the data from the config map", configMap.ObjectMeta.Namespace, configMap.ObjectMeta.Name, action)
		err := vpc.refreshClusterVpcSubnetIDs(configMap)
		if err != nil {
			klog.Warningf("Error occurred refreshing config map: %v", err)
		}
	}
}

// InformerConfigMapUpdate is called when a secret is changed
func InformerConfigMapUpdate(oldObj, newObj interface{}) {
	configMap := newObj.(*v1.ConfigMap)
	InformerConfigMap(configMap, "updated")
}

// InformerSecret is called to process the add/delete/update of a Kubernetes secret
func InformerSecret(secret *v1.Secret, action string) {
	// If the VPC environment has not been initialized, simply return
	vpc := GetCloudVpc()
	if vpc == nil {
		return
	}
	// Check the secret to determine if VPC settings need to be reset
	if (secret.ObjectMeta.Namespace == VpcSecretNamespace && secret.ObjectMeta.Name == VpcSecretFileName) ||
		(secret.ObjectMeta.Namespace == VpcSdnlbNamespace && secret.ObjectMeta.Name == VpcSdnlbFileName) {
		klog.Infof("VPC secret %s/%s had been %s. Reset the VPC config data", secret.ObjectMeta.Namespace, secret.ObjectMeta.Name, action)
		ResetCloudVpc()
	}
}

// InformerSecretAdd is called when a secret is added
func InformerSecretAdd(obj interface{}) {
	secret := obj.(*v1.Secret)
	InformerSecret(secret, "added")
}

// InformerSecretDelete is called when a secret is deleted
func InformerSecretDelete(obj interface{}) {
	secret := obj.(*v1.Secret)
	InformerSecret(secret, "deleted")
}

// InformerSecretUpdate is called when a secret is changed
func InformerSecretUpdate(oldObj, newObj interface{}) {
	secret := newObj.(*v1.Secret)
	InformerSecret(secret, "updated")
}

func SetInformers(informerFactory informers.SharedInformerFactory) {
	VpcGoRoutinesAllowed = true
	// By default, "IPI mode" will be set to false
	// If VPC initialized, grab "ipi mode" setting from VPC config
	ipiMode := false
	vpc := GetCloudVpc()
	if vpc != nil {
		ipiMode = vpc.Config.ipiMode
	}
	// The RBAC for cloud-controller-manager on IPI installed system does not allow watch/list on config maps.
	// A watch on kube-system/ibm-cloud-provider-data is not needed on IPI, since there is no network
	// microservice to update the subnet list
	if ipiMode {
		klog.Infof("Running in IPI mode. Do not configure watch on config maps")
	} else {
		klog.Infof("Configure watch on config maps and secrets")
		configMapInformer := informerFactory.Core().V1().ConfigMaps().Informer()
		// nolint:errcheck // Error return code was added in v0.26.0-beta.0. Ignore err for now
		configMapInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			UpdateFunc: InformerConfigMapUpdate,
		}) // #nosec G104 error is ignored for now
	}
	secretInformer := informerFactory.Core().V1().Secrets().Informer()
	// nolint:errcheck // Error return code was added in v0.26.0-beta.0. Ignore err for now
	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    InformerSecretAdd,
		DeleteFunc: InformerSecretDelete,
		UpdateFunc: InformerSecretUpdate,
	}) // #nosec G104 error is ignored for now
}

// --------------------------------------------------------------------------------------------------------------------
// VPCSecret struct for holding VPC information from the cluster secret
//
// NOTE:
// The keys listed below do NOT match what is actually stored in the secret.
// The keys names have been updated by replacing all underscores "_" with dashes "-".
// The GO package "gopkg.in/gcfg.v1" can not handle underscores in the key names.
// The values may also contain underscores. This is valid and allowed by: "gopkg.in/gcfg.v1"
type VPCSecret struct {
	// G2 VPC "2"
	G2TokenExchangeEndpointURL        string `gcfg:"g2-token-exchange-endpoint-url"`
	G2TokenExchangeEndpointPrivateURL string `gcfg:"g2-token-exchange-endpoint-private-url"`
	G2RIaaSEndpointURL                string `gcfg:"g2-riaas-endpoint-url"`
	G2RIaaSEndpointPrivateURL         string `gcfg:"g2-riaas-endpoint-private-url"`
	G2ResourceGroupID                 string `gcfg:"g2-resource-group-id"`
	G2APIKey                          string `gcfg:"g2-api-key"`

	// Generic flags
	Encryption      bool   `gcfg:"encryption"`
	ProviderType    string `gcfg:"provider-type"`
	IKSPrivateRoute string `gcfg:"iks-token-exchange-endpoint-private-url"`
}

// ClusterSecret contains the VPC information read from the secret.  Other data in the secret is not needed
type ClusterSecret struct {
	VPC VPCSecret
}

// --------------------------------------------------------------------------------------------------------------------

// ConfigVpc is the VPC configuration information
type ConfigVpc struct {
	// Externalized config settings from caller
	AccountID           string // Used to check if we are running on IPI installed cluster, is same as WorkerAccountID
	APIKeySecret        string // Used if specified otherwise value read from storage-secret
	ClusterID           string // Required
	EnablePrivate       bool   // Required
	IamEndpointOverride string // Optional
	ProviderType        string // Required, replaced by value from storage-secret. "g2" = Gen2, "fake" = test logic
	Region              string // Used if we are running on IPI installed cluster
	ResourceGroupName   string // Used if we are running on IPI installed cluster
	RmEndpointOverride  string // Optional
	SubnetNames         string // Used if we are running on IPI installed cluster
	WorkerAccountID     string // Required for NLB and sDNLB
	VpcName             string // Used if we are running on IPI installed cluster
	VpcEndpointOverride string // Optional
	// Internal config settings
	clusterCrnPrefix     string               // Read from cluster-config/config map. CRN prefix for the current environment
	clusterSubnetIDs     string               // Read from ibm-cloud-provider-data/config map
	computeResourceToken string               // Read from mounted volume or retrieved from debug tool pod
	encryption           bool                 // Read from storage-secret, Is the user's API key encrypted?
	endpointURL          string               // Read from storage-secret
	ipiMode              bool                 // IPI configuration passed into cloud controller manager
	kubeClient           kubernetes.Interface // Kubernetes client
	lbNameCache          map[string]string    // Cache of LB name to LB IDs
	lbSecurityGroupID    string               // Set during CreateLoadBalancer. ID of security group to attach to VPC ALBs
	resourceGroupID      string               // Read from storage-secret, resource group ID of the cluster
	resourceManagerURL   string               // Resource manager endpoint URL - used in IPI to convert resource group name to id
	securityGroupMutex   sync.Mutex           // Mutex to serial access to security group rule operations
	serviceAPIKey        string               // Read from sDNLB secret. API key of the sDNLB service ID
	serviceErr           string               // Error that occurred reading the sDNLB secret
	serviceType          string               // Read from sDNLB secret. Indicates which service endpoint to call
	tokenExchangeURL     string               // Read from storage-secret
	trustedProfileID     string               // Read from ibm-cloud-credentials secret
	vpcID                string               // Set during [Create/Update]LoadBalancer. VPC id for the IKS cluster. Needed for sDNLB CreateLB
}

// addLbToCache - add the specified LB to the cache
func (c *ConfigVpc) addLbToCache(lb *VpcLoadBalancer) {
	c.lbNameCache[lb.Name] = lb.ID
}

// adjustSecretData - Selectively replace underscores with dashes (only in the keys)
//
// This routine is needed because the GO package "gopkg.in/gcfg.v1" does not allow
// underscores to be used in the keys.
func (c *ConfigVpc) adjustSecretData(secretString string) (string, error) {
	inputLines := strings.Split(secretString, "\n")
	outputLines := []string{}
	for _, line := range inputLines {
		if !strings.Contains(line, " = ") || !strings.Contains(line, "_") {
			// No change needed if line does not contain both: " = " and "_"
			outputLines = append(outputLines, line)
			continue
		}
		// Only need to replace underscores in the key.  Must not alter the value
		keyValue := strings.Split(line, " = ")
		if len(keyValue) > 2 {
			// Line should never contain multiple: " = "
			return "", fmt.Errorf("Unrecognized string in secret: %s", line)
		}
		newLine := strings.ReplaceAll(keyValue[0], "_", "-") + " = " + keyValue[1]
		outputLines = append(outputLines, newLine)
	}
	return strings.Join(outputLines, "\n"), nil
}

// DecryptAPIKey - un-encrypt the users API key (if it was encrypted)
func (c *ConfigVpc) DecryptAPIKey() (string, error) {
	if !c.encryption {
		return c.APIKeySecret, nil
	}
	cipher := newCipher(c.ClusterID)
	apiKey, err := cipher.Decrypt(c.APIKeySecret)
	if err != nil {
		return "", err
	}
	return apiKey, nil
}

// GetAuthenticator - get the correct authenticator based on the configuration data
func (c *ConfigVpc) GetAuthenticator() (core.Authenticator, error) {
	apiKey, err := c.DecryptAPIKey()
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt API key: %v", err)
	}
	return NewAuthenticator(apiKey, c.trustedProfileID, c.computeResourceToken, c.tokenExchangeURL, c.kubeClient), nil
}

// getIamEndpoint - retrieve the correct IAM endpoint for the current config
func (c *ConfigVpc) getIamEndpoint() string {
	if c.IamEndpointOverride != "" {
		return c.IamEndpointOverride
	}
	if strings.Contains(c.Region, "stage") {
		if c.EnablePrivate {
			return iamStagePrivateTokenExchangeURL
		}
		return iamStageTestPublicTokenExchangeURL
	}
	if c.EnablePrivate {
		return iamPrivateTokenExchangeURL
	}
	return iamPublicTokenExchangeURL
}

// GetResourceGroup - returns the resource group ID
func (c *ConfigVpc) GetResourceGroup() string {
	return c.resourceGroupID
}

// getResourceManagerEndpoint - retrieve the correct resource manager endpoint for the current config
func (c *ConfigVpc) getResourceManagerEndpoint() string {
	if c.RmEndpointOverride != "" {
		return c.RmEndpointOverride
	}
	// Determine the resource manager endpoint URL
	if strings.Contains(c.endpointURL, "iaasdev.cloud.ibm.com") {
		return "https://resource-controller.test.cloud.ibm.com"
	}
	return resourcemanagerv2.DefaultServiceURL
}

// getVpcEndpoint - retrieve the correct VPC endpoint for the current config
func (c *ConfigVpc) getVpcEndpoint() string {
	if c.VpcEndpointOverride != "" {
		return c.VpcEndpointOverride
	}
	endpoint := vpcEndpointIaaSProdURL
	if strings.Contains(c.Region, "stage") {
		endpoint = vpcEndpointIaaSStageURL
	}
	if c.EnablePrivate {
		return fmt.Sprintf("https://%s.%s.%s", c.Region, "private", endpoint)
	}
	return fmt.Sprintf("https://%s.%s", c.Region, endpoint)
}

// GetSummary - returns a string containing the configuration information
func (c *ConfigVpc) GetSummary() string {
	return fmt.Sprintf("ClusterID:%s Encryption:%v Endpoint:%s Provider:%s ResourceGroup:%s TokenExchangeURL:%s",
		c.ClusterID,
		c.encryption,
		c.endpointURL,
		c.ProviderType,
		c.resourceGroupID,
		c.tokenExchangeURL,
	)
}

// GetToken - retrieves a token from the specified Authenticator
func (c *ConfigVpc) GetToken(auth core.Authenticator) (string, error) {
	req := &http.Request{Header: make(http.Header)}
	err := auth.Authenticate(req)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "), nil
}

// initialize - extract secret data into the VPC config object
func (c *ConfigVpc) initialize(secretData string) error {
	var secretStruct ClusterSecret
	secretString, err := c.adjustSecretData(secretData)
	if err != nil {
		return fmt.Errorf("Secret not formatted correctly: %v", err)
	}
	err = gcfg.FatalOnly(gcfg.ReadStringInto(&secretStruct, secretString))
	if err != nil {
		return fmt.Errorf("Failed to decode secret: %v", err)
	}
	// If cloud config ProviderType is set to "secret", use the value from the secret
	if c.ProviderType == VpcProviderTypeSecret {
		c.ProviderType = secretStruct.VPC.ProviderType
	}

	// Extract values from the the secret
	if c.ProviderType == VpcProviderTypeGen2 {
		// If the API key has not been set, check the env variable
		if c.APIKeySecret == "" {
			apiKey := os.Getenv(envVarAPIKey)
			if strings.Contains(apiKey, " ") {
				klog.Warningf("API key read from env variable is not valid: [%v]", apiKey)
			} else {
				c.APIKeySecret = apiKey
			}
		}
		// If the API key has not been set, check to see if trusted profile has been set
		// If we are able to get the trusted profile ID, check to see if we can get the compute resource token
		// If we are able to retrieve both, then set API key secret to indicate we are going to use trusted profile instead
		if c.APIKeySecret == "" {
			c.trustedProfileID, err = GetTrustedProfileID(c.kubeClient)
			if err == nil {
				c.computeResourceToken, err = GetComputeResourceToken(c.kubeClient)
				if err == nil {
					c.APIKeySecret = vpcUseTrustedProfile
				}
			}
		}
		// If the API key has not been set, use the value from the secret
		if c.APIKeySecret == "" {
			c.APIKeySecret = secretStruct.VPC.G2APIKey
			c.encryption = secretStruct.VPC.Encryption
		}

		// Determine the correct RIaaS endpoint from what is in the secret
		switch {
		case c.VpcEndpointOverride != "":
			c.endpointURL = c.VpcEndpointOverride
		case c.EnablePrivate && secretStruct.VPC.G2RIaaSEndpointPrivateURL != "":
			c.endpointURL = secretStruct.VPC.G2RIaaSEndpointPrivateURL
		case secretStruct.VPC.G2RIaaSEndpointURL != "":
			c.endpointURL = secretStruct.VPC.G2RIaaSEndpointURL
		}
		// Extract resource group id if it is set
		if secretStruct.VPC.G2ResourceGroupID != "" {
			c.resourceGroupID = secretStruct.VPC.G2ResourceGroupID
		}
		// Determine the resource manager URL
		c.resourceManagerURL = c.getResourceManagerEndpoint()
		// Determine the correct IAM endpoint from what is in the secret
		switch {
		case c.IamEndpointOverride != "":
			c.tokenExchangeURL = c.IamEndpointOverride
		case c.EnablePrivate && secretStruct.VPC.G2TokenExchangeEndpointPrivateURL != "":
			c.tokenExchangeURL = secretStruct.VPC.G2TokenExchangeEndpointPrivateURL
		case c.EnablePrivate && secretStruct.VPC.IKSPrivateRoute != "":
			c.tokenExchangeURL = secretStruct.VPC.IKSPrivateRoute
		case secretStruct.VPC.G2TokenExchangeEndpointURL != "":
			c.tokenExchangeURL = secretStruct.VPC.G2TokenExchangeEndpointURL
		}
	}

	// If there was not API Key in the secret, then return error
	if c.APIKeySecret == "" && c.ProviderType != VpcProviderTypeFake {
		return fmt.Errorf("Secret does not contain VPC info: \n%v", secretData)
	}

	// If private service endpoint in enabled (and IAM endpoint override was not configured)
	if c.EnablePrivate && c.IamEndpointOverride == "" {
		// If trusted profile is being used, then can't use IKS for token exchange
		if c.APIKeySecret == vpcUseTrustedProfile {
			if strings.Contains(c.endpointURL, "stage") {
				c.tokenExchangeURL = iamStagePrivateTokenExchangeURL
			} else {
				c.tokenExchangeURL = iamPrivateTokenExchangeURL
			}
		}
	}

	// Strip any trailing "/" off the endpoint URL before we add the "/v1"
	c.endpointURL = strings.TrimSuffix(c.endpointURL, "/")

	// Make sure there is a trailing "/v1" on the endpointURL
	if !strings.HasSuffix(c.endpointURL, "/v1") {
		c.endpointURL += "/v1"
	}
	return nil
}

// initializeDefaultEndpoints - initialize the default endpoints for IPI so secret is not needed
func (c *ConfigVpc) initializeDefaultEndpoints() {
	// Determine the VPC endpoint URL
	c.endpointURL = c.getVpcEndpoint()
	c.endpointURL += "/v1"

	// Determine the resource manager endpoint URL
	c.resourceManagerURL = c.getResourceManagerEndpoint()

	// Determine the token exchange URL
	c.tokenExchangeURL = c.getIamEndpoint()
	c.tokenExchangeURL += "/identity/token"
}

// removeLbFromCache - remove the specified LB from the cache
func (c *ConfigVpc) removeLbFromCache(lb *VpcLoadBalancer) {
	if lb != nil {
		c.removeLbNameFromCache(lb.Name)
	}
}

// removeLbNameFromCache - remove the specified LB name from the cache
func (c *ConfigVpc) removeLbNameFromCache(name string) {
	if c.lbNameCache[name] != "" {
		delete(c.lbNameCache, name)
	}
}

// searchCacheForLb - search the LB cache for a specific VPC LB name
func (c *ConfigVpc) searchCacheForLb(name string) string {
	return c.lbNameCache[name]
}

// validate - verify the config data stored in the ConfigVpc object
func (c *ConfigVpc) validate() error {
	// Check the fields in the config
	switch {
	case c.ClusterID == "":
		return fmt.Errorf("Missing required cloud configuration setting: clusterID")
	case c.ProviderType == VpcProviderTypeFake:
		return nil
	case c.ProviderType == VpcProviderTypeSecret:
		return nil
	case c.ProviderType != VpcProviderTypeGen2:
		return fmt.Errorf("Invalid cloud configuration setting for cluster-default-provider: %s", c.ProviderType)
	}
	// Validation passed
	return nil
}

// filterLoadBalancersOnlyNLB - find all of the network load balancers in the list
func (c *CloudVpc) filterLoadBalancersOnlyNLB(lbs []*VpcLoadBalancer) []*VpcLoadBalancer {
	nlbList := []*VpcLoadBalancer{}
	for _, lb := range lbs {
		if lb.IsNLB() {
			nlbList = append(nlbList, lb)
		}
	}
	// Return list of network load balancers
	return nlbList
}

// filterNodesByEdgeLabel - extract only the edge nodes if there any any -or- return all nodes
func (c *CloudVpc) filterNodesByEdgeLabel(nodes []*v1.Node) []*v1.Node {
	edgeNodes := c.findNodesMatchingLabelValue(nodes, nodeLabelDedicated, nodeLabelValueEdge)
	if len(edgeNodes) == 0 {
		return nodes
	}
	return edgeNodes
}

// filterNodesByNodeNames - filter list of nodes to only those nodes in the specified map
func (c *CloudVpc) filterNodesByNodeNames(nodes []*v1.Node, nodeCounts map[string]int) []*v1.Node {
	foundNodes := []*v1.Node{}
	for _, node := range nodes {
		if nodeCounts[node.ObjectMeta.Name] > 0 {
			foundNodes = append(foundNodes, node)
		}
	}
	return foundNodes
}

// filterNodesByServiceMemberQuota - limit the nodes we select based on the current quota from service annotation
func (c *CloudVpc) filterNodesByServiceMemberQuota(nodes []*v1.Node, existingNodes []string, service *v1.Service, options *ServiceOptions) ([]string, error) {
	// If externalTrafficPolicy:Local is enabled on the service, then simply return the current node list.  No filtering will be done
	if service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeLocal {
		return c.getNodeIDs(nodes, options), nil
	}

	// Determine the quota we should use. If annotation is not set, use default. If the annotation is not properly formatted, return error
	quota, err := c.getServiceMemberQuota(service)
	if err != nil {
		return nil, err
	}

	// Determine how many nodes are located in each zone
	zoneNodeCount := c.getNodeCountInEachZone(nodes)

	// Check the quota against the node count in each of the zones
	if !c.isNodeQuotaFilteringNeeded(quota, zoneNodeCount) {
		return c.getNodeIDs(nodes, options), nil
	}

	// If we are updating an existing LB, we want to give priority to those nodes that are already configured as VPC LB pool members
	// The existingNodes is an array of those existing pool members on the VPC LB. Convert this array to a string to make searches easier
	existingNodeList := " " + strings.Join(existingNodes, " ") + " "

	// finalNodes will contain the final list of nodes that we will use for the VPC LB: zoneA + zoneB + zoneC
	finalNodes := []string{}

	// Process the nodes in each zone separately
	for zone := range zoneNodeCount {
		// Reduce the total list of nodes to only those in the current zone and generate node IDs
		nodesInZone := c.filterNodesByZone(nodes, zone)
		desiredNodes := c.getNodeIDs(nodesInZone, options)
		selectedNodes := []string{}

		// On the CreateLB path, we won't have any existing nodes for the LB so the following logic will be skipped
		// On the UpdateLB path, we want to give preference to the existing nodes on the LB instead of new nodes that were just added to the cluster
		if len(existingNodes) > 0 {
			remainingNodes := []string{}
			for _, desiredNode := range desiredNodes {
				if strings.Contains(existingNodeList, " "+desiredNode+" ") {
					selectedNodes = append(selectedNodes, desiredNode)
					if len(selectedNodes) == quota {
						break
					}
				} else {
					remainingNodes = append(remainingNodes, desiredNode)
				}
			}
			// Update the desired nodes list to contain those nodes that have NOT been moved into the selected list for this zone
			desiredNodes = remainingNodes
		}

		// Copy over the desired nodes one by one until the zone quota is reached
		for _, desiredNode := range desiredNodes {
			if len(selectedNodes) == quota {
				break
			}
			selectedNodes = append(selectedNodes, desiredNode)
		}

		// Copy the zone selected nodes onto the final node list
		finalNodes = append(finalNodes, selectedNodes...)
	}

	// Return list of nodes
	return finalNodes, nil
}

// filterNodesByZone - return list of nodes in the request zone
func (c *CloudVpc) filterNodesByZone(nodes []*v1.Node, zone string) []*v1.Node {
	if zone != "" {
		return c.findNodesMatchingLabelValue(nodes, nodeLabelZone, zone)
	}
	return nodes
}

// filterSubnetsBySubnetIDs - find all of the subnets in the list with matching subnet IDs
func (c *CloudVpc) filterSubnetsBySubnetIDs(subnets []*VpcSubnet, subnetIDs []string) []*VpcSubnet {
	matchingSubnets := []*VpcSubnet{}
	desiredSubnetIDs := " " + strings.Join(subnetIDs, " ") + " "
	for _, subnet := range subnets {
		if strings.Contains(desiredSubnetIDs, " "+subnet.ID+" ") {
			matchingSubnets = append(matchingSubnets, subnet)
		}
	}
	// Return subnets with the requested IDs
	return matchingSubnets
}

// filterSubnetsByZone - find all of the subnets in the requested zone
func (c *CloudVpc) filterSubnetsByZone(subnets []*VpcSubnet, zone string) []*VpcSubnet {
	matchingSubnets := []*VpcSubnet{}
	for _, subnet := range subnets {
		if subnet.Zone == zone {
			matchingSubnets = append(matchingSubnets, subnet)
		}
	}
	// Return subnets in the specified zone
	return matchingSubnets
}

// filterZonesByNodeCountsInEachZone - filter the subnet zones if there are no nodes in that zone
func (c *CloudVpc) filterZonesByNodeCountsInEachZone(subnetZones []string, nodeCounts map[string]int) []string {
	returnedZones := []string{}
	for _, subnetZone := range subnetZones {
		for nodeZone := range nodeCounts {
			// If we have nodes in the subnet zone, keep this zone in the return list
			if nodeZone == subnetZone {
				returnedZones = append(returnedZones, subnetZone)
				break
			}
		}
	}
	return returnedZones
}

// findNodesMatchingLabelValue - find all of the nodes that match the requested label and value
func (c *CloudVpc) findNodesMatchingLabelValue(nodes []*v1.Node, filterLabel, filterValue string) []*v1.Node {
	matchingNodes := []*v1.Node{}
	for _, node := range nodes {
		if v, ok := node.Labels[filterLabel]; ok && v == filterValue {
			matchingNodes = append(matchingNodes, node)
		}
	}
	// Return matching nodes
	return matchingNodes
}

// findRenamedLoadBalancer - search for renamed load balancer based on hostname / external IPs
func (c *CloudVpc) findRenamedLoadBalancer(hostname, externalIPs string) (*VpcLoadBalancer, error) {
	// Retrieve list of existing load balancers
	lbs, err := c.Sdk.ListLoadBalancers()
	if err != nil {
		// Error occurred trying to get list of VPC LBs
		return nil, err
	}
	// If we have external IPs, make sure the list is sorted
	if externalIPs != "" {
		sliceExtIPs := strings.Split(externalIPs, ",")
		sort.Strings(sliceExtIPs)
		externalIPs = strings.Join(sliceExtIPs, ",")
	}
	// Loop through all of the VPC LBs in the current account
	for _, lb := range lbs {
		if hostname != "" && hostname == lb.Hostname {
			// Found VPC LB with this service hostname
			return lb, nil
		}
		if externalIPs != "" {
			sort.Strings(lb.PublicIps)
			sort.Strings(lb.PrivateIps)
			if externalIPs == strings.Join(lb.PublicIps, ",") {
				// Found VPC LB with the service external IPs
				return lb, nil
			}
			if externalIPs == strings.Join(lb.PrivateIps, ",") {
				// Found VPC LB with the service external IPs
				return lb, nil
			}
		}
	}
	// Renamed VPC LB was not found
	return nil, nil
}

// GetClusterVpcSubnetIDs - retrieve the VPC and subnet IDs associated with the cluster
func (c *CloudVpc) GetClusterVpcSubnetIDs() (string, []string, error) {
	// If we have a VPC name and don't have the VPC ID, grab all VPCs and search for it
	if c.Config.vpcID == "" && c.Config.VpcName != "" {
		vpcList, err := c.Sdk.ListVPCs()
		if err != nil {
			return "", nil, err
		}
		for _, vpc := range vpcList {
			if vpc.Name == c.Config.VpcName {
				c.Config.vpcID = vpc.ID
				break
			}
		}
		if c.Config.vpcID == "" {
			return "", nil, fmt.Errorf("Failed to locate VPC with name: %s", c.Config.VpcName)
		}
	}
	// If we have a list of subnet names and don't have the subnet IDs, grab all VPC subnets and search
	if c.Config.clusterSubnetIDs == "" && c.Config.SubnetNames != "" {
		subnetList, err := c.Sdk.ListSubnets()
		if err != nil {
			return "", nil, err
		}
		subnetIDs := []string{}
		for _, name := range strings.Split(c.Config.SubnetNames, ",") {
			found := false
			for _, subnet := range subnetList {
				if subnet.Name == name && subnet.Vpc.ID == c.Config.vpcID {
					subnetIDs = append(subnetIDs, subnet.ID)
					found = true
					break
				}
			}
			if !found {
				return "", nil, fmt.Errorf("Failed to locate VPC subnet with name: %s", name)
			}
		}
		sort.Strings(subnetIDs)
		c.Config.clusterSubnetIDs = strings.Join(subnetIDs, ",")
	}
	if c.Config.vpcID != "" && c.Config.clusterSubnetIDs != "" {
		return c.Config.vpcID, strings.Split(c.Config.clusterSubnetIDs, ","), nil
	}
	cm, err := c.KubeClient.CoreV1().ConfigMaps(VpcCloudProviderNamespace).Get(context.TODO(), VpcCloudProviderConfigMap, metav1.GetOptions{})
	if err != nil {
		return "", nil, fmt.Errorf("Failed to get %v/%v config map: %v", VpcCloudProviderNamespace, VpcCloudProviderConfigMap, err)
	}
	vpcID := cm.Data[VpcCloudProviderVpcIDKey]
	subnets := cm.Data[VpcCloudProviderSubnetsKey]
	if subnets == "" {
		return "", nil, fmt.Errorf("The %v/%v config map does not contain key: [%s]", VpcCloudProviderNamespace, VpcCloudProviderConfigMap, VpcCloudProviderSubnetsKey)
	}
	c.Config.vpcID = vpcID
	c.Config.clusterSubnetIDs = subnets
	return vpcID, strings.Split(subnets, ","), nil
}

// GetClusterVpcID - determine the VPC the current cluster is allocated in
func (c *CloudVpc) GetClusterVpcID() (string, error) {
	if c.Config.vpcID != "" {
		return c.Config.vpcID, nil
	}
	vpcID, clusterSubnets, err := c.GetClusterVpcSubnetIDs()
	if err != nil {
		return "", err
	}
	if vpcID != "" {
		c.Config.vpcID = vpcID
		return c.Config.vpcID, nil
	}
	vpcSubnet, err := c.Sdk.GetSubnet(clusterSubnets[0])
	if err != nil {
		return "", err
	}
	c.Config.vpcID = vpcSubnet.Vpc.ID
	return c.Config.vpcID, nil
}

// getLoadBalancerCountInEachZone - retrieve the count of how many nodes are in each of zones
func (c *CloudVpc) getLoadBalancerCountInEachZone(lbs []*VpcLoadBalancer, vpcSubnets []*VpcSubnet) map[string]int {
	zonesFound := map[string]int{}
	for _, lb := range lbs {
		zones := lb.getZones(vpcSubnets)
		for _, zone := range zones {
			zonesFound[zone]++
		}
	}
	return zonesFound
}

// getNodeCountInEachZone - retrieve the count of how many nodes are in each of zones
func (c *CloudVpc) getNodeCountInEachZone(nodes []*v1.Node) map[string]int {
	zonesFound := map[string]int{}
	for _, node := range nodes {
		zone := node.Labels[nodeLabelZone]
		if zone != "" {
			zonesFound[zone]++
		}
	}
	return zonesFound
}

// getNodeIDs - get the node identifier for each node in the list
func (c *CloudVpc) getNodeIDs(nodeList []*v1.Node, options *ServiceOptions) []string {
	nodeIDs := []string{}
	for _, node := range nodeList {
		switch {
		case options.isNLB():
			id := node.Labels[nodeLabelInstanceID]
			if id == "" && c.Config.ipiMode {
				id = node.Labels[nodeLabelIpiInstanceID]
			}
			if id != "" {
				nodeIDs = append(nodeIDs, id)
			}
		case options.isSdnlb():
			id := node.Labels[nodeLabelInstanceID]
			if id == "" && c.Config.ipiMode {
				id = node.Labels[nodeLabelIpiInstanceID]
			}
			zone := node.Labels[nodeLabelZone]
			if id != "" && zone != "" {
				nodeIDs = append(nodeIDs, zone+"/"+id)
			}
		default:
			nodeInternalAddress := c.getNodeInternalIP(node)
			if nodeInternalAddress != "" {
				nodeIDs = append(nodeIDs, nodeInternalAddress)
			}
		}
	}
	return nodeIDs
}

// getNodeInternalIP - get the Internal IP of the node from label or status
func (c *CloudVpc) getNodeInternalIP(node *v1.Node) string {
	nodeInternalAddress := node.Labels[nodeLabelInternalIP]
	if nodeInternalAddress == "" {
		for _, address := range node.Status.Addresses {
			if address.Type == v1.NodeInternalIP {
				nodeInternalAddress = address.Address
				break
			}
		}
	}
	return nodeInternalAddress
}

// getPoolMemberTargets - get the targets (IP address/Instance ID) for all of the pool members
func (c *CloudVpc) getPoolMemberTargets(members []*VpcLoadBalancerPoolMember, options *ServiceOptions) []string {
	memberTargets := []string{}
	for _, member := range members {
		switch {
		case options.isNLB():
			memberTargets = append(memberTargets, member.TargetInstanceID)
		case options.isSdnlb():
			memberTargets = append(memberTargets, member.TargetInstanceID)
		default:
			memberTargets = append(memberTargets, member.TargetIPAddress)
		}
	}
	return memberTargets
}

// getPortMaxFromPortRanges - determine the portMax if we find a matching portMin
func (c *CloudVpc) getPortMaxFromPortRanges(port int, servicePortRange string) int {
	// If there are no port ranges, then min == max
	if servicePortRange == "" {
		return port
	}
	// Search the port ranges for a matching portMin
	for _, portRange := range strings.Split(servicePortRange, ",") {
		ports := strings.Split(portRange, "-")
		portMin, err := strconv.Atoi(ports[0])
		if err != nil {
			continue
		}
		portMax, err := strconv.Atoi(ports[1])
		if err != nil {
			continue
		}
		if port == portMin {
			return portMax
		}
	}
	// Range not found for the port that was passed in
	return port
}

// getServiceAnnotationInt - retrieve the specified service annotation and validate value with the specified min/max
func (c *CloudVpc) getServiceAnnotationInt(service *v1.Service, annotation string, min, max, def int) (int, error) {
	str := service.ObjectMeta.Annotations[annotation]
	if str == "" {
		return def, nil
	}
	// Convert string to an int
	val, err := strconv.Atoi(str)
	if err != nil {
		return -1, fmt.Errorf("The annotation %s on service %s is not set to a valid value [%v]",
			annotation, c.getServiceName(service), str)
	}
	// Validate min/max values for the port
	if val < min || val > max {
		return -1, fmt.Errorf("The annotation %s on service %s is not set to a value in the allowed range (%d - %d) [%d]",
			annotation, c.getServiceName(service), min, max, val)
	}
	return val, nil
}

// getServiceEnabledFeatures - retrieve the vpc-subnets annotation
func (c *CloudVpc) getServiceEnabledFeatures(service *v1.Service) string {
	return strings.ToLower(strings.ReplaceAll(service.ObjectMeta.Annotations[serviceAnnotationEnableFeatures], " ", ""))
}

// getServiceEndpointNodeCounts - retrieve map of the node IP addresses and count of how many application pods are on each node
func (c *CloudVpc) getServiceEndpointNodeCounts(service *v1.Service) (map[string]int, error) {
	nodesFound := map[string]int{}
	endpoints, err := c.KubeClient.CoreV1().Endpoints(service.ObjectMeta.Namespace).Get(context.TODO(), service.ObjectMeta.Name, metav1.GetOptions{})
	if err != nil {
		return nodesFound, fmt.Errorf("Failed to get %s endpoints: %v", c.getServiceName(service), err)
	}
	for _, subset := range endpoints.Subsets {
		for _, addr := range subset.Addresses {
			if addr.NodeName != nil {
				nodeName := *addr.NodeName
				if nodeName != "" {
					nodesFound[nodeName]++
				}
			}
		}
	}
	return nodesFound, nil
}

// getServiceExternalIPs - retrieve the external IPs associated with the service
func (c *CloudVpc) getServiceExternalIPs(service *v1.Service) string {
	// If there is no status, return ""
	if service.Status.LoadBalancer.Ingress == nil {
		return ""
	}
	// Scan through the status looking for external IPs
	externalIPs := []string{}
	for _, lbIngress := range service.Status.LoadBalancer.Ingress {
		if lbIngress.IP != "" {
			externalIPs = append(externalIPs, lbIngress.IP)
		}
	}
	sort.Strings(externalIPs)
	return strings.Join(externalIPs, ",")
}

// getServiceHealthCheckDelay - retrieve the health check delay annotation and validate value if set
func (c *CloudVpc) getServiceHealthCheckDelay(service *v1.Service) (int, error) {
	return c.getServiceAnnotationInt(service, serviceAnnotationHealthCheckDelay, healthCheckDelayMin, healthCheckDelayMax, healthCheckDelayDefault)
}

// getServiceHealthCheckNodePort - retrieve the health check node port for the service
func (c *CloudVpc) getServiceHealthCheckNodePort(service *v1.Service) int {
	if service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeLocal {
		return int(service.Spec.HealthCheckNodePort)
	}
	return 0
}

// getServiceHealthCheckPath - retrieve the health check path annotation
func (c *CloudVpc) getServiceHealthCheckPath(service *v1.Service) (string, error) {
	path := service.ObjectMeta.Annotations[serviceAnnotationHealthCheckPath]
	if path == "" {
		return "/", nil
	}
	// Validate against valid options
	if strings.Contains(path, " ") {
		return "", fmt.Errorf("The annotation %s on service %s is not set to a valid value [%s]",
			serviceAnnotationHealthCheckPath, c.getServiceName(service), path)
	}
	return path, nil
}

// getServiceHealthCheckPort - retrieve the health check port annotation and validate value if set
func (c *CloudVpc) getServiceHealthCheckPort(service *v1.Service) (int, error) {
	return c.getServiceAnnotationInt(service, serviceAnnotationHealthCheckPort, 1, 65535, 0)
}

// getServiceHealthCheckProtocol - retrieve the health check protocol annotation and validate value if set
func (c *CloudVpc) getServiceHealthCheckProtocol(service *v1.Service) (string, error) {
	proto := service.ObjectMeta.Annotations[serviceAnnotationHealthCheckProtocol]
	if proto == "" {
		return "", nil
	}
	// Validate against valid options
	if proto != "http" && proto != "https" && proto != "tcp" {
		return "", fmt.Errorf("The annotation %s on service %s is not set to a valid value [%s]",
			serviceAnnotationHealthCheckProtocol, c.getServiceName(service), proto)
	}
	return proto, nil
}

// getServiceHealthCheckRetries - retrieve the health check retries annotation and validate value if set
func (c *CloudVpc) getServiceHealthCheckRetries(service *v1.Service) (int, error) {
	return c.getServiceAnnotationInt(service, serviceAnnotationHealthCheckRetries, healthCheckRetriesMin, healthCheckRetriesMax, healthCheckRetriesDefault)
}

// getServiceHealthCheckTimeout - retrieve the health check timeout annotation and validate value if set
func (c *CloudVpc) getServiceHealthCheckTimeout(service *v1.Service) (int, error) {
	return c.getServiceAnnotationInt(service, serviceAnnotationHealthCheckTimeout, healthCheckTimeoutMin, healthCheckTimeoutMax, healthCheckTimeoutDefault)
}

// getServiceHealthCheckUDP - retrieve the health node port to use for UDP ports and validate value if set
func (c *CloudVpc) getServiceHealthCheckUDP(service *v1.Service) (int, error) {
	return c.getServiceAnnotationInt(service, serviceAnnotationHealthCheckUDP, 1, 65535, 0)
}

// getServiceHostname - retrieve the hostname associated with the service
func (c *CloudVpc) getServiceHostname(service *v1.Service) string {
	// If there is no status, return ""
	if service.Status.LoadBalancer.Ingress == nil {
		return ""
	}
	// Scan through the status looking for a hostname
	for _, lbIngress := range service.Status.LoadBalancer.Ingress {
		if lbIngress.Hostname != "" {
			return lbIngress.Hostname
		}
	}
	return ""
}

// getServiceIdleConnectionTimeout - retrieve the idle connection timeout annotation and validate value if set
func (c *CloudVpc) getServiceIdleConnectionTimeout(service *v1.Service) (int, error) {
	return c.getServiceAnnotationInt(service, serviceAnnotationIdleConnTimeout, idleConnTimeoutMin, idleConnTimeoutMax, idleConnTimeoutDefault)
}

// getServiceNodeSelectorFilter - retrieve the service annotation used to filter the backend worker nodes
func (c *CloudVpc) getServiceNodeSelectorFilter(service *v1.Service) (string, string, error) {
	filter := strings.ReplaceAll(service.ObjectMeta.Annotations[serviceAnnotationNodeSelector], " ", "")
	if filter == "" {
		return "", "", nil
	}
	filterLabelValue := strings.Split(filter, "=")
	if len(filterLabelValue) != 2 {
		return "", "", fmt.Errorf("The annotation %s on service %s is not set to a valid value [%s]",
			serviceAnnotationNodeSelector, c.getServiceName(service), filter)
	}
	return filterLabelValue[0], filterLabelValue[1], nil
}

// getServiceMemberQuota - retrieve the service annotation used to filter the backend worker nodes
func (c *CloudVpc) getServiceMemberQuota(service *v1.Service) (int, error) {
	quota := strings.ToLower(service.ObjectMeta.Annotations[serviceAnnotationMemberQuota])
	if quota == "" {
		return defaultPoolMemberQuota, nil
	}
	// If quota checking is disabled, return 0
	if quota == "disable" || quota == "max" {
		return 0, nil
	}
	// Convert quota string to an int
	val, err := strconv.Atoi(quota)
	if err != nil {
		return -1, fmt.Errorf("The annotation %s on service %s is not set to a valid value [%s]",
			serviceAnnotationMemberQuota, c.getServiceName(service), quota)
	}
	// Return result
	return val, nil
}

// getServiceName - retrieve the service namespace and name
func (c *CloudVpc) getServiceName(service *v1.Service) string {
	return fmt.Sprintf("%s/%s", service.ObjectMeta.Namespace, service.ObjectMeta.Name)
}

// getServicePoolNames - get list of pool names for the service ports
func (c *CloudVpc) getServicePoolNames(service *v1.Service, options *ServiceOptions) ([]string, error) {
	poolList := []string{}
	servicePortRange, err := c.validateServicePortRange(service, options)
	if err != nil {
		return poolList, err
	}
	for _, kubePort := range service.Spec.Ports {
		poolList = append(poolList, genLoadBalancerPoolName(kubePort, servicePortRange))
	}
	return poolList, nil
}

// getServicePortRange - retrieve the service annotation used to indicate a port range
func (c *CloudVpc) getServicePortRange(service *v1.Service) string {
	return strings.ReplaceAll(service.Annotations[serviceAnnotationPortRange], " ", "")
}

// getServiceSubnets - retrieve the vpc-subnets annotation
func (c *CloudVpc) getServiceSubnets(service *v1.Service) string {
	return strings.ReplaceAll(service.ObjectMeta.Annotations[serviceAnnotationSubnets], " ", "")
}

// getSubnetIDs - get the IDs for all of the subnets that were passed in
func (c *CloudVpc) getSubnetIDs(subnets []*VpcSubnet) []string {
	subnetIDs := []string{}
	for _, subnet := range subnets {
		subnetIDs = append(subnetIDs, subnet.ID)
	}
	// Return the IDs of all of the subnets
	return subnetIDs
}

// getSubnetsForLoadBalancer - calculate the subnets to use for this load balancer
func (c *CloudVpc) getSubnetsForLoadBalancer(service *v1.Service, vpcSubnets []*VpcSubnet, options *ServiceOptions) ([]string, error) {
	vpcID, subnetList, err := c.GetClusterVpcSubnetIDs()
	if err != nil {
		return nil, err
	}
	clusterSubnets, err := c.validateClusterSubnetIDs(subnetList, vpcSubnets)
	if err != nil {
		return nil, err
	}
	serviceSubnets := options.getServiceSubnets()
	serviceZone := options.getServiceZone()
	if serviceSubnets != "" {
		subnetList, err = c.validateServiceSubnets(service, serviceSubnets, vpcID, vpcSubnets)
	} else if serviceZone != "" {
		subnetList, err = c.validateServiceZone(service, serviceZone, clusterSubnets)
	}
	if err != nil {
		return nil, err
	}
	return subnetList, nil
}

// getUpdatedSubnetsForForLoadBalancer - determine if tbe subnets need to be updated for VPC ALB
func (c *CloudVpc) getUpdatedSubnetsForForLoadBalancer(service *v1.Service, lb *VpcLoadBalancer, vpcSubnets []*VpcSubnet, options *ServiceOptions) ([]string, error) {
	// Determine what subnets the current Kubernetes load balancer service would get
	desiredSubnets, err := c.getSubnetsForLoadBalancer(service, vpcSubnets, options)
	if err != nil {
		return nil, err
	}
	// Determine the current subnets of the VPC ALB
	actualSubnets := []string{}
	for _, subnet := range lb.Subnets {
		actualSubnets = append(actualSubnets, subnet.ID)
	}
	// Sort both arrays to make comparison easier
	sort.Strings(desiredSubnets)
	sort.Strings(actualSubnets)
	if strings.Join(desiredSubnets, ",") != strings.Join(actualSubnets, ",") {
		serviceName := c.getServiceName(service)
		klog.Infof("%s: actual subnets:  %+v", serviceName, actualSubnets)
		klog.Infof("%s: desired subnets: %+v", serviceName, desiredSubnets)
		return desiredSubnets, nil
	}
	// desired == actual, no need to update anything.  Return empty array
	return []string{}, nil
}

// getZonesContainingSubnets - retrieve the zones that contain the specified subnets
func (c *CloudVpc) getZonesContainingSubnets(subnets []*VpcSubnet) []string {
	zonesFound := map[string]bool{}
	for _, subnet := range subnets {
		zone := subnet.Zone
		if zone != "" {
			zonesFound[zone] = true
		}
	}
	zoneList := []string{}
	for zone := range zonesFound {
		zoneList = append(zoneList, zone)
	}
	sort.Strings(zoneList)
	return zoneList
}

// initialize - Initialize the CloudVpc
func (c *CloudVpc) initialize() error {
	c.Config.kubeClient = c.KubeClient
	err := c.Config.validate()
	if err != nil {
		return err
	}
	// Check to see if IPI mode shoud be enabled
	if c.Config.ResourceGroupName != "" && c.Config.SubnetNames != "" && c.Config.VpcName != "" &&
		c.Config.AccountID != "" && c.Config.AccountID == c.Config.WorkerAccountID {
		c.Config.ipiMode = true
		c.Config.initializeDefaultEndpoints()
	}
	// Retrieve the storage-secret-store secret
	if c.Config.ProviderType != VpcProviderTypeFake {
		secretData, err := c.ReadKubeSecret()
		if err != nil {
			// Failed to read storage-secret-store.  Don't return err in IPI mode
			if !c.Config.ipiMode {
				return err
			}
		} else {
			// Process the data from the storage secret
			err = c.Config.initialize(secretData)
			if err != nil {
				return err
			}
		}
	}
	// Initialize VPC name -> id cache
	c.Config.lbNameCache = map[string]string{}

	// Retrieve the sDNLB config settings and save the values we need
	sdnlbConfig, err := c.GetSdnlbConfig()
	if err != nil {
		c.Config.serviceErr = err.Error()
	}
	if sdnlbConfig != nil {
		c.Config.clusterCrnPrefix = sdnlbConfig.ClusterCRN
		c.Config.serviceAPIKey = sdnlbConfig.ServiceAPIKey
		c.Config.serviceType = sdnlbConfig.ServiceType
	}
	return nil
}

// isNodeQuotaFilteringNeeded - do we need to limit the number of nodes used for pool members
func (c *CloudVpc) isNodeQuotaFilteringNeeded(quota int, zoneNodeCount map[string]int) bool {
	// If there is no quota or no zones, then no filtering is needed
	if quota == 0 || len(zoneNodeCount) == 0 {
		return false
	}
	// If the zone is over the quota, then we need to filter
	for _, count := range zoneNodeCount {
		if count > quota {
			return true
		}
	}
	// All zones checked. No need to filter
	return false
}

// isServicePortEqualListener - does the specified service port equal the values specified
func (c *CloudVpc) isServicePortEqualListener(kubePort v1.ServicePort, servicePortRange string, listener *VpcLoadBalancerListener) bool {
	return int(listener.PortMin) == int(kubePort.Port) &&
		int(listener.PortMax) == c.getPortMaxFromPortRanges(int(kubePort.Port), servicePortRange) &&
		strings.EqualFold(listener.Protocol, string(kubePort.Protocol))
}

// isServicePortEqualPoolName - does the specified service port equal the fields of a pool name
func (c *CloudVpc) isServicePortEqualPoolName(kubePort v1.ServicePort, servicePortRange string, poolName *VpcPoolNameFields) bool {
	return poolName.PortMin == int(kubePort.Port) &&
		poolName.PortMax == c.getPortMaxFromPortRanges(int(kubePort.Port), servicePortRange) &&
		strings.EqualFold(poolName.Protocol, string(kubePort.Protocol))
}

// isServiceUDP - retrieve true if a UDP port was specified on this service
func (c *CloudVpc) isServiceUDP(service *v1.Service) bool {
	for _, kubePort := range service.Spec.Ports {
		if kubePort.Protocol == v1.ProtocolUDP {
			return true
		}
	}
	return false
}

// ReadKubeSecret - read the Kube secret and extract tbe data into a string
func (c *CloudVpc) ReadKubeSecret() (string, error) {
	kubeSecret, err := c.KubeClient.CoreV1().Secrets(VpcSecretNamespace).Get(context.TODO(), VpcSecretFileName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("Failed to get secret: %v", err)
	}
	return string(kubeSecret.Data[VpcClientDataKey]), nil
}

// refreshClusterVpcSubnetIDs - refresh the cached copy of VPC and subnet IDs associated with the cluster
func (c *CloudVpc) refreshClusterVpcSubnetIDs(configMap *v1.ConfigMap) error {
	if configMap == nil {
		return fmt.Errorf("Config map %v/%v was not specified", VpcCloudProviderNamespace, VpcCloudProviderConfigMap)
	}
	vpcID := configMap.Data[VpcCloudProviderVpcIDKey]
	subnetIDs := configMap.Data[VpcCloudProviderSubnetsKey]
	if vpcID == "" || subnetIDs == "" {
		return fmt.Errorf("Config map %v/%v does not contain valid data: [%v]", VpcCloudProviderNamespace, VpcCloudProviderConfigMap, configMap.Data)
	}
	if c.Config.vpcID != vpcID || c.Config.clusterSubnetIDs != subnetIDs {
		klog.Infof("Current vpc / subnet IDs: %v / %v", c.Config.vpcID, c.Config.clusterSubnetIDs)
		klog.Infof("Updated vpc / subnet IDs: %v / %v", vpcID, subnetIDs)
		c.Config.vpcID = vpcID
		c.Config.clusterSubnetIDs = subnetIDs
	}
	return nil
}

// selectSingleZoneForSubnet - select a single zone and calculate the subnet IDs and nodes in that zone
func (c *CloudVpc) selectSingleZoneForSubnet(serviceName string, vpcSubnets []*VpcSubnet, subnetZones []string, nodes []*v1.Node) ([]string, error) {
	originalSubnetZoneCount := len(subnetZones)
	nodeCountsByZone := map[string]int{}

	// If there are multiple subnet zones choices, we don't want to choose a zone that does not have any worker nodes
	if len(subnetZones) > 1 {
		// Determine how many nodes are in each zone
		nodeCountsByZone = c.getNodeCountInEachZone(nodes)

		klog.Infof("%s: node zones: %+v", serviceName, nodeCountsByZone)
		workerZones := c.filterZonesByNodeCountsInEachZone(subnetZones, nodeCountsByZone)

		// If there no worker nodes in any of the subnet zones, then just pick the first subnet zone
		if len(workerZones) == 0 {
			subnetZones = []string{subnetZones[0]}
		} else {
			// Only consider those zones that contain worker nodes
			subnetZones = workerZones
		}
	}

	// If we still have multiple subnet zones, let's take into consideration the NLBs that already exist on this cluster
	if len(subnetZones) > 1 {
		lbs, err := c.getLoadBalancersInCluster()
		if err != nil {
			return nil, err
		}
		// Filter the LBs to only include NLBs
		lbs = c.filterLoadBalancersOnlyNLB(lbs)
		// Determine the zones for the existing NLBs
		nlbCountsByZone := c.getLoadBalancerCountInEachZone(lbs, vpcSubnets)
		klog.Infof("%s: existing NLB zones: %+v", serviceName, nlbCountsByZone)
		// Select the "best" zone based on the existing NLBs & worker nodes in the cluster
		subnetZones = c.selectSubnetZoneForNLB(subnetZones, nlbCountsByZone, nodeCountsByZone)
	}

	// If we originally had more than one subnet zone, adjust the subnet IDs to only reference one zone
	if originalSubnetZoneCount > 1 {
		klog.Infof("%s: selected zone for NLB: %+v", serviceName, subnetZones[0])
		vpcSubnets = c.filterSubnetsByZone(vpcSubnets, subnetZones[0])
	}

	// Retrieve list of subnets IDs for the subnets in the desired zone
	subnetList := c.getSubnetIDs(vpcSubnets)
	if originalSubnetZoneCount > 1 {
		klog.Infof("%s: selected subnets: %+v", serviceName, subnetList)
	}

	// If there are multiple subnets in the selected zone, select the first one
	if len(subnetList) > 1 {
		singleSubnet := []string{subnetList[0]}
		return singleSubnet, nil
	}

	// Return the updated subnet list
	return subnetList, nil
}

// selectSubnetZoneForNLB - algorithm to determine the "best" zone to place the NLB in
func (c *CloudVpc) selectSubnetZoneForNLB(subnetZones []string, lbZones, nodeZones map[string]int) []string {
	zoneSelected := ""
	var lbCount int
	var nodeCount int
	for _, zone := range subnetZones {
		// Select a new zone if:
		// - first time through loop
		// - zone has fewer NLBs then the selected zone
		// - zone has same number of NLBs, but more worker nodes then the selected zone
		if zoneSelected == "" ||
			lbZones[zone] < lbCount ||
			(lbZones[zone] == lbCount && nodeZones[zone] > nodeCount) {
			zoneSelected = zone
			lbCount = lbZones[zone]
			nodeCount = nodeZones[zone]
		}
	}
	return []string{zoneSelected}
}

// Validate the cluster subnets from the config map
func (c *CloudVpc) validateClusterSubnetIDs(clusterSubnets []string, vpcSubnets []*VpcSubnet) ([]*VpcSubnet, error) {
	foundSubnets := []*VpcSubnet{}
	for _, subnetID := range clusterSubnets {
		found := false
		for _, subnet := range vpcSubnets {
			if subnetID == subnet.ID {
				found = true
				foundSubnets = append(foundSubnets, subnet)
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("The config map %s/%s contains invalid VPC subnet %s",
				VpcCloudProviderNamespace, VpcCloudProviderConfigMap, subnetID)
		}
	}
	if len(foundSubnets) > 1 {
		vpcID := foundSubnets[0].Vpc.ID
		for _, subnet := range foundSubnets {
			if vpcID != subnet.Vpc.ID {
				return nil, fmt.Errorf("The config map %s/%s contains VPC subnets in different VPCs: %s and %s",
					VpcCloudProviderNamespace, VpcCloudProviderConfigMap, foundSubnets[0].ID, subnet.ID)
			}
		}
	}
	return foundSubnets, nil
}

// validateService - validate the service and the options on the service
func (c *CloudVpc) validateService(service *v1.Service) (*ServiceOptions, error) {
	// service.Spec.SessionAffinity is currently not supported
	// See issue: https://github.ibm.com/alchemy-containers/armada-network/issues/3470
	//
	// if service.Spec.SessionAffinity == v1.ServiceAffinityClientIP {
	// 	options += "," + LoadBalancerOptionSessionAffinity
	// }
	path := ""
	port := 0
	protocol, err := c.getServiceHealthCheckProtocol(service)
	if err != nil {
		return nil, err
	}
	if protocol != "" {
		port, err = c.getServiceHealthCheckPort(service)
		if err != nil {
			return nil, err
		}
		if protocol == "http" || protocol == "https" {
			path, err = c.getServiceHealthCheckPath(service)
			if err != nil {
				return nil, err
			}
		}
	}
	delay, err := c.getServiceHealthCheckDelay(service)
	if err != nil {
		return nil, err
	}
	retries, err := c.getServiceHealthCheckRetries(service)
	if err != nil {
		return nil, err
	}
	timeout, err := c.getServiceHealthCheckTimeout(service)
	if err != nil {
		return nil, err
	}
	udpPort, err := c.getServiceHealthCheckUDP(service)
	if err != nil {
		return nil, err
	}
	idleTimeout, err := c.getServiceIdleConnectionTimeout(service)
	if err != nil {
		return nil, err
	}
	if delay <= timeout {
		return nil, fmt.Errorf("The health check timeout [%d] on service %s must be less than the health check delay [%d]",
			timeout, c.getServiceName(service), delay)
	}
	options := c.getServiceOptions(service)
	options.setHealthCheckDelay(delay)
	options.setHealthCheckPath(path)
	options.setHealthCheckPort(port)
	options.setHealthCheckProtocol(protocol)
	options.setHealthCheckRetries(retries)
	options.setHealthCheckTimeout(timeout)
	options.setHealthCheckUDP(udpPort)
	options.setIdleConnectionTimeout(idleTimeout)
	nlbRequested := options.isNLB()
	// NLB does not support proxy protocol
	if nlbRequested && options.isProxyProtocol() {
		return nil, fmt.Errorf("Service annotation %s can not include both %s and %s options",
			serviceAnnotationEnableFeatures, LoadBalancerOptionNLB, LoadBalancerOptionProxyProtocol)
	}
	// NLB private load balancers requires separate VPC subnet to be specified
	if nlbRequested && !options.isPublic() && options.getServiceSubnets() == "" {
		return nil, fmt.Errorf("Private network load balancers require the %s annotation", serviceAnnotationSubnets)
	}
	// NLB can not be done if we don't have a service account ID
	if nlbRequested && c.Config.WorkerAccountID == "" {
		return nil, fmt.Errorf("Service annotation %s:%s is not possible due to missing config",
			serviceAnnotationEnableFeatures, LoadBalancerOptionNLB)
	}
	// No additional checks needed for NLB
	if nlbRequested || options.isSdnlb() {
		// Make sure that Idle connection timeout was not requested
		if service.ObjectMeta.Annotations[serviceAnnotationIdleConnTimeout] != "" {
			return nil, fmt.Errorf("Service annotation %s is only supported on application load balancers", serviceAnnotationIdleConnTimeout)
		}
		// Make sure that only TCP / UDP are allowed
		for _, kubePort := range service.Spec.Ports {
			if kubePort.Protocol != v1.ProtocolTCP && kubePort.Protocol != v1.ProtocolUDP {
				return nil, fmt.Errorf("Service %s is configured with %s protocol. Only TCP and UDP are supported",
					c.getServiceName(service), kubePort.Protocol)
			}
		}
		// Verify we can configure a HTTP / TCP health check if this is UDP
		if options.isUDP() && options.getHealthCheckNodePort() == 0 && options.getHealthCheckUDP() == 0 {
			return nil, fmt.Errorf("Service %s is a UDP load balancer, externalTrafficPolicy is set to Cluster, and UDP health check was not specified",
				c.getServiceName(service))
		}
		return options, nil
	}
	// Only TCP is supported
	for _, kubePort := range service.Spec.Ports {
		if kubePort.Protocol != v1.ProtocolTCP {
			return nil, fmt.Errorf("Service %s is a %s load balancer. Only TCP is supported",
				c.getServiceName(service), kubePort.Protocol)
		}
	}
	// All other service annotation options we ignore and just pass through
	return options, nil
}

// validateServicePortRange - validate the service and the requested features on the service
func (c *CloudVpc) validateServicePortRange(service *v1.Service, options *ServiceOptions) (string, error) {
	servicePortRange := c.getServicePortRange(service)
	if servicePortRange == "" {
		return "", nil
	}
	switch {
	case options.isSdnlb(): // Port range supported by sDNLB
	case options.isNLB() && options.isPublic(): // Port range supported by public NLB
	default:
		return "", fmt.Errorf("Service annotation %s is not supported", serviceAnnotationPortRange)
	}
	for _, portRange := range strings.Split(servicePortRange, ",") {
		// Port range must have: "portMin - portMax"
		ports := strings.Split(portRange, "-")
		if len(ports) != 2 {
			return "", fmt.Errorf("Improperly formatted data in service annotation %s: %s", serviceAnnotationPortRange, servicePortRange)
		}
		// Make sure portMin is numeric
		portMin, err := strconv.Atoi(ports[0])
		if err != nil {
			return "", fmt.Errorf("Invalid port value in service annotation %s: %s %v", serviceAnnotationPortRange, servicePortRange, err)
		}
		// Make sure portMax is numeric
		portMax, err := strconv.Atoi(ports[1])
		if err != nil {
			return "", fmt.Errorf("Invalid port value in service annotation %s: %s %v", serviceAnnotationPortRange, servicePortRange, err)
		}
		// Make sure portMin and portMax are different and that portMax is greater than portMin
		if portMin == portMax || portMin > portMax {
			return "", fmt.Errorf("Specified port range %s is not valid in service annotation %s", portRange, serviceAnnotationPortRange)
		}
		// Make sure that there is matching port in the service spec for the portMin
		// and make sure that there the port range does not overlap with anything else in the service spec
		found := false
		for _, kubePort := range service.Spec.Ports {
			servicePort := int(kubePort.Port)
			if servicePort == portMin {
				found = true
			} else if servicePort > portMin && servicePort <= portMax {
				return "", fmt.Errorf("Port range %s overlaps with service port %d", portRange, servicePort)
			}
		}
		if !found {
			return "", fmt.Errorf("No matching service port for the port range: %s", portRange)
		}
	}
	// Finished validating the port ranges, return success
	return servicePortRange, nil
}

// Validate the subnets annotation on the service
func (c *CloudVpc) validateServiceSubnets(service *v1.Service, serviceSubnets, vpcID string, vpcSubnets []*VpcSubnet) ([]string, error) {
	desiredSubnetMap := map[string]bool{}
	for _, subnetID := range strings.Split(serviceSubnets, ",") {
		found := false
		for _, subnet := range vpcSubnets {
			if subnetID == subnet.ID {
				if vpcID != subnet.Vpc.ID {
					return nil, fmt.Errorf("The annotation %s on service %s contains VPC subnet %s that is located in a different VPC",
						serviceAnnotationSubnets, c.getServiceName(service), subnetID)
				}
				found = true
				desiredSubnetMap[subnetID] = true
				break
			}
			// Make sure that we only look at subnet names and CIDRs in the current VPC
			if vpcID != subnet.Vpc.ID {
				continue
			}
			// Check to see if the subnet in the service annotation matches the VPC subnet's name or CIDR
			if subnetID == subnet.Name || subnetID == subnet.Ipv4CidrBlock {
				found = true
				desiredSubnetMap[subnet.ID] = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("The annotation %s on service %s contains invalid VPC subnet %s",
				serviceAnnotationSubnets, c.getServiceName(service), subnetID)
		}
	}
	// The user may have specified the same service "value" on the annotation multiple times: ID, name, and CIDR
	// Using a map to hold initial evaluation allows us to easily filter out any repeats
	desiredSubnets := []string{}
	for subnet := range desiredSubnetMap {
		desiredSubnets = append(desiredSubnets, subnet)
	}

	// If this is a private NLB, then additional checks are needed
	options := c.getServiceOptions(service)
	if options.isNLB() && !options.isPublic() {
		if len(desiredSubnets) > 1 {
			return nil, fmt.Errorf("Private network load balancers require a single VPC subnet in the %s annotation", serviceAnnotationSubnets)
		}
		_, clusterSubnets, err := c.GetClusterVpcSubnetIDs()
		if err != nil {
			return nil, err
		}
		clusterSubnetString := strings.Join(clusterSubnets, ",")
		if strings.Contains(clusterSubnetString, desiredSubnets[0]) {
			return nil, fmt.Errorf("Private network load balancers require a dedicated VPC subnet in the %s annotation that is in the same VPC and zone as your worker nodes, but no worker nodes can be attached to the subnet", serviceAnnotationSubnets)
		}
	}

	// Return list of VPC subnet IDs
	return desiredSubnets, nil
}

// Validate that the subnets service annotation was not updated
func (c *CloudVpc) validateServiceSubnetsNotUpdated(service *v1.Service, lb *VpcLoadBalancer, vpcSubnets []*VpcSubnet) error {
	// If the annotation is not set, return
	serviceSubnets := c.getServiceSubnets(service)
	if serviceSubnets == "" {
		return nil
	}
	// Translate the subnet service annotation into actual subnet IDs
	vpcID := lb.getVpcID(vpcSubnets)
	requested, err := c.validateServiceSubnets(service, serviceSubnets, vpcID, vpcSubnets)
	if err != nil {
		return err
	}
	// Translate the LB subnet IDs into an array
	actual := []string{}
	for _, subnet := range lb.Subnets {
		actual = append(actual, subnet.ID)
	}
	// Compare the request subnet IDs from the annotation with the actual subnet IDs of the load balancer
	sort.Strings(requested)
	sort.Strings(actual)
	if strings.Join(requested, ",") != strings.Join(actual, ",") {
		return fmt.Errorf("The load balancer was created with subnets %s. This setting can not be changed", strings.Join(actual, ","))
	}
	// No update was detected
	return nil
}

// Validate that the public/private annotation on the service was not updated
func (c *CloudVpc) validateServiceTypeNotUpdated(options *ServiceOptions, lb *VpcLoadBalancer) error {
	if options.isPublic() != lb.IsPublic {
		lbType := servicePrivateLB
		if lb.IsPublic {
			lbType = servicePublicLB
		}
		return fmt.Errorf("The load balancer was created as a %s load balancer. This setting can not be changed", lbType)
	}
	if options.isNLB() != lb.IsNLB() {
		lbType := "application"
		if lb.IsNLB() {
			lbType = "network"
		}
		return fmt.Errorf("The load balancer was created as a %s load balancer. This setting can not be changed", lbType)
	}
	return nil
}

// Validate the zone annotation on the service
func (c *CloudVpc) validateServiceZone(service *v1.Service, serviceZone string, vpcSubnets []*VpcSubnet) ([]string, error) {
	clusterSubnets := []string{}
	for _, subnet := range vpcSubnets {
		if serviceZone == subnet.Zone {
			clusterSubnets = append(clusterSubnets, subnet.ID)
		}
	}
	if len(clusterSubnets) == 0 {
		return nil, fmt.Errorf("The annotation %s on service %s contains invalid zone %s. There are no cluster subnets in that zone",
			serviceAnnotationZone, c.getServiceName(service), serviceZone)
	}
	return clusterSubnets, nil
}

// Validate that the zone annotation on the service was not updated on a NLB
func (c *CloudVpc) validateServiceZoneNotUpdated(serviceZone string, lbZones []string) error {
	// If the service zone was not set, no need to check anything
	if serviceZone == "" {
		return nil
	}
	// Verify that there is only 1 zone if this is a network load balancer (this error check should never trigger)
	if len(lbZones) != 1 {
		return fmt.Errorf("Invalid number of zones associated with the network load balancer: %v", lbZones)
	}
	// Verify that the service zone and LB zone are the same
	if serviceZone != lbZones[0] {
		return fmt.Errorf("The load balancer was created in zone %v. This setting can not be changed", lbZones[0])
	}
	return nil
}

// VerifyServiceStatusIsNull - verify that the service did not already have a VPC LB associated with it
func (c *CloudVpc) VerifyServiceStatusIsNull(service *v1.Service) error {
	// If there is no status, return no error
	if service.Status.LoadBalancer.Ingress == nil {
		return nil
	}
	hostname := c.getServiceHostname(service)
	externalIPs := c.getServiceExternalIPs(service)
	lbName := c.GenerateLoadBalancerName(service)
	if hostname != "" || externalIPs != "" {
		lb, err := c.findRenamedLoadBalancer(hostname, externalIPs)
		if err != nil {
			return err
		}
		if lb != nil {
			return fmt.Errorf("The load balancer service requires the VPC load balancer resource to be named [%s], however it was renamed to [%s]. In order for this load balancer service to function properly, the VPC resource needs to be renamed back to the original name", lbName, lb.Name)
		}
		return fmt.Errorf("The VPC load balancer resource [%s] associated with this load balancer service can not be located", lbName)
	}
	// Service did not already have VPC LB associated with it
	return nil
}
