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
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	cluster = "bqcssbbd0bsui62odcdg"
)

var gen2Data = `[VPC]
g2_token_exchange_endpoint_url = "https://iam.bluemix.net"
g2_riaas_endpoint_url = "https://us-south.iaas.cloud.ibm.com:443"
g2_riaas_endpoint_private_url = "https://private-us-south.iaas.cloud.ibm.com:443"
g2_resource_group_id = "resourceGroup"
g2_api_key = "CK6eOquQMkcWQWqOKwnYfufwCMNcy4+RaE0Jvp7bOzEttvJl2GM7zRJIaVZWQChKOd83bT5O8MGGy63TUle8MA=="
encryption = true
provider_type = "g2"
iks_token_exchange_endpoint_private_url = "https://private.us-south.containers.cloud.ibm.com"`
var gen2CloudVpc = &CloudVpc{
	Config: &ConfigVpc{
		APIKeySecret:     "CK6eOquQMkcWQWqOKwnYfufwCMNcy4+RaE0Jvp7bOzEttvJl2GM7zRJIaVZWQChKOd83bT5O8MGGy63TUle8MA==",
		ClusterID:        "bqcssbbd0bsui62odcdg",
		EnablePrivate:    true,
		encryption:       true,
		endpointURL:      "https://private-us-south.iaas.cloud.ibm.com:443/v1",
		lbNameCache:      map[string]string{},
		ProviderType:     "g2",
		resourceGroupID:  "resourceGroup",
		WorkerAccountID:  "workerAccountID",
		tokenExchangeURL: "https://private.us-south.containers.cloud.ibm.com",
	}}

var mockCloud = CloudVpc{KubeClient: fake.NewSimpleClientset(), Config: &ConfigVpc{}}

// Node without InternalIP label but with status
var mockNode1 = &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "192.168.1.1",
	Labels: map[string]string{nodeLabelZone: "zoneA", nodeLabelDedicated: nodeLabelValueEdge}}, Status: v1.NodeStatus{Addresses: []v1.NodeAddress{{Address: "192.168.1.1", Type: v1.NodeInternalIP}}}}

// Node with InteralIP label but without status
var mockNode2 = &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "192.168.2.2",
	Labels: map[string]string{nodeLabelZone: "zoneB", nodeLabelInternalIP: "192.168.2.2"}}}

// Node without InternalIP label and status
var mockNode3 = &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "192.168.3.3",
	Labels: map[string]string{nodeLabelZone: "zoneB"}}}

// Node without InternalIP label with nil Addresses status
var mockNode4 = &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "192.168.1.1",
	Labels: map[string]string{nodeLabelZone: "zoneA", nodeLabelDedicated: nodeLabelValueEdge}}, Status: v1.NodeStatus{Addresses: nil}}

func getSecretNotFound() kubernetes.Interface {
	return fake.NewSimpleClientset()
}
func getSecretData(secretData string) kubernetes.Interface {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: VpcSecretFileName, Namespace: VpcSecretNamespace},
		Data:       map[string][]byte{VpcClientDataKey: []byte(secretData)},
	}
	return fake.NewSimpleClientset(secret)
}

func TestNewCloudVpc(t *testing.T) {
	type args struct {
		kubeClient            kubernetes.Interface
		clusterID             string
		enablePrivateEndpoint bool
	}
	tests := []struct {
		name    string
		args    args
		want    *CloudVpc
		wantErr bool
	}{
		{
			name: "No secret",
			args: args{kubeClient: getSecretNotFound(), clusterID: cluster, enablePrivateEndpoint: false},
			want: nil, wantErr: true,
		},
		{
			name: "No [VPC] data in the secret",
			args: args{kubeClient: getSecretData("Secret Data"), clusterID: cluster, enablePrivateEndpoint: false},
			want: nil, wantErr: true,
		},
		{
			name: "No API Key in the secret",
			args: args{kubeClient: getSecretData("[VPC]"), clusterID: cluster, enablePrivateEndpoint: false},
			want: nil, wantErr: true,
		},
		{
			name: "Unable to decrypt API Key",
			args: args{kubeClient: getSecretData(gen2Data), clusterID: "invalid cluster id", enablePrivateEndpoint: true},
			want: nil, wantErr: true,
		},
		{
			name: "Valid Gen2 secret - encrypted / private service endpoint",
			args: args{kubeClient: getSecretData(gen2Data), clusterID: cluster, enablePrivateEndpoint: true},
			want: gen2CloudVpc, wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ConfigVpc{
				ClusterID:       tt.args.clusterID,
				EnablePrivate:   tt.args.enablePrivateEndpoint,
				ProviderType:    VpcProviderTypeGen2,
				WorkerAccountID: "workerAccountID",
			}
			got, err := NewCloudVpc(tt.args.kubeClient, config, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCloudVpc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// if got != nil && tt.want != nil && !equalCloudVpc(got, tt.want) {
			if got != nil && tt.want != nil {
				got.Config.kubeClient = tt.want.Config.kubeClient                 // Don't check the kubeClient field
				got.Config.serviceErr = tt.want.Config.serviceErr                 // Don't check the serviceErr field
				got.Config.resourceManagerURL = tt.want.Config.resourceManagerURL // Don't check the resourceManagerURL field
				if !reflect.DeepEqual(got.Config, tt.want.Config) {
					t.Errorf("NewCloudVpc()\ngot = %+v\nwant = %+v", got.Config, tt.want.Config)
				}
			}
		})
	}
}

func TestInformerSecretAdd(t *testing.T) {
	// VPC environment not initialized
	ResetCloudVpc()
	secret := &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"}}
	InformerSecretAdd(secret)
	assert.Nil(t, GetCloudVpc())
	// VPC environment initialized, secret does not contain any VPC data
	SetCloudVpc(&CloudVpc{})
	InformerSecretAdd(secret)
	assert.NotNil(t, GetCloudVpc())
	ResetCloudVpc()
}

func TestInformerSecretDelete(t *testing.T) {
	// VPC environment not initialized
	ResetCloudVpc()
	secret := &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"}}
	InformerSecretDelete(secret)
	assert.Nil(t, GetCloudVpc())
	// VPC environment initialized, secret does not contain any VPC data
	SetCloudVpc(&CloudVpc{})
	InformerSecretDelete(secret)
	assert.NotNil(t, GetCloudVpc())
	ResetCloudVpc()
}

func TestInformerSecretUpdate(t *testing.T) {
	// VPC environment not initialized
	ResetCloudVpc()
	secret := &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"}}
	InformerSecretUpdate(nil, secret)
	assert.Nil(t, GetCloudVpc())
	// VPC environment initialized, secret does not contain any VPC data
	SetCloudVpc(&CloudVpc{})
	InformerSecretUpdate(nil, secret)
	assert.NotNil(t, GetCloudVpc())
	ResetCloudVpc()
}

func TestInformerConfigMapUpdate(t *testing.T) {
	// VPC environment not initialized
	ResetCloudVpc()
	configMap := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "my-config", Namespace: "default"}}
	InformerConfigMapUpdate(nil, configMap)
	assert.Nil(t, GetCloudVpc())
	// VPC environment initialized, config map is not the one that is being monitored
	SetCloudVpc(&CloudVpc{})
	InformerConfigMapUpdate(nil, configMap)
	assert.NotNil(t, GetCloudVpc())
	ResetCloudVpc()
}

func TestConfigVpc_getIamEndpoint(t *testing.T) {
	config := &ConfigVpc{
		Region: "us-south",
	}
	// Check that IAM endpoint can be overridden
	config.IamEndpointOverride = "https://override.iam.cloud.ibm.com"
	url := config.getIamEndpoint()
	assert.Equal(t, url, "https://override.iam.cloud.ibm.com")
	config.IamEndpointOverride = ""

	// Check prod public IAM endpoint
	url = config.getIamEndpoint()
	assert.Equal(t, url, iamPublicTokenExchangeURL)

	// Check prod private IAM endpoint
	config.EnablePrivate = true
	url = config.getIamEndpoint()
	assert.Equal(t, url, iamPrivateTokenExchangeURL)

	// Check stage public IAM endpoint
	config.EnablePrivate = false
	config.Region = "us-south-stage01"
	url = config.getIamEndpoint()
	assert.Equal(t, url, iamStageTestPublicTokenExchangeURL)

	// Check stage private IAM endpoint
	config.EnablePrivate = true
	url = config.getIamEndpoint()
	assert.Equal(t, url, iamStagePrivateTokenExchangeURL)
}

func TestConfigVpc_getResourceGroup(t *testing.T) {
	config := &ConfigVpc{resourceGroupID: "ID"}
	// Retrieve resource group ID
	result := config.GetResourceGroup()
	assert.Equal(t, result, "ID")
}

func TestConfigVpc_getResourceManagerEndpoint(t *testing.T) {
	config := &ConfigVpc{}
	// Check that resource manager endpoint can be overridden
	config.RmEndpointOverride = "https://override.rm.cloud.ibm.com"
	url := config.getResourceManagerEndpoint()
	assert.Equal(t, url, "https://override.rm.cloud.ibm.com")
	config.RmEndpointOverride = ""

	// Check prod resource manager endpoint
	url = config.getResourceManagerEndpoint()
	assert.Equal(t, url, "https://resource-controller.cloud.ibm.com")

	// Check stage resource manager endpoint
	config.endpointURL = "https://us-south-stage01.iaasdev.cloud.ibm.com"
	url = config.getResourceManagerEndpoint()
	assert.Equal(t, url, "https://resource-controller.test.cloud.ibm.com")
}

func TestConfigVpc_getVpcEndpoint(t *testing.T) {
	config := &ConfigVpc{
		Region: "us-south",
	}
	// Check that VPC endpoint can be overridden
	config.VpcEndpointOverride = "https://override.iaas.cloud.ibm.com"
	url := config.getVpcEndpoint()
	assert.Equal(t, url, "https://override.iaas.cloud.ibm.com")
	config.VpcEndpointOverride = ""

	// Check prod public VPC endpoint
	url = config.getVpcEndpoint()
	assert.Equal(t, url, "https://us-south.iaas.cloud.ibm.com")

	// Check prod private VPC endpoint
	config.EnablePrivate = true
	url = config.getVpcEndpoint()
	assert.Equal(t, url, "https://us-south.private.iaas.cloud.ibm.com")

	// Check stage public VPC endpoint
	config.EnablePrivate = false
	config.Region = "us-south-stage01"
	url = config.getVpcEndpoint()
	assert.Equal(t, url, "https://us-south-stage01.iaasdev.cloud.ibm.com")

	// Check stage private VPC endpoint
	config.EnablePrivate = true
	url = config.getVpcEndpoint()
	assert.Equal(t, url, "https://us-south-stage01.private.iaasdev.cloud.ibm.com")
}

func TestConfigVpc_GetSummary(t *testing.T) {
	config := ConfigVpc{
		ClusterID:        "clusterID",
		encryption:       true,
		endpointURL:      "https://us-south.iaas.cloud.ibm.com:443/v1",
		ProviderType:     "g2",
		resourceGroupID:  "resourceGroupID",
		tokenExchangeURL: "https://iam.bluemix.net",
	}
	result := config.GetSummary()
	assert.Equal(t, result, "ClusterID:clusterID Encryption:true Endpoint:https://us-south.iaas.cloud.ibm.com:443/v1 Provider:g2 ResourceGroup:resourceGroupID TokenExchangeURL:https://iam.bluemix.net")
}

func TestConfigVpc_initializeDefaultEndpoints(t *testing.T) {
	config := &ConfigVpc{Region: "us-south"}
	config.initializeDefaultEndpoints()
	assert.Equal(t, config.endpointURL, "https://us-south.iaas.cloud.ibm.com/v1")
	assert.Equal(t, config.resourceManagerURL, "https://resource-controller.cloud.ibm.com")
	assert.Equal(t, config.tokenExchangeURL, "https://iam.cloud.ibm.com/identity/token")

	// Test endpoints for stage
	config.Region = "us-south-stage01"
	config.initializeDefaultEndpoints()
	assert.Equal(t, config.endpointURL, "https://us-south-stage01.iaasdev.cloud.ibm.com/v1")
	assert.Equal(t, config.resourceManagerURL, "https://resource-controller.test.cloud.ibm.com")
	assert.Equal(t, config.tokenExchangeURL, "https://iam.stage1.bluemix.net/identity/token")

	// Test endpoint overrides
	config.IamEndpointOverride = "https://override.iam.cloud.ibm.com"
	config.RmEndpointOverride = "https://override.rm.cloud.ibm.com"
	config.VpcEndpointOverride = "https://override.iaas.cloud.ibm.com"
	config.initializeDefaultEndpoints()
	assert.Equal(t, config.endpointURL, "https://override.iaas.cloud.ibm.com/v1")
	assert.Equal(t, config.resourceManagerURL, "https://override.rm.cloud.ibm.com")
	assert.Equal(t, config.tokenExchangeURL, "https://override.iam.cloud.ibm.com/identity/token")
}

func TestConfigVpc_LbNameCache(t *testing.T) {
	config := ConfigVpc{lbNameCache: map[string]string{}}
	assert.Equal(t, len(config.lbNameCache), 0)

	// Add to load balancers to the cache
	lb1 := &VpcLoadBalancer{ID: "1", Name: "lb_1"}
	config.addLbToCache(lb1)
	assert.Equal(t, len(config.lbNameCache), 1)
	lb2 := &VpcLoadBalancer{ID: "2", Name: "lb_2"}
	config.addLbToCache(lb2)
	assert.Equal(t, len(config.lbNameCache), 2)

	// Verify that the LB IDs can be retried
	id := config.searchCacheForLb("lb_1")
	assert.Equal(t, id, "1")
	id = config.searchCacheForLb("lb_3")
	assert.Equal(t, id, "")

	// Verify that cache entries can be removed
	config.removeLbFromCache(lb1)
	assert.Equal(t, len(config.lbNameCache), 1)
	config.removeLbNameFromCache("not found in cache")
	assert.Equal(t, len(config.lbNameCache), 1)
	config.removeLbNameFromCache("lb_2")
	assert.Equal(t, len(config.lbNameCache), 0)
}

func TestConfigVpc_validate(t *testing.T) {
	config := ConfigVpc{}

	// Empty config
	err := config.validate()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Missing required cloud configuration setting")

	// Valid "fake" config
	config.ClusterID = "clusterID"
	config.ProviderType = VpcProviderTypeFake
	err = config.validate()
	assert.Nil(t, err)

	// Valid "secret" config
	config.ProviderType = VpcProviderTypeSecret
	err = config.validate()
	assert.Nil(t, err)

	// Valid "G2" config
	config.ProviderType = VpcProviderTypeGen2
	err = config.validate()
	assert.Nil(t, err)

	// Valid "G2" config
	config.ProviderType = "invalid"
	err = config.validate()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Invalid cloud configuration setting")
}

func TestCloudVpc_filterLoadBalancersOnlyNLB(t *testing.T) {
	lb1 := &VpcLoadBalancer{ID: "lb1", Name: "kube-clusterID-1234", ProfileFamily: "network"}
	lb2 := &VpcLoadBalancer{ID: "lb2", Name: "kube-clusterID-1234"}

	// Find the one NLB node in the list
	inLBs := []*VpcLoadBalancer{lb1, lb2}
	outLBs := mockCloud.filterLoadBalancersOnlyNLB(inLBs)
	assert.Equal(t, len(outLBs), 1)
	assert.Equal(t, outLBs[0].ID, "lb1")
}

func TestCloudVpc_FilterNodesByEdgeLabel(t *testing.T) {
	// Pull out the 1 edge node from the list of 2 nodes
	inNodes := []*v1.Node{mockNode1, mockNode2}
	outNodes := mockCloud.filterNodesByEdgeLabel(inNodes)
	assert.Equal(t, len(outNodes), 1)
	assert.Equal(t, outNodes[0].Name, mockNode1.Name)

	// No edge nodes in the list
	inNodes = []*v1.Node{mockNode2}
	outNodes = mockCloud.filterNodesByEdgeLabel(inNodes)
	assert.Equal(t, len(outNodes), 1)
	assert.Equal(t, outNodes[0].Name, mockNode2.Name)
}

func TestCloudVpc_filterNodesByNodeNames(t *testing.T) {
	// Pull out the 1 node that is in the map
	nodeNames := map[string]int{"192.168.1.1": 1, "192.168.2.2": 0}
	inNodes := []*v1.Node{mockNode1, mockNode2}
	outNodes := mockCloud.filterNodesByNodeNames(inNodes, nodeNames)
	assert.Equal(t, len(outNodes), 1)
	assert.Equal(t, outNodes[0].Name, mockNode1.Name)

	// No nodes are listed in the map
	nodeNames = map[string]int{"192.168.1.1": 0, "192.168.2.2": 0, "192.168.3.3": 0}
	inNodes = []*v1.Node{mockNode1, mockNode2}
	outNodes = mockCloud.filterNodesByNodeNames(inNodes, nodeNames)
	assert.Equal(t, len(outNodes), 0)
}

func TestCloudVpc_FilterNodesByServiceMemberQuota(t *testing.T) {
	mockService := &v1.Service{}
	mockOptions := newServiceOptions()
	node1a := &v1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{nodeLabelZone: "zoneA", nodeLabelInternalIP: "192.168.1.1"}}}
	node2a := &v1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{nodeLabelZone: "zoneA", nodeLabelInternalIP: "192.168.1.2"}}}
	node3a := &v1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{nodeLabelZone: "zoneA", nodeLabelInternalIP: "192.168.1.3"}}}
	node4a := &v1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{nodeLabelZone: "zoneA", nodeLabelInternalIP: "192.168.1.4"}}}
	node1b := &v1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{nodeLabelZone: "zoneB", nodeLabelInternalIP: "192.168.2.1"}}}
	node2b := &v1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{nodeLabelZone: "zoneB", nodeLabelInternalIP: "192.168.2.2"}}}
	node1c := &v1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{nodeLabelZone: "zoneC", nodeLabelInternalIP: "192.168.3.1"}}}
	desiredNodes := []*v1.Node{node1a, node2a, node3a, node4a}
	existingNodes := []string{"192.168.1.2", "192.168.1.5", "192.168.1.6"}
	// Invalid annotation on the service
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "invalid"}
	nodes, err := mockCloud.filterNodesByServiceMemberQuota(desiredNodes, existingNodes, mockService, mockOptions)
	assert.Nil(t, nodes)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Disable quota checking annotation on the service
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "disable"}
	nodes, err = mockCloud.filterNodesByServiceMemberQuota(desiredNodes, existingNodes, mockService, mockOptions)
	assert.Equal(t, len(nodes), len(desiredNodes))
	assert.Nil(t, err)

	// Number of nodes is less than the service quota
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "10"}
	nodes, err = mockCloud.filterNodesByServiceMemberQuota(desiredNodes, existingNodes, mockService, mockOptions)
	assert.Equal(t, len(nodes), len(desiredNodes))
	assert.Nil(t, err)

	// ExternalTrafficPolicy: Local and we are over the quota. All desired nodes are returned
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "2"}
	mockService.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeLocal
	nodes, err = mockCloud.filterNodesByServiceMemberQuota(desiredNodes, existingNodes, mockService, mockOptions)
	assert.Equal(t, len(nodes), len(desiredNodes))
	assert.Nil(t, err)
	mockService.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeCluster

	// ExternalTrafficPolicy: Cluster and we are over the quota
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "1"}
	nodes, err = mockCloud.filterNodesByServiceMemberQuota(desiredNodes, existingNodes, mockService, mockOptions)
	assert.Equal(t, len(nodes), 1)
	assert.Nil(t, err)
	assert.Equal(t, nodes[0], "192.168.1.2")

	// ExternalTrafficPolicy: Cluster and we are over the quota
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "2"}
	nodes, err = mockCloud.filterNodesByServiceMemberQuota(desiredNodes, existingNodes, mockService, mockOptions)
	assert.Equal(t, len(nodes), 2)
	assert.Nil(t, err)
	assert.Equal(t, nodes[0], "192.168.1.2")
	assert.Equal(t, nodes[1], "192.168.1.1")

	// ExternalTrafficPolicy: Cluster and we are over the quota
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "3"}
	nodes, err = mockCloud.filterNodesByServiceMemberQuota(desiredNodes, existingNodes, mockService, mockOptions)
	assert.Equal(t, len(nodes), 3)
	assert.Nil(t, err)
	assert.Equal(t, nodes[0], "192.168.1.2")
	assert.Equal(t, nodes[1], "192.168.1.1")
	assert.Equal(t, nodes[2], "192.168.1.3")

	// ExternalTrafficPolicy: Cluster and we are over the quota. 2 zones.
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "1"}
	desiredNodes = []*v1.Node{node1a, node2a, node3a, node4a, node1b, node2b}
	existingNodes = []string{}
	nodes, err = mockCloud.filterNodesByServiceMemberQuota(desiredNodes, existingNodes, mockService, mockOptions)
	assert.Equal(t, len(nodes), 2)
	assert.Nil(t, err)
	sort.Strings(nodes)
	assert.Equal(t, nodes[0], "192.168.1.1")
	assert.Equal(t, nodes[1], "192.168.2.1")

	// ExternalTrafficPolicy: Cluster and we are over the quota. 3 zones.
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "2"}
	desiredNodes = []*v1.Node{node1a, node2a, node3a, node4a, node1b, node2b, node1c}
	nodes, err = mockCloud.filterNodesByServiceMemberQuota(desiredNodes, existingNodes, mockService, mockOptions)
	assert.Equal(t, len(nodes), 5)
	assert.Nil(t, err)
	sort.Strings(nodes)
	assert.Equal(t, nodes[0], "192.168.1.1")
	assert.Equal(t, nodes[1], "192.168.1.2")
	assert.Equal(t, nodes[2], "192.168.2.1")
	assert.Equal(t, nodes[3], "192.168.2.2")
	assert.Equal(t, nodes[4], "192.168.3.1")
}

func TestCloudVpc_filterNodesByZone(t *testing.T) {
	// No nodes matching the request zone
	inNodes := []*v1.Node{mockNode1, mockNode2}
	outNodes := mockCloud.filterNodesByZone(inNodes, "zoneX")
	assert.Equal(t, len(outNodes), 0)

	// Find nodes matching one of the zones
	outNodes = mockCloud.filterNodesByZone(inNodes, "zoneA")
	assert.Equal(t, len(outNodes), 1)
	assert.Equal(t, outNodes[0].Name, mockNode1.Name)

	// No zone specified. All nodes returned
	outNodes = mockCloud.filterNodesByZone(inNodes, "")
	assert.Equal(t, len(outNodes), 2)
}

func TestCloudVpc_filterSubnetsBySubnetIDs(t *testing.T) {
	// No subnets matching the requested subnet ID
	inSubnets := []*VpcSubnet{{ID: "subnet1"}, {ID: "subnet2"}, {ID: "subnet3"}}
	outSubnets := mockCloud.filterSubnetsBySubnetIDs(inSubnets, []string{"subnet"})
	assert.Equal(t, len(outSubnets), 0)

	// Find the two subnets that match
	outSubnets = mockCloud.filterSubnetsBySubnetIDs(inSubnets, []string{"subnet1", "subnet3"})
	assert.Equal(t, len(outSubnets), 2)
	assert.Equal(t, outSubnets[0].ID, "subnet1")
	assert.Equal(t, outSubnets[1].ID, "subnet3")
}

func TestCloudVpc_filterSubnetsByZone(t *testing.T) {
	// No subnets matching the requested zone
	inSubnets := []*VpcSubnet{{ID: "subnet1", Zone: "zoneA"}, {ID: "subnet2", Zone: "zoneB"}, {ID: "subnet3", Zone: "zoneA"}}
	outSubnets := mockCloud.filterSubnetsByZone(inSubnets, "zone")
	assert.Equal(t, len(outSubnets), 0)

	// Find the two subnets that match
	outSubnets = mockCloud.filterSubnetsByZone(inSubnets, "zoneA")
	assert.Equal(t, len(outSubnets), 2)
	assert.Equal(t, outSubnets[0].ID, "subnet1")
	assert.Equal(t, outSubnets[1].ID, "subnet3")
}

func TestCloudVpc_filterZonesByNodeCountsInEachZone(t *testing.T) {
	// None of the input subnets have nodes
	nodeCounts := map[string]int{"zoneA": 1, "zoneB": 3, "zoneC": 2}
	inZones := []string{"zoneX", "zoneY", "zoneZ"}
	outZones := mockCloud.filterZonesByNodeCountsInEachZone(inZones, nodeCounts)
	assert.Equal(t, len(outZones), 0)

	// Two of subnets have worker nodes
	inZones = []string{"zoneA", "zoneB", "zoneX", "zoneY", "zoneZ"}
	outZones = mockCloud.filterZonesByNodeCountsInEachZone(inZones, nodeCounts)
	assert.Equal(t, len(outZones), 2)
	assert.Equal(t, outZones[0], "zoneA")
	assert.Equal(t, outZones[1], "zoneB")
}

func TestCloudVpc_FindNodesMatchingLabelValue(t *testing.T) {
	// Pull out the 1 edge node from the list of 2 nodes
	inNodes := []*v1.Node{mockNode1, mockNode2}
	outNodes := mockCloud.findNodesMatchingLabelValue(inNodes, nodeLabelDedicated, nodeLabelValueEdge)
	assert.Equal(t, len(outNodes), 1)
	assert.Equal(t, outNodes[0].Name, mockNode1.Name)

	// No edge nodes in the list, return matches = 0
	inNodes = []*v1.Node{mockNode2}
	outNodes = mockCloud.findNodesMatchingLabelValue(inNodes, nodeLabelDedicated, nodeLabelValueEdge)
	assert.Equal(t, len(outNodes), 0)
}

func TestCloudVpc_findRenamedLoadBalancer(t *testing.T) {
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake, WorkerAccountID: "workerAccountID"}, nil)
	// Test failure to get list of load balancers
	c.SetFakeSdkError("ListLoadBalancers")
	lb, err := c.findRenamedLoadBalancer("hostname", "192.168.0.1")
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "ListLoadBalancers failed")
	c.ClearFakeSdkError("ListLoadBalancers")

	// Find  existing VPC LB based on hostname
	lb, err = c.findRenamedLoadBalancer("lb.ibm.com", "")
	assert.Nil(t, err)
	assert.NotNil(t, lb)

	// Find existing VPC LB based on pubic IP
	lb, err = c.findRenamedLoadBalancer("", "192.168.0.2,192.168.0.1")
	assert.Nil(t, err)
	assert.NotNil(t, lb)

	// Find existing VPC LB based on private IP
	lb, err = c.findRenamedLoadBalancer("", "10.0.0.2,10.0.0.1")
	assert.Nil(t, err)
	assert.NotNil(t, lb)

	// Existing VPC LB not found
	lb, err = c.findRenamedLoadBalancer("hostname-not-found", "1.2.3.4")
	assert.Nil(t, err)
	assert.Nil(t, lb)
}

func TestCloudVpc_GetClusterVpcSubnetIDs(t *testing.T) {
	// Config map was not created yet
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	vpcID, subnets, err := c.GetClusterVpcSubnetIDs()
	assert.Equal(t, vpcID, "")
	assert.Equal(t, len(subnets), 0)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("Failed to get %s/%s config map", VpcCloudProviderNamespace, VpcCloudProviderConfigMap))

	// Config map not formatted properly
	configMap := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: VpcCloudProviderConfigMap, Namespace: VpcCloudProviderNamespace}}
	c.KubeClient = fake.NewSimpleClientset(configMap)
	vpcID, subnets, err = c.GetClusterVpcSubnetIDs()
	assert.Equal(t, vpcID, "")
	assert.Equal(t, len(subnets), 0)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "config map does not contain key")

	// Successfully retrieved values from config map
	configMap.Data = map[string]string{VpcCloudProviderSubnetsKey: "f16dd75c-dce9-4724-bab4-59db6aa2300a", VpcCloudProviderVpcIDKey: "1234-5678"}
	c.KubeClient = fake.NewSimpleClientset(configMap)
	vpcID, subnets, err = c.GetClusterVpcSubnetIDs()
	assert.Equal(t, vpcID, "1234-5678")
	assert.Equal(t, len(subnets), 1)
	assert.Equal(t, subnets[0], "f16dd75c-dce9-4724-bab4-59db6aa2300a")
	assert.Nil(t, err)

	// Config map not created.  Data extracted from saved values
	c.Config.clusterSubnetIDs = "subnetID-1,subnetID-2"
	c.Config.vpcID = "vpcID"
	c.KubeClient = fake.NewSimpleClientset()
	vpcID, subnets, err = c.GetClusterVpcSubnetIDs()
	assert.Equal(t, vpcID, "vpcID")
	assert.Equal(t, len(subnets), 2)
	assert.Equal(t, subnets[0], "subnetID-1")
	assert.Nil(t, err)

	// VPC name specified, failed to get list of VPCs
	c.Config.vpcID = ""
	c.Config.VpcName = "vpc"
	c.SetFakeSdkError("ListVPCs")
	vpcID, subnets, err = c.GetClusterVpcSubnetIDs()
	assert.Equal(t, vpcID, "")
	assert.Equal(t, len(subnets), 0)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ListVPCs failed")
	c.ClearFakeSdkError("ListVPCs")

	// VPC name specified, not found in list of VPCs
	c.Config.vpcID = ""
	c.Config.VpcName = "not-found-vpc"
	vpcID, subnets, err = c.GetClusterVpcSubnetIDs()
	assert.Equal(t, vpcID, "")
	assert.Equal(t, len(subnets), 0)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Failed to locate VPC with name")

	// VPC subnet names specified, failed to get list of subnets
	c.Config.vpcID = ""
	c.Config.VpcName = "vpc"
	c.Config.clusterSubnetIDs = ""
	c.Config.SubnetNames = "subnet,subnetVpc2"
	c.SetFakeSdkError("ListSubnets")
	vpcID, subnets, err = c.GetClusterVpcSubnetIDs()
	assert.Equal(t, vpcID, "")
	assert.Equal(t, len(subnets), 0)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ListSubnets failed")
	c.ClearFakeSdkError("ListSubnets")

	// VPC subnet names specified, not found in list of subnets
	c.Config.clusterSubnetIDs = ""
	c.Config.SubnetNames = "subnet,subnetVpc2"
	vpcID, subnets, err = c.GetClusterVpcSubnetIDs()
	assert.Equal(t, vpcID, "")
	assert.Equal(t, len(subnets), 0)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Failed to locate VPC subnet with name")

	// VPC subnet names specified, not found in list of subnets
	c.Config.vpcID = ""
	c.Config.VpcName = "vpc"
	c.Config.clusterSubnetIDs = ""
	c.Config.SubnetNames = "subnet"
	vpcID, subnets, err = c.GetClusterVpcSubnetIDs()
	assert.Nil(t, err)
	assert.Equal(t, vpcID, "vpcID")
	assert.Equal(t, len(subnets), 1)
	assert.Equal(t, subnets[0], "subnetID")
	assert.Equal(t, c.Config.vpcID, "vpcID")
	assert.Equal(t, c.Config.clusterSubnetIDs, "subnetID")
}

func TestCloudVpc_GetClusterVpcID(t *testing.T) {
	// Failed to get the cloud provider config map
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	vpcID, err := c.GetClusterVpcID()
	assert.Equal(t, vpcID, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("Failed to get %s/%s config map", VpcCloudProviderNamespace, VpcCloudProviderConfigMap))
	configMap := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: VpcCloudProviderConfigMap, Namespace: VpcCloudProviderNamespace},
		Data:       map[string]string{VpcCloudProviderSubnetsKey: "subnetID"},
	}
	c.KubeClient = fake.NewSimpleClientset(configMap)

	// Failed to get list of VPCs
	c.SetFakeSdkError("GetSubnet")
	vpcID, err = c.GetClusterVpcID()
	assert.Equal(t, vpcID, "")
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "GetSubnet failed")
	c.ClearFakeSdkError("GetSubnet")

	// Success - found the VPC ID that was cached in the config
	c.Config.vpcID = "cachedVpcID"
	vpcID, err = c.GetClusterVpcID()
	assert.Equal(t, vpcID, "cachedVpcID")
	assert.Equal(t, c.Config.vpcID, "cachedVpcID")
	assert.Nil(t, err)

	// Success - found the VPC ID by comparing cluster subnets and actual subnets
	c.Config.vpcID = ""
	vpcID, err = c.GetClusterVpcID()
	assert.Equal(t, vpcID, "vpcID")
	assert.Equal(t, c.Config.vpcID, "vpcID")
	assert.Nil(t, err)

	// Success - VPC ID is stored in the config map
	c.Config.vpcID = ""
	configMap = &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: VpcCloudProviderConfigMap, Namespace: VpcCloudProviderNamespace},
		Data:       map[string]string{VpcCloudProviderSubnetsKey: "subnetID", VpcCloudProviderVpcIDKey: "vpcFromConfigMap"},
	}
	c.KubeClient = fake.NewSimpleClientset(configMap)
	vpcID, err = c.GetClusterVpcID()
	assert.Equal(t, vpcID, "vpcFromConfigMap")
	assert.Equal(t, c.Config.vpcID, "vpcFromConfigMap")
	assert.Nil(t, err)
}

func TestCloudVpc_getNodeCountInEachZone(t *testing.T) {
	nodes := []*v1.Node{mockNode1, mockNode2, mockNode1}
	result := mockCloud.getNodeCountInEachZone(nodes)
	assert.Equal(t, len(result), 2)
	assert.Equal(t, result["zoneA"], 2)
	assert.Equal(t, result["zoneB"], 1)
}

func TestCloudVpc_getLoadBalancerCountInEachZone(t *testing.T) {
	lbA := &VpcLoadBalancer{Subnets: []VpcObjectReference{{ID: "subnetA"}}}
	lbB := &VpcLoadBalancer{Subnets: []VpcObjectReference{{ID: "subnetA"}, {ID: "subnetB"}}}
	lbC := &VpcLoadBalancer{Subnets: []VpcObjectReference{{ID: "subnetA"}, {ID: "subnetB"}, {ID: "subnetC"}}}
	vpcSubnets := []*VpcSubnet{
		{ID: "subnetA", Zone: "zoneA"},
		{ID: "subnetB", Zone: "zoneB"},
		{ID: "subnetC", Zone: "zoneC"},
	}
	lbs := []*VpcLoadBalancer{lbA, lbB, lbC}
	result := mockCloud.getLoadBalancerCountInEachZone(lbs, vpcSubnets)
	assert.Equal(t, len(result), 3)
	assert.Equal(t, result["zoneA"], 3)
	assert.Equal(t, result["zoneB"], 2)
	assert.Equal(t, result["zoneC"], 1)
}

func TestCloudVpc_GetNodeIDs(t *testing.T) {
	nodes := []*v1.Node{mockNode1, mockNode2, mockNode3}
	options := newServiceOptions()
	nodeIDs := mockCloud.getNodeIDs(nodes, options)
	assert.Equal(t, len(nodeIDs), 2)
	assert.Equal(t, nodeIDs[0], mockNode1.Name)
	assert.Equal(t, nodeIDs[1], mockNode2.Name)

	// Get node identifiers - nlb
	mockNode1.Labels[nodeLabelInstanceID] = "instance1"
	mockNode2.Labels[nodeLabelInstanceID] = "instance2"
	options.enabledFeatures = LoadBalancerOptionNLB
	nodeIDs = mockCloud.getNodeIDs(nodes, options)
	assert.Equal(t, len(nodeIDs), 2)
	assert.Equal(t, nodeIDs[0], "instance1")
	assert.Equal(t, nodeIDs[1], "instance2")

	// Get node identifiers - sdnlb
	mockNode1.Labels[nodeLabelInstanceID] = "instance1"
	mockNode2.Labels[nodeLabelInstanceID] = "instance2"
	options.enabledFeatures = LoadBalancerOptionsSdnlbInternal
	nodeIDs = mockCloud.getNodeIDs(nodes, options)
	assert.Equal(t, len(nodeIDs), 2)
	assert.Equal(t, nodeIDs[0], "zoneA/instance1")
	assert.Equal(t, nodeIDs[1], "zoneB/instance2")

	// ipiMode=true, Get node identifiers - nlb
	mockCloud.Config.ipiMode = true
	mockNode1.Labels[nodeLabelIpiInstanceID] = "instance1"
	mockNode2.Labels[nodeLabelIpiInstanceID] = "instance2"
	options.enabledFeatures = LoadBalancerOptionNLB
	nodeIDs = mockCloud.getNodeIDs(nodes, options)
	assert.Equal(t, len(nodeIDs), 2)
	assert.Equal(t, nodeIDs[0], "instance1")
	assert.Equal(t, nodeIDs[1], "instance2")

	// ipiMode=true, Get node identifiers - sdnlb
	mockCloud.Config.ipiMode = true
	mockNode1.Labels[nodeLabelIpiInstanceID] = "instance1"
	mockNode2.Labels[nodeLabelIpiInstanceID] = "instance2"
	options.enabledFeatures = LoadBalancerOptionsSdnlbInternal
	nodeIDs = mockCloud.getNodeIDs(nodes, options)
	assert.Equal(t, len(nodeIDs), 2)
	assert.Equal(t, nodeIDs[0], "zoneA/instance1")
	assert.Equal(t, nodeIDs[1], "zoneB/instance2")
}

func TestCloudVpc_GetNodeInteralIP(t *testing.T) {
	internalIP := mockCloud.getNodeInternalIP(mockNode1)
	assert.Equal(t, "192.168.1.1", internalIP)

	internalIP = mockCloud.getNodeInternalIP(mockNode2)
	assert.Equal(t, "192.168.2.2", internalIP)

	internalIP = mockCloud.getNodeInternalIP(mockNode3)
	assert.Equal(t, "", internalIP)

	internalIP = mockCloud.getNodeInternalIP(mockNode4)
	assert.Equal(t, "", internalIP)
}

func TestCloudVpc_GetPoolMemberTargets(t *testing.T) {
	members := []*VpcLoadBalancerPoolMember{{TargetIPAddress: "192.168.1.1", TargetInstanceID: "1234-56-7890"}}
	options := newServiceOptions()
	result := mockCloud.getPoolMemberTargets(members, options)
	assert.Equal(t, len(result), 1)
	assert.Equal(t, result[0], "192.168.1.1")
	options.enabledFeatures = LoadBalancerOptionNLB
	result = mockCloud.getPoolMemberTargets(members, options)
	assert.Equal(t, len(result), 1)
	assert.Equal(t, result[0], "1234-56-7890")
	options.enabledFeatures = LoadBalancerOptionsSdnlbInternal
	result = mockCloud.getPoolMemberTargets(members, options)
	assert.Equal(t, len(result), 1)
	assert.Equal(t, result[0], "1234-56-7890")
}

func TestCloudVpc_getPortMaxFromPortRanges(t *testing.T) {
	// getPortMaxFromPortRanges, empty port range. max = min
	result := mockCloud.getPortMaxFromPortRanges(80, "")
	assert.Equal(t, result, 80)

	// getPortMaxFromPortRanges, request port not in port range
	result = mockCloud.getPortMaxFromPortRanges(80, "30000-32767")
	assert.Equal(t, result, 80)

	// getPortMaxFromPortRanges, request port in port range
	result = mockCloud.getPortMaxFromPortRanges(30000, "30000-32767")
	assert.Equal(t, result, 32767)
}

func TestCloudVpc_getServiceEndpointNodeCounts(t *testing.T) {
	// No endpoint found for the service
	mockService := &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default", UID: "1234"}}
	nodesFound, err := mockCloud.getServiceEndpointNodeCounts(mockService)
	assert.Empty(t, nodesFound)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Failed to get default/echo-server endpoints")

	// Endpoint defined for the service, no backend pods
	endpoints := &v1.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default"}}
	mockCloud.KubeClient = fake.NewSimpleClientset(endpoints)
	nodesFound, err = mockCloud.getServiceEndpointNodeCounts(mockService)
	assert.Empty(t, nodesFound)
	assert.Nil(t, err)

	// Endpoint defined for the service, multiple backend pods on multiple nodes
	node1 := mockNode1.Name
	node2 := mockNode2.Name
	endpoints = &v1.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default"},
		Subsets: []v1.EndpointSubset{{Addresses: []v1.EndpointAddress{{NodeName: &node1}, {NodeName: &node2}, {NodeName: &node1}}}}}
	mockCloud.KubeClient = fake.NewSimpleClientset(endpoints)
	nodesFound, err = mockCloud.getServiceEndpointNodeCounts(mockService)
	assert.Nil(t, err)
	assert.Equal(t, len(nodesFound), 2)
	assert.Equal(t, nodesFound[node1], 2)
	assert.Equal(t, nodesFound[node2], 1)
	mockCloud.KubeClient = fake.NewSimpleClientset()
}

func TestCloudVpc_GetServiceExternalIPs(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default"},
	}
	// No status listed set in the service
	externalIP := mockCloud.getServiceExternalIPs(service)
	assert.Empty(t, externalIP)

	// Load balancer has status, but there is no external IP
	service.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{Hostname: "hostname"}}
	externalIP = mockCloud.getServiceExternalIPs(service)
	assert.Empty(t, externalIP)

	// Extract external IPs from the service
	service.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{
		{IP: "192.168.3.3", Hostname: "hostname"},
		{IP: "192.168.1.1"},
		{IP: "192.168.2.2"},
	}
	externalIP = mockCloud.getServiceExternalIPs(service)
	assert.Equal(t, externalIP, "192.168.1.1,192.168.2.2,192.168.3.3")
}

func TestCloudVpc_getServiceHealthCheckDelay(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	// No annotation specified, return 5, nil
	delay, err := mockCloud.getServiceHealthCheckDelay(service)
	assert.Equal(t, delay, healthCheckDelayDefault)
	assert.Nil(t, err)

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckDelay] = "invalid"
	delay, err = mockCloud.getServiceHealthCheckDelay(service)
	assert.Equal(t, delay, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckDelay] = "62"
	delay, err = mockCloud.getServiceHealthCheckDelay(service)
	assert.Equal(t, delay, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a value in the allowed range")

	// Valid annotation specified
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckDelay] = "10"
	delay, err = mockCloud.getServiceHealthCheckDelay(service)
	assert.Equal(t, delay, 10)
	assert.Nil(t, err)
}

func TestCloudVpc_getServiceHealthCheckPath(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	// No annotation specified, return "/"
	path, err := mockCloud.getServiceHealthCheckPath(service)
	assert.Equal(t, path, "/")
	assert.Nil(t, err)

	// Invalid annotation specified, return "" and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckPath] = "invalid path"
	path, err = mockCloud.getServiceHealthCheckPath(service)
	assert.Equal(t, path, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Valid annotation specified
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckPath] = "/health"
	path, err = mockCloud.getServiceHealthCheckPath(service)
	assert.Equal(t, path, "/health")
	assert.Nil(t, err)
}

func TestCloudVpc_getServiceHealthCheckPort(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	// No annotation specified, return 0, nil
	port, err := mockCloud.getServiceHealthCheckPort(service)
	assert.Equal(t, port, 0)
	assert.Nil(t, err)

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckPort] = "invalid"
	port, err = mockCloud.getServiceHealthCheckPort(service)
	assert.Equal(t, port, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckPort] = "99999"
	port, err = mockCloud.getServiceHealthCheckPort(service)
	assert.Equal(t, port, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a value in the allowed range")

	// Valid annotation specified
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckPort] = "443"
	port, err = mockCloud.getServiceHealthCheckPort(service)
	assert.Equal(t, port, 443)
	assert.Nil(t, err)
}

func TestCloudVpc_getServiceHealthCheckProtocol(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	// No annotation specified, return "", nil
	protocol, err := mockCloud.getServiceHealthCheckProtocol(service)
	assert.Equal(t, protocol, "")
	assert.Nil(t, err)

	// Invalid annotation specified, return "" and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckProtocol] = "invalid"
	protocol, err = mockCloud.getServiceHealthCheckProtocol(service)
	assert.Equal(t, protocol, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Valid annotation specified
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckProtocol] = "http"
	protocol, err = mockCloud.getServiceHealthCheckProtocol(service)
	assert.Equal(t, protocol, "http")
	assert.Nil(t, err)
}

func TestCloudVpc_getServiceHealthCheckRetries(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	// No annotation specified, return 5, nil
	retries, err := mockCloud.getServiceHealthCheckRetries(service)
	assert.Equal(t, retries, healthCheckRetriesDefault)
	assert.Nil(t, err)

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckRetries] = "invalid"
	retries, err = mockCloud.getServiceHealthCheckRetries(service)
	assert.Equal(t, retries, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckRetries] = "12"
	retries, err = mockCloud.getServiceHealthCheckRetries(service)
	assert.Equal(t, retries, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a value in the allowed range")

	// Valid annotation specified
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckRetries] = "3"
	retries, err = mockCloud.getServiceHealthCheckRetries(service)
	assert.Equal(t, retries, 3)
	assert.Nil(t, err)
}

func TestCloudVpc_getServiceHealthCheckTimeout(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	// No annotation specified, return 5, nil
	timeout, err := mockCloud.getServiceHealthCheckTimeout(service)
	assert.Equal(t, timeout, healthCheckTimeoutDefault)
	assert.Nil(t, err)

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckTimeout] = "invalid"
	timeout, err = mockCloud.getServiceHealthCheckTimeout(service)
	assert.Equal(t, timeout, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckTimeout] = "62"
	timeout, err = mockCloud.getServiceHealthCheckTimeout(service)
	assert.Equal(t, timeout, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a value in the allowed range")

	// Valid annotation specified
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckTimeout] = "3"
	timeout, err = mockCloud.getServiceHealthCheckTimeout(service)
	assert.Equal(t, timeout, 3)
	assert.Nil(t, err)
}

func TestCloudVpc_getServiceHealthCheckUDP(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolUDP, Port: 80, NodePort: 30123}}},
	}
	// No annotation specified, return 0, nil
	port, err := mockCloud.getServiceHealthCheckUDP(service)
	assert.Equal(t, port, 0)
	assert.Nil(t, err)

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckUDP] = "invalid"
	port, err = mockCloud.getServiceHealthCheckUDP(service)
	assert.Equal(t, port, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckUDP] = "99999"
	port, err = mockCloud.getServiceHealthCheckUDP(service)
	assert.Equal(t, port, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a value in the allowed range")

	// Valid annotation specified
	service.ObjectMeta.Annotations[serviceAnnotationHealthCheckUDP] = "10250"
	port, err = mockCloud.getServiceHealthCheckUDP(service)
	assert.Equal(t, port, 10250)
	assert.Nil(t, err)
}

func TestCloudVpc_GetServiceHostname(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default"},
	}
	// No status listed set in the service
	hostname := mockCloud.getServiceHostname(service)
	assert.Empty(t, hostname)

	// Load balancer has status, but there is no hostname
	service.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{IP: "192.169.1.1"}, {IP: "192.169.2.2"}}
	hostname = mockCloud.getServiceHostname(service)
	assert.Empty(t, hostname)

	// Extract hostname from service
	service.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{IP: "192.169.1.1", Hostname: "hostname"}}
	hostname = mockCloud.getServiceHostname(service)
	assert.Equal(t, hostname, "hostname")
}

func TestCloudVpc_getServiceIdleConnectionTimeout(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	// No annotation specified, return 5, nil
	timeout, err := mockCloud.getServiceIdleConnectionTimeout(service)
	assert.Equal(t, timeout, idleConnTimeoutDefault)
	assert.Nil(t, err)

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationIdleConnTimeout] = "invalid"
	timeout, err = mockCloud.getServiceIdleConnectionTimeout(service)
	assert.Equal(t, timeout, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationIdleConnTimeout] = "7201"
	timeout, err = mockCloud.getServiceIdleConnectionTimeout(service)
	assert.Equal(t, timeout, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a value in the allowed range")

	// Invalid annotation specified, return -1 and error
	service.ObjectMeta.Annotations[serviceAnnotationIdleConnTimeout] = "49"
	timeout, err = mockCloud.getServiceIdleConnectionTimeout(service)
	assert.Equal(t, timeout, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a value in the allowed range")

	// Valid annotation specified
	service.ObjectMeta.Annotations[serviceAnnotationIdleConnTimeout] = "60"
	timeout, err = mockCloud.getServiceIdleConnectionTimeout(service)
	assert.Equal(t, timeout, 60)
	assert.Nil(t, err)
}

func TestCloudVpc_GetServiceNodeSelectorFilter(t *testing.T) {
	// No annotation on the service. Output should be ""
	mockService := &v1.Service{}
	filterLabel, filterValue, err := mockCloud.getServiceNodeSelectorFilter(mockService)
	assert.Equal(t, filterLabel, "")
	assert.Equal(t, filterValue, "")
	assert.Nil(t, err)

	// Invalid annotation on the service. Output should be ""
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationNodeSelector: "invalid"}
	filterLabel, filterValue, err = mockCloud.getServiceNodeSelectorFilter(mockService)
	assert.Equal(t, filterLabel, "")
	assert.Equal(t, filterValue, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Valid key in the annotation on the service.  Output should match the annotation value
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationNodeSelector: "node.kubernetes.io/instance-type=cx2.2x4"}
	filterLabel, filterValue, err = mockCloud.getServiceNodeSelectorFilter(mockService)
	assert.Equal(t, filterLabel, "node.kubernetes.io/instance-type")
	assert.Equal(t, filterValue, "cx2.2x4")
	assert.Nil(t, err)
}

func TestCloudVpc_GetServiceMemberQuota(t *testing.T) {
	// No annotation on the service. Return the default quota value
	mockService := &v1.Service{}
	quota, err := mockCloud.getServiceMemberQuota(mockService)
	assert.Equal(t, quota, defaultPoolMemberQuota)
	assert.Nil(t, err)

	// Annotation set to disale quota checks
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "disable"}
	quota, err = mockCloud.getServiceMemberQuota(mockService)
	assert.Equal(t, quota, 0)
	assert.Nil(t, err)

	// Invalid annotation on the service
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "invalid"}
	quota, err = mockCloud.getServiceMemberQuota(mockService)
	assert.Equal(t, quota, -1)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")

	// Valid quota specified in the annotation on the service
	mockService.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "100"}
	quota, err = mockCloud.getServiceMemberQuota(mockService)
	assert.Equal(t, quota, 100)
	assert.Nil(t, err)
}

func TestCloudVpc_getServicePoolNames(t *testing.T) {
	// getPoolNamesForService failed, port range annotation invalid
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	service.ObjectMeta.Annotations[serviceAnnotationEnableFeatures] = LoadBalancerOptionsSdnlbInternal
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "invalid-port-range"
	options := mockCloud.getServiceOptions(service)
	poolNames, err := mockCloud.getServicePoolNames(service, options)
	assert.Empty(t, poolNames)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Improperly formatted data")

	// getPoolNamesForService success, port range in the pool name
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "80-100"
	options = mockCloud.getServiceOptions(service)
	poolNames, err = mockCloud.getServicePoolNames(service, options)
	assert.Nil(t, err)
	assert.Equal(t, len(poolNames), 1)
	assert.Equal(t, poolNames[0], "tcp-80x100-30123")

	// getPoolNamesForService success, port range in the pool name
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = ""
	options = mockCloud.getServiceOptions(service)
	poolNames, err = mockCloud.getServicePoolNames(service, options)
	assert.Nil(t, err)
	assert.Equal(t, len(poolNames), 1)
	assert.Equal(t, poolNames[0], "tcp-80-30123")
}

func TestCloudVpc_getSubnetIDs(t *testing.T) {
	subnets := []*VpcSubnet{{ID: "subnet1"}, {ID: "subnet2"}}
	result := mockCloud.getSubnetIDs(subnets)
	assert.Equal(t, len(result), 2)
	assert.Equal(t, result[0], "subnet1")
	assert.Equal(t, result[1], "subnet2")
}

func TestCloudVpc_getSubnetsForLoadBalancer(t *testing.T) {
	// Config map was not created yet
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	vpcSubnets := []*VpcSubnet{
		{ID: "subnetA", Vpc: VpcObjectReference{ID: "vpcID"}},
		{ID: "subnetB", Vpc: VpcObjectReference{ID: "vpcID"}},
	}
	options := c.getServiceOptions(service)
	subnets, err := c.getSubnetsForLoadBalancer(service, vpcSubnets, options)
	assert.Equal(t, len(subnets), 0)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("Failed to get %s/%s config map", VpcCloudProviderNamespace, VpcCloudProviderConfigMap))

	// Invalid VPC/subnet IDs cached
	c.Config.clusterSubnetIDs = "subnetX"
	c.Config.vpcID = "vpcID"
	subnets, err = c.getSubnetsForLoadBalancer(service, vpcSubnets, options)
	assert.Equal(t, len(subnets), 0)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "contains invalid VPC subnet")

	// Successfully return subnets IDs from config map
	c.Config.clusterSubnetIDs = "subnetA"
	subnets, err = c.getSubnetsForLoadBalancer(service, vpcSubnets, options)
	assert.Nil(t, err)
	assert.Equal(t, len(subnets), 1)
	assert.Equal(t, subnets[0], "subnetA")
}

func TestCloudVpc_getUpdatedSubnetsForForLoadBalancer(t *testing.T) {
	// Config map was not created yet
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	lb := &VpcLoadBalancer{Subnets: []VpcObjectReference{{ID: "subnetA"}}}
	vpcSubnets := []*VpcSubnet{
		{ID: "subnetA", Vpc: VpcObjectReference{ID: "vpcID"}},
		{ID: "subnetB", Vpc: VpcObjectReference{ID: "vpcID"}},
	}
	options := c.getServiceOptions(service)
	subnets, err := c.getUpdatedSubnetsForForLoadBalancer(service, lb, vpcSubnets, options)
	assert.Equal(t, len(subnets), 0)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("Failed to get %s/%s config map", VpcCloudProviderNamespace, VpcCloudProviderConfigMap))

	// Successfully return empty array since no change in subnets
	c.Config.clusterSubnetIDs = "subnetA"
	c.Config.vpcID = "vpcID"
	subnets, err = c.getUpdatedSubnetsForForLoadBalancer(service, lb, vpcSubnets, options)
	assert.Nil(t, err)
	assert.Equal(t, len(subnets), 0)

	// Successfully return array of config map subnets since diff than LB
	c.Config.clusterSubnetIDs = "subnetA,subnetB"
	subnets, err = c.getUpdatedSubnetsForForLoadBalancer(service, lb, vpcSubnets, options)
	assert.Nil(t, err)
	assert.Equal(t, len(subnets), 2)
	assert.Equal(t, subnets[0], "subnetA")
	assert.Equal(t, subnets[1], "subnetB")
}

func TestCloudVpc_getZonesContainingSubnets(t *testing.T) {
	subnets := []*VpcSubnet{{ID: "subnet1", Zone: "zoneA"}, {ID: "subnet2", Zone: "zoneB"}, {ID: "subnet3", Zone: "zoneA"}}
	result := mockCloud.getZonesContainingSubnets(subnets)
	assert.Equal(t, len(result), 2)
	assert.Equal(t, result[0], "zoneA")
	assert.Equal(t, result[1], "zoneB")
}

func TestCloudVpc_initialize(t *testing.T) {
	// Attempt to initiate cloud object, missing cluster ID
	sdnlbSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "sdnlb-config", Namespace: "kube-system"},
		Data: map[string][]byte{"sdnlb.toml": []byte(`[SDNLB]
		cluster_crn = "crn:v1:staging:public:containers-kubernetes:us-south:9625bec6195d552ef0d5612e1587a1f3:c1ahmkk20m9ured3o40g"
		service_apikey = "api-key"`)}}
	cloud := CloudVpc{
		KubeClient: fake.NewSimpleClientset(sdnlbSecret),
		Config: &ConfigVpc{
			AccountID:         "123",
			ResourceGroupName: "resourceGroup",
			SubnetNames:       "subnets",
			VpcName:           "vpc",
			WorkerAccountID:   "123",
		}}
	err := cloud.initialize()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Missing required cloud configuration setting: clusterID")

	// IPI Mode configured
	cloud.Config.ClusterID = "clusterID"
	cloud.Config.ProviderType = VpcProviderTypeGen2
	err = cloud.initialize()
	assert.Nil(t, err)
	assert.Equal(t, cloud.Config.clusterCrnPrefix, "crn:v1:staging:public")
	assert.True(t, cloud.Config.ipiMode)
	assert.Equal(t, cloud.Config.serviceAPIKey, "api-key")
	assert.Equal(t, cloud.Config.serviceType, "internal")
}

func TestCloudVpc_isNodeQuotaFilteringNeeded(t *testing.T) {
	// Invalid quota length
	zoneNodeCount := map[string]int{"ZoneA": 5}
	result := mockCloud.isNodeQuotaFilteringNeeded(0, zoneNodeCount)
	assert.False(t, result)

	// No zones listed in zone node count map
	zoneNodeCount = map[string]int{}
	result = mockCloud.isNodeQuotaFilteringNeeded(5, zoneNodeCount)
	assert.False(t, result)

	// All zones are less than the quota
	zoneNodeCount = map[string]int{"ZoneA": 3, "ZoneB": 4, "ZoneC": 5}
	result = mockCloud.isNodeQuotaFilteringNeeded(8, zoneNodeCount)
	assert.False(t, result)

	// One of the zones has too many nodes
	result = mockCloud.isNodeQuotaFilteringNeeded(4, zoneNodeCount)
	assert.True(t, result)
}

func TestCloudVpc_isServiceUDP(t *testing.T) {
	// Retrieve node port of TCP port
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30123}}},
	}
	result := mockCloud.isServiceUDP(service)
	assert.False(t, result)

	// No TCP port, should return 0
	service.Spec.Ports[0].Protocol = v1.ProtocolUDP
	result = mockCloud.isServiceUDP(service)
	assert.True(t, result)
}

func TestCloudVpc_RefreshClusterVpcSubnetIDs(t *testing.T) {
	// Config map was not specified
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	err := c.refreshClusterVpcSubnetIDs(nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "was not specified")

	// Config map not formatted properly
	configMap := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: VpcCloudProviderConfigMap, Namespace: VpcCloudProviderNamespace}}
	err = c.refreshClusterVpcSubnetIDs(configMap)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "does not contain valid data")

	// Successfully retrieved values from config map
	configMap.Data = map[string]string{VpcCloudProviderSubnetsKey: "f16dd75c-dce9-4724-bab4-59db6aa2300a", VpcCloudProviderVpcIDKey: "1234-5678"}
	err = c.refreshClusterVpcSubnetIDs(configMap)
	assert.Nil(t, err)
	assert.Equal(t, c.Config.vpcID, "1234-5678")
	assert.Equal(t, c.Config.clusterSubnetIDs, "f16dd75c-dce9-4724-bab4-59db6aa2300a")
}

func TestCloudVpc_selectSingleZoneForSubnetAndNodes(t *testing.T) {
	// selectSingleZoneForSubnetAndNodes, 2 zones passed in, only nodes in one of the zones
	nodes := []*v1.Node{mockNode1, mockNode2} // Nodes are in zoneA & zoneB
	subnetZones := []string{"zoneA", "zoneC"}
	vpcSubnets := []*VpcSubnet{{ID: "subnetA", Zone: "zoneA"}, {ID: "subnetC", Zone: "zoneC"}}
	retSubnets, err := mockCloud.selectSingleZoneForSubnet("", vpcSubnets, subnetZones, nodes)
	assert.Nil(t, err)
	assert.Equal(t, len(retSubnets), 1)
	assert.Equal(t, retSubnets[0], "subnetA")

	// selectSingleZoneForSubnetAndNodes, 2 zones passed in, no nodes in any of the zones
	nodes = []*v1.Node{mockNode1} // Node1 is in zoneA
	subnetZones = []string{"zoneC", "zoneD"}
	retSubnets, err = mockCloud.selectSingleZoneForSubnet("", vpcSubnets, subnetZones, nodes)
	assert.Nil(t, err)
	assert.Equal(t, len(retSubnets), 1)
	assert.Equal(t, retSubnets[0], "subnetC")

	// selectSingleZoneForSubnetAndNodes, failed to get list of load balancers
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	nodes = []*v1.Node{mockNode1, mockNode2} // Nodes are in zoneA & zoneB
	subnetZones = []string{"zoneA", "zoneB"}
	vpcSubnets = []*VpcSubnet{{ID: "subnetA", Zone: "zoneA"}, {ID: "subnetB", Zone: "zoneB"}}
	c.SetFakeSdkError("ListLoadBalancers")
	retSubnets, err = c.selectSingleZoneForSubnet("", vpcSubnets, subnetZones, nodes)
	assert.Nil(t, retSubnets)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "ListLoadBalancers failed")
	c.ClearFakeSdkError("ListLoadBalancers")

	// selectSingleZoneForSubnetAndNodes, retrieved list of load balancers
	retSubnets, err = c.selectSingleZoneForSubnet("", vpcSubnets, subnetZones, nodes)
	assert.Nil(t, err)
	assert.Equal(t, len(retSubnets), 1)
}

func TestCloudVpc_selectSubnetZoneForNLB(t *testing.T) {
	lbZones := map[string]int{"zoneA": 1}
	nodeZones := map[string]int{"zoneA": 1, "zoneB": 2, "zoneC": 3}
	// "zoneB" - selected because fewer NLBs in zoneB
	result := mockCloud.selectSubnetZoneForNLB([]string{"zoneA", "zoneB"}, lbZones, nodeZones)
	assert.Equal(t, len(result), 1)
	assert.Equal(t, result[0], "zoneB")

	// "zoneC" - selected because: no NLBs and the most nodes
	result = mockCloud.selectSubnetZoneForNLB([]string{"zoneA", "zoneB", "zoneC"}, lbZones, nodeZones)
	assert.Equal(t, len(result), 1)
	assert.Equal(t, result[0], "zoneC")
}

func TestCloudVpc_ValidateClusterSubnetIDs(t *testing.T) {
	clusterSubnets := []string{"subnetID"}
	vpcSubnets := []*VpcSubnet{{ID: "subnetID"}}

	// validateClusterSubnetIDs, success
	foundSubnets, err := mockCloud.validateClusterSubnetIDs(clusterSubnets, vpcSubnets)
	assert.Equal(t, len(foundSubnets), 1)
	assert.Nil(t, err)

	// validateClusterSubnetIDs failed, invalid subnet ID
	clusterSubnets = []string{"invalid subnet"}
	foundSubnets, err = mockCloud.validateClusterSubnetIDs(clusterSubnets, vpcSubnets)
	assert.Nil(t, foundSubnets)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid VPC subnet")

	// validateClusterSubnetIDs failed, multiple subnets across different VPCs
	clusterSubnets = []string{"subnet1", "subnet2"}
	vpcSubnets = []*VpcSubnet{
		{ID: "subnet1", Vpc: VpcObjectReference{ID: "vpc1"}},
		{ID: "subnet2", Vpc: VpcObjectReference{ID: "vpc2"}},
	}
	foundSubnets, err = mockCloud.validateClusterSubnetIDs(clusterSubnets, vpcSubnets)
	assert.Nil(t, foundSubnets)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "subnets in different VPCs")
}

func TestCloudVpc_validateService(t *testing.T) {
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default", Annotations: map[string]string{}},
		Spec:       v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80}}},
	}
	// validateService, nlb does not support proxy-protocol
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationEnableFeatures: LoadBalancerOptionNLB + "," + LoadBalancerOptionProxyProtocol}
	options, err := mockCloud.validateService(service)
	assert.Nil(t, options)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "can not include both")

	// validateService, private nlb requires vpc-subnet annotation to be set
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationEnableFeatures: LoadBalancerOptionNLB, serviceAnnotationIPType: servicePrivateLB}
	options, err = mockCloud.validateService(service)
	assert.Nil(t, options)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Private network load balancers require the service.kubernetes.io/ibm-load-balancer-cloud-provider-vpc-subnets annotation")

	// validateService, nlb can not be done if we don't have a service account
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationEnableFeatures: LoadBalancerOptionNLB}
	options, err = mockCloud.validateService(service)
	assert.Nil(t, options)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "not possible due to missing config")

	// validateService, idle connection timeout is only supported for ALB
	mockCloud.Config.WorkerAccountID = "workerAccountID"
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationEnableFeatures: LoadBalancerOptionNLB, serviceAnnotationIdleConnTimeout: "60"}
	options, err = mockCloud.validateService(service)
	assert.Nil(t, options)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is only supported on application load balancers")

	// validateService, only TCP or UDP protocol is supported for NLB
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationEnableFeatures: LoadBalancerOptionNLB}
	service.Spec.Ports[0].Protocol = v1.ProtocolSCTP
	options, err = mockCloud.validateService(service)
	assert.Nil(t, options)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Only TCP and UDP are supported")

	// validateService, fail if UDP protocol and then externalTrafficPolicy: Cluster
	service.Spec.Ports[0].Protocol = v1.ProtocolUDP
	options, err = mockCloud.validateService(service)
	assert.Nil(t, options)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "UDP load balancer, externalTrafficPolicy is set to Cluster")

	// validateService, only TCP protocol is supported for ALB
	service.ObjectMeta.Annotations = map[string]string{}
	service.Spec.Ports[0].Protocol = v1.ProtocolUDP
	options, err = mockCloud.validateService(service)
	assert.Nil(t, options)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Only TCP is supported")

	// validateService, other options passed on through
	service.Spec.Ports[0].Protocol = v1.ProtocolTCP
	options, err = mockCloud.validateService(service)
	assert.NotNil(t, options)
	assert.Nil(t, err)
}

func TestCloudVpc_validateServicePortRange(t *testing.T) {
	// validateServicePortRange, port range annotation not allowed if not sdnlb
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80}}},
	}
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "30000-32767"
	options := mockCloud.getServiceOptions(service)
	portRange, err := mockCloud.validateServicePortRange(service, options)
	assert.Equal(t, portRange, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "vpc-port-range is not supported")

	// validateServicePortRange, invalid port range specified
	service.ObjectMeta.Annotations[serviceAnnotationEnableFeatures] = LoadBalancerOptionsSdnlbInternal
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "invalid-port-range"
	options = mockCloud.getServiceOptions(service)
	portRange, err = mockCloud.validateServicePortRange(service, options)
	assert.Equal(t, portRange, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Improperly formatted data in service annotation")

	// validateServicePortRange, invalid or missing min port
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "badMinPort-32767"
	options = mockCloud.getServiceOptions(service)
	portRange, err = mockCloud.validateServicePortRange(service, options)
	assert.Equal(t, portRange, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Invalid port value in service annotation")

	// validateServicePortRange, invalid or missing max port
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "30000-badMaxPort"
	options = mockCloud.getServiceOptions(service)
	portRange, err = mockCloud.validateServicePortRange(service, options)
	assert.Equal(t, portRange, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Invalid port value in service annotation")

	// validateServicePortRange, port min == port max
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "30000-30000"
	options = mockCloud.getServiceOptions(service)
	portRange, err = mockCloud.validateServicePortRange(service, options)
	assert.Equal(t, portRange, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Specified port range 30000-30000 is not valid in service annotation")

	// validateServicePortRange, port min > port max
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "32767-30000"
	options = mockCloud.getServiceOptions(service)
	portRange, err = mockCloud.validateServicePortRange(service, options)
	assert.Equal(t, portRange, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Specified port range 32767-30000 is not valid in service annotation")

	// validateServicePortRange, no matching portMin in the service spec
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "30000-32767"
	options = mockCloud.getServiceOptions(service)
	portRange, err = mockCloud.validateServicePortRange(service, options)
	assert.Equal(t, portRange, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "No matching service port for the port range")

	// validateServicePortRange, port range overlaps with 2nd port in the spec
	service.Spec.Ports = []v1.ServicePort{
		{Protocol: v1.ProtocolTCP, Port: 80},
		{Protocol: v1.ProtocolTCP, Port: 443}}
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "80-1000"
	options = mockCloud.getServiceOptions(service)
	portRange, err = mockCloud.validateServicePortRange(service, options)
	assert.Equal(t, portRange, "")
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Port range 80-1000 overlaps with service port 443")

	// validateServicePortRange, success port range returned, spaces removed
	service.ObjectMeta.Annotations[serviceAnnotationPortRange] = "  80   -  100   "
	options = mockCloud.getServiceOptions(service)
	portRange, err = mockCloud.validateServicePortRange(service, options)
	assert.Equal(t, portRange, "80-100")
	assert.Nil(t, err)
}

func TestCloudVpc_ValidateServiceSubnets(t *testing.T) {
	service := &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default"}}
	vpcSubnets := []*VpcSubnet{{ID: "subnetID", Name: "subnetName", Ipv4CidrBlock: "10.240.0.0/24", Vpc: VpcObjectReference{ID: "vpcID"}}}

	// validateServiceSubnets, success
	subnetIDs, err := mockCloud.validateServiceSubnets(service, "subnetID", "vpcID", vpcSubnets)
	assert.Equal(t, len(subnetIDs), 1)
	assert.Nil(t, err)

	// validateServiceSubnets failed, invalid subnet in the service annotation
	subnetIDs, err = mockCloud.validateServiceSubnets(service, "invalid subnet", "vpcID", vpcSubnets)
	assert.Nil(t, subnetIDs)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid VPC subnet")

	// validateServiceSubnets failed, service subnet is in a different VPC
	subnetIDs, err = mockCloud.validateServiceSubnets(service, "subnetID", "vpc2", vpcSubnets)
	assert.Nil(t, subnetIDs)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "located in a different VPC")

	// validateServiceSubnets, success, subnetID, subnetName and CIDR all passed in for the same subnet
	subnetIDs, err = mockCloud.validateServiceSubnets(service, "subnetID,subnetName,10.240.0.0/24", "vpcID", vpcSubnets)
	assert.Equal(t, len(subnetIDs), 1)
	assert.Equal(t, subnetIDs[0], "subnetID")
	assert.Nil(t, err)

	// validateServiceSubnets, private NLB, failed multiple VPC subnets specified
	service = &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default",
			Annotations: map[string]string{serviceAnnotationEnableFeatures: LoadBalancerOptionNLB, serviceAnnotationIPType: servicePrivateLB}}}
	vpcSubnets = []*VpcSubnet{
		{ID: "subnetID", Name: "subnetName", Ipv4CidrBlock: "10.240.0.0/24", Vpc: VpcObjectReference{ID: "vpcID"}},
		{ID: "subnetID-2", Name: "subnetName2", Ipv4CidrBlock: "10.240.2.0/24", Vpc: VpcObjectReference{ID: "vpcID"}},
	}
	subnetIDs, err = mockCloud.validateServiceSubnets(service, "subnetName,subnetName2", "vpcID", vpcSubnets)
	assert.Nil(t, subnetIDs)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Private network load balancers require a single VPC subnet")

	// validateServiceSubnets, private NLB, failed to read cluster subnets
	subnetIDs, err = mockCloud.validateServiceSubnets(service, "subnetName", "vpcID", vpcSubnets)
	assert.Nil(t, subnetIDs)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Failed to get kube-system/ibm-cloud-provider-data config map")

	// validateServiceSubnets, private NLB, requested subnet is being used by IKS worker nodes
	configMap := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: VpcCloudProviderConfigMap, Namespace: VpcCloudProviderNamespace}}
	configMap.Data = map[string]string{VpcCloudProviderSubnetsKey: "subnetID"}
	mockCloud.KubeClient = fake.NewSimpleClientset(configMap)
	subnetIDs, err = mockCloud.validateServiceSubnets(service, "subnetID", "vpcID", vpcSubnets)
	assert.Nil(t, subnetIDs)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Private network load balancers require a dedicated VPC subnet")
}

func TestCloudVpc_ValidateServiceSubnetsNotUpdated(t *testing.T) {
	lb := &VpcLoadBalancer{Subnets: []VpcObjectReference{{ID: "subnetID"}}}
	service := &v1.Service{ObjectMeta: metav1.ObjectMeta{
		Name: "echo-server", Namespace: "default",
		Annotations: map[string]string{}},
	}
	vpcSubnets := []*VpcSubnet{{ID: "subnetID"}, {ID: "subnetID2"}}

	// validateServiceSubnetsNotUpdated, success - annotation not set
	err := mockCloud.validateServiceSubnetsNotUpdated(service, lb, vpcSubnets)
	assert.Nil(t, err)

	// validateServiceSubnetsNotUpdated, success - no change in annotation
	service.ObjectMeta.Annotations[serviceAnnotationSubnets] = "subnetID"
	err = mockCloud.validateServiceSubnetsNotUpdated(service, lb, vpcSubnets)
	assert.Nil(t, err)

	// validateServiceSubnetsNotUpdated, Failed, diff subnet specified
	service.ObjectMeta.Annotations[serviceAnnotationSubnets] = "subnetID2"
	err = mockCloud.validateServiceSubnetsNotUpdated(service, lb, vpcSubnets)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "setting can not be changed")
}

func TestCloudVpc_ValidateServiceTypeNotUpdated(t *testing.T) {
	lb := &VpcLoadBalancer{IsPublic: true}
	options := newServiceOptions()

	// validateServiceTypeNotUpdated, success - annotation not set
	err := mockCloud.validateServiceTypeNotUpdated(options, lb)
	assert.Nil(t, err)

	// validateServiceTypeNotUpdated, success - lb public, service private
	options.annotations[serviceAnnotationIPType] = servicePrivateLB
	err = mockCloud.validateServiceTypeNotUpdated(options, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "setting can not be changed")

	// validateServiceTypeNotUpdated, success - lb private, service public
	lb.IsPublic = false
	options.annotations[serviceAnnotationIPType] = servicePublicLB
	err = mockCloud.validateServiceTypeNotUpdated(options, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "setting can not be changed")
	lb.IsPublic = true

	// validateServiceTypeNotUpdated, success - lb = non-nlb, service nlb
	options.enabledFeatures = LoadBalancerOptionNLB
	err = mockCloud.validateServiceTypeNotUpdated(options, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "setting can not be changed")

	// validateServiceTypeNotUpdated, success - lb = non-nlb, service nlb
	lb.ProfileFamily = "network"
	options.enabledFeatures = ""
	err = mockCloud.validateServiceTypeNotUpdated(options, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "setting can not be changed")
}

func TestCloudVpc_ValidateServiceZone(t *testing.T) {
	service := &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default"}}
	vpcSubnets := []*VpcSubnet{{ID: "subnetID", Zone: "zoneA"}}

	// validateServiceZone, success
	subnetIDs, err := mockCloud.validateServiceZone(service, "zoneA", vpcSubnets)
	assert.Equal(t, len(subnetIDs), 1)
	assert.Nil(t, err)

	// validateServiceZone failed, no cluster subnets in that zone
	subnetIDs, err = mockCloud.validateServiceZone(service, "zoneX", vpcSubnets)
	assert.Nil(t, subnetIDs)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "no cluster subnets in that zone")
}

func TestCloudVpc_validateServiceZoneNotUpdated(t *testing.T) {
	// validateServiceZoneNotUpdated, no subnets on NLB
	err := mockCloud.validateServiceZoneNotUpdated("zoneA", []string{})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Invalid number of zones associated with the network load balancer")

	// validateServiceZoneNotUpdated, 2 subnets on NLB
	err = mockCloud.validateServiceZoneNotUpdated("zoneA", []string{"zoneA", "zoneB"})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Invalid number of zones associated with the network load balancer")

	// validateServiceZoneNotUpdated, service zone and LB zone different
	err = mockCloud.validateServiceZoneNotUpdated("zoneA", []string{"zoneB"})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "setting can not be changed")

	// validateServiceZoneNotUpdated, success - service zone and LB zone same
	err = mockCloud.validateServiceZoneNotUpdated("zoneA", []string{"zoneA"})
	assert.Nil(t, err)
}

func TestCloudVpc_VerifyServiceStatusIsNull(t *testing.T) {
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake, WorkerAccountID: "workerAccountID"}, nil)
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default"},
	}
	// No status listed set in the service
	err := c.VerifyServiceStatusIsNull(service)
	assert.NoError(t, err)

	// Load balancer has status, VPC LB was not found
	service.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{Hostname: "hostname", IP: "192.169.1.1"}}
	err = c.VerifyServiceStatusIsNull(service)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "can not be located")

	// Load balancer has status, renamed VPC LB located
	service.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{Hostname: "lb.ibm.com", IP: "192.169.1.1"}}
	err = c.VerifyServiceStatusIsNull(service)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "was renamed")
}
