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
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCloudVpc_CreateLoadBalancer(t *testing.T) {
	configMap := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: VpcCloudProviderConfigMap, Namespace: VpcCloudProviderNamespace},
		Data:       map[string]string{VpcCloudProviderSubnetsKey: "subnetID", VpcCloudProviderVpcIDKey: "vpcID"},
	}
	node := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "192.168.0.1", Labels: map[string]string{nodeLabelZone: "zoneA"}}, Status: v1.NodeStatus{Addresses: []v1.NodeAddress{{Address: "192.168.0.1", Type: v1.NodeInternalIP}}}}
	service := &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default", UID: "1234"},
		Spec: v1.ServiceSpec{
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeLocal,
			HealthCheckNodePort:   36963,
			Type:                  v1.ServiceTypeLoadBalancer,
			Ports:                 []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 31000}},
		}}
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake, WorkerAccountID: "workerAccountID"}, nil)
	// Create load balancer failed, name not specified
	lb, err := c.CreateLoadBalancer("", service, []*v1.Node{})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Required argument is missing")

	// Create load balancer failed, service = UDP load balancer
	service.Spec.Ports[0].Protocol = v1.ProtocolUDP
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Service default/echo-server is a UDP load balancer")
	service.Spec.Ports[0].Protocol = v1.ProtocolTCP

	// Create load balancer failed, SDK call to list subnets failed
	c.SetFakeSdkError("ListSubnets")
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "ListSubnets failed")
	c.ClearFakeSdkError("ListSubnets")

	// Create load balancer failed, failed to get cluster subnets from config map
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("Failed to get %s/%s config map", VpcCloudProviderNamespace, VpcCloudProviderConfigMap))

	// Create load balancer failed, cluster subnet config map contains invalid subnet IDs
	configMap.Data[VpcCloudProviderSubnetsKey] = "invalid subnet"
	c.KubeClient = fake.NewSimpleClientset(configMap)
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid VPC subnet")
	configMap.Data[VpcCloudProviderSubnetsKey] = "subnetID"
	c.Config.clusterSubnetIDs = ""

	// Create load balancer failed, backend nodes service annotation results in no nodes selected
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationNodeSelector: nodeLabelZone + "=" + "zoneX"}
	c.KubeClient = fake.NewSimpleClientset(configMap)
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "no available nodes for this service")

	// Create load balancer failed, invalid member quota service annotation
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "invalid"}
	service.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeCluster
	c.KubeClient = fake.NewSimpleClientset(configMap)
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")
	service.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeLocal

	// Create load balancer failed, no cluster subnets in the service annotation zone
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationZone: "zoneA"}
	c.KubeClient = fake.NewSimpleClientset(configMap)
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "no cluster subnets in that zone")

	// Create load balancer failed, subnet annotation contains invalid subnets IDs
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationSubnets: "subnetID,subnetID-not-valid"}
	c.KubeClient = fake.NewSimpleClientset(configMap)
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid VPC subnet")

	// Create load balancer failed, subnet annotation contains multiple subnet zones and NLB created
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationSubnets: "subnetID,subnetID2", serviceAnnotationEnableFeatures: LoadBalancerOptionNLB}
	c.Sdk.(*VpcSdkFake).Subnet2.ID = "subnetID2"
	c.Sdk.(*VpcSdkFake).Subnet2.Vpc = c.Sdk.(*VpcSdkFake).Subnet1.Vpc
	c.KubeClient = fake.NewSimpleClientset(configMap)
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "only one zone is allowed with NLB")
	service.ObjectMeta.Annotations = map[string]string{}

	// Create load balancer failed, no nodes defined
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "no available nodes for this service")

	// Create load balancer - SUCCESS
	c.KubeClient = fake.NewSimpleClientset(configMap)
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.NotNil(t, lb)
	assert.Nil(t, err)
	assert.Equal(t, len(c.Config.lbNameCache), 1)

	// Create a network load balancer - SUCCESS
	c.KubeClient = fake.NewSimpleClientset(configMap)
	service.ObjectMeta.Annotations[serviceAnnotationEnableFeatures] = LoadBalancerOptionNLB
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.NotNil(t, lb)
	assert.Nil(t, err)
	service.ObjectMeta.Annotations[serviceAnnotationEnableFeatures] = ""

	// SDK create load balancer operation failed
	service.Spec.SessionAffinity = v1.ServiceAffinityClientIP
	c.KubeClient = fake.NewSimpleClientset(configMap)
	c.SetFakeSdkError("CreateLoadBalancer")
	lb, err = c.CreateLoadBalancer("load balancer", service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "CreateLoadBalancer failed")
}

func TestCloudVpc_DeleteLoadBalancer(t *testing.T) {
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)

	// Delete load balancer failed, LB not specified
	err := c.DeleteLoadBalancer(nil, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Required argument is missing")

	// Delete load balancer worked
	lb := &VpcLoadBalancer{ID: "Ready", Name: "kube-clusterID-1234"}
	c.Config.addLbToCache(lb)
	err = c.DeleteLoadBalancer(lb, nil)
	assert.Nil(t, err)
	assert.Equal(t, len(c.Config.lbNameCache), 0)

	// Delete a sDNLB load balancer - service not found
	c.KubeClient = fake.NewSimpleClientset()
	lb = &VpcLoadBalancer{ID: "Ready", Name: "Service not found", IsService: true}
	err = c.DeleteLoadBalancer(lb, nil)
	assert.Nil(t, err)

	// Delete a sDNLB load balancer - service found
	service := &v1.Service{ObjectMeta: metav1.ObjectMeta{
		Name:        "echo-server",
		Namespace:   "default",
		UID:         "1234",
		Annotations: map[string]string{serviceAnnotationServiceCRN: "crn"}},
		Spec: v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer}}
	c.Config.ClusterID = "clusterID"
	c.KubeClient = fake.NewSimpleClientset(service)
	lb = &VpcLoadBalancer{ID: "Ready", Name: "kube-clusterID-1234", IsService: true}
	err = c.DeleteLoadBalancer(lb, service)
	assert.Nil(t, err)
}

func TestCloudVpc_FindLoadBalancer(t *testing.T) {
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	// Load balancer failed, name not specified
	lb, err := c.FindLoadBalancer("", nil)
	assert.Nil(t, lb)
	assert.NotNil(t, err)

	// Load balancer not found
	lb, err = c.FindLoadBalancer("lb", nil)
	assert.Nil(t, lb)
	assert.Nil(t, err)

	// Load balancer was found
	lb, err = c.FindLoadBalancer("Ready", nil)
	assert.NotNil(t, lb)
	assert.Nil(t, err)

	// Save the fake "Ready" LB into the LB name cache
	assert.Equal(t, len(c.Config.lbNameCache), 0)
	c.Config.addLbToCache(lb)
	assert.Equal(t, len(c.Config.lbNameCache), 1)

	// Find LB in the cache, GetLoadBalancer() succeeds, FindLoadBalancer() is not called
	c.SetFakeSdkError("FindLoadBalancer")
	lb, err = c.FindLoadBalancer(lb.Name, nil)
	assert.NotNil(t, lb)
	assert.Nil(t, err)
	assert.Equal(t, len(c.Config.lbNameCache), 1)
	c.ClearFakeSdkError("FindLoadBalancer")

	// Find LB in the cache, force GetLoadBalancer() to fail, cache entry is cleared
	c.SetFakeSdkError("GetLoadBalancer")
	lb, err = c.FindLoadBalancer(lb.Name, nil)
	assert.NotNil(t, lb)
	assert.Nil(t, err)
	assert.Equal(t, len(c.Config.lbNameCache), 0)
	c.ClearFakeSdkError("GetLoadBalancer")
}

func TestCloudVpc_getLoadBalancersInCluster(t *testing.T) {
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)

	// getLoadBalancersInCluster failed, failed to get list of load balancers
	c.SetFakeSdkError("ListLoadBalancers")
	lbs, err := c.getLoadBalancersInCluster()
	assert.Nil(t, lbs)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "ListLoadBalancers failed")
	c.ClearFakeSdkError("ListLoadBalancers")

	// getLoadBalancersInCluster worked, but no load balancers found in current cluster
	c.Config.ClusterID = "invalid-clusterID"
	lbs, err = c.getLoadBalancersInCluster()
	assert.NotNil(t, lbs)
	assert.Empty(t, lbs)
	assert.Nil(t, err)

	// getLoadBalancersInCluster worked, two load balancers found in current cluster
	c.Config.ClusterID = "clusterID"
	lbs, err = c.getLoadBalancersInCluster()
	assert.NotNil(t, lbs)
	assert.Equal(t, len(lbs), 2)
	assert.Nil(t, err)
}

func TestCloudVpc_GetLoadBalancerStatus(t *testing.T) {
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	service := &v1.Service{ObjectMeta: metav1.ObjectMeta{
		Name: "echo-server", Namespace: "default"}}
	// Standard VPC LB
	status := c.GetLoadBalancerStatus(service, &VpcLoadBalancer{Hostname: "hostname"})
	assert.NotNil(t, status)
	assert.Equal(t, len(status.Ingress), 1)
	assert.Equal(t, status.Ingress[0].Hostname, "hostname")
	assert.Equal(t, status.Ingress[0].IP, "")

	// NLB service and hostname already resolved
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationEnableFeatures: LoadBalancerOptionNLB}
	service.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{{Hostname: "hostname", IP: "10.1.1.1"}}
	status = c.GetLoadBalancerStatus(service, &VpcLoadBalancer{Hostname: "hostname"})
	assert.NotNil(t, status)
	assert.Equal(t, len(status.Ingress), 1)
	assert.Equal(t, status.Ingress[0].Hostname, "hostname")
	assert.Equal(t, status.Ingress[0].IP, "10.1.1.1")

	// sDNLB service with 3 IP addresses returned
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationEnableFeatures: LoadBalancerOptionsSdnlbInternal}
	service.Status.LoadBalancer.Ingress = nil
	status = c.GetLoadBalancerStatus(service, &VpcLoadBalancer{PrivateIps: []string{"10.12.131.0", "10.12.132.0", "10.12.133.0"}})
	assert.NotNil(t, status)
	assert.Equal(t, len(status.Ingress), 3)
	assert.Equal(t, status.Ingress[0].IP, "10.12.131.0")
	assert.Equal(t, status.Ingress[1].IP, "10.12.132.0")
	assert.Equal(t, status.Ingress[2].IP, "10.12.133.0")
}

func TestCloudVpc_UpdateLoadBalancer(t *testing.T) {
	node := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "192.168.1.1", Labels: map[string]string{nodeLabelZone: "zoneA"}}, Status: v1.NodeStatus{Addresses: []v1.NodeAddress{{Address: "192.168.1.1", Type: v1.NodeInternalIP}}}}
	node2 := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "192.168.2.2"}, Status: v1.NodeStatus{Addresses: []v1.NodeAddress{{Address: "192.168.2.2", Type: v1.NodeInternalIP}}}}
	node3 := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "192.168.3.3"}, Status: v1.NodeStatus{Addresses: []v1.NodeAddress{{Address: "192.168.3.3", Type: v1.NodeInternalIP}}}}

	publicLB := &VpcLoadBalancer{
		IsPublic:           true,
		OperatingStatus:    LoadBalancerOperatingStatusOnline,
		ProvisioningStatus: LoadBalancerProvisioningStatusActive,
		Subnets:            []VpcObjectReference{{ID: "subnetID"}},
	}
	configMap := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: VpcCloudProviderConfigMap, Namespace: VpcCloudProviderNamespace},
		Data:       map[string]string{VpcCloudProviderSubnetsKey: "subnetID", VpcCloudProviderVpcIDKey: "vpcID"},
	}
	service := &v1.Service{ObjectMeta: metav1.ObjectMeta{Name: "echo-server", Namespace: "default", UID: "Ready", Annotations: map[string]string{}},
		Spec: v1.ServiceSpec{
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeCluster,
			HealthCheckNodePort:   36963,
			Type:                  v1.ServiceTypeLoadBalancer,
			Ports:                 []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30303}},
		}}
	c, _ := NewCloudVpc(fake.NewSimpleClientset(configMap), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	// Update load balancer failed, service was not specified
	lb, err := c.UpdateLoadBalancer(publicLB, nil, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Required argument is missing")

	// Update load balancer failed, load balancer was not specified
	lb, err = c.UpdateLoadBalancer(nil, service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Load balancer not found")

	// Update load balancer failed, lb is not in a ready state
	notReadyLB := &VpcLoadBalancer{IsPublic: true, OperatingStatus: LoadBalancerOperatingStatusOffline, ProvisioningStatus: LoadBalancerProvisioningStatusCreatePending}
	lb, err = c.UpdateLoadBalancer(notReadyLB, service, []*v1.Node{node})
	assert.NotNil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "load balancer not ready")

	// Update load balancer failed, attempting to update a UDP service
	service.Spec.Ports[0].Protocol = v1.ProtocolUDP
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Only TCP is supported")
	service.Spec.Ports[0].Protocol = v1.ProtocolTCP

	// Update load balancer failed, attempting to change public LB to a private LB
	service.ObjectMeta.Annotations[serviceAnnotationIPType] = servicePrivateLB
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "was created as a public load balancer")
	service.ObjectMeta.Annotations = map[string]string{}

	// Update load balancer failed, failed to get list of VPC subnets
	c.SetFakeSdkError("ListSubnets")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ListSubnets failed")
	c.ClearFakeSdkError("ListSubnets")

	// Update load balancer failed, attempting to subnet annotation to an invalid subnet ID
	service.ObjectMeta.Annotations[serviceAnnotationSubnets] = "invalidSubnetID"
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid VPC subnet")
	service.ObjectMeta.Annotations = map[string]string{}

	// Update load balancer failed, no nodes for the LB
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "no available nodes")

	// Update load balancer failed, no nodes for the LB
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationNodeSelector: nodeLabelZone + "=" + "zoneX"}
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "no available nodes")
	service.ObjectMeta.Annotations = map[string]string{}

	// Update load balancer failed, invalid value for the member quota service annotation
	service.ObjectMeta.Annotations = map[string]string{serviceAnnotationMemberQuota: "invalid"}
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "is not set to a valid value")
	service.ObjectMeta.Annotations = map[string]string{}

	// Update load balancer failed, failed to get list of listeners
	c.SetFakeSdkError("ListLoadBalancerListeners")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ListLoadBalancerListeners failed")
	c.ClearFakeSdkError("ListLoadBalancerListeners")

	// Update load balancer failed, failed to get list of listeners
	c.SetFakeSdkError("ListLoadBalancerPools")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ListLoadBalancerPools failed")
	c.ClearFakeSdkError("ListLoadBalancerPools")

	// Update load balancer failed, no updates needed
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.NotNil(t, lb)
	assert.Nil(t, err)

	// Update load balancer failed, failed to delete existing listener, external port 80 deleted
	service.Spec.Ports[0].Port = 443
	c.SetFakeSdkError("DeleteLoadBalancerListener")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "DeleteLoadBalancerListener failed")
	c.ClearFakeSdkError("DeleteLoadBalancerListener")
	sdk, _ := NewVpcSdkFake()
	c.Sdk = sdk
	service.Spec.Ports[0].Port = 80

	// Update load balancer failed, failed to delete existing pool, external port 80 deleted
	service.Spec.Ports[0].Port = 443
	c.SetFakeSdkError("DeleteLoadBalancerPool")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "DeleteLoadBalancerPool failed")
	c.ClearFakeSdkError("DeleteLoadBalancerPool")
	sdk, _ = NewVpcSdkFake()
	c.Sdk = sdk
	service.Spec.Ports[0].Port = 80

	// Update load balancer failed, failed to delete existing pool member, node was deleted
	c.SetFakeSdkError("DeleteLoadBalancerPoolMember")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "DeleteLoadBalancerPoolMember failed")
	c.ClearFakeSdkError("DeleteLoadBalancerPoolMember")

	// Update load balancer failed, failed to create a new pool member for new node
	c.SetFakeSdkError("CreateLoadBalancerPoolMember")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2, node3})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "CreateLoadBalancerPoolMember failed")
	c.ClearFakeSdkError("CreateLoadBalancerPoolMember")

	// Update load balancer failed, failed to update pool members - node removed/node added
	c.SetFakeSdkError("ReplaceLoadBalancerPoolMembers")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node3})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ReplaceLoadBalancerPoolMembers failed")
	c.ClearFakeSdkError("ReplaceLoadBalancerPoolMembers")

	// Update load balancer failed, failed to create a new pool
	service.Spec.Ports = append(service.Spec.Ports, v1.ServicePort{Protocol: v1.ProtocolTCP, Port: 443, NodePort: 31313})
	c.SetFakeSdkError("CreateLoadBalancerPool")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "CreateLoadBalancerPool failed")
	c.ClearFakeSdkError("CreateLoadBalancerPool")

	// Update load balancer failed, failed to create a new listener, pool not found
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Pool tcp-443-31313 not found")

	// Update load balancer failed, failed to create a new listener, pool was found
	c.Sdk.(*VpcSdkFake).LoadBalancerReady.Pools = []VpcObjectReference{
		{Name: "tcp-80-30303", ID: "pool80"},
		{Name: "tcp-443-31313", ID: "pool443"}}
	c.SetFakeSdkError("CreateLoadBalancerListener")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "CreateLoadBalancerListener failed")
	c.ClearFakeSdkError("CreateLoadBalancerListener")
	sdk, _ = NewVpcSdkFake()
	c.Sdk = sdk
	service.Spec.Ports = []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: 80, NodePort: 30303}}

	// Update load balancer failed, failed to update pool, service externalTrafficPolicy was changed
	service.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeLocal
	c.SetFakeSdkError("UpdateLoadBalancerPool")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "UpdateLoadBalancerPool failed")
	c.ClearFakeSdkError("UpdateLoadBalancerPool")
	service.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeCluster

	// Update load balancer failed, failed to update pool, pool is using HTTP health check
	c.Sdk.(*VpcSdkFake).Pool.HealthMonitor.Type = LoadBalancerProtocolHTTP
	c.SetFakeSdkError("UpdateLoadBalancerPool")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "UpdateLoadBalancerPool failed")
	c.ClearFakeSdkError("UpdateLoadBalancerPool")
	c.Sdk.(*VpcSdkFake).Pool.HealthMonitor.Type = LoadBalancerProtocolTCP

	// Update load balancer failed, failed to update pool, node port of the service was changed
	service.Spec.Ports[0].NodePort = 31313
	c.SetFakeSdkError("UpdateLoadBalancerPool")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "UpdateLoadBalancerPool failed")
	c.ClearFakeSdkError("UpdateLoadBalancerPool")
	service.Spec.Ports[0].NodePort = 30303

	// LoadBalancerOptionSessionAffinity / LoadBalancerOptionLeastConnections are currently not supported
	// See issue: https://github.ibm.com/alchemy-containers/armada-network/issues/3470

	// Update load balancer failed, failed to update pool, least connections scheduler requested
	// service.ObjectMeta.Annotations[serviceAnnotationEnableFeatures] = LoadBalancerOptionLeastConnections
	// c.SetFakeSdkError("UpdateLoadBalancerPool")
	// lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	// assert.Nil(t, lb)
	// assert.NotNil(t, err)
	// assert.Contains(t, err.Error(), "UpdateLoadBalancerPool failed")
	// c.ClearFakeSdkError("UpdateLoadBalancerPool")
	// service.ObjectMeta.Annotations[serviceAnnotationEnableFeatures] = ""

	// Update load balancer failed, failed to update pool, session affinity requested
	// service.Spec.SessionAffinity = v1.ServiceAffinityClientIP
	// c.SetFakeSdkError("UpdateLoadBalancerPool")
	// lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	// assert.Nil(t, lb)
	// assert.NotNil(t, err)
	// assert.Contains(t, err.Error(), "UpdateLoadBalancerPool failed")
	// c.ClearFakeSdkError("UpdateLoadBalancerPool")
	// service.Spec.SessionAffinity = v1.ServiceAffinityNone

	// Update load balancer failed, failed to update pool, no session affinity requested
	// c.Sdk.(*VpcSdkFake).Pool.SessionPersistence = LoadBalancerSessionPersistenceSourceIP
	// c.SetFakeSdkError("DeleteLoadBalancerListener")
	// lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	// assert.Nil(t, lb)
	// assert.NotNil(t, err)
	// assert.Contains(t, err.Error(), "DeleteLoadBalancerListener failed")
	// sdk, _ = NewVpcSdkFake(ConfigVpc{})
	// c.Sdk = sdk

	// Update load balancer failed, failed to update pool members, node port of the service was changed
	service.Spec.Ports[0].NodePort = 31313
	c.SetFakeSdkError("ReplaceLoadBalancerPoolMembers")
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ReplaceLoadBalancerPoolMembers failed")
	c.ClearFakeSdkError("ReplaceLoadBalancerPoolMembers")
	service.Spec.Ports[0].NodePort = 30303

	// Update load balancer successful
	service.Spec.Ports[0].NodePort = 31313
	lb, err = c.UpdateLoadBalancer(publicLB, service, []*v1.Node{node, node2})
	assert.NotNil(t, lb)
	assert.Nil(t, err)
	service.Spec.Ports[0].NodePort = 30303
}

func TestCloudVpc_UpdateLoadBalancerAsync(t *testing.T) {
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	lb := &VpcLoadBalancer{
		ID:                 "Ready",
		OperatingStatus:    LoadBalancerOperatingStatusOnline,
		ProvisioningStatus: LoadBalancerProvisioningStatusActive,
	}
	minSleep := 1
	nodeList := []string{"10.1.1.1"}
	subnetList := []string{"subnetID"}
	updateList := []string{"CREATE-POOL-MEMBER tcp-89-32607 r134-d837bae3-d3d7-474b-a2c9-ec98b201057f 10.240.0.30"}
	pools := []*VpcLoadBalancerPool{}
	options := &ServiceOptions{}

	// Call async updates with nothing left to do
	vpcMapAsyncUpdates[lb.ID] = nil
	c.updateLoadBalancerAsync(lb, 1, minSleep, nodeList, subnetList, updateList, pools, options)
	assert.NotNil(t, vpcMapAsyncUpdates[lb.ID])

	// Call async updates with invalid update. processUpdate will fail
	updateList[0] = "Invalid update"
	vpcMapAsyncUpdates[lb.ID] = nil
	c.updateLoadBalancerAsync(lb, 0, minSleep, nodeList, subnetList, updateList, pools, options)
	assert.NotNil(t, vpcMapAsyncUpdates[lb.ID])

	// Call async updates.  Update successful, but GetLB fails
	updateList[0] = "CREATE-POOL-MEMBER poolName poolID nodeIP"
	vpcMapAsyncUpdates[lb.ID] = nil
	c.SetFakeSdkError("GetLoadBalancer")
	c.updateLoadBalancerAsync(lb, 0, minSleep, nodeList, subnetList, updateList, pools, options)
	c.ClearFakeSdkError("GetLoadBalancer")
	assert.NotNil(t, vpcMapAsyncUpdates[lb.ID])
}

func TestCloudVpc_WaitLoadBalancerReady(t *testing.T) {
	c, _ := NewCloudVpc(fake.NewSimpleClientset(), &ConfigVpc{ClusterID: "clusterID", ProviderType: VpcProviderTypeFake}, nil)
	lb := &VpcLoadBalancer{
		ID:                 "Ready",
		OperatingStatus:    LoadBalancerOperatingStatusOffline,
		ProvisioningStatus: LoadBalancerProvisioningStatusCreatePending,
	}
	// Wait for Load Balancer to be ready
	lb, err := c.WaitLoadBalancerReady(lb, 1, 2, true)
	assert.NotNil(t, lb)
	assert.Nil(t, err)

	// Failed to retrieve load balancer from SDK
	lb = &VpcLoadBalancer{ID: "NotReady"}
	c.SetFakeSdkError("GetLoadBalancer")
	lb, err = c.WaitLoadBalancerReady(lb, 1, 1, true)
	assert.Nil(t, lb)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "GetLoadBalancer failed")
	c.ClearFakeSdkError("GetLoadBalancer")

	// Load Balancer does not ever get to ready state
	lb = &VpcLoadBalancer{ID: "NotReady"}
	lb, err = c.WaitLoadBalancerReady(lb, 1, 1, true)
	assert.NotNil(t, lb)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "load balancer not ready")
}
