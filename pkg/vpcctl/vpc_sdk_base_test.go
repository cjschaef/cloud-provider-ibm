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
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestExtractPortsFromPoolName(t *testing.T) {
	// Invalid pool name
	protocol, portMin, portMax, nodePort, err := extractProtocolPortsFromPoolName("poolName")
	assert.Equal(t, protocol, "")
	assert.Equal(t, portMin, -1)
	assert.Equal(t, portMax, -1)
	assert.Equal(t, nodePort, -1)
	assert.NotNil(t, err)

	// Invalid protocol
	protocol, portMin, portMax, nodePort, err = extractProtocolPortsFromPoolName("sctp-80-31234")
	assert.Equal(t, protocol, "")
	assert.Equal(t, portMin, -1)
	assert.Equal(t, portMax, -1)
	assert.Equal(t, nodePort, -1)
	assert.NotNil(t, err)

	// Invalid port
	protocol, portMin, portMax, nodePort, err = extractProtocolPortsFromPoolName("tcp-abc-31234")
	assert.Equal(t, protocol, "")
	assert.Equal(t, portMin, -1)
	assert.Equal(t, portMax, -1)
	assert.Equal(t, nodePort, -1)
	assert.NotNil(t, err)

	// Invalid nodePort
	protocol, portMin, portMax, nodePort, err = extractProtocolPortsFromPoolName("tcp-80-xyz")
	assert.Equal(t, protocol, "")
	assert.Equal(t, portMin, -1)
	assert.Equal(t, portMax, -1)
	assert.Equal(t, nodePort, -1)
	assert.NotNil(t, err)

	// Success - single port
	protocol, portMin, portMax, nodePort, err = extractProtocolPortsFromPoolName("tcp-80-31234")
	assert.Equal(t, protocol, "tcp")
	assert.Equal(t, portMin, 80)
	assert.Equal(t, portMax, 80)
	assert.Equal(t, nodePort, 31234)
	assert.Nil(t, err)

	// Success - port range
	protocol, portMin, portMax, nodePort, err = extractProtocolPortsFromPoolName("tcp-80x88-31234")
	assert.Equal(t, protocol, "tcp")
	assert.Equal(t, portMin, 80)
	assert.Equal(t, portMax, 88)
	assert.Equal(t, nodePort, 31234)
	assert.Nil(t, err)
}

func TestGenLoadBalancerPoolName(t *testing.T) {
	kubePort := v1.ServicePort{Protocol: "TCP", Port: 80, NodePort: 31234}
	result := genLoadBalancerPoolName(kubePort, "")
	assert.Equal(t, result, "tcp-80-31234")
}

func TestNewServiceOptions(t *testing.T) {
	options := newServiceOptions()
	assert.NotNil(t, options)
	assert.Empty(t, options.annotations)
	assert.Equal(t, options.enabledFeatures, "")
	assert.Equal(t, options.healthCheckNodePort, 0)
}

func TestGetServiceOptions(t *testing.T) {
	mockCloud := &CloudVpc{}
	mockService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "echo-server",
			Namespace: "default",
			Annotations: map[string]string{
				serviceAnnotationEnableFeatures:      LoadBalancerOptionNLB,
				serviceAnnotationHealthCheckDelay:    "10",
				serviceAnnotationHealthCheckProtocol: "https",
				serviceAnnotationHealthCheckPort:     "443",
				serviceAnnotationHealthCheckPath:     "/health",
				serviceAnnotationHealthCheckRetries:  "5",
				serviceAnnotationHealthCheckTimeout:  "4",
				serviceAnnotationHealthCheckUDP:      "10250",
				serviceAnnotationIPType:              servicePrivateLB,
				serviceAnnotationServiceCRN:          "serviceCRN",
				serviceAnnotationSubnets:             "vpc-subnets",
				serviceAnnotationZone:                "us-south-1",
			}},
		Spec: v1.ServiceSpec{
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyTypeLocal,
			HealthCheckNodePort:   36963,
			Ports: []v1.ServicePort{
				{Protocol: v1.ProtocolUDP, Port: 80, NodePort: 30123},
				{Protocol: v1.ProtocolTCP, Port: 443, NodePort: 34567}}}}

	// getServiceOptions called with no service
	options := mockCloud.getServiceOptions(nil)
	assert.NotNil(t, options)
	assert.Empty(t, options.annotations)
	assert.Equal(t, options.enabledFeatures, "")
	assert.Equal(t, options.healthCheckDelay, 0)
	assert.Equal(t, options.healthCheckNodePort, 0)
	assert.Equal(t, options.healthCheckPath, "")
	assert.Equal(t, options.healthCheckPort, 0)
	assert.Equal(t, options.healthCheckProtocol, "")
	assert.Equal(t, options.healthCheckRetries, 0)
	assert.Equal(t, options.healthCheckTimeout, 0)
	assert.Equal(t, options.healthCheckUDP, 0)
	assert.Equal(t, options.idleConnTimeout, 0)
	assert.False(t, options.serviceUDP)
	assert.Equal(t, options.getHealthCheckNodePort(), 0)
	assert.Equal(t, options.getHealthCheckUDP(), 0)
	assert.Equal(t, options.getServiceCRN(), "")
	assert.Equal(t, options.getServiceName(), "")
	assert.Equal(t, options.getServiceSubnets(), "")
	assert.Equal(t, options.getServiceType(), "alb")
	assert.Equal(t, options.getServiceZone(), "")
	assert.True(t, options.isALB())
	assert.False(t, options.isNLB())
	assert.False(t, options.isProxyProtocol())
	assert.True(t, options.isPublic())
	assert.False(t, options.isSdnlb())
	assert.False(t, options.isSdnlbInternal())
	assert.False(t, options.isSdnlbPartner())
	assert.False(t, options.isUDP())
	assert.Equal(t, options.getSdnlbOption(), "")

	// getServiceOptions created by validating a mock service
	mockCloud = &CloudVpc{Config: &ConfigVpc{WorkerAccountID: "workerAccountID"}}
	options, err := mockCloud.validateService(mockService)
	assert.Nil(t, err)
	assert.NotNil(t, options)
	assert.Equal(t, len(options.annotations), 12)
	assert.Equal(t, options.enabledFeatures, options.annotations[serviceAnnotationEnableFeatures])
	assert.Equal(t, options.healthCheckNodePort, 36963)
	assert.Equal(t, options.healthCheckUDP, 10250)
	assert.True(t, options.serviceUDP)
	assert.Equal(t, options.getHealthCheckDelay(), 10)
	assert.Equal(t, options.getHealthCheckNodePort(), 36963)
	assert.Equal(t, options.getHealthCheckPath(), "/health")
	assert.Equal(t, options.getHealthCheckPort(), 443)
	assert.Equal(t, options.getHealthCheckProtocol(), "https")
	assert.Equal(t, options.getHealthCheckRetries(), 5)
	assert.Equal(t, options.getHealthCheckTimeout(), 4)
	assert.Equal(t, options.getHealthCheckUDP(), 10250)
	assert.Equal(t, options.getIdleConnectionTimeout(), 50)
	assert.Equal(t, options.getServiceCRN(), "serviceCRN")
	assert.Equal(t, options.getServiceName(), "default/echo-server")
	assert.Equal(t, options.getServiceSubnets(), "vpc-subnets")
	assert.Equal(t, options.getServiceType(), "nlb")
	assert.Equal(t, options.getServiceZone(), "us-south-1")
	assert.False(t, options.isALB())
	assert.True(t, options.isNLB())
	assert.False(t, options.isProxyProtocol())
	assert.False(t, options.isPublic())
	assert.False(t, options.isSdnlb())
	assert.False(t, options.isSdnlbInternal())
	assert.False(t, options.isSdnlbPartner())
	assert.True(t, options.isUDP())

	// Make sure partner sDNLB is returned correctly for the service
	mockService.Annotations[serviceAnnotationEnableFeatures] = LoadBalancerOptionsSdnlbPartner
	options = mockCloud.getServiceOptions(mockService)
	assert.True(t, options.isSdnlb())
	assert.False(t, options.isSdnlbInternal())
	assert.True(t, options.isSdnlbPartner())
	assert.Equal(t, options.getSdnlbOption(), LoadBalancerOptionsSdnlbPartner)
}

func TestIsVpcOptionEnabled(t *testing.T) {
	result := isVpcOptionEnabled("", "item")
	assert.False(t, result)
	result = isVpcOptionEnabled("itemA,itemB,itemC", "item")
	assert.False(t, result)
	result = isVpcOptionEnabled("itemA,itemB,itemC", "itemC")
	assert.True(t, result)
}

func TestSafePointerBool(t *testing.T) {
	var ptr *bool
	result := SafePointerBool(ptr)
	assert.Equal(t, result, false)

	val := true
	ptr = &val
	result = SafePointerBool(ptr)
	assert.Equal(t, result, true)
}

func TestSafePointerDate(t *testing.T) {
	var ptr *strfmt.DateTime
	result := SafePointerDate(ptr)
	assert.Equal(t, result, "nil")

	val := strfmt.NewDateTime()
	ptr = &val
	result = SafePointerDate(ptr)
	assert.Equal(t, result, "1970-01-01T00:00:00.000Z")
}

func TestSafePointerInt64(t *testing.T) {
	var ptr *int64
	result := SafePointerInt64(ptr)
	assert.Equal(t, result, int64(0))

	val := int64(1234)
	ptr = &val
	result = SafePointerInt64(ptr)
	assert.Equal(t, result, int64(1234))
}

func TestSafePointerString(t *testing.T) {
	var ptr *string
	result := SafePointerString(ptr)
	assert.Equal(t, result, "nil")

	val := "apple"
	ptr = &val
	result = SafePointerString(ptr)
	assert.Equal(t, result, "apple")
}

func TestVpcLoadBalancer_GetStatus(t *testing.T) {
	lb := &VpcLoadBalancer{
		ProvisioningStatus: LoadBalancerProvisioningStatusActive,
		OperatingStatus:    LoadBalancerOperatingStatusOnline,
	}
	result := lb.GetStatus()
	assert.Equal(t, result, "online/active")
}

func TestVpcLoadBalancer_getSubnetIDs(t *testing.T) {
	lb := &VpcLoadBalancer{
		Subnets: []VpcObjectReference{{ID: "subnet-1"}, {ID: "subnet-2"}},
	}
	result := lb.getSubnetIDs()
	assert.Equal(t, len(result), 2)
	assert.Equal(t, result[0], "subnet-1")
	assert.Equal(t, result[1], "subnet-2")
}

func TestVpcLoadBalancer_GetSuccessString(t *testing.T) {
	lb := &VpcLoadBalancer{
		Hostname:   "hostname",
		PrivateIps: []string{"10.0.0.1", "10.0.0.2"},
	}
	result := lb.GetSuccessString()
	assert.Equal(t, result, "hostname")
	lb.Hostname = ""
	result = lb.GetSuccessString()
	assert.Equal(t, result, "10.0.0.1,10.0.0.2")
}

func TestVpcLoadBalancer_GetSummary(t *testing.T) {
	lb := &VpcLoadBalancer{
		Name:               "LoadBalancer",
		ID:                 "1234",
		Hostname:           "lb.ibm.com",
		Pools:              []VpcObjectReference{{Name: "tcp-80-30303"}},
		PrivateIps:         []string{"10.0.0.1", "10.0.0.2"},
		PublicIps:          []string{"192.168.0.1", "192.168.0.2"},
		ProvisioningStatus: LoadBalancerProvisioningStatusActive,
		OperatingStatus:    LoadBalancerOperatingStatusOnline,
	}
	result := lb.GetSummary()
	assert.Equal(t, result, "Name:LoadBalancer ID:1234 Status:online/active Hostname:lb.ibm.com Pools:tcp-80-30303 Private:10.0.0.1,10.0.0.2 Public:192.168.0.1,192.168.0.2")
}

func TestVpcLoadBalancer_getVpcID(t *testing.T) {
	lb := &VpcLoadBalancer{
		Subnets: []VpcObjectReference{{ID: "subnetID"}},
	}
	vpcSubnets := []*VpcSubnet{{ID: "subnetID", Vpc: VpcObjectReference{ID: "vpcID"}}}
	// Found VPC ID
	result := lb.getVpcID(vpcSubnets)
	assert.Equal(t, result, "vpcID")

	// No matching subnet ID, vpcID is returned as""
	lb.Subnets[0].ID = "invalid-subnetID"
	result = lb.getVpcID(vpcSubnets)
	assert.Equal(t, result, "")
}

func TestVpcLoadBalancer_getZones(t *testing.T) {
	lb := &VpcLoadBalancer{
		Subnets: []VpcObjectReference{{ID: "subnetA"}, {ID: "subnetB"}, {ID: "subnetC"}},
	}
	vpcSubnets := []*VpcSubnet{
		{ID: "subnetA", Zone: "us-south-1"},
		{ID: "subnetB", Zone: "us-south-2"},
		{ID: "subnetC", Zone: "us-south-1"},
	}
	// Retrieve zones for the LB
	result := lb.getZones(vpcSubnets)
	assert.Equal(t, len(result), 2)
	assert.Equal(t, result[0], "us-south-1")
	assert.Equal(t, result[1], "us-south-2")
}

func TestVpcLoadBalancer_IsNLB(t *testing.T) {
	// Normal LB
	lb := &VpcLoadBalancer{}
	rc := lb.IsNLB()
	assert.False(t, rc)

	// NLB
	lb = &VpcLoadBalancer{ProfileFamily: "network"}
	rc = lb.IsNLB()
	assert.True(t, rc)
}

func TestVpcLoadBalancer_IsReady(t *testing.T) {
	// Status is "online/active"
	lb := &VpcLoadBalancer{
		ProvisioningStatus: LoadBalancerProvisioningStatusActive,
		OperatingStatus:    LoadBalancerOperatingStatusOnline,
	}
	ready := lb.IsReady()
	assert.Equal(t, ready, true)

	// Status is "offline/create_pending"
	lb = &VpcLoadBalancer{
		ProvisioningStatus: LoadBalancerProvisioningStatusCreatePending,
		OperatingStatus:    LoadBalancerOperatingStatusOffline,
	}
	ready = lb.IsReady()
	assert.Equal(t, ready, false)
}

func TestVpcSecurityGroupRule_allowsTraffic(t *testing.T) {
	rule := VpcSecurityGroupRule{
		Direction: SecurityGroupRuleDirectionInbound,
		Protocol:  SecurityGroupRuleProtocolTCP,
		PortMin:   30000,
		PortMax:   32767,
	}
	result := rule.allowsTraffic("inbound", "tcp", 30303, 30303)
	assert.True(t, result)
	result = rule.allowsTraffic("outbound", "tcp", 30303, 30303)
	assert.False(t, result)
	result = rule.allowsTraffic("inbound", "udp", 30303, 30303)
	assert.False(t, result)
	result = rule.allowsTraffic("inbound", "tcp", 30303, 33333)
	assert.False(t, result)
}

func TestVpcSecurityGroupRule_display(t *testing.T) {
	rule := VpcSecurityGroupRule{
		ID:        "ruleID",
		Direction: SecurityGroupRuleDirectionInbound,
		Protocol:  SecurityGroupRuleProtocolTCP,
		PortMin:   30000,
		PortMax:   32767,
	}
	result := rule.display()
	assert.Equal(t, result, "{ ID:ruleID Direction:inbound Protocol:tcp Ports:30000-32767 }")
}

func TestVpcSecurityGroupRule_insidePortRange(t *testing.T) {
	rule := VpcSecurityGroupRule{
		Direction: SecurityGroupRuleDirectionInbound,
		Protocol:  SecurityGroupRuleProtocolTCP,
		PortMin:   30303,
		PortMax:   30303,
	}
	result := rule.insidePortRange("inbound", "tcp", 30000, 32767)
	assert.True(t, result)
	result = rule.insidePortRange("outbound", "tcp", 30000, 32767)
	assert.False(t, result)
	result = rule.insidePortRange("inbound", "udp", 30000, 32767)
	assert.False(t, result)
	result = rule.insidePortRange("inbound", "tcp", 32000, 32767)
	assert.False(t, result)
}

func TestVpcSecurityGroupRule_matchesPorts(t *testing.T) {
	rule := VpcSecurityGroupRule{
		Direction: SecurityGroupRuleDirectionInbound,
		Protocol:  SecurityGroupRuleProtocolTCP,
		PortMin:   30303,
		PortMax:   30303,
	}
	result := rule.matchesPorts("inbound", "tcp", 30303, 30303)
	assert.True(t, result)
	result = rule.matchesPorts("outbound", "tcp", 30303, 30303)
	assert.False(t, result)
	result = rule.matchesPorts("inbound", "udp", 30303, 30303)
	assert.False(t, result)
	result = rule.matchesPorts("inbound", "tcp", 30300, 30303)
	assert.False(t, result)
}
