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
	"strconv"
	"strings"

	"golang.org/x/exp/slices"
)

// VpcSdkFake SDK methods
type VpcSdkFake struct {
	Error                map[string]error
	LoadBalancerReady    *VpcLoadBalancer
	LoadBalancerNotReady *VpcLoadBalancer
	Listener             *VpcLoadBalancerListener
	Pool                 *VpcLoadBalancerPool
	Member1              *VpcLoadBalancerPoolMember
	Member2              *VpcLoadBalancerPoolMember
	SecurityGroup        *VpcSecurityGroup
	SecurityGroups       []*VpcSecurityGroup
	SecurityGroupRule    *VpcSecurityGroupRule
	ServiceRegistration  *VpcServiceRegistration
	Subnet1              *VpcSubnet
	Subnet2              *VpcSubnet
	Vpc                  *Vpc
	Counter              int
}

// NewVpcSdkFake - create new mock SDK client
func NewVpcSdkFake() (CloudVpcSdk, error) {
	lbReady := &VpcLoadBalancer{
		Name:               VpcLbNamePrefix + "-clusterID-Ready",
		ID:                 "Ready",
		IsPublic:           true,
		Hostname:           "lb.ibm.com",
		Pools:              []VpcObjectReference{{Name: "tcp-80-30303"}},
		PrivateIps:         []string{"10.0.0.1", "10.0.0.2"},
		PublicIps:          []string{"192.168.0.1", "192.168.0.2"},
		ProvisioningStatus: LoadBalancerProvisioningStatusActive,
		OperatingStatus:    LoadBalancerOperatingStatusOnline,
		Subnets:            []VpcObjectReference{{Name: "subnet1", ID: "1111"}},
	}
	lbNotReady := &VpcLoadBalancer{
		Name:               VpcLbNamePrefix + "-clusterID-NotReady",
		ID:                 "NotReady",
		IsPublic:           true,
		Hostname:           "notready.lb.ibm.com",
		Pools:              []VpcObjectReference{{Name: "tcp-80-30303"}},
		PrivateIps:         []string{"10.0.0.1", "10.0.0.2"},
		PublicIps:          []string{"192.168.0.1", "192.168.0.2"},
		ProvisioningStatus: LoadBalancerProvisioningStatusCreatePending,
		OperatingStatus:    LoadBalancerOperatingStatusOffline,
		Subnets:            []VpcObjectReference{{Name: "subnet2", ID: "2222"}},
	}
	listener := &VpcLoadBalancerListener{
		DefaultPool:        VpcObjectReference{Name: "tcp-80-30303"},
		ID:                 "listener",
		PortMin:            80,
		PortMax:            80,
		Protocol:           LoadBalancerProtocolTCP,
		ProvisioningStatus: LoadBalancerProvisioningStatusActive,
	}
	member1 := &VpcLoadBalancerPoolMember{
		Health:             "ok",
		ID:                 "memberID",
		Port:               30303,
		ProvisioningStatus: LoadBalancerProvisioningStatusActive,
		TargetIPAddress:    "192.168.1.1",
		Weight:             50,
	}
	member2 := &VpcLoadBalancerPoolMember{
		Health:             "ok",
		ID:                 "memberID",
		Port:               30303,
		ProvisioningStatus: LoadBalancerProvisioningStatusActive,
		TargetIPAddress:    "192.168.2.2",
		Weight:             50,
	}
	pool := &VpcLoadBalancerPool{
		Algorithm: LoadBalancerAlgorithmRoundRobin,
		HealthMonitor: VpcLoadBalancerPoolHealthMonitor{
			Delay:      healthCheckDelayDefault,
			MaxRetries: healthCheckRetriesDefault,
			Port:       30303,
			Timeout:    healthCheckTimeoutDefault,
			Type:       LoadBalancerProtocolTCP,
			URLPath:    "/",
		},
		ID:                 "poolID",
		Members:            []*VpcLoadBalancerPoolMember{member1, member2},
		Name:               "tcp-80-30303",
		Protocol:           LoadBalancerProtocolTCP,
		ProvisioningStatus: LoadBalancerProvisioningStatusActive,
		SessionPersistence: "None",
	}
	secGroup := &VpcSecurityGroup{
		ID:   "securityGroupID",
		Name: "kube-vpcID",
	}
	secGroupRule := &VpcSecurityGroupRule{
		ID: "securityGroupID",
	}
	serviceRegisration := &VpcServiceRegistration{
		ID:   "serviceRegisrationID",
		Name: "serviceRegisration",
	}
	subnet1 := &VpcSubnet{
		AvailableIpv4AddressCount: 246,
		ID:                        "subnetID",
		IPVersion:                 "ipv4",
		Ipv4CidrBlock:             "10.240.0.0/24",
		Name:                      "subnet",
		Status:                    "available",
		TotalIpv4AddressCount:     256,
		Vpc:                       VpcObjectReference{Name: "vpc", ID: "vpcID"},
		Zone:                      "us-south-1",
	}
	subnet2 := &VpcSubnet{
		ID:   "subnetVpc2",
		Name: "subnetVpc2",
		Vpc:  VpcObjectReference{Name: "vpc2", ID: "vpc2ID"},
		Zone: "us-south-2",
	}
	vpc := &Vpc{
		ClassicAccess:        false,
		DefaultSecurityGroup: VpcObjectReference{Name: "securityGroup", ID: "securityGroupID"},
		ID:                   "vpcID",
		Name:                 "vpc",
		Status:               VPCStatusAvailable,
	}
	v := &VpcSdkFake{
		Error:                map[string]error{},
		LoadBalancerReady:    lbReady,
		LoadBalancerNotReady: lbNotReady,
		Listener:             listener,
		Pool:                 pool,
		Member1:              member1,
		Member2:              member2,
		SecurityGroup:        secGroup,
		SecurityGroups:       []*VpcSecurityGroup{secGroup},
		SecurityGroupRule:    secGroupRule,
		ServiceRegistration:  serviceRegisration,
		Subnet1:              subnet1,
		Subnet2:              subnet2,
		Vpc:                  vpc,
	}
	return v, nil
}

// ClearFakeSdkError - Clear the error string for the specific SDK mock method
func (c *CloudVpc) ClearFakeSdkError(methodName string) {
	c.Sdk.(*VpcSdkFake).Error[methodName] = nil
}

// SetFakeSdkError - Set an error string to be returned for the specific SDK mock method
func (c *CloudVpc) SetFakeSdkError(methodName string) {
	c.Sdk.(*VpcSdkFake).Error[methodName] = fmt.Errorf("%s failed", methodName)
}

// CreateLoadBalancer - create a load balancer
func (v *VpcSdkFake) CreateLoadBalancer(lbName string, nodeList, poolList, subnetList []string, options *ServiceOptions) (*VpcLoadBalancer, error) {
	if v.Error["CreateLoadBalancer"] != nil {
		return nil, v.Error["CreateLoadBalancer"]
	}
	if strings.HasSuffix(lbName, "-Ready") {
		return v.LoadBalancerReady, nil
	}
	return v.LoadBalancerNotReady, nil
}

// CreateLoadBalancerListener - create a load balancer listener
func (v *VpcSdkFake) CreateLoadBalancerListener(lbID, poolName, poolID string, options *ServiceOptions) (*VpcLoadBalancerListener, error) {
	if v.Error["CreateLoadBalancerListener"] != nil {
		return nil, v.Error["CreateLoadBalancerListener"]
	}
	return v.Listener, nil
}

// CreateLoadBalancerPool - create a load balancer pool
func (v *VpcSdkFake) CreateLoadBalancerPool(lbID, poolName string, nodeList []string, options *ServiceOptions) (*VpcLoadBalancerPool, error) {
	if v.Error["CreateLoadBalancerPool"] != nil {
		return nil, v.Error["CreateLoadBalancerPool"]
	}
	return v.Pool, nil
}

// CreateLoadBalancerPoolMember - create a load balancer pool member
func (v *VpcSdkFake) CreateLoadBalancerPoolMember(lbID, poolName, poolID, nodeID string, options *ServiceOptions) (*VpcLoadBalancerPoolMember, error) {
	if v.Error["CreateLoadBalancerPoolMember"] != nil {
		return nil, v.Error["CreateLoadBalancerPoolMember"]
	}
	return v.Member1, nil
}

// CreateSecurityGroupRule - create an inbound, TCP security group rule for the specified port
func (v *VpcSdkFake) CreateSecurityGroupRule(secGroupID, direction, protocol string, portMin, portMax int, remoteSG string) (*VpcSecurityGroupRule, error) {
	if v.Error["CreateSecurityGroupRule"] != nil {
		return nil, v.Error["CreateSecurityGroupRule"]
	}
	// locate the correct SG
	for i, sg := range v.SecurityGroups {
		if sg.ID == secGroupID {
			v.Counter++
			rule := VpcSecurityGroupRule{
				Direction: direction,
				ID:        sg.ID + "-" + strconv.Itoa(v.Counter),
				IPVersion: SecurityGroupRuleIPVersionIpv4,
				Protocol:  protocol,
				PortMin:   int64(portMin),
				PortMax:   int64(portMax),
				Remote:    VpcSecurityGroupRuleRemote{ID: remoteSG},
			}
			v.SecurityGroups[i].Rules = append(v.SecurityGroups[i].Rules, rule)
			return &rule, nil
		}
	}
	return v.SecurityGroupRule, nil
}

// DeleteLoadBalancer - delete the specified VPC load balancer
func (v *VpcSdkFake) DeleteLoadBalancer(lbID string, options *ServiceOptions) error {
	return v.Error["DeleteLoadBalancer"]
}

// DeleteLoadBalancerListener - delete the specified VPC load balancer listener
func (v *VpcSdkFake) DeleteLoadBalancerListener(lbID, listenerID string) error {
	return v.Error["DeleteLoadBalancerListener"]
}

// DeleteLoadBalancerPool - delete the specified VPC load balancer pool
func (v *VpcSdkFake) DeleteLoadBalancerPool(lbID, poolID string) error {
	return v.Error["DeleteLoadBalancerPool"]
}

// DeleteLoadBalancerPoolMember - delete the specified VPC load balancer pool member
func (v *VpcSdkFake) DeleteLoadBalancerPoolMember(lbID, poolID, memberID string) error {
	return v.Error["DeleteLoadBalancerPoolMember"]
}

// DeleteSecurityGroupRule - delete the specified VPC security group rule
func (v *VpcSdkFake) DeleteSecurityGroupRule(secGroupID, ruleID string) error {
	if v.Error["DeleteSecurityGroupRule"] != nil {
		return v.Error["DeleteSecurityGroupRule"]
	}
	// locate the correct SG
	for i, sg := range v.SecurityGroups {
		if sg.ID == secGroupID {
			// locate the correct rule
			for j, rule := range sg.Rules {
				if rule.ID == ruleID {
					v.SecurityGroups[i].Rules = slices.Delete(v.SecurityGroups[i].Rules, j, j+1)
					return nil
				}
			}
		}
	}
	return v.Error["DeleteSecurityGroupRule"]
}

// DeleteServiceRegistration - delete the service registration for the specified service CRN
func (v *VpcSdkFake) DeleteServiceRegistration(serviceCRN string) error {
	return v.Error["DeleteServiceRegistration"]
}

// FindLoadBalancer - locate a VPC load balancer based on the Name, ID, or hostname
func (v *VpcSdkFake) FindLoadBalancer(nameID string, options *ServiceOptions) (*VpcLoadBalancer, error) {
	if v.Error["FindLoadBalancer"] != nil {
		return nil, v.Error["FindLoadBalancer"]
	}
	lbs := []*VpcLoadBalancer{}
	lbs = append(lbs, v.LoadBalancerReady, v.LoadBalancerNotReady)
	for _, lb := range lbs {
		if nameID == lb.ID || nameID == lb.Name || nameID == lb.Hostname {
			return lb, nil
		}
	}
	return nil, nil
}

// GetLoadBalancer - get a specific load balancer
func (v *VpcSdkFake) GetLoadBalancer(lbID string) (*VpcLoadBalancer, error) {
	if v.Error["GetLoadBalancer"] != nil {
		return nil, v.Error["GetLoadBalancer"]
	}
	if lbID == v.LoadBalancerNotReady.ID {
		return v.LoadBalancerNotReady, nil
	}
	return v.LoadBalancerReady, nil
}

// GetSecurityGroup - return a specific security group
func (v *VpcSdkFake) GetSecurityGroup(secGroupID string) (*VpcSecurityGroup, error) {
	if v.Error["GetSecurityGroup"] != nil {
		return nil, v.Error["GetSecurityGroup"]
	}
	if secGroupID != v.SecurityGroup.ID {
		return nil, nil
	}
	return v.SecurityGroup, nil
}

// GetSubnet - get a specific subnet
func (v *VpcSdkFake) GetSubnet(subnetID string) (*VpcSubnet, error) {
	if v.Error["GetSubnet"] != nil {
		return nil, v.Error["GetSubnet"]
	}
	return v.Subnet1, nil
}

// GetVPC - return a specific VPC
func (v *VpcSdkFake) GetVPC(vpcID string) (*Vpc, error) {
	if v.Error["GetVPC"] != nil {
		return nil, v.Error["GetVPC"]
	}
	if vpcID != v.Vpc.ID {
		return nil, nil
	}
	return v.Vpc, nil
}

// ListLoadBalancers - return list of load balancers
func (v *VpcSdkFake) ListLoadBalancers() ([]*VpcLoadBalancer, error) {
	lbs := []*VpcLoadBalancer{}
	if v.Error["ListLoadBalancers"] != nil {
		return lbs, v.Error["ListLoadBalancers"]
	}
	lbs = append(lbs, v.LoadBalancerReady, v.LoadBalancerNotReady)
	return lbs, nil
}

// ListLoadBalancerListeners - return list of load balancer listeners
func (v *VpcSdkFake) ListLoadBalancerListeners(lbID string) ([]*VpcLoadBalancerListener, error) {
	listeners := []*VpcLoadBalancerListener{}
	if v.Error["ListLoadBalancerListeners"] != nil {
		return listeners, v.Error["ListLoadBalancerListeners"]
	}
	listeners = append(listeners, v.Listener)
	return listeners, nil
}

// ListLoadBalancerPools - return list of load balancer pools
func (v *VpcSdkFake) ListLoadBalancerPools(lbID string) ([]*VpcLoadBalancerPool, error) {
	pools := []*VpcLoadBalancerPool{}
	if v.Error["ListLoadBalancerPools"] != nil {
		return pools, v.Error["ListLoadBalancerPools"]
	}
	pools = append(pools, v.Pool)
	return pools, nil
}

// ListLoadBalancerPoolMembers - return list of load balancer pool members
func (v *VpcSdkFake) ListLoadBalancerPoolMembers(lbID, poolID string) ([]*VpcLoadBalancerPoolMember, error) {
	members := []*VpcLoadBalancerPoolMember{}
	if v.Error["ListLoadBalancerPoolMembers"] != nil {
		return members, v.Error["ListLoadBalancerPoolMembers"]
	}
	members = append(members, v.Member1, v.Member2)
	return members, nil
}

// ListNetworkACLs - return list of Access Control Lists
func (v *VpcSdkFake) ListNetworkACLs() ([]*VpcNetworkACL, error) {
	acls := []*VpcNetworkACL{}
	if v.Error["ListNetworkACLs"] != nil {
		return acls, v.Error["ListNetworkACLs"]
	}
	return acls, nil
}

// ListSecurityGroups - return list of security groups
func (v *VpcSdkFake) ListSecurityGroups(vpcID string) ([]*VpcSecurityGroup, error) {
	if v.Error["ListSecurityGroups"] != nil {
		return v.SecurityGroups, v.Error["ListSecurityGroups"]
	}
	secGroups := []*VpcSecurityGroup{}
	for _, sg := range v.SecurityGroups {
		newSG := *sg
		newSG.Rules = []VpcSecurityGroupRule{}
		for _, rule := range sg.Rules {
			newRule := rule
			newSG.Rules = append(newSG.Rules, newRule)
		}
		secGroups = append(secGroups, &newSG)
	}
	return secGroups, nil
}

// ListServiceRegistrations - return list of service registrations
func (v *VpcSdkFake) ListServiceRegistrations() ([]*VpcServiceRegistration, error) {
	svcRegistration := []*VpcServiceRegistration{}
	if v.Error["ListServiceRegistrations"] != nil {
		return svcRegistration, v.Error["ListServiceRegistrations"]
	}
	svcRegistration = append(svcRegistration, v.ServiceRegistration)
	return svcRegistration, nil
}

// ListSubnets - return list of subnets
func (v *VpcSdkFake) ListSubnets() ([]*VpcSubnet, error) {
	subnets := []*VpcSubnet{}
	if v.Error["ListSubnets"] != nil {
		return subnets, v.Error["ListSubnets"]
	}
	subnets = append(subnets, v.Subnet1, v.Subnet2)
	return subnets, nil
}

// ListVPCs - return list of VPCs
func (v *VpcSdkFake) ListVPCs() ([]*Vpc, error) {
	vpcs := []*Vpc{}
	if v.Error["ListVPCs"] != nil {
		return vpcs, v.Error["ListVPCs"]
	}
	vpcs = append(vpcs, v.Vpc)
	return vpcs, nil
}

// ReplaceLoadBalancerPoolMembers - update list of load balancer pool members
func (v *VpcSdkFake) ReplaceLoadBalancerPoolMembers(lbID, poolName, poolID string, nodeList []string, options *ServiceOptions) ([]*VpcLoadBalancerPoolMember, error) {
	members := []*VpcLoadBalancerPoolMember{}
	if v.Error["ReplaceLoadBalancerPoolMembers"] != nil {
		return nil, v.Error["ReplaceLoadBalancerPoolMembers"]
	}
	members = append(members, v.Member1, v.Member2)
	return members, nil
}

// UpdateLoadBalancer - update a load balancer
func (v *VpcSdkFake) UpdateLoadBalancer(lbID string, updateList, nodeList, poolList []string, options *ServiceOptions) error {
	if v.Error["UpdateLoadBalancer"] != nil {
		return v.Error["UpdateLoadBalancer"]
	}
	return nil
}

// UpdateLoadBalancerListener - update a load balancer listener
func (v *VpcSdkFake) UpdateLoadBalancerListener(lbID, listenerID string, options *ServiceOptions) (*VpcLoadBalancerListener, error) {
	if v.Error["UpdateLoadBalancerListener"] != nil {
		return nil, v.Error["UpdateLoadBalancerListener"]
	}
	return v.Listener, nil
}

// UpdateLoadBalancerPool - update a load balancer pool
func (v *VpcSdkFake) UpdateLoadBalancerPool(lbID, newPoolName string, existingPool *VpcLoadBalancerPool, options *ServiceOptions) (*VpcLoadBalancerPool, error) {
	if v.Error["UpdateLoadBalancerPool"] != nil {
		return nil, v.Error["UpdateLoadBalancerPool"]
	}
	return v.Pool, nil
}

// UpdateLoadBalancerSubnets - update a load balancer subnets
func (v *VpcSdkFake) UpdateLoadBalancerSubnets(lbID string, subnetList []string, options *ServiceOptions) (*VpcLoadBalancer, error) {
	if v.Error["UpdateLoadBalancerSubnets"] != nil {
		return nil, v.Error["UpdateLoadBalancerSubnets"]
	}
	return v.LoadBalancerReady, nil
}
