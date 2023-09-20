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
	"net/url"
	"regexp"
	"sort"
	"time"

	"cloud.ibm.com/cloud-provider-ibm/pkg/klog"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	sdk "github.com/IBM/vpc-go-sdk/vpcv1"
)

// VpcSdkGen2 SDK methods
type VpcSdkGen2 struct {
	Client *sdk.VpcV1
	Config *ConfigVpc
}

// NewVpcSdkGen2 - create new SDK client
func NewVpcSdkGen2(c *ConfigVpc) (CloudVpcSdk, error) {
	authenticator, err := c.GetAuthenticator()
	if err != nil {
		return nil, err
	}
	client, err := sdk.NewVpcV1(&sdk.VpcV1Options{
		Authenticator: authenticator,
		URL:           c.endpointURL})
	if err != nil {
		return nil, fmt.Errorf("Failed to create SDK client: %v", err)
	}
	// Convert the resource group name to an ID
	if c.resourceGroupID == "" && c.ResourceGroupName != "" {
		err = convertResourceGroupNameToID(c, authenticator)
		if err != nil {
			return nil, err
		}
	}
	// Default VPC timeout is 30 seconds.  This is not long enough for some operations.
	// Change the default timeout for all VPC REST calls to be 90 seconds.
	client.Service.Client.Timeout = time.Second * 90
	v := &VpcSdkGen2{
		Client: client,
		Config: c,
	}
	return v, nil
}

// convertResourceGroupNameToID - convert the resource group name into an ID
func convertResourceGroupNameToID(c *ConfigVpc, authenticator core.Authenticator) error {
	// Create resource manager client
	client, err := resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{URL: c.resourceManagerURL, Authenticator: authenticator})
	if err != nil {
		return fmt.Errorf("Failed to create resource manager v2 client: %v", err)
	}
	// Retrieve the resource group
	listOptions := &resourcemanagerv2.ListResourceGroupsOptions{AccountID: &c.AccountID, Name: &c.ResourceGroupName}
	list, response, err := client.ListResourceGroups(listOptions)
	if err != nil {
		if response != nil {
			klog.Infof("Response (%d): %+v", response.StatusCode, response.Result)
		}
		return fmt.Errorf("Failed to ListResourceGroups: %v", err)
	}
	if len(list.Resources) != 1 {
		return fmt.Errorf("%d resource groups match name: %s", len(list.Resources), c.ResourceGroupName)
	}
	resourceGroup := list.Resources[0]
	if resourceGroup.ID != nil {
		c.resourceGroupID = *resourceGroup.ID
	}
	return nil
}

// CreateLoadBalancer - create a load balancer
func (v *VpcSdkGen2) CreateLoadBalancer(lbName string, nodeList, poolList, subnetList []string, options *ServiceOptions) (*VpcLoadBalancer, error) {
	// For each of the ports in the Kubernetes service
	isNLB := options.isNLB()
	listeners := []sdk.LoadBalancerListenerPrototypeLoadBalancerContext{}
	pools := []sdk.LoadBalancerPoolPrototype{}
	for _, poolName := range poolList {
		poolNameFields, err := extractFieldsFromPoolName(poolName)
		if err != nil {
			return nil, err
		}
		pool := sdk.LoadBalancerPoolPrototype{
			Algorithm:     core.StringPtr(sdk.LoadBalancerPoolPrototypeAlgorithmRoundRobinConst),
			HealthMonitor: v.genLoadBalancerHealthMonitor(poolNameFields, options),
			Members:       v.genLoadBalancerMembers(poolNameFields.NodePort, nodeList, options),
			Name:          core.StringPtr(poolName),
			Protocol:      core.StringPtr(poolNameFields.Protocol),
			ProxyProtocol: core.StringPtr(sdk.LoadBalancerPoolProxyProtocolDisabledConst),
		}
		// NLB does not support setting the proxy protocol field
		if isNLB {
			pool.ProxyProtocol = nil
		}
		// Set proxy protocol if it was requested on the service annotation (we don't support v2)
		if options.isProxyProtocol() {
			pool.ProxyProtocol = core.StringPtr(sdk.LoadBalancerPoolProxyProtocolV1Const)
		}
		// LoadBalancerOptionLeastConnections / LoadBalancerOptionSessionAffinity are currently not supported
		// See issue: https://github.ibm.com/alchemy-containers/armada-network/issues/3470
		//
		// if isVpcOptionEnabled(options, LoadBalancerOptionLeastConnections) {
		// 	pool.Algorithm = core.StringPtr(sdk.LoadBalancerPoolPrototypeAlgorithmLeastConnectionsConst)
		// }
		// if isVpcOptionEnabled(options, LoadBalancerOptionSessionAffinity) {
		// 	pool.SessionPersistence = &sdk.LoadBalancerPoolSessionPersistencePrototype{Type: core.StringPtr(sdk.LoadBalancerPoolSessionPersistencePrototypeTypeSourceIPConst)}
		// }
		pools = append(pools, pool)
		listener := sdk.LoadBalancerListenerPrototypeLoadBalancerContext{
			DefaultPool: &sdk.LoadBalancerPoolIdentityByName{Name: core.StringPtr(poolName)},
			Port:        core.Int64Ptr(int64(poolNameFields.PortMin)),
			Protocol:    core.StringPtr(poolNameFields.Protocol),
		}
		// Connection limit and idle connection timeout only supported by ALBs
		if options.isALB() {
			listener.ConnectionLimit = core.Int64Ptr(15000)
			listener.IdleConnectionTimeout = core.Int64Ptr(int64(options.getIdleConnectionTimeout()))
		} else if poolNameFields.PortMin != poolNameFields.PortMax {
			// Port ranges are only supported by NLBs
			listener.Port = nil
			listener.PortMin = core.Int64Ptr(int64(poolNameFields.PortMin))
			listener.PortMax = core.Int64Ptr(int64(poolNameFields.PortMax))
		}
		listeners = append(listeners, listener)
	}

	// Fill out the subnets where the VPC LB will be placed
	subnetIds := []sdk.SubnetIdentityIntf{}
	for _, subnet := range subnetList {
		subnetIds = append(subnetIds, &sdk.SubnetIdentity{ID: core.StringPtr(subnet)})
	}

	// Initialize all of the create options
	createOptions := &sdk.CreateLoadBalancerOptions{
		IsPublic:      core.BoolPtr(options.isPublic()),
		Subnets:       subnetIds,
		Listeners:     listeners,
		Name:          core.StringPtr(lbName),
		Pools:         pools,
		ResourceGroup: &sdk.ResourceGroupIdentity{ID: core.StringPtr(v.Config.resourceGroupID)},
	}
	if isNLB {
		createOptions.Profile = &sdk.LoadBalancerProfileIdentityByName{Name: core.StringPtr("network-fixed")}
		createOptions.Headers = map[string]string{"x-instance-account-id": v.Config.WorkerAccountID}
	} else if v.Config.lbSecurityGroupID != "" {
		secGrp := &sdk.SecurityGroupIdentityByID{ID: core.StringPtr(v.Config.lbSecurityGroupID)}
		createOptions.SecurityGroups = []sdk.SecurityGroupIdentityIntf{secGrp}
	}

	// Create the VPC LB
	lb, response, err := v.Client.CreateLoadBalancer(createOptions)
	if err != nil {
		// If an error occurred creating the LB with a secGroupID, maybe the secGroupID is no longer valid. Reset it
		if len(createOptions.SecurityGroups) > 1 {
			v.Config.lbSecurityGroupID = ""
		}
		v.logResponseError(response)
		return nil, err
	}

	// Map the generated object back to the common format
	return v.mapLoadBalancer(*lb), nil
}

// CreateLoadBalancerListener - create a load balancer listener
func (v *VpcSdkGen2) CreateLoadBalancerListener(lbID, poolName, poolID string, options *ServiceOptions) (*VpcLoadBalancerListener, error) {
	// Extract values from poolName
	poolNameFields, err := extractFieldsFromPoolName(poolName)
	if err != nil {
		return nil, err
	}
	// Initialize the create options
	createOptions := &sdk.CreateLoadBalancerListenerOptions{
		LoadBalancerID: core.StringPtr(lbID),
		Port:           core.Int64Ptr(int64(poolNameFields.PortMin)),
		Protocol:       core.StringPtr(poolNameFields.Protocol),
		DefaultPool:    &sdk.LoadBalancerPoolIdentity{ID: core.StringPtr(poolID)},
	}
	// Connection limit and idle connection timeout only supported by ALBs
	if options.isALB() {
		createOptions.ConnectionLimit = core.Int64Ptr(15000)
		createOptions.IdleConnectionTimeout = core.Int64Ptr(int64(options.getIdleConnectionTimeout()))
	} else if poolNameFields.PortMin != poolNameFields.PortMax {
		// Port ranges are only supported by NLBs
		createOptions.Port = nil
		createOptions.PortMin = core.Int64Ptr(int64(poolNameFields.PortMin))
		createOptions.PortMax = core.Int64Ptr(int64(poolNameFields.PortMax))
	}
	// Create the VPC LB listener
	listener, response, err := v.Client.CreateLoadBalancerListener(createOptions)
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	// Map the generated object back to the common format
	return v.mapLoadBalancerListener(*listener), nil
}

// CreateLoadBalancerPool - create a load balancer pool
func (v *VpcSdkGen2) CreateLoadBalancerPool(lbID, poolName string, nodeList []string, options *ServiceOptions) (*VpcLoadBalancerPool, error) {
	// Extract values from poolName
	poolNameFields, err := extractFieldsFromPoolName(poolName)
	if err != nil {
		return nil, err
	}
	// Initialize the create options
	createOptions := &sdk.CreateLoadBalancerPoolOptions{
		LoadBalancerID: core.StringPtr(lbID),
		Algorithm:      core.StringPtr(sdk.CreateLoadBalancerPoolOptionsAlgorithmRoundRobinConst),
		HealthMonitor:  v.genLoadBalancerHealthMonitor(poolNameFields, options),
		Members:        v.genLoadBalancerMembers(poolNameFields.NodePort, nodeList, options),
		Name:           core.StringPtr(poolName),
		Protocol:       core.StringPtr(poolNameFields.Protocol),
	}
	// LoadBalancerOptionLeastConnections / LoadBalancerOptionSessionAffinity are currently not supported
	// See issue: https://github.ibm.com/alchemy-containers/armada-network/issues/3470
	//
	// if isVpcOptionEnabled(options, LoadBalancerOptionLeastConnections) {
	// 	createOptions.Algorithm = core.StringPtr(sdk.CreateLoadBalancerPoolOptionsAlgorithmLeastConnectionsConst)
	// }
	// if isVpcOptionEnabled(options, LoadBalancerOptionSessionAffinity) {
	// 	createOptions.SessionPersistence = &sdk.LoadBalancerPoolSessionPersistencePrototype{Type: core.StringPtr(sdk.LoadBalancerPoolSessionPersistencePrototypeTypeSourceIPConst)}
	// }
	if options.isNLB() {
		createOptions.Headers = map[string]string{"x-instance-account-id": v.Config.WorkerAccountID}
	}
	// Create the VPC LB pool
	pool, response, err := v.Client.CreateLoadBalancerPool(createOptions)
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	// Map the generated object back to the common format
	return v.mapLoadBalancerPool(*pool), nil
}

// CreateLoadBalancerPoolMember - create a load balancer pool member
func (v *VpcSdkGen2) CreateLoadBalancerPoolMember(lbID, poolName, poolID, nodeID string, options *ServiceOptions) (*VpcLoadBalancerPoolMember, error) {
	// Extract values from poolName
	poolNameFields, err := extractFieldsFromPoolName(poolName)
	if err != nil {
		return nil, err
	}
	// Initialize the create options
	createOptions := &sdk.CreateLoadBalancerPoolMemberOptions{
		LoadBalancerID: core.StringPtr(lbID),
		PoolID:         core.StringPtr(poolID),
		Port:           core.Int64Ptr(int64(poolNameFields.NodePort)),
	}
	if options.isNLB() {
		createOptions.Target = &sdk.LoadBalancerPoolMemberTargetPrototypeInstanceIdentityInstanceIdentityByID{ID: core.StringPtr(nodeID)}
		createOptions.Headers = map[string]string{"x-instance-account-id": v.Config.WorkerAccountID}
	} else {
		createOptions.Target = &sdk.LoadBalancerPoolMemberTargetPrototypeIP{Address: core.StringPtr(nodeID)}
	}
	// Create the VPC LB pool member
	member, response, err := v.Client.CreateLoadBalancerPoolMember(createOptions)
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	// Map the generated object back to the common format
	return v.mapLoadBalancerPoolMember(*member), nil
}

// CreateSecurityGroupRule - create an inbound, TCP security group rule for the specified port
func (v *VpcSdkGen2) CreateSecurityGroupRule(secGroupID, direction, protocol string, portMin, portMax int, remoteSG string) (*VpcSecurityGroupRule, error) {
	// Set up the rule options
	ruleOptions := &sdk.SecurityGroupRulePrototypeSecurityGroupRuleProtocolTcpudp{
		Direction: core.StringPtr(direction),
		IPVersion: core.StringPtr(sdk.SecurityGroupRulePrototypeSecurityGroupRuleProtocolTcpudpIPVersionIpv4Const),
		PortMin:   core.Int64Ptr(int64(portMin)),
		PortMax:   core.Int64Ptr(int64(portMax)),
		Protocol:  core.StringPtr(protocol),
	}
	// TODO: Can't set remote rule due to quota limitation.
	//
	// Exceeded limit of remote rules per security group (the limit is 5 remote rules per security group)
	// Adding a rule would exceed the limit of remote rules per security group. Consider creating another security group.
	//
	// if remoteSG != "" {
	// 	ruleOptions.Remote = &sdk.SecurityGroupRuleRemotePrototype{ID: core.StringPtr(remoteSG)}
	// }
	// Initialize the create options
	createOptions := &sdk.CreateSecurityGroupRuleOptions{
		SecurityGroupID:            core.StringPtr(secGroupID),
		SecurityGroupRulePrototype: ruleOptions,
	}
	// Create the VPC LB listener
	rule, response, err := v.Client.CreateSecurityGroupRule(createOptions)
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	// Map the generated object back to the common format
	return v.mapSecurityGroupRule(rule), nil
}

// DeleteLoadBalancer - delete the specified VPC load balancer
func (v *VpcSdkGen2) DeleteLoadBalancer(lbID string, options *ServiceOptions) error {
	response, err := v.Client.DeleteLoadBalancer(&sdk.DeleteLoadBalancerOptions{ID: &lbID})
	if err != nil {
		v.logResponseError(response)
	}
	return err
}

// DeleteLoadBalancerListener - delete the specified VPC load balancer listener
func (v *VpcSdkGen2) DeleteLoadBalancerListener(lbID, listenerID string) error {
	response, err := v.Client.DeleteLoadBalancerListener(&sdk.DeleteLoadBalancerListenerOptions{LoadBalancerID: &lbID, ID: &listenerID})
	if err != nil {
		v.logResponseError(response)
	}
	return err
}

// DeleteLoadBalancerPool - delete the specified VPC load balancer pool
func (v *VpcSdkGen2) DeleteLoadBalancerPool(lbID, poolID string) error {
	response, err := v.Client.DeleteLoadBalancerPool(&sdk.DeleteLoadBalancerPoolOptions{LoadBalancerID: &lbID, ID: &poolID})
	if err != nil {
		v.logResponseError(response)
	}
	return err
}

// DeleteLoadBalancerPoolMember - delete the specified VPC load balancer pool
func (v *VpcSdkGen2) DeleteLoadBalancerPoolMember(lbID, poolID, memberID string) error {
	response, err := v.Client.DeleteLoadBalancerPoolMember(&sdk.DeleteLoadBalancerPoolMemberOptions{LoadBalancerID: &lbID, PoolID: &poolID, ID: &memberID})
	if err != nil {
		v.logResponseError(response)
	}
	return err
}

// DeleteSecurityGroupRule - delete the specified VPC security group rule
func (v *VpcSdkGen2) DeleteSecurityGroupRule(secGroupID, rulelID string) error {
	response, err := v.Client.DeleteSecurityGroupRule(&sdk.DeleteSecurityGroupRuleOptions{SecurityGroupID: &secGroupID, ID: &rulelID})
	if err != nil {
		v.logResponseError(response)
	}
	return err
}

// DeleteServiceRegistration - delete the service registration for the specified service CRN
func (v *VpcSdkGen2) DeleteServiceRegistration(serviceCRN string) error {
	return fmt.Errorf("Not supported")
}

// FindLoadBalancer - locate a VPC load balancer based on the Name, ID, or hostname
func (v *VpcSdkGen2) FindLoadBalancer(nameID string, options *ServiceOptions) (*VpcLoadBalancer, error) {
	// If nameID looks like an "ID", r134-d985bb3a-371d-4aa2-8462-626461a955e1, then attempt to extract that single LB
	match, err := regexp.MatchString("[a-z0-9]{4}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", nameID)
	if match && err == nil {
		lb, err := v.GetLoadBalancer(nameID)
		if err == nil {
			return lb, nil
		}
	}
	lbs, err := v.ListLoadBalancers()
	if err != nil {
		return nil, err
	}
	for _, lb := range lbs {
		if nameID == lb.ID || nameID == lb.Name || nameID == lb.Hostname {
			return lb, nil
		}
	}
	return nil, nil
}

// genLoadBalancerHealthMonitor - generate the VPC health monitor template for load balancer
func (v *VpcSdkGen2) genLoadBalancerHealthMonitor(poolNameFields *VpcPoolNameFields, options *ServiceOptions) *sdk.LoadBalancerPoolHealthMonitorPrototype {
	// Define health monitor for load balancer.
	//
	// The Delay, MaxRetries, and Timeout values listed below are the default values that are selected when
	// a load balancer is created in the VPC UI.  These values may need to be adjusted for IKS clusters.
	healthMonitor := &sdk.LoadBalancerPoolHealthMonitorPrototype{
		Delay:      core.Int64Ptr(int64(options.getHealthCheckDelay())),
		MaxRetries: core.Int64Ptr(int64(options.getHealthCheckRetries())),
		Port:       core.Int64Ptr(int64(poolNameFields.NodePort)),
		Timeout:    core.Int64Ptr(int64(options.getHealthCheckTimeout())),
		Type:       core.StringPtr(sdk.LoadBalancerPoolHealthMonitorPrototypeTypeTCPConst),
	}
	// If UDP protocol, then change the port to the UDP health check port
	if poolNameFields.Protocol == "udp" {
		healthMonitor.Port = core.Int64Ptr(int64(options.getHealthCheckUDP()))
	}
	// If custom health check annotations were specified, update the type, port, and path
	if options.getHealthCheckProtocol() != "" {
		healthMonitor.Type = core.StringPtr(options.getHealthCheckProtocol())
		if options.getHealthCheckPort() != 0 {
			healthMonitor.Port = core.Int64Ptr(int64(options.getHealthCheckPort()))
		} else {
			healthMonitor.Port = core.Int64Ptr(int64(poolNameFields.NodePort))
		}
		if options.getHealthCheckProtocol() != "tcp" {
			healthMonitor.URLPath = core.StringPtr(options.getHealthCheckPath())
		}
	} else if options.getHealthCheckNodePort() > 0 {
		// If the service has: "externalTrafficPolicy: local", then set the health check to be HTTP
		healthMonitor.Port = core.Int64Ptr(int64(options.getHealthCheckNodePort()))
		healthMonitor.Type = core.StringPtr(sdk.LoadBalancerPoolHealthMonitorPrototypeTypeHTTPConst)
		healthMonitor.URLPath = core.StringPtr("/")
	}
	return healthMonitor
}

// genLoadBalancerHealthMonitorUpdate - generate the VPC health monitor update template for load balancer pool
func (v *VpcSdkGen2) genLoadBalancerHealthMonitorUpdate(poolNameFields *VpcPoolNameFields, options *ServiceOptions) *sdk.LoadBalancerPoolHealthMonitorPatch {
	// Define health monitor for load balancer.
	//
	// The Delay, MaxRetries, and Timeout values listed below are the default values that are selected when
	// a load balancer is created in the VPC UI.  These values may need to be adjusted for IKS clusters.
	healthMonitor := &sdk.LoadBalancerPoolHealthMonitorPatch{
		Delay:      core.Int64Ptr(int64(options.getHealthCheckDelay())),
		MaxRetries: core.Int64Ptr(int64(options.getHealthCheckRetries())),
		Port:       core.Int64Ptr(int64(poolNameFields.NodePort)),
		Timeout:    core.Int64Ptr(int64(options.getHealthCheckTimeout())),
		Type:       core.StringPtr(sdk.LoadBalancerPoolHealthMonitorPrototypeTypeTCPConst),
	}
	// If UDP protocol, then change the port to the UDP health check port
	if poolNameFields.Protocol == "udp" {
		healthMonitor.Port = core.Int64Ptr(int64(options.getHealthCheckUDP()))
	}
	// If custom health check annotations were specified, update the type, port, and path
	if options.getHealthCheckProtocol() != "" {
		healthMonitor.Type = core.StringPtr(options.getHealthCheckProtocol())
		if options.getHealthCheckPort() != 0 {
			healthMonitor.Port = core.Int64Ptr(int64(options.getHealthCheckPort()))
		} else {
			healthMonitor.Port = core.Int64Ptr(int64(poolNameFields.NodePort))
		}
		if options.getHealthCheckProtocol() != "tcp" {
			healthMonitor.URLPath = core.StringPtr(options.getHealthCheckPath())
		}
	} else if options.getHealthCheckNodePort() > 0 {
		// If the service has: "externalTrafficPolicy: local", then set the health check to be HTTP
		healthMonitor.Port = core.Int64Ptr(int64(options.getHealthCheckNodePort()))
		healthMonitor.Type = core.StringPtr(sdk.LoadBalancerPoolHealthMonitorPrototypeTypeHTTPConst)
		healthMonitor.URLPath = core.StringPtr("/")
	}
	return healthMonitor
}

// genLoadBalancerMembers - generate the VPC member template for load balancer
func (v *VpcSdkGen2) genLoadBalancerMembers(nodePort int, nodeList []string, options *ServiceOptions) []sdk.LoadBalancerPoolMemberPrototype {
	// Create list of backend nodePorts on each of the nodes
	members := []sdk.LoadBalancerPoolMemberPrototype{}
	nodeInstanceIDs := options.isNLB()
	for _, node := range nodeList {
		member := sdk.LoadBalancerPoolMemberPrototype{Port: core.Int64Ptr(int64(nodePort))}
		if nodeInstanceIDs {
			member.Target = &sdk.LoadBalancerPoolMemberTargetPrototypeInstanceIdentityInstanceIdentityByID{ID: core.StringPtr(node)}
		} else {
			member.Target = &sdk.LoadBalancerPoolMemberTargetPrototypeIP{Address: core.StringPtr(node)}
		}
		members = append(members, member)
	}
	return members
}

// GetLoadBalancer - get a specific load balancer
func (v *VpcSdkGen2) GetLoadBalancer(lbID string) (*VpcLoadBalancer, error) {
	lb, response, err := v.Client.GetLoadBalancer(&sdk.GetLoadBalancerOptions{ID: &lbID})
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	return v.mapLoadBalancer(*lb), nil
}

// GetSecurityGroup - return a specific security group
func (v *VpcSdkGen2) GetSecurityGroup(secGroupID string) (*VpcSecurityGroup, error) {
	secGroup, response, err := v.Client.GetSecurityGroup(&sdk.GetSecurityGroupOptions{ID: &secGroupID})
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	return v.mapSecurityGroup(*secGroup), nil
}

// GetSubnet - get a specific subnet
func (v *VpcSdkGen2) GetSubnet(subnetID string) (*VpcSubnet, error) {
	subnet, response, err := v.Client.GetSubnet(&sdk.GetSubnetOptions{ID: &subnetID})
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	return v.mapSubnet(*subnet), nil
}

// GetVPC - return a specific VPC
func (v *VpcSdkGen2) GetVPC(vpcID string) (*Vpc, error) {
	vpc, response, err := v.Client.GetVPC(&sdk.GetVPCOptions{ID: &vpcID})
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	return v.mapVpc(*vpc), nil
}

// ListLoadBalancers - return list of load balancers
func (v *VpcSdkGen2) ListLoadBalancers() ([]*VpcLoadBalancer, error) {
	lbs := []*VpcLoadBalancer{}
	var start *string
	for {
		list, response, err := v.Client.ListLoadBalancers(&sdk.ListLoadBalancersOptions{Start: start})
		if err != nil {
			v.logResponseError(response)
			return lbs, err
		}
		for _, item := range list.LoadBalancers {
			lbs = append(lbs, v.mapLoadBalancer(item))
		}
		// Check to see if more need to be retrieved
		if list.Next == nil || list.Next.Href == nil {
			break
		}
		// We need to pull out the "start" query value and re-issue the call to RIaaS to get the next block of objects
		u, err := url.Parse(*list.Next.Href)
		if err != nil {
			return lbs, err
		}
		qryArgs := u.Query()
		start = core.StringPtr(qryArgs.Get("start"))
	}
	return lbs, nil
}

// ListLoadBalancerListeners - return list of load balancer listeners
func (v *VpcSdkGen2) ListLoadBalancerListeners(lbID string) ([]*VpcLoadBalancerListener, error) {
	listeners := []*VpcLoadBalancerListener{}
	list, response, err := v.Client.ListLoadBalancerListeners(&sdk.ListLoadBalancerListenersOptions{LoadBalancerID: &lbID})
	if err != nil {
		v.logResponseError(response)
		return listeners, err
	}
	for _, item := range list.Listeners {
		listeners = append(listeners, v.mapLoadBalancerListener(item))
	}
	return listeners, nil
}

// ListLoadBalancerPools - return list of load balancer pools
func (v *VpcSdkGen2) ListLoadBalancerPools(lbID string) ([]*VpcLoadBalancerPool, error) {
	pools := []*VpcLoadBalancerPool{}
	list, response, err := v.Client.ListLoadBalancerPools(&sdk.ListLoadBalancerPoolsOptions{LoadBalancerID: &lbID})
	if err != nil {
		v.logResponseError(response)
		return pools, err
	}
	for _, item := range list.Pools {
		pool := v.mapLoadBalancerPool(item)
		members, err := v.ListLoadBalancerPoolMembers(lbID, pool.ID)
		if err != nil {
			return pools, err
		}
		pool.Members = members
		pools = append(pools, pool)
	}
	return pools, nil
}

// ListLoadBalancerPoolMembers - return list of load balancer pool members
func (v *VpcSdkGen2) ListLoadBalancerPoolMembers(lbID, poolID string) ([]*VpcLoadBalancerPoolMember, error) {
	members := []*VpcLoadBalancerPoolMember{}
	list, response, err := v.Client.ListLoadBalancerPoolMembers(&sdk.ListLoadBalancerPoolMembersOptions{LoadBalancerID: &lbID, PoolID: &poolID})
	if err != nil {
		v.logResponseError(response)
		return members, err
	}
	for _, item := range list.Members {
		members = append(members, v.mapLoadBalancerPoolMember(item))
	}
	return members, nil
}

func (v *VpcSdkGen2) ListNetworkACLs() ([]*VpcNetworkACL, error) {
	acls := []*VpcNetworkACL{}
	var start *string
	for {
		list, response, err := v.Client.ListNetworkAcls(&sdk.ListNetworkAclsOptions{Start: start})
		if err != nil {
			v.logResponseError(response)
			return acls, err
		}
		for _, item := range list.NetworkAcls {
			acls = append(acls, v.mapNetworkACL(item))
		}
		// Check to see if more need to be retrieved
		if list.Next == nil || list.Next.Href == nil {
			break
		}
		// We need to pull out the "start" query value and re-issue the call to RIaaS to get the next block of objects
		u, err := url.Parse(*list.Next.Href)
		if err != nil {
			return acls, err
		}
		qryArgs := u.Query()
		start = core.StringPtr(qryArgs.Get("start"))
	}
	return acls, nil
}

// ListSecurityGroups - return list of security groups
func (v *VpcSdkGen2) ListSecurityGroups(vpcID string) ([]*VpcSecurityGroup, error) {
	secGroups := []*VpcSecurityGroup{}
	var start *string
	var filterVpcID *string
	if vpcID != "" {
		filterVpcID = core.StringPtr(vpcID)
	}
	for {
		list, response, err := v.Client.ListSecurityGroups(&sdk.ListSecurityGroupsOptions{Start: start, VPCID: filterVpcID})
		if err != nil {
			v.logResponseError(response)
			return secGroups, err
		}
		for _, item := range list.SecurityGroups {
			secGroups = append(secGroups, v.mapSecurityGroup(item))
		}
		// Check to see if more need to be retrieved
		if list.Next == nil || list.Next.Href == nil {
			break
		}
		// We need to pull out the "start" query value and re-issue the call to RIaaS to get the next block of objects
		u, err := url.Parse(*list.Next.Href)
		if err != nil {
			return secGroups, err
		}
		qryArgs := u.Query()
		start = core.StringPtr(qryArgs.Get("start"))
	}
	return secGroups, nil
}

// ListServiceRegistrations - return list of service registrations
func (v *VpcSdkGen2) ListServiceRegistrations() ([]*VpcServiceRegistration, error) {
	serviceRegisration := []*VpcServiceRegistration{}
	return serviceRegisration, fmt.Errorf("Not supported")
}

// ListSubnets - return list of subnets
func (v *VpcSdkGen2) ListSubnets() ([]*VpcSubnet, error) {
	subnets := []*VpcSubnet{}
	// Default quota limitation on account:
	//   - VPCs / region: 10
	//   - Subnets / VPC: 15
	// Without ever altering the quotas on the account, a single region can have: 10 x 15 = 150 subnets
	// Default limit on subnets returned from VPC in a single call: 50  (maximum = 100)
	// Since there is no way to filter the subnet results, pagination will need to be used.
	// RIaaS request was made to allow subnets to be filtered based on VPC id: https://jiracloud.swg.usma.ibm.com:8443/browse/RNOS-3427
	var start *string
	for {
		list, response, err := v.Client.ListSubnets(&sdk.ListSubnetsOptions{Start: start})
		if err != nil {
			v.logResponseError(response)
			return subnets, err
		}
		for _, item := range list.Subnets {
			subnets = append(subnets, v.mapSubnet(item))
		}
		// Check to see if more subnets need to be retrieved
		if list.Next == nil || list.Next.Href == nil {
			break
		}
		// The list.Next.Href value will be set to something like:
		//   "https://us-south.iaas.cloud.ibm.com/v1/subnets?limit=50&start=0717-52e6fbc8-e4e3-4699-87aa-aa33a8e841a7"
		// We need to pull out the "start" query value and re-issue the call to RIaaS to get the next block of objects
		u, err := url.Parse(*list.Next.Href)
		if err != nil {
			return subnets, err
		}
		qryArgs := u.Query()
		start = core.StringPtr(qryArgs.Get("start"))
	}
	return subnets, nil
}

// ListVPCs - return list of VPCs
func (v *VpcSdkGen2) ListVPCs() ([]*Vpc, error) {
	vpcs := []*Vpc{}
	var start *string
	for {
		list, response, err := v.Client.ListVpcs(&sdk.ListVpcsOptions{Start: start})
		if err != nil {
			v.logResponseError(response)
			return vpcs, err
		}
		for _, item := range list.Vpcs {
			vpcs = append(vpcs, v.mapVpc(item))
		}
		// Check to see if more need to be retrieved
		if list.Next == nil || list.Next.Href == nil {
			break
		}
		// We need to pull out the "start" query value and re-issue the call to RIaaS to get the next block of objects
		u, err := url.Parse(*list.Next.Href)
		if err != nil {
			return vpcs, err
		}
		qryArgs := u.Query()
		start = core.StringPtr(qryArgs.Get("start"))
	}
	return vpcs, nil
}

// logResponseError - write the response details to stdout so it will appear in logs
func (v *VpcSdkGen2) logResponseError(response *core.DetailedResponse) {
	if response != nil {
		klog.Infof("Response (%d): %+v", response.StatusCode, response.Result)
	}
}

// mapLoadBalancer - map the LoadBalancer to generic format
func (v *VpcSdkGen2) mapLoadBalancer(item sdk.LoadBalancer) *VpcLoadBalancer {
	lb := &VpcLoadBalancer{
		SdkObject:          item,
		CreatedAt:          SafePointerDate(item.CreatedAt),
		Hostname:           SafePointerString(item.Hostname),
		ID:                 SafePointerString(item.ID),
		IsPublic:           SafePointerBool(item.IsPublic),
		Name:               SafePointerString(item.Name),
		OperatingStatus:    SafePointerString(item.OperatingStatus),
		ProvisioningStatus: SafePointerString(item.ProvisioningStatus),
	}
	// Listener IDs
	for _, listenerRef := range item.Listeners {
		lb.ListenerIDs = append(lb.ListenerIDs, SafePointerString(listenerRef.ID))
	}
	// Pools
	for _, poolRef := range item.Pools {
		lb.Pools = append(lb.Pools, VpcObjectReference{ID: SafePointerString(poolRef.ID), Name: SafePointerString(poolRef.Name)})
	}
	// Private IPs
	for _, item := range item.PrivateIps {
		lb.PrivateIps = append(lb.PrivateIps, SafePointerString(item.Address))
	}
	sort.Strings(lb.PrivateIps)
	// Profile
	if item.Profile != nil {
		lb.ProfileFamily = SafePointerString(item.Profile.Family)
	}
	// Public IPs
	for _, item := range item.PublicIps {
		lb.PublicIps = append(lb.PublicIps, SafePointerString(item.Address))
	}
	sort.Strings(lb.PublicIps)
	// Resource Group
	if item.ResourceGroup != nil {
		lb.ResourceGroup = VpcObjectReference{ID: SafePointerString(item.ResourceGroup.ID), Name: SafePointerString(item.ResourceGroup.Name)}
	}
	// SecurityGroups
	for _, secGroup := range item.SecurityGroups {
		lb.SecurityGroups = append(lb.SecurityGroups, VpcObjectReference{ID: SafePointerString(secGroup.ID), Name: SafePointerString(secGroup.Name)})
	}
	// Subnets
	for _, subnetRef := range item.Subnets {
		lb.Subnets = append(lb.Subnets, VpcObjectReference{ID: SafePointerString(subnetRef.ID), Name: SafePointerString(subnetRef.Name)})
	}
	return lb
}

// mapLoadBalancerListener - map the LoadBalancerListener to generic format
func (v *VpcSdkGen2) mapLoadBalancerListener(item sdk.LoadBalancerListener) *VpcLoadBalancerListener {
	listener := &VpcLoadBalancerListener{
		ConnectionLimit:    SafePointerInt64(item.ConnectionLimit),
		IdleConnTimeout:    SafePointerInt64(item.IdleConnectionTimeout),
		ID:                 SafePointerString(item.ID),
		PortMin:            SafePointerInt64(item.PortMin),
		PortMax:            SafePointerInt64(item.PortMax),
		Protocol:           SafePointerString(item.Protocol),
		ProvisioningStatus: SafePointerString(item.ProvisioningStatus),
	}
	if listener.PortMin == 0 {
		listener.PortMin = SafePointerInt64(item.Port)
	}
	if listener.PortMax == 0 {
		listener.PortMax = listener.PortMin
	}
	if item.DefaultPool != nil {
		listener.DefaultPool = VpcObjectReference{ID: SafePointerString(item.DefaultPool.ID), Name: SafePointerString(item.DefaultPool.Name)}
	}
	return listener
}

// mapLoadBalancerPool - map the LoadBalancerPool to generic format
func (v *VpcSdkGen2) mapLoadBalancerPool(item sdk.LoadBalancerPool) *VpcLoadBalancerPool {
	pool := &VpcLoadBalancerPool{
		Algorithm:          SafePointerString(item.Algorithm),
		ID:                 SafePointerString(item.ID),
		Name:               SafePointerString(item.Name),
		Protocol:           SafePointerString(item.Protocol),
		ProvisioningStatus: SafePointerString(item.ProvisioningStatus),
		ProxyProtocol:      SafePointerString(item.ProxyProtocol),
		SessionPersistence: "None",
	}
	if item.HealthMonitor != nil {
		pool.HealthMonitor = v.mapLoadBalancerPoolHealthMonitor(*item.HealthMonitor)
	}
	for _, memberRef := range item.Members {
		pool.Members = append(pool.Members, &VpcLoadBalancerPoolMember{ID: SafePointerString(memberRef.ID)})
	}
	if item.SessionPersistence != nil {
		pool.SessionPersistence = SafePointerString(item.SessionPersistence.Type)
	}
	return pool
}

// mapLoadBalancerPoolHealthMonitor - map the LoadBalancerPoolHealthMonitor to generic format
func (v *VpcSdkGen2) mapLoadBalancerPoolHealthMonitor(item sdk.LoadBalancerPoolHealthMonitor) VpcLoadBalancerPoolHealthMonitor {
	healthMonitor := VpcLoadBalancerPoolHealthMonitor{
		Delay:      SafePointerInt64(item.Delay),
		MaxRetries: SafePointerInt64(item.MaxRetries),
		Port:       SafePointerInt64(item.Port),
		Timeout:    SafePointerInt64(item.Timeout),
		Type:       SafePointerString(item.Type),
		URLPath:    SafePointerString(item.URLPath),
	}
	return healthMonitor
}

// mapLoadBalancerPoolMember - map the LoadBalancerPoolMember to generic format
func (v *VpcSdkGen2) mapLoadBalancerPoolMember(item sdk.LoadBalancerPoolMember) *VpcLoadBalancerPoolMember {
	member := &VpcLoadBalancerPoolMember{
		Health:             SafePointerString(item.Health),
		ID:                 SafePointerString(item.ID),
		Port:               SafePointerInt64(item.Port),
		ProvisioningStatus: SafePointerString(item.ProvisioningStatus),
		Weight:             SafePointerInt64(item.Weight),
	}
	if item.Target != nil {
		member.TargetIPAddress = SafePointerString(item.Target.(*sdk.LoadBalancerPoolMemberTarget).Address)
		member.TargetInstanceID = SafePointerString(item.Target.(*sdk.LoadBalancerPoolMemberTarget).ID)
	}
	return member
}

// mapNetworkACL - map the vpcv1 NetworkAcl to generic format
func (v *VpcSdkGen2) mapNetworkACL(item sdk.NetworkACL) *VpcNetworkACL {
	netACL := &VpcNetworkACL{
		SdkObject: item,
		CreatedAt: SafePointerDate(item.CreatedAt),
		ID:        SafePointerString(item.ID),
		Name:      SafePointerString(item.Name),
	}
	// ResourceGroup
	if item.ResourceGroup != nil {
		netACL.ResourceGroup = VpcObjectReference{ID: SafePointerString(item.ResourceGroup.ID), Name: SafePointerString(item.ResourceGroup.Name)}
	}
	// Rules
	for _, rule := range item.Rules {
		netACL.Rules = append(netACL.Rules, *v.mapNetworkACLRule(rule))
	}
	// Vpc
	if item.VPC != nil {
		netACL.Vpc = VpcObjectReference{ID: SafePointerString(item.VPC.ID), Name: SafePointerString(item.VPC.Name)}
	}
	return netACL
}

// mapNetworkACLRule - map the NetworkAclRule to generic format
func (v *VpcSdkGen2) mapNetworkACLRule(item sdk.NetworkACLRuleItemIntf) *VpcNetworkACLRule {
	return &VpcNetworkACLRule{
		SdkObject: item,
	}
}

// mapSecurityGroup - map the SecurityGroup to generic format
func (v *VpcSdkGen2) mapSecurityGroup(item sdk.SecurityGroup) *VpcSecurityGroup {
	secGroup := &VpcSecurityGroup{
		SdkObject: item,
		CreatedAt: SafePointerDate(item.CreatedAt),
		ID:        SafePointerString(item.ID),
		Name:      SafePointerString(item.Name),
	}
	// ResourceGroup
	if item.ResourceGroup != nil {
		secGroup.ResourceGroup = VpcObjectReference{ID: SafePointerString(item.ResourceGroup.ID), Name: SafePointerString(item.ResourceGroup.Name)}
	}
	// Rules
	for _, rule := range item.Rules {
		secGroup.Rules = append(secGroup.Rules, *v.mapSecurityGroupRule(rule))
	}
	// Targets
	for _, target := range item.Targets {
		secGroup.Targets = append(secGroup.Targets, *v.mapSecurityGroupTarget(target))
	}
	// Vpc
	if item.VPC != nil {
		secGroup.Vpc = VpcObjectReference{ID: SafePointerString(item.VPC.ID), Name: SafePointerString(item.VPC.Name)}
	}
	return secGroup
}

// mapSecurityGroupRule - map the SecurityGroupRule to generic format
func (v *VpcSdkGen2) mapSecurityGroupRule(item sdk.SecurityGroupRuleIntf) *VpcSecurityGroupRule {
	rule := &VpcSecurityGroupRule{SdkObject: item}
	switch ruleType := item.(type) {
	case *sdk.SecurityGroupRuleSecurityGroupRuleProtocolAll:
		rule.Direction = SafePointerString(ruleType.Direction)
		rule.ID = SafePointerString(ruleType.ID)
		rule.IPVersion = SafePointerString(ruleType.IPVersion)
		rule.Protocol = SafePointerString(ruleType.Protocol)
		rule.Remote = v.mapSecurityGroupRuleRemote(ruleType.Remote)
	case *sdk.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
		rule.Direction = SafePointerString(ruleType.Direction)
		rule.ID = SafePointerString(ruleType.ID)
		rule.IPVersion = SafePointerString(ruleType.IPVersion)
		rule.Protocol = SafePointerString(ruleType.Protocol)
		rule.Remote = v.mapSecurityGroupRuleRemote(ruleType.Remote)
	case *sdk.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
		rule.Direction = SafePointerString(ruleType.Direction)
		rule.ID = SafePointerString(ruleType.ID)
		rule.IPVersion = SafePointerString(ruleType.IPVersion)
		rule.PortMax = SafePointerInt64(ruleType.PortMax)
		rule.PortMin = SafePointerInt64(ruleType.PortMin)
		rule.Protocol = SafePointerString(ruleType.Protocol)
		rule.Remote = v.mapSecurityGroupRuleRemote(ruleType.Remote)
	}
	return rule
}

// mapSecurityGroupRemote - map the SecurityGroupRuleRemote to generic format
func (v *VpcSdkGen2) mapSecurityGroupRuleRemote(item sdk.SecurityGroupRuleRemoteIntf) VpcSecurityGroupRuleRemote {
	remote := VpcSecurityGroupRuleRemote{}
	switch remoteType := item.(type) {
	case *sdk.SecurityGroupRuleRemoteCIDR:
		remote.CIDRBlock = SafePointerString(remoteType.CIDRBlock)
	case *sdk.SecurityGroupRuleRemoteIP:
		remote.Address = SafePointerString(remoteType.Address)
	case *sdk.SecurityGroupRuleRemoteSecurityGroupReference:
		remote.ID = SafePointerString(remoteType.ID)
		remote.Name = SafePointerString(remoteType.Name)
	case *sdk.SecurityGroupRuleRemote:
		if remoteType.CIDRBlock != nil {
			remote.CIDRBlock = SafePointerString(remoteType.CIDRBlock)
		}
		if remoteType.Address != nil {
			remote.Address = SafePointerString(remoteType.Address)
		}
		if remoteType.ID != nil {
			remote.ID = SafePointerString(remoteType.ID)
		}
		if remoteType.Name != nil {
			remote.Name = SafePointerString(remoteType.Name)
		}
	}
	return remote
}

// mapSecurityGroupTarget - map the SecurityGroupTargetReference to generic format
func (v *VpcSdkGen2) mapSecurityGroupTarget(item sdk.SecurityGroupTargetReferenceIntf) *VpcSecurityGroupTarget {
	return &VpcSecurityGroupTarget{SdkObject: item}
}

// mapSubnet - map the Subnet to generic format
func (v *VpcSdkGen2) mapSubnet(item sdk.Subnet) *VpcSubnet {
	subnet := &VpcSubnet{
		SdkObject:                 item,
		AvailableIpv4AddressCount: SafePointerInt64(item.AvailableIpv4AddressCount),
		CreatedAt:                 SafePointerDate(item.CreatedAt),
		ID:                        SafePointerString(item.ID),
		IPVersion:                 SafePointerString(item.IPVersion),
		Ipv4CidrBlock:             SafePointerString(item.Ipv4CIDRBlock),
		Name:                      SafePointerString(item.Name),
		Status:                    SafePointerString(item.Status),
		TotalIpv4AddressCount:     SafePointerInt64(item.TotalIpv4AddressCount),
	}
	// NetworkACL
	if item.NetworkACL != nil {
		subnet.NetworkACL = VpcObjectReference{ID: SafePointerString(item.NetworkACL.ID), Name: SafePointerString(item.NetworkACL.Name)}
	}
	// PublicGateway
	if item.PublicGateway != nil {
		subnet.PublicGateway = VpcObjectReference{ID: SafePointerString(item.PublicGateway.ID), Name: SafePointerString(item.PublicGateway.Name)}
	}
	// Resource Group
	if item.ResourceGroup != nil {
		subnet.ResourceGroup = VpcObjectReference{ID: SafePointerString(item.ResourceGroup.ID), Name: SafePointerString(item.ResourceGroup.Name)}
	}
	// VPC
	if item.VPC != nil {
		subnet.Vpc = VpcObjectReference{ID: SafePointerString(item.VPC.ID), Name: SafePointerString(item.VPC.Name)}
	}
	// Zone
	if item.Zone != nil {
		subnet.Zone = SafePointerString(item.Zone.Name)
	}
	return subnet
}

// mapVpc - map the Vpc to generic format
func (v *VpcSdkGen2) mapVpc(item sdk.VPC) *Vpc {
	vpc := &Vpc{
		SdkObject:     item,
		ClassicAccess: SafePointerBool(item.ClassicAccess),
		CreatedAt:     SafePointerDate(item.CreatedAt),
		ID:            SafePointerString(item.ID),
		Name:          SafePointerString(item.Name),
		Status:        SafePointerString(item.Status),
	}
	// CseSourceIP
	for _, CseSourceIP := range item.CseSourceIps {
		cseString := ""
		if CseSourceIP.IP != nil {
			cseString += fmt.Sprintf("IP:%s ", SafePointerString(CseSourceIP.IP.Address))
		}
		if CseSourceIP.Zone != nil {
			cseString += fmt.Sprintf("Zone:%s", SafePointerString(CseSourceIP.Zone.Name))
		}
		vpc.CseSourceIPs = append(vpc.CseSourceIPs, cseString)
	}
	// DefaultNetworkACL
	if item.DefaultNetworkACL != nil {
		vpc.DefaultNetworkACL = VpcObjectReference{ID: SafePointerString(item.DefaultNetworkACL.ID), Name: SafePointerString(item.DefaultNetworkACL.Name)}
	}
	// DefaultSecurityGroup
	if item.DefaultSecurityGroup != nil {
		vpc.DefaultSecurityGroup = VpcObjectReference{ID: SafePointerString(item.DefaultSecurityGroup.ID), Name: SafePointerString(item.DefaultSecurityGroup.Name)}
	}
	// ResourceGroup
	if item.ResourceGroup != nil {
		vpc.ResourceGroup = VpcObjectReference{ID: SafePointerString(item.ResourceGroup.ID), Name: SafePointerString(item.ResourceGroup.Name)}
	}
	return vpc
}

// ReplaceLoadBalancerPoolMembers - update a load balancer pool members
func (v *VpcSdkGen2) ReplaceLoadBalancerPoolMembers(lbID, poolName, poolID string, nodeList []string, options *ServiceOptions) ([]*VpcLoadBalancerPoolMember, error) {
	// Extract values from poolName
	poolNameFields, err := extractFieldsFromPoolName(poolName)
	if err != nil {
		return nil, err
	}
	// Initialize the create options
	replaceOptions := &sdk.ReplaceLoadBalancerPoolMembersOptions{
		LoadBalancerID: core.StringPtr(lbID),
		PoolID:         core.StringPtr(poolID),
		Members:        v.genLoadBalancerMembers(poolNameFields.NodePort, nodeList, options),
	}
	// Update the VPC LB pool member
	if options.isNLB() {
		replaceOptions.Headers = map[string]string{"x-instance-account-id": v.Config.WorkerAccountID}
	}
	list, response, err := v.Client.ReplaceLoadBalancerPoolMembers(replaceOptions)
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	// Map the generated object back to the common format
	members := []*VpcLoadBalancerPoolMember{}
	for _, item := range list.Members {
		members = append(members, v.mapLoadBalancerPoolMember(item))
	}
	return members, nil
}

// UpdateLoadBalancer - update a load balancer
func (v *VpcSdkGen2) UpdateLoadBalancer(lbID string, updateList, nodeList, poolList []string, options *ServiceOptions) error {
	// Updates to the LB are handled by the other routines
	return nil
}

// UpdateLoadBalancerListener - update a load balancer listener
func (v *VpcSdkGen2) UpdateLoadBalancerListener(lbID, listenerID string, options *ServiceOptions) (*VpcLoadBalancerListener, error) {
	// Make sure that we are not attempting to update a NLB (this check should never trigger, NLB checked earlier)
	if options.isNLB() {
		return nil, fmt.Errorf("NLB does not support updating load balancer listeners")
	}
	// Initialize the LoadBalancerListenerPatch
	updateListener := &sdk.LoadBalancerListenerPatch{
		IdleConnectionTimeout: core.Int64Ptr(int64(options.getIdleConnectionTimeout())),
	}
	updatePatch, err := updateListener.AsPatch()
	if err != nil {
		return nil, err
	}
	// Initialize the UpdateLoadBalancerListenerOptions
	updateOptions := &sdk.UpdateLoadBalancerListenerOptions{
		LoadBalancerID:            core.StringPtr(lbID),
		ID:                        core.StringPtr(listenerID),
		LoadBalancerListenerPatch: updatePatch,
	}
	// Update the VPC LB listener
	listener, response, err := v.Client.UpdateLoadBalancerListener(updateOptions)
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}

	// Map the generated object back to the common format
	return v.mapLoadBalancerListener(*listener), nil
}

// UpdateLoadBalancerPool - update a load balancer pool
func (v *VpcSdkGen2) UpdateLoadBalancerPool(lbID, newPoolName string, existingPool *VpcLoadBalancerPool, options *ServiceOptions) (*VpcLoadBalancerPool, error) {
	// Extract values from poolName
	poolNameFields, err := extractFieldsFromPoolName(newPoolName)
	if err != nil {
		return nil, err
	}
	proxyProtocolRequested := options.isProxyProtocol()
	proxyProtocolSupported := !options.isNLB()
	// LoadBalancerOptionLeastConnections is not currently supported
	// See issue: https://github.ibm.com/alchemy-containers/armada-network/issues/3503
	//
	// algorithm := sdk.LoadBalancerPoolPatchAlgorithmRoundRobinConst
	// if isVpcOptionEnabled(options, LoadBalancerOptionLeastConnections) {
	// 	algorithm = sdk.LoadBalancerPoolPatchAlgorithmLeastConnectionsConst
	// }
	//
	// Initialize the LoadBalancerPoolPatch. Set those options that can be updated
	updatePool := &sdk.LoadBalancerPoolPatch{
		// Algorithm:  core.StringPtr(algorithm),
		HealthMonitor: v.genLoadBalancerHealthMonitorUpdate(poolNameFields, options),
	}
	// Only update the pool name if it has changed
	if newPoolName != existingPool.Name {
		updatePool.Name = core.StringPtr(newPoolName)
	}
	// Only update the proxy-protocol value if VPC supports it -AND- the value has changed
	if proxyProtocolSupported {
		if proxyProtocolRequested && existingPool.ProxyProtocol != sdk.LoadBalancerPoolProxyProtocolV1Const {
			updatePool.ProxyProtocol = core.StringPtr(sdk.LoadBalancerPoolProxyProtocolV1Const)
		}
		if !proxyProtocolRequested && existingPool.ProxyProtocol != sdk.LoadBalancerPoolProxyProtocolDisabledConst {
			updatePool.ProxyProtocol = core.StringPtr(sdk.LoadBalancerPoolProxyProtocolDisabledConst)
		}
	}
	updatePatch, err := updatePool.AsPatch()
	if err != nil {
		return nil, err
	}
	// LoadBalancerOptionSessionAffinity is not currently supported
	// See issue: https://github.ibm.com/alchemy-containers/armada-network/issues/3470
	//
	// Session affinity must be set after the updatePatch is created so that "nil" can be used to un-set the session affinity
	// if isVpcOptionEnabled(options, LoadBalancerOptionSessionAffinity) {
	// 	updatePatch["session_persistence"] = map[string]string{"type": sdk.LoadBalancerPoolSessionPersistencePatchTypeSourceIPConst}
	// } else {
	// 	updatePatch["session_persistence"] = nil
	// }
	//
	// Initialize the update pool options
	updateOptions := &sdk.UpdateLoadBalancerPoolOptions{
		LoadBalancerID:        core.StringPtr(lbID),
		ID:                    core.StringPtr(existingPool.ID),
		LoadBalancerPoolPatch: updatePatch,
	}
	// Update the VPC LB pool
	pool, response, err := v.Client.UpdateLoadBalancerPool(updateOptions)
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}

	// Map the generated object back to the common format
	return v.mapLoadBalancerPool(*pool), nil
}

// UpdateLoadBalancerSubnets - update a load balancer subnets
func (v *VpcSdkGen2) UpdateLoadBalancerSubnets(lbID string, subnetList []string, options *ServiceOptions) (*VpcLoadBalancer, error) {
	// We need to determine the "Etag" for the load balancer resource because this is required on the update
	// Retrieve the individual load balacner and extract the "Etag" from the headers
	_, response, err := v.Client.GetLoadBalancer(&sdk.GetLoadBalancerOptions{ID: &lbID})
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	eTag := response.Headers.Get("Etag")
	if eTag == "" {
		return nil, fmt.Errorf("Unable to determine ETag for the load balancer resource")
	}
	// Convert the list of subnet IDs over to the correct VPC subnet identity array
	subnetIds := []sdk.SubnetIdentityIntf{}
	for _, subnet := range subnetList {
		subnetIds = append(subnetIds, &sdk.SubnetIdentity{ID: core.StringPtr(subnet)})
	}
	// Initialize the subnets in the LoadBalancerPatch.  We are not patching any of the other fields
	updateSubnets := &sdk.LoadBalancerPatch{
		Subnets: subnetIds,
	}
	// Create the patch
	updatePatch, err := updateSubnets.AsPatch()
	if err != nil {
		return nil, err
	}
	// Initialize the update options
	updateOptions := &sdk.UpdateLoadBalancerOptions{
		IfMatch:           core.StringPtr(eTag),
		ID:                core.StringPtr(lbID),
		LoadBalancerPatch: updatePatch,
	}
	// Finally, update the load balancer
	lb, response, err := v.Client.UpdateLoadBalancer(updateOptions)
	if err != nil {
		v.logResponseError(response)
		return nil, err
	}
	return v.mapLoadBalancer(*lb), nil
}
