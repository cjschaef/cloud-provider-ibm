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
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"cloud.ibm.com/cloud-provider-ibm/pkg/klog"
	v1 "k8s.io/api/core/v1"
)

const (
	actionCreateListener     = "CREATE-LISTENER"
	actionCreatePool         = "CREATE-POOL"
	actionCreatePoolMember   = "CREATE-POOL-MEMBER"
	actionDeleteListener     = "DELETE-LISTENER"
	actionDeletePool         = "DELETE-POOL"
	actionDeletePoolMember   = "DELETE-POOL-MEMBER"
	actionReplacePoolMembers = "REPLACE-POOL-MEMBERS"
	actionUpdateListener     = "UPDATE-LISTENER"
	actionUpdatePool         = "UPDATE-POOL"
	actionUpdateSubnets      = "UPDATE-SUBNETS"

	poolToBeDeleted = "POOL-TO-BE-DELETED"
)

// checkForMultiplePoolMemberUpdates - replace multiple CREATE-POOL-MEMBER / DELETE-POOL-MEMBER actions with a single REPLACE-POOL-MEMBERS
//
// Each time that a CREATE-POOL-MEMBER or DELETE-POOL-MEMBER operation needs to be done against an existing LB it takes 30 seconds.
// If there are multiple of these operations queued up for a given LB pool, it is more efficient to do a single REPLACE-POOL-MEMBERS.
// In the general case, nodes being added/removed from the cluster, the scenario of multiple create/delete operations on a single pool
// will not occur that often. The case in which multiple create/delete pool members will most occur is when the service annotations are
// updated on the LB such that the pool members needs to get adjusted.
//
// Example: 9 node cluster, spread across 3 zones (A, B, and C), with 3 nodes in each zone. The service is updated with the "zone" annotation
// which states only Zone-A should be allowed. The 6 pool members in the other zones need to be deleted from the pool. The 6 delete
// operations (30 sec/each) would take roughly 3 minutes. A single REPLACE-POOL-MEMBERS would only take 30 seconds.
func (c *CloudVpc) checkForMultiplePoolMemberUpdates(updatesRequired []string) []string {
	// Determine how many pool member updates are being done to each of the load balancer pools
	poolUpdates := map[string]int{}
	for _, update := range updatesRequired {
		updateArgs := strings.Fields(update)
		cmd := updateArgs[0]
		poolName := updateArgs[1]
		if cmd == actionCreatePoolMember || cmd == actionDeletePoolMember {
			poolUpdates[poolName]++
		}
	}

	// Check to see if there are any pools with multiple pool member updates needed
	filterNeeded := false
	for _, count := range poolUpdates {
		if count > 1 {
			filterNeeded = true
		}
	}
	// No filtering needs to be done.  Return original list
	if !filterNeeded {
		return updatesRequired
	}

	// We need to regenerate the updatesRequired array and replace the first pool member update with
	// an REPLACE-POOL-MEMBERS and then delete the rest of the pool member updates for that specific pool.
	// All other update operations for the LB need to be kept.
	filteredUpdates := []string{}
	for _, update := range updatesRequired {
		updateArgs := strings.Fields(update)
		cmd := updateArgs[0]
		if cmd != actionCreatePoolMember && cmd != actionDeletePoolMember {
			// Keep all non-pool member update operations
			filteredUpdates = append(filteredUpdates, update)
			continue
		}
		poolName := updateArgs[1]
		poolID := updateArgs[2]
		switch {
		case poolUpdates[poolName] == 1:
			// If this is the only pool member update to this pool, then there is no need to change the update
			filteredUpdates = append(filteredUpdates, update)
		case poolUpdates[poolName] > 1:
			// If there are multiple pool member updates to this pool and this is the first one that we have found,
			// replace this update with an REPLACE-POOL-MEMBERS and set the count to 0 so that all other pool member
			// updates for this pool will be ignored.
			filteredUpdates = append(filteredUpdates, fmt.Sprintf("%s %s %s", actionReplacePoolMembers, poolName, poolID))
			poolUpdates[poolName] = 0
		}
	}
	return filteredUpdates
}

// checkListenersForExtPortAddedToService - check to see if we have existing listener for the specified Kube service
func (c *CloudVpc) checkListenersForExtPortAddedToService(updatesRequired []string, listeners []*VpcLoadBalancerListener, servicePort v1.ServicePort, servicePortRange string) []string {
	for _, listener := range listeners {
		// If this listener was marked for deletion, ignore the ports it was using
		if listener.DefaultPool.Name == poolToBeDeleted {
			continue
		}
		if c.isServicePortEqualListener(servicePort, servicePortRange, listener) {
			// Found an existing listener for the external port, no additional update needed
			return updatesRequired
		}
	}
	// Listener for this service port was not found. Create the listener
	poolName := genLoadBalancerPoolName(servicePort, servicePortRange)
	updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s", actionCreateListener, poolName))
	return updatesRequired
}

// checkListenerForExtPortDeletedFromService - check if there is a Kube service for the specified listener
func (c *CloudVpc) checkListenerForExtPortDeletedFromService(updatesRequired []string, listener *VpcLoadBalancerListener, ports []v1.ServicePort, servicePortRange string) []string {
	// If the listener pool was marked for deletion, don't bother checking anything
	if listener.DefaultPool.Name == poolToBeDeleted {
		return updatesRequired
	}
	// Search for a matching port
	for _, kubePort := range ports {
		if c.isServicePortEqualListener(kubePort, servicePortRange, listener) {
			// A service was found for the listener.  No updated needed.
			return updatesRequired
		}
	}
	// Make sure "" is not passed as the pool name
	poolName := listener.DefaultPool.Name
	if poolName == "" {
		poolName = "unknown"
	}
	// Port for this listener must have been deleted. Delete the listener
	updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s", actionDeleteListener, poolName, listener.ID))
	return updatesRequired
}

// checkPoolsForExtPortAddedToService - check to see if we have existing pool for the specified Kube service
func (c *CloudVpc) checkPoolsForExtPortAddedToService(updatesRequired []string, pools []*VpcLoadBalancerPool, servicePort v1.ServicePort, servicePortRange string) ([]string, error) {
	poolName := genLoadBalancerPoolName(servicePort, servicePortRange)
	for _, pool := range pools {
		if pool.Name == poolName {
			// Found an existing pool for the pool name, no additional update needed
			return updatesRequired, nil
		}
		// If the pool was marked for deletion, move on to the next one
		if pool.Name == poolToBeDeleted {
			continue
		}
		poolNameFields, err := extractFieldsFromPoolName(pool.Name)
		if err != nil {
			return updatesRequired, err
		}
		// If we already have a pool for the external port, no need to create a new pool
		if c.isServicePortEqualPoolName(servicePort, servicePortRange, poolNameFields) {
			return updatesRequired, nil
		}
	}
	updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s", actionCreatePool, poolName))
	return updatesRequired, nil
}

// checkPoolForExtPortDeletedFromService - check to see if we have a Kube service for the specific pool
func (c *CloudVpc) checkPoolForExtPortDeletedFromService(updatesRequired []string, pool *VpcLoadBalancerPool, ports []v1.ServicePort, servicePortRange string) ([]string, error) {
	// If the pool was marked for deletion, don't bother checking anything else
	if pool.Name == poolToBeDeleted {
		return updatesRequired, nil
	}
	// Search through the service ports to find a matching external port
	poolNameFields, err := extractFieldsFromPoolName(pool.Name)
	if err != nil {
		return updatesRequired, err
	}
	for _, kubePort := range ports {
		if c.isServicePortEqualPoolName(kubePort, servicePortRange, poolNameFields) {
			// Found a service for the pool, no additional update needed
			return updatesRequired, nil
		}
	}
	// Update the pool name indicating that it is being deleted.  This will prevent pool members from being created/deleted
	updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s", actionDeletePool, pool.Name, pool.ID))
	pool.Name = poolToBeDeleted

	// External port for this pool must have been deleted. Delete the pool
	return updatesRequired, nil
}

// checkPoolForNodesToAdd - check to see if any of the existing members of a VPC pool need to be deleted
func (c *CloudVpc) checkPoolForNodesToAdd(updatesRequired []string, pool *VpcLoadBalancerPool, ports []v1.ServicePort, nodeList []string, useInstanceID bool, servicePortRange string) ([]string, error) {
	// If the pool was marked for deletion, don't bother checking the members
	if pool.Name == poolToBeDeleted {
		return updatesRequired, nil
	}
	// Extract the fields from the pool name
	poolNameFields, err := extractFieldsFromPoolName(pool.Name)
	if err != nil {
		return updatesRequired, err
	}
	// Make sure that the node port of the pool is correct, i.e. generated poolName for Kube service must match actual pool name
	for _, kubePort := range ports {
		if c.isServicePortEqualPoolName(kubePort, servicePortRange, poolNameFields) {
			// Found the correct kube service
			if poolNameFields.NodePort != int(kubePort.NodePort) {
				// Node port for the pool has changed.  All members (nodes) will be refreshed
				return updatesRequired, nil
			}
		}
	}
	// Verify that we have a pool member for each of the nodes AND the node port in the member is correct
	for _, nodeID := range nodeList {
		foundMember := false
		for _, member := range pool.Members {
			memberTarget := member.TargetIPAddress
			if useInstanceID {
				memberTarget = member.TargetInstanceID
			}
			if nodeID == memberTarget && poolNameFields.NodePort == int(member.Port) {
				// There is a pool member for this node.  Move on to the next node
				foundMember = true
				break
			}
		}
		// If we failed to find member for the node, then we need to create one
		if !foundMember {
			updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s %s", actionCreatePoolMember, pool.Name, pool.ID, nodeID))
		}
	}
	return updatesRequired, nil
}

// checkPoolForNodesToDelete - check to see if any of the existing members of a VPC pool need to be deleted
func (c *CloudVpc) checkPoolForNodesToDelete(updatesRequired []string, pool *VpcLoadBalancerPool, ports []v1.ServicePort, nodeList []string, useInstanceID bool, servicePortRange string) ([]string, error) {
	// If the pool was marked for deletion, don't bother checking the members
	if pool.Name == poolToBeDeleted {
		return updatesRequired, nil
	}
	// Extract the fields from the pool name
	poolNameFields, err := extractFieldsFromPoolName(pool.Name)
	if err != nil {
		return updatesRequired, err
	}
	// Make sure that the node port of the pool is correct, i.e. generated poolName for Kube service must match actual pool name
	for _, kubePort := range ports {
		if c.isServicePortEqualPoolName(kubePort, servicePortRange, poolNameFields) {
			// Found the correct kube service port for the specified pool
			if poolNameFields.NodePort != int(kubePort.NodePort) {
				// Node port for the pool has changed.
				// All members (nodes) will be refreshed by a REPLACE-POOL-MEMBERS update when checkPoolForServiceChanges() runs
				return updatesRequired, nil
			}
		}
	}
	// Verify that each pool member refers to a node AND the node port in the member is correct
	nodeString := " " + strings.Join(nodeList, " ") + " "
	for _, member := range pool.Members {
		memberTarget := member.TargetIPAddress
		if useInstanceID {
			memberTarget = member.TargetInstanceID
		}
		if !strings.Contains(nodeString, " "+memberTarget+" ") || poolNameFields.NodePort != int(member.Port) {
			updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s %s %s", actionDeletePoolMember, pool.Name, pool.ID, member.ID, memberTarget))
		}
	}
	return updatesRequired, nil
}

// checkListenerForServiceChanges - check to see if updates are needed to existing listener
func (c *CloudVpc) checkListenerForServiceChanges(updatesRequired []string, listener *VpcLoadBalancerListener, options *ServiceOptions) []string {
	// If the listener pool was marked for deletion, don't bother checking anything
	if listener.DefaultPool.Name == poolToBeDeleted {
		return updatesRequired
	}
	// Verify that the idle connection timeout in the service matches the listener
	if options.isALB() && options.getIdleConnectionTimeout() != int(listener.IdleConnTimeout) {
		idleTimeout := fmt.Sprintf("idle:%d-->%d", listener.IdleConnTimeout, options.getIdleConnectionTimeout())
		updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s %s", actionUpdateListener, listener.DefaultPool.Name, listener.ID, idleTimeout))
	}
	return updatesRequired
}

// checkPoolForServiceChanges - check to see if updates are needed to an existing pool
func (c *CloudVpc) checkPoolForServiceChanges(updatesRequired []string, pool *VpcLoadBalancerPool, service *v1.Service, options *ServiceOptions, servicePortRange string) ([]string, error) {
	// If the pool was marked for deletion, don't bother checking to see if needs to get updated
	if pool.Name == poolToBeDeleted {
		return updatesRequired, nil
	}
	// Extract the fields from the pool name
	poolNameFields, err := extractFieldsFromPoolName(pool.Name)
	if err != nil {
		return updatesRequired, err
	}
	// Search through the service ports to find a matching external port
	for _, kubePort := range service.Spec.Ports {
		if !c.isServicePortEqualPoolName(kubePort, servicePortRange, poolNameFields) {
			// If this is not the correct Kube service port, move on to the next one
			continue
		}
		// LoadBalancerOptionLeastConnections / LoadBalancerOptionSessionAffinity are currently not supported
		// See issue: https://github.ibm.com/alchemy-containers/armada-network/issues/3470
		//
		// desiredPersistence := "None"
		// desiredScheduler := LoadBalancerAlgorithmRoundRobin
		// if isVpcOptionEnabled(options, LoadBalancerOptionLeastConnections) {
		// 	desiredScheduler = LoadBalancerAlgorithmLeastConnections
		// }
		// if isVpcOptionEnabled(options, LoadBalancerOptionSessionAffinity) {
		// 	desiredPersistence = LoadBalancerSessionPersistenceSourceIP
		// }
		poolName := genLoadBalancerPoolName(kubePort, servicePortRange)
		updatePool := false
		replacePoolMembers := false
		proxyProtocolRequested := options.isProxyProtocol()
		proxyProtocolSupported := !options.isNLB() && !options.isSdnlb()
		switch {
		case poolName != pool.Name:
			updatePool = true
			replacePoolMembers = true

		case options.getHealthCheckDelay() != int(pool.HealthMonitor.Delay):
			updatePool = true

		case options.getHealthCheckRetries() != int(pool.HealthMonitor.MaxRetries):
			updatePool = true

		case options.getHealthCheckTimeout() != int(pool.HealthMonitor.Timeout):
			updatePool = true

		case options.getHealthCheckProtocol() != "" && options.getHealthCheckProtocol() != pool.HealthMonitor.Type:
			updatePool = true

		case options.getHealthCheckProtocol() != "" && options.getHealthCheckPort() != 0 && options.getHealthCheckPort() != int(pool.HealthMonitor.Port):
			updatePool = true

		case (options.getHealthCheckProtocol() == "http" || options.getHealthCheckProtocol() == "https") && options.getHealthCheckPath() != pool.HealthMonitor.URLPath:
			updatePool = true

		case service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeCluster &&
			options.isUDP() && pool.HealthMonitor.Port != int64(options.healthCheckUDP):
			updatePool = true

		case proxyProtocolSupported && proxyProtocolRequested && pool.ProxyProtocol != LoadBalancerProxyProtocolV1:
			updatePool = true

		case proxyProtocolSupported && !proxyProtocolRequested && pool.ProxyProtocol != LoadBalancerProxyProtocolDisabled:
			updatePool = true

		case poolNameFields.isPortRange():
			// This is a port range pool. Don't bother checking the health check settings. We are never going to update the pool if those change
			updatePool = false

		// case pool.SessionPersistence != desiredPersistence:
		// 	updatePool = true

		// case pool.Algorithm != desiredScheduler:
		// 	updatePool = true

		case service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeLocal && service.Spec.HealthCheckNodePort > 0 &&
			(pool.HealthMonitor.Type != LoadBalancerProtocolHTTP || pool.HealthMonitor.Port != int64(service.Spec.HealthCheckNodePort)):
			updatePool = true

		case service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeCluster &&
			(pool.HealthMonitor.Type != LoadBalancerProtocolTCP || pool.HealthMonitor.Port != int64(kubePort.NodePort)):
			updatePool = true
		}

		if updatePool {
			updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s", actionUpdatePool, poolName, pool.ID))
		}
		if replacePoolMembers {
			updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s", actionReplacePoolMembers, poolName, pool.ID))
		}
		break
	}
	return updatesRequired, nil
}

// CreateLoadBalancer - create a VPC load balancer
func (c *CloudVpc) CreateLoadBalancer(lbName string, service *v1.Service, nodes []*v1.Node) (*VpcLoadBalancer, error) {
	if lbName == "" || service == nil || nodes == nil {
		return nil, fmt.Errorf("Required argument is missing")
	}

	// Validate the service tht was passed in and the options on that service
	options, err := c.validateService(service)
	if err != nil {
		return nil, err
	}
	// Validate the service if sdnlb annotation was specified
	err = c.validateServiceSdnlb(options)
	if err != nil {
		return nil, err
	}
	nlbCreate := options.isNLB()
	sdnlbCreate := options.isSdnlb()

	// Determine what VPC subnets associated with this account
	vpcSubnets, err := c.Sdk.ListSubnets()
	if err != nil {
		return nil, err
	}
	serviceName := c.getServiceName(service)

	// Determine what VPC subnets to associate with this load balancer
	subnetList, err := c.getSubnetsForLoadBalancer(service, vpcSubnets, options)
	if err != nil {
		return nil, err
	}
	klog.Infof("%s: subnets: %+v", serviceName, subnetList)

	// If we are creating a NLB, verify multiple subnets were not requested
	subnetZones := []string{}
	if nlbCreate {
		vpcSubnets = c.filterSubnetsBySubnetIDs(vpcSubnets, subnetList)
		subnetZones = c.getZonesContainingSubnets(vpcSubnets)
		klog.Infof("%s: subnet zones: %+v", serviceName, subnetZones)
		if len(subnetZones) > 1 && options.getServiceSubnets() != "" {
			return nil, fmt.Errorf("Annotation %s on service %s requested subnets in zones: %v, but only one zone is allowed with NLB",
				serviceAnnotationSubnets, c.getServiceName(service), subnetZones)
		}
	}

	// Filter node list by the service annotations (if specified) and node edge label (if set)
	filterLabel, filterValue, err := c.getServiceNodeSelectorFilter(service)
	if err != nil {
		return nil, err
	}
	if filterLabel != "" {
		nodes = c.findNodesMatchingLabelValue(nodes, filterLabel, filterValue)
	} else {
		nodes = c.filterNodesByZone(nodes, options.getServiceZone())
		nodes = c.filterNodesByEdgeLabel(nodes)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("There are no available nodes for this service")
	}

	// If we are creating a NLB, make sure that the subnets are only located in a single zone
	if nlbCreate {
		subnetList, err = c.selectSingleZoneForSubnet(serviceName, vpcSubnets, subnetZones, nodes)
		if err != nil {
			return nil, err
		}
	}
	// If we are creating a sDNLB, validate the worker nodes don't have 10.x.x.x
	if sdnlbCreate {
		err = c.validateNodesSdnlb(options, nodes)
		if err != nil {
			return nil, err
		}
	}

	// Determine the IP address or the VSI instance ID for each of the nodes
	existingNodes := []string{}
	nodeList, err := c.filterNodesByServiceMemberQuota(nodes, existingNodes, service, options)
	if err != nil {
		return nil, err
	}
	sort.Strings(nodeList)
	klog.Infof("%s: nodes: %v", serviceName, nodeList)

	// Determine what ports are associated with the service
	klog.Infof("%s: ports: %+v", serviceName, service.Spec.Ports)
	poolList, err := c.getServicePoolNames(service, options)
	if err != nil {
		return nil, err
	}
	klog.Infof("%s: pools: %+v", serviceName, poolList)

	// If this is an ALB, locate the security group to attach to the VPC ALB
	// This ALB security group attach logic is ignored if we are running in IPI mode
	if options.isALB() && !c.Config.ipiMode {
		listNames, err := c.GetSecurityGroupNamesForLBs()
		if err != nil {
			return nil, err
		}
		secGroup, err := c.FindSecurityGroup(listNames)
		if err != nil {
			return nil, err
		}
		if secGroup == nil {
			return nil, fmt.Errorf("Unable to find the security group to attach to the VPC ALB. Perform a Kubernetes master reset to recreate the missing security group")
		}
		c.Config.lbSecurityGroupID = secGroup.ID
	}

	// Create the load balancer
	lb, err := c.Sdk.CreateLoadBalancer(lbName, nodeList, poolList, subnetList, options)
	if err != nil {
		return nil, err
	}

	// New LB was created. Add the LB to the cache
	c.Config.addLbToCache(lb)

	// Update the cluster and LBaaS security group rules for this new LB service
	err = c.CreateSecurityGroupRulesForService(service)
	if err != nil {
		return nil, err
	}

	return lb, nil
}

// createLoadBalancerListener - create a VPC load balancer listener
func (c *CloudVpc) createLoadBalancerListener(lb *VpcLoadBalancer, poolName string, options *ServiceOptions) error {
	poolID := ""
	for _, pool := range lb.Pools {
		if poolName == pool.Name {
			poolID = pool.ID
			break
		}
	}
	if poolID == "" {
		return fmt.Errorf("Unable to create listener. Pool %s not found", poolName)
	}
	_, err := c.Sdk.CreateLoadBalancerListener(lb.ID, poolName, poolID, options)
	return err
}

// createLoadBalancerPool - create a VPC load balancer pool
func (c *CloudVpc) createLoadBalancerPool(lb *VpcLoadBalancer, poolName string, nodeList []string, options *ServiceOptions) error {
	_, err := c.Sdk.CreateLoadBalancerPool(lb.ID, poolName, nodeList, options)
	return err
}

// createLoadBalancerPoolMember - create a VPC load balancer pool member
func (c *CloudVpc) createLoadBalancerPoolMember(lb *VpcLoadBalancer, args string, options *ServiceOptions) error {
	argsArray := strings.Fields(args)
	if lb == nil || len(argsArray) != 3 {
		return fmt.Errorf("Required argument is missing")
	}
	poolName := argsArray[0]
	poolID := argsArray[1]
	nodeID := argsArray[2]
	_, err := c.Sdk.CreateLoadBalancerPoolMember(lb.ID, poolName, poolID, nodeID, options)
	return err
}

// DeleteLoadBalancer - delete a VPC load balancer
func (c *CloudVpc) DeleteLoadBalancer(lb *VpcLoadBalancer, service *v1.Service) error {
	if lb == nil {
		return fmt.Errorf("Required argument is missing")
	}
	// Update the cluster and LBaaS security group rules for this deleted LB service
	if service != nil {
		err := c.DeleteSecurityGroupRulesForService(service)
		if err != nil {
			return err
		}
	}
	// Delete the VPC LB
	err := c.Sdk.DeleteLoadBalancer(lb.ID, c.getServiceOptions(service))

	// Since delete has been called, remove the LB from the cache (if it exists)
	c.Config.removeLbFromCache(lb)
	return err
}

// deleteLoadBalancerListener - delete a VPC load balancer listener
func (c *CloudVpc) deleteLoadBalancerListener(lb *VpcLoadBalancer, args string) error {
	argsArray := strings.Fields(args)
	if lb == nil || len(argsArray) != 2 {
		return fmt.Errorf("Required argument is missing")
	}
	// poolName := argsArray[0]
	listenerID := argsArray[1]
	return c.Sdk.DeleteLoadBalancerListener(lb.ID, listenerID)
}

// deleteLoadBalancerPool - delete a VPC load balancer pool
func (c *CloudVpc) deleteLoadBalancerPool(lb *VpcLoadBalancer, args string) error {
	argsArray := strings.Fields(args)
	if lb == nil || len(argsArray) != 2 {
		return fmt.Errorf("Required argument is missing")
	}
	// poolName := argsArray[0]
	poolID := argsArray[1]
	return c.Sdk.DeleteLoadBalancerPool(lb.ID, poolID)
}

// deleteLoadBalancerPoolMember - delete a VPC load balancer pool member
func (c *CloudVpc) deleteLoadBalancerPoolMember(lb *VpcLoadBalancer, args string) error {
	argsArray := strings.Fields(args)
	if lb == nil || len(argsArray) != 4 {
		return fmt.Errorf("Required argument is missing")
	}
	// poolName := argsArray[0]
	poolID := argsArray[1]
	memberID := argsArray[2]
	// nodeID := argsArray[3]
	return c.Sdk.DeleteLoadBalancerPoolMember(lb.ID, poolID, memberID)
}

// FindLoadBalancer - locate a VPC load balancer based on the Name, ID, or hostname
func (c *CloudVpc) FindLoadBalancer(nameID string, service *v1.Service) (*VpcLoadBalancer, error) {
	if nameID == "" {
		return nil, fmt.Errorf("Required argument is missing")
	}
	id := c.Config.searchCacheForLb(nameID)
	if id != "" {
		lb, err := c.Sdk.GetLoadBalancer(id)
		if lb != nil && err == nil && lb.Name == nameID {
			return lb, nil
		}
		// Failed to retrieve LB from the cached ID. Remove the id from the cache
		c.Config.removeLbNameFromCache(nameID)
	}
	return c.Sdk.FindLoadBalancer(nameID, c.getServiceOptions(service))
}

// getLoadBalancersInCluster - locate all of the VPC load balancers in the current cluster
func (c *CloudVpc) getLoadBalancersInCluster() ([]*VpcLoadBalancer, error) {
	lbs, err := c.Sdk.ListLoadBalancers()
	if err != nil {
		return nil, err
	}
	clusterLbs := []*VpcLoadBalancer{}
	prefix := VpcLbNamePrefix + "-" + c.Config.ClusterID
	for _, lb := range lbs {
		if strings.HasPrefix(lb.Name, prefix) {
			clusterLbs = append(clusterLbs, lb)
		}
	}
	// Return list of lbs in the current cluster
	return clusterLbs, nil
}

// GetLoadBalancerStatus returns the load balancer status for a given VPC host name
func (c *CloudVpc) GetLoadBalancerStatus(service *v1.Service, lb *VpcLoadBalancer) *v1.LoadBalancerStatus {
	lbStatus := &v1.LoadBalancerStatus{}
	hostname := lb.Hostname
	if hostname == "" {
		for _, ipArrayItem := range lb.PrivateIps {
			ipArrayItem = strings.TrimSpace(ipArrayItem)
			ingressObject := v1.LoadBalancerIngress{IP: ipArrayItem}
			lbStatus.Ingress = append(lbStatus.Ingress, ingressObject)
		}
		return lbStatus
	}
	lbStatus.Ingress = []v1.LoadBalancerIngress{{Hostname: hostname}}
	options := c.getServiceOptions(service)
	if options.isNLB() {
		// If the hostname and static IP address are already stored in the service, then don't
		// repeat the overhead of the DNS hostname resolution again
		if service.Status.LoadBalancer.Ingress != nil &&
			len(service.Status.LoadBalancer.Ingress) == 1 &&
			service.Status.LoadBalancer.Ingress[0].Hostname == hostname &&
			service.Status.LoadBalancer.Ingress[0].IP != "" {
			lbStatus.Ingress[0].IP = service.Status.LoadBalancer.Ingress[0].IP
		} else {
			ipAddrs, err := net.LookupIP(hostname)
			if err == nil && len(ipAddrs) > 0 {
				lbStatus.Ingress[0].IP = ipAddrs[0].String()
			}
		}
	}
	return lbStatus
}

// processUpdate - perform the given update operation
func (c *CloudVpc) processUpdate(lb *VpcLoadBalancer, update string, index, total int, nodeList, subnetList []string, pools []*VpcLoadBalancerPool, options *ServiceOptions) error {
	// Process the current update
	var err error
	klog.Infof("%s: processing update [%d of %d]: %s", options.getServiceName(), index+1, total, update)
	action := strings.Fields(update)[0]
	args := strings.TrimSpace(strings.TrimPrefix(update, action))
	switch action {
	case actionCreateListener:
		err = c.createLoadBalancerListener(lb, args, options)
	case actionCreatePool:
		err = c.createLoadBalancerPool(lb, args, nodeList, options)
	case actionCreatePoolMember:
		err = c.createLoadBalancerPoolMember(lb, args, options)
	case actionDeleteListener:
		err = c.deleteLoadBalancerListener(lb, args)
	case actionDeletePool:
		err = c.deleteLoadBalancerPool(lb, args)
	case actionDeletePoolMember:
		err = c.deleteLoadBalancerPoolMember(lb, args)
	case actionReplacePoolMembers:
		err = c.replaceLoadBalancerPoolMembers(lb, args, nodeList, options)
	case actionUpdateListener:
		err = c.updateLoadBalancerListener(lb, args, options)
	case actionUpdatePool:
		err = c.updateLoadBalancerPool(lb, args, pools, options)
	case actionUpdateSubnets:
		err = c.updateLoadBalancerSubnets(lb, subnetList, options)
	default:
		err = fmt.Errorf("Unsupported update operation: %s", update)
	}
	return err
}

// replaceLoadBalancerPoolMembers - replace the load balancer pool members
func (c *CloudVpc) replaceLoadBalancerPoolMembers(lb *VpcLoadBalancer, args string, nodeList []string, options *ServiceOptions) error {
	argsArray := strings.Fields(args)
	if lb == nil || len(argsArray) != 2 {
		return fmt.Errorf("Required argument is missing")
	}
	poolName := argsArray[0]
	poolID := argsArray[1]
	_, err := c.Sdk.ReplaceLoadBalancerPoolMembers(lb.ID, poolName, poolID, nodeList, options)
	return err
}

// UpdateLoadBalancer - update a VPC load balancer
func (c *CloudVpc) UpdateLoadBalancer(lb *VpcLoadBalancer, service *v1.Service, nodes []*v1.Node) (*VpcLoadBalancer, error) {
	if service == nil || nodes == nil {
		return nil, fmt.Errorf("Required argument is missing")
	}

	// Validate the service tht was passed in and extract the advanced options requested
	options, err := c.validateService(service)
	if err != nil {
		return nil, err
	}
	err = c.validateServiceSdnlb(options)
	if err != nil {
		return nil, err
	}
	if lb == nil {
		return nil, fmt.Errorf("Load balancer not found")
	}
	nlbUpdate := options.isNLB()
	sdnlbUpdate := options.isSdnlb()
	serviceName := c.getServiceName(service)

	// If the service has been changed from public to private (or vice-versa)
	// If the service has been changed to a network load balancer (or vice versa)
	err = c.validateServiceTypeNotUpdated(options, lb)
	if err != nil {
		return nil, err
	}
	err = c.validateServiceSdnlbNotUpdated(options, lb)
	if err != nil {
		return nil, err
	}

	// Obtain mutex to serialize access to the updates for this LB
	mutex := vpcMapUpdateMutex[lb.ID]
	if mutex == nil {
		mutex = &sync.Mutex{}
		vpcMapUpdateMutex[lb.ID] = mutex
	}
	mutex.Lock()
	defer mutex.Unlock()

	// Check to see if async update is already in progress
	done := vpcMapAsyncUpdates[lb.ID]
	if done != nil {
		klog.Infof("%s: wait for the async updates to complete", serviceName)
		select {
		case <-done:
			klog.Infof("%s: async updates are complete", serviceName)
			delete(vpcMapAsyncUpdates, lb.ID)
			lb, err = c.Sdk.GetLoadBalancer(lb.ID)
			if err != nil {
				return nil, err
			}
		case <-time.After(time.Minute):
			klog.Infof("%s: async updates are still being processed", serviceName)
			lb.OperatingStatus = LoadBalancerOperatingStatusOnline
			lb.ProvisioningStatus = LoadBalancerProvisioningStatusUpdatePending
			return lb, fmt.Errorf("Updates are being performed, load balancer not ready")
		}
	}

	// Verify that the load balancer is in the correct state
	if !lb.IsReady() {
		return lb, fmt.Errorf("Update can not be performed, load balancer not ready: %v", lb.GetStatus())
	}

	// Retrieve list of all VPC subnets
	vpcSubnets, err := c.Sdk.ListSubnets()
	if err != nil {
		return nil, err
	}

	subnetList := []string{}
	// If the VPC subnets annotation on the service has been changed, detect this case and return error
	if nlbUpdate {
		err = c.validateServiceSubnetsNotUpdated(service, lb, vpcSubnets)
		if err != nil {
			return nil, err
		}
	} else if !sdnlbUpdate {
		// Check to see if the subnets of the VPC ALB need to be updated
		subnetList, err = c.getUpdatedSubnetsForForLoadBalancer(service, lb, vpcSubnets, options)
		if err != nil {
			return nil, err
		}
	}

	// Verify that there are nodes available to associate with this load balancer
	serviceZone := options.getServiceZone()
	filterLabel, filterValue, err := c.getServiceNodeSelectorFilter(service)
	if err != nil {
		return nil, err
	}
	if filterLabel != "" {
		nodes = c.findNodesMatchingLabelValue(nodes, filterLabel, filterValue)
	} else {
		nodes = c.filterNodesByZone(nodes, serviceZone)
		nodes = c.filterNodesByEdgeLabel(nodes)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("There are no available nodes for this load balancer")
	}

	// If this is a network load balancer, verify zone has not changed
	if nlbUpdate {
		// Verify that the zone was not changed
		lbZones := lb.getZones(vpcSubnets)
		err = c.validateServiceZoneNotUpdated(serviceZone, lbZones)
		if err != nil {
			return nil, err
		}
	}
	// If we are updated a sDNLB, validate the worker nodes don't have 10.x.x.x
	if sdnlbUpdate {
		err = c.validateNodesSdnlb(options, nodes)
		if err != nil {
			return nil, err
		}
	}

	// Retrieve list of listeners for the current load balancer
	listeners, err := c.Sdk.ListLoadBalancerListeners(lb.ID)
	if err != nil {
		return nil, err
	}

	// Retrieve list of pools for the current load balancer
	pools, err := c.Sdk.ListLoadBalancerPools(lb.ID)
	if err != nil {
		return nil, err
	}

	// Verify that we did not exceed quota for number of load balancer pool members
	existingNodes := []string{}
	if len(pools) > 0 {
		existingNodes = c.getPoolMemberTargets(pools[0].Members, options)
	}
	nodeList, err := c.filterNodesByServiceMemberQuota(nodes, existingNodes, service, options)
	if err != nil {
		return nil, err
	}
	sort.Strings(nodeList)
	klog.Infof("%s: nodes: %v", serviceName, nodeList)

	// Validate the port range annotation on the service (if it set)
	servicePortRange, err := c.validateServicePortRange(service, options)
	if err != nil {
		return nil, err
	}
	// Generate list of pool names for the service ports
	poolList := []string{}
	for _, kubePort := range service.Spec.Ports {
		poolList = append(poolList, genLoadBalancerPoolName(kubePort, servicePortRange))
	}

	// The following array is going to be used to keep track of ALL of the updates that need to be done
	// There will be 1 line of text for each update that needs to be done.
	// The first word will indicate what type of operation needs to be done
	// The rest of the line will contain all of the necessary options needed to perform that update (space separated)
	// The arguments for each operation will be different
	// Care must be taken to ensure that the arg string is consistently ordered/handle by both the caller and the called function
	// Update operations must be performed in a specific order.  Rules concerning the supported operations:
	//   0. Verify customer did not edit/corrupt the VPC LB pool names
	//   1. DELETE-LISTENER must be done before the pool can be cleaned up with DELETE-POOL
	//   2. CREATE-POOL must be done before the pool can be referenced by an CREATE-LISTENER
	//   3. CREATE-LISTENER can not be done for an external port that is being used by an existing listener
	//   4. Since any CREATE operations cause cause us to hit the account quota, all CREATE operations will be done last
	//   5. No need to CREATE-POOL-MEMBER or DELETE-POOL-MEMBER if the entire pool was tagged to be deleted by a DELETE-POOL
	//   6. UPDATE-POOL handles updating the health check settings on the pool and/or changing the name of pool (node port change)
	//   7. REPLACE-POOL-MEMBERS handles updating the node port of all the pool members
	//   8. The listener is never updated. The listener will always points to the same pool once it has been created
	//   9. The load balancer object is never updated or modified.  All update processing is done on the listeners, pools, and members
	updatesRequired := []string{}

	// Step 0: Verify that the VPC LB pool names were not corrupted by the customer
	updatesRequired = c.verifyVpcPoolNamesAreValid(updatesRequired, listeners, pools)

	// Step 1: Delete the VPC LB listener if the Kube service external port was deleted
	for _, listener := range listeners {
		updatesRequired = c.checkListenerForExtPortDeletedFromService(updatesRequired, listener, service.Spec.Ports, servicePortRange)
	}

	// Step 2: Delete the VPC LB pool if the Kube service external port was deleted
	for _, pool := range pools {
		updatesRequired, err = c.checkPoolForExtPortDeletedFromService(updatesRequired, pool, service.Spec.Ports, servicePortRange)
		if err != nil {
			return nil, err
		}
	}

	// Step 3: Delete VPC LB pool members for any nodes that are no longer in the cluster
	for _, pool := range pools {
		updatesRequired, err = c.checkPoolForNodesToDelete(updatesRequired, pool, service.Spec.Ports, nodeList, nlbUpdate || sdnlbUpdate, servicePortRange)
		if err != nil {
			return nil, err
		}
	}

	// Step 4.1: Update the existing listeners if the Kube service was changed - idle connection timeout annotation
	for _, listener := range listeners {
		updatesRequired = c.checkListenerForServiceChanges(updatesRequired, listener, options)
	}

	// Step 4.2: Update the existing pools and pool members if the Kube service node port was changed -OR- if the externalTrafficPolicy was changed
	for _, pool := range pools {
		updatesRequired, err = c.checkPoolForServiceChanges(updatesRequired, pool, service, options, servicePortRange)
		if err != nil {
			return nil, err
		}
	}

	// Step 5: Create new VPC LB pool members if new nodes were added to the cluster
	for _, pool := range pools {
		updatesRequired, err = c.checkPoolForNodesToAdd(updatesRequired, pool, service.Spec.Ports, nodeList, nlbUpdate || sdnlbUpdate, servicePortRange)
		if err != nil {
			return nil, err
		}
	}

	// Step 6: Create a new VPC LB pool if a new external port was added to the Kube service
	for _, servicePort := range service.Spec.Ports {
		updatesRequired, err = c.checkPoolsForExtPortAddedToService(updatesRequired, pools, servicePort, servicePortRange)
		if err != nil {
			return nil, err
		}

		// Step 7: Create a new VPC LB listener if a new external port was added to the Kube service
		updatesRequired = c.checkListenersForExtPortAddedToService(updatesRequired, listeners, servicePort, servicePortRange)
	}

	// Step 8: Check to see if VPC ALB subnets need to get updated
	if len(subnetList) > 0 {
		updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s", actionUpdateSubnets, strings.Join(subnetList, ",")))
	}

	// Update the cluster and LBaaS security group rules (if needed)
	err = c.UpdateSecurityGroupRulesForService(service)
	if err != nil {
		return nil, err
	}

	// If no updates are required, then return
	if len(updatesRequired) == 0 {
		klog.Infof("%s: no updates needed", serviceName)
		return lb, nil
	}

	// Display list of all required updates
	for i, update := range updatesRequired {
		klog.Infof("%s: updates required [%d]: %s", serviceName, i+1, update)
	}

	// Step 8: Replace multiple CREATE-POOL-MEMBER / DELETE-POOL-MEMBER actions with a single REPLACE-POOL-MEMBERS
	updateCount := len(updatesRequired)
	updatesRequired = c.checkForMultiplePoolMemberUpdates(updatesRequired)
	if updateCount > len(updatesRequired) {
		klog.Infof("%s: number of updates reduced from: %d to %d", serviceName, updateCount, len(updatesRequired))
	}

	// Inform the SDK layer that updates are coming
	err = c.Sdk.UpdateLoadBalancer(lb.ID, updatesRequired, nodeList, poolList, options)
	if err != nil {
		return nil, err
	}

	// Set min sleep and max wait times. Increase times for NLB
	maxWait := 2 * 60
	minSleep := 8
	if lb.IsNLB() {
		maxWait = 3 * 60
		minSleep = 14
	} else if lb.IsService {
		minSleep = 2
	}

	// Determine if updates should be handled asynchronously
	//  - if Go routines are allowed
	//  - if there is more than one LB associated with this cluster
	asyncUpdate := false
	if VpcGoRoutinesAllowed && len(c.Config.lbNameCache) > 1 {
		asyncUpdate = true
	}

	// Process all of the updates that are needed
	for i, update := range updatesRequired {
		// Get the updated load balancer object (if not first time through this loop)
		if i > 0 {
			lb, err = c.Sdk.GetLoadBalancer(lb.ID)
			if err != nil {
				return nil, err
			}
			// Wait for the LB to be "ready" before performing the actual update
			if !lb.IsReady() {
				// If async update is enabled, then create async GO routine for the rest of the updates
				if asyncUpdate {
					klog.Infof("%s: load balancer not ready: %s. Use async thread for the [%d] remaining updates", serviceName, lb.GetStatus(), len(updatesRequired)-i)
					go c.updateLoadBalancerAsync(lb, i, minSleep, nodeList, subnetList, updatesRequired, pools, options)
					return lb, fmt.Errorf("load balancer not ready: %s", lb.GetStatus())
				}
				lb, err = c.WaitLoadBalancerReady(lb, minSleep, maxWait, true)
				if err != nil {
					return nil, err
				}
			}
		}
		// Process the current update
		err = c.processUpdate(lb, update, i, len(updatesRequired), nodeList, subnetList, pools, options)
		if err != nil {
			return nil, err
		}
	}

	// Return the updated load balancer
	klog.Infof("%s: done with updates ", serviceName)
	return lb, nil
}

// updateLoadBalancerAsync - asynchronously finish making updates to a a VPC load balancer
func (c *CloudVpc) updateLoadBalancerAsync(lb *VpcLoadBalancer, index, minSleep int, nodeList, subnetList, updateList []string, pools []*VpcLoadBalancerPool, options *ServiceOptions) {
	// Initialize config so that subsequent update-LB attempts can see this update is still in progress
	serviceName := options.getServiceName()
	klog.Infof("%s: starting async updates", serviceName)
	done := make(chan string)
	vpcMapAsyncUpdates[lb.ID] = done
	defer close(done)

	// Add one more update to force a final get-lb/wait-lb to be done so that
	// and pending update-lb will not still see the online/update-pending state
	updateList = append(updateList, "Done with updates")

	// Process all of the updates that need to be done
	var err error
	for i, update := range updateList {
		// Skip over the updates that were already done
		if i < index {
			continue
		}
		// Wait for the LB to be "ready" before performing the actual update
		if !lb.IsReady() {
			lb, err = c.WaitLoadBalancerReady(lb, minSleep, 60*5, false) // Max wait of 5 min for the last operation to complete
			if err != nil {
				return
			}
		}
		// Check to see if we are done with updates
		if update == "Done with updates" {
			break
		}
		// Process the update
		err = c.processUpdate(lb, update, i, len(updateList)-1, nodeList, subnetList, pools, options)
		if err != nil {
			return
		}
		// Check the status of the LB
		lb, err = c.Sdk.GetLoadBalancer(lb.ID)
		if err != nil {
			return
		}
	}
	// Return the updated load balancer
	klog.Infof("%s: done with async updates", serviceName)
}

// updateLoadBalancerListener - update a VPC load balancer listener
func (c *CloudVpc) updateLoadBalancerListener(lb *VpcLoadBalancer, args string, options *ServiceOptions) error {
	argsArray := strings.Fields(args)
	if lb == nil || len(argsArray) != 3 {
		return fmt.Errorf("Required argument is missing")
	}
	// poolName := argsArray[0] - only included so that it shows up in the logs
	listenerID := argsArray[1]
	// timeout := argsArray[2] - only included so that it shows up in the logs
	_, err := c.Sdk.UpdateLoadBalancerListener(lb.ID, listenerID, options)
	return err
}

// updateLoadBalancerPool - update a VPC load balancer pool
func (c *CloudVpc) updateLoadBalancerPool(lb *VpcLoadBalancer, args string, pools []*VpcLoadBalancerPool, options *ServiceOptions) error {
	argsArray := strings.Fields(args)
	if lb == nil || len(argsArray) != 2 {
		return fmt.Errorf("Required argument is missing")
	}
	poolName := argsArray[0]
	poolID := argsArray[1]
	var existingPool *VpcLoadBalancerPool
	for _, pool := range pools {
		if pool.ID == poolID {
			existingPool = pool
			break
		}
	}
	if existingPool == nil {
		return fmt.Errorf("Existing pool nof found for pool ID: %s", poolID)
	}
	_, err := c.Sdk.UpdateLoadBalancerPool(lb.ID, poolName, existingPool, options)
	return err
}

// updateLoadBalancerSubnets - update the subnets associated with VPC ALB
func (c *CloudVpc) updateLoadBalancerSubnets(lb *VpcLoadBalancer, subnetList []string, options *ServiceOptions) error {
	_, err := c.Sdk.UpdateLoadBalancerSubnets(lb.ID, subnetList, options)
	return err
}

// verifyVpcListenerDefaultPoolName - verify that the VPC listener's default pool name is correct
func (c *CloudVpc) verifyVpcPoolNamesAreValid(updatesRequired []string, listeners []*VpcLoadBalancerListener, pools []*VpcLoadBalancerPool) []string {
	// Check each of the VPC listeners on this VPC load balancer
	for _, listener := range listeners {
		// Verify we don't have "" for the listener's default pool name
		poolName := listener.DefaultPool.Name
		if poolName == "" {
			updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s", actionDeleteListener, "unknown", listener.ID))
			listener.DefaultPool.Name = poolToBeDeleted
			continue
		}
		// Verify that the listeners default pool name is correctly formatted
		poolNameFields, err := extractFieldsFromPoolName(poolName)
		if err != nil {
			updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s", actionDeleteListener, poolName, listener.ID))
			listener.DefaultPool.Name = poolToBeDeleted
			continue
		}
		// Verify that the listener protocol and port(s) are correct in the pool name
		if listener.Protocol != poolNameFields.Protocol || listener.PortMin != int64(poolNameFields.PortMin) || listener.PortMax != int64(poolNameFields.PortMax) {
			updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s", actionDeleteListener, poolName, listener.ID))
			listener.DefaultPool.Name = poolToBeDeleted
			// Locate the associated pool and delete it as well.
			for _, pool := range pools {
				if poolName == pool.Name {
					updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s", actionDeletePool, pool.Name, pool.ID))
					pool.Name = poolToBeDeleted
					break
				}
			}
		}
	}
	// Check each of the VPC pools on this VPC load balancer
	for _, pool := range pools {
		// If the pool was marked for deletion, don't bother checking anything else
		if pool.Name == poolToBeDeleted {
			continue
		}
		// Check to see if the pool name was corrupted (will only be true if there is no listener for this pool)
		poolNameFields, err := extractFieldsFromPoolName(pool.Name)
		if err != nil {
			updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s", actionDeletePool, pool.Name, pool.ID))
			pool.Name = poolToBeDeleted
			continue
		}
		// Verify that the protocol is the same in the pool and the pool name. External port and node port will be checked later
		if pool.Protocol != poolNameFields.Protocol {
			updatesRequired = append(updatesRequired, fmt.Sprintf("%s %s %s", actionDeletePool, pool.Name, pool.ID))
			pool.Name = poolToBeDeleted
		}
	}
	// Return with the updates
	return updatesRequired
}

// WaitLoadBalancerReady will call the Get() operation on the load balancer every minSleep seconds until the state
// of the load balancer goes to Online/Active -OR- until the maxWait timeout occurs
func (c *CloudVpc) WaitLoadBalancerReady(lb *VpcLoadBalancer, minSleep, maxWait int, logStatus bool) (*VpcLoadBalancer, error) {
	// Wait for the load balancer to Online/Active
	var err error
	lbID := lb.ID
	startTime := time.Now()
	for i := 0; i < (maxWait / minSleep); i++ {
		if logStatus {
			suffix := ""
			if lb.ProvisioningStatus == LoadBalancerProvisioningStatusCreatePending {
				suffix = fmt.Sprintf(" Public:%s Private:%s", strings.Join(lb.PublicIps, ","), strings.Join(lb.PrivateIps, ","))
			}
			klog.Infof(" %3d) %9s %s%s", i+1, time.Since(startTime).Round(time.Millisecond), lb.GetStatus(), suffix)
		}
		if lb.IsReady() {
			return lb, nil
		}
		if time.Since(startTime).Seconds() > float64(maxWait) {
			break
		}
		time.Sleep(time.Second * time.Duration(minSleep))
		lb, err = c.Sdk.GetLoadBalancer(lbID)
		if err != nil {
			klog.Errorf("Failed to get load balancer %v: %v", lbID, err)
			return nil, err
		}
	}
	// If LB is actually ready, don't return error that it is not
	if lb.IsReady() {
		return lb, nil
	}
	return lb, fmt.Errorf("load balancer not ready: %s", lb.GetStatus())
}
