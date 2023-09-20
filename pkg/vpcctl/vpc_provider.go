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
	"errors"
	"fmt"
	"sort"
	"strings"

	"cloud.ibm.com/cloud-provider-ibm/pkg/klog"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
)

const (
	creatingCloudLoadBalancerFailed  = "CreatingCloudLoadBalancerFailed"
	deletingCloudLoadBalancerFailed  = "DeletingCloudLoadBalancerFailed"
	gettingCloudLoadBalancerFailed   = "GettingCloudLoadBalancerFailed"
	updatingCloudLoadBalancerFailed  = "UpdatingCloudLoadBalancerFailed"
	verifyingCloudLoadBalancerFailed = "VerifyingCloudLoadBalancerFailed"

	vpcLbStatusOnlineActive              = LoadBalancerOperatingStatusOnline + "/" + LoadBalancerProvisioningStatusActive
	vpcLbStatusOfflineCreatePending      = LoadBalancerOperatingStatusOffline + "/" + LoadBalancerProvisioningStatusCreatePending
	vpcLbStatusOfflineMaintenancePending = LoadBalancerOperatingStatusOffline + "/" + LoadBalancerProvisioningStatusMaintenancePending
	vpcLbStatusOfflineFailed             = LoadBalancerOperatingStatusOffline + "/" + LoadBalancerProvisioningStatusFailed
	vpcLbStatusOfflineNotFound           = LoadBalancerOperatingStatusOffline + "/not_found"
)

// CloudVpc is the main VPC cloud provider implementation.
type CloudVpc struct {
	KubeClient kubernetes.Interface
	Config     *ConfigVpc
	Sdk        CloudVpcSdk
	Recorder   record.EventRecorder
}

// Global variables
var (
	// Persistent storage for CloudVpc object
	persistentCloudVpc *CloudVpc

	// VpcLbNamePrefix - Prefix to be used for VPC load balancer
	VpcLbNamePrefix = "kube"
)

// GetCloudVpc - Retrieve the global VPC cloud object.  Return nil if not initialized.
func GetCloudVpc() *CloudVpc {
	return persistentCloudVpc
}

// ResetCloudVpc - Reset the global VPC cloud object
func ResetCloudVpc() {
	persistentCloudVpc = nil
}

// SetCloudVpc - Set the global VPC cloud object.  Specify nil to clear value
func SetCloudVpc(vpc *CloudVpc) {
	persistentCloudVpc = vpc
}

func NewCloudVpc(kubeClient kubernetes.Interface, config *ConfigVpc, recorder record.EventRecorder) (*CloudVpc, error) {
	if config == nil {
		return nil, fmt.Errorf("Missing cloud configuration")
	}
	c := &CloudVpc{KubeClient: kubeClient, Config: config, Recorder: recorder}
	err := c.initialize()
	if err != nil {
		return nil, err
	}
	c.Sdk, err = NewCloudVpcSdk(c.Config)
	if err != nil {
		return nil, err
	}
	SetCloudVpc(c)
	return c, nil
}

// EnsureLoadBalancer - called by cloud provider to create/update the load balancer
func (c *CloudVpc) EnsureLoadBalancer(lbName string, service *v1.Service, nodes []*v1.Node) (*v1.LoadBalancerStatus, error) {
	// Check to see if the VPC load balancer exists
	lb, err := c.FindLoadBalancer(lbName, service)
	if err != nil {
		errString := fmt.Sprintf("Failed getting LoadBalancer: %v", err)
		klog.Errorf(errString)
		return nil, c.recordServiceWarningEvent(service, creatingCloudLoadBalancerFailed, lbName, errString)
	}

	// If the specified VPC load balancer was not found, create it
	if lb == nil {
		// Check to see if a VPC load balancer was already allocated for this service
		err = c.VerifyServiceStatusIsNull(service)
		if err != nil {
			errString := fmt.Sprintf("Failed verifying service: %v", err)
			klog.Errorf(errString)
			return nil, c.recordServiceWarningEvent(service, creatingCloudLoadBalancerFailed, lbName, errString)
		}
		lb, err = c.CreateLoadBalancer(lbName, service, nodes)
		if err != nil {
			errString := fmt.Sprintf("Failed ensuring LoadBalancer: %v", err)
			klog.Errorf(errString)
			return nil, c.recordServiceWarningEvent(service, creatingCloudLoadBalancerFailed, lbName, errString)
		}
		// Log basic stats about the load balancer and return success (if the LB is READY or not NLB)
		// - return SUCCESS for non-NLB to remain backward compatibility, no additional operations need to be done
		// - don't return SUCCESS for NLB, because we can't do the DNS lookup of static IP if the LB is still pending
		if lb.IsReady() || !lb.IsNLB() {
			klog.Infof(lb.GetSummary())
			klog.Infof("Load balancer %s for service %s has been created", lbName, c.getServiceName(service))
			return c.GetLoadBalancerStatus(service, lb), nil
		}
	}

	// Log basic stats about the load balancer
	klog.Infof(lb.GetSummary())

	// The load balancer state is Online/Active.  This means that additional operations can be done.
	// Update the existing LB with any service or node changes that may have occurred.
	lb, err = c.UpdateLoadBalancer(lb, service, nodes)
	if err != nil {
		// Check to see if the LB was not ready
		if lb != nil && !lb.IsReady() {
			errString := fmt.Sprintf("LoadBalancer is busy: %s", lb.GetStatus())
			klog.Warningf("LoadBalancer %s for service %s is busy: %s", lbName, c.getServiceName(service), lb.GetStatus())
			return nil, c.recordServiceWarningEvent(service, updatingCloudLoadBalancerFailed, lbName, errString)
		}
		errString := fmt.Sprintf("Failed ensuring LoadBalancer: %v", err)
		klog.Errorf(errString)
		return nil, c.recordServiceWarningEvent(service, updatingCloudLoadBalancerFailed, lbName, errString)
	}

	// Return success
	klog.Infof("Load balancer %s for service %s has been updated", lbName, c.getServiceName(service))
	return c.GetLoadBalancerStatus(service, lb), nil
}

// EnsureLoadBalancerDeleted - called by cloud provider to delete the load balancer
func (c *CloudVpc) EnsureLoadBalancerDeleted(lbName string, service *v1.Service) error {
	// Check to see if the VPC load balancer exists
	lb, err := c.FindLoadBalancer(lbName, service)
	if err != nil {
		errString := fmt.Sprintf("Failed getting LoadBalancer: %v", err)
		klog.Errorf(errString)
		return c.recordServiceWarningEvent(service, deletingCloudLoadBalancerFailed, lbName, errString)
	}

	// If the load balancer does not exist, return
	if lb == nil {
		klog.Infof("Load balancer %v not found", lbName)
		return nil
	}

	// Log basic stats about the load balancer
	klog.Infof(lb.GetSummary())

	// The load balancer state is Online/Active.  Attempt to delete the load balancer
	err = c.DeleteLoadBalancer(lb, service)
	if err != nil {
		errString := fmt.Sprintf("Failed deleting LoadBalancer: %v", err)
		klog.Errorf(errString)
		return c.recordServiceWarningEvent(service, deletingCloudLoadBalancerFailed, lbName, errString)
	}

	// Return success
	klog.Infof("Load balancer %s for service %s has been deleted", lbName, c.getServiceName(service))
	return nil
}

// EnsureLoadBalancerUpdated - updates the hosts under the specified load balancer
func (c *CloudVpc) EnsureLoadBalancerUpdated(lbName string, service *v1.Service, nodes []*v1.Node) error {
	// Check to see if the VPC load balancer exists
	lb, err := c.FindLoadBalancer(lbName, service)
	if err != nil {
		errString := fmt.Sprintf("Failed getting LoadBalancer: %v", err)
		klog.Errorf(errString)
		return c.recordServiceWarningEvent(service, updatingCloudLoadBalancerFailed, lbName, errString)
	}
	// Log basic stats about the load balancer
	if lb != nil {
		klog.Infof(lb.GetSummary())
	}

	// Update the existing LB with any service or node changes that may have occurred.
	lb, err = c.UpdateLoadBalancer(lb, service, nodes)
	if err != nil {
		// Check to see if the LB was not ready
		if lb != nil && !lb.IsReady() {
			errString := fmt.Sprintf("LoadBalancer is busy: %s", lb.GetStatus())
			klog.Warningf("LoadBalancer %s for service %s is busy: %s", lbName, c.getServiceName(service), lb.GetStatus())
			return c.recordServiceWarningEvent(service, updatingCloudLoadBalancerFailed, lbName, errString)
		}
		errString := fmt.Sprintf("Failed updating LoadBalancer: %v", err)
		klog.Errorf(errString)
		return c.recordServiceWarningEvent(service, updatingCloudLoadBalancerFailed, lbName, errString)
	}

	// Return success
	klog.Infof("Load balancer %s for service %s has been updated", lbName, c.getServiceName(service))
	return nil
}

// GatherLoadBalancers - returns status of all VPC load balancers associated with Kube LBs in this cluster
func (c *CloudVpc) GatherLoadBalancers(services *v1.ServiceList) (map[string]*v1.Service, map[string]*VpcLoadBalancer, error) {
	// Verify we were passed a list of Kube services
	if services == nil {
		klog.Errorf("Required argument is missing")
		return nil, nil, errors.New("Required argument is missing")
	}
	// Retrieve list of all load balancers
	lbs, err := c.Sdk.ListLoadBalancers()
	if err != nil {
		return nil, nil, err
	}

	// Create map of all VPC LBs
	vpcMap := map[string]*VpcLoadBalancer{}
	for _, lb := range lbs {
		lbPtr := lb
		vpcMap[lbPtr.Name] = lbPtr
	}

	// Create map of Kubernetes LB services
	lbMap := map[string]*v1.Service{}
	for _, service := range services.Items {
		// Keep track of all load balancer services.
		kubeService := service
		if kubeService.Spec.Type == v1.ServiceTypeLoadBalancer {
			lbName := c.GenerateLoadBalancerName(&kubeService)
			lbMap[lbName] = &kubeService
		}
	}

	// Return the LB and VPC maps to the caller
	return lbMap, vpcMap, nil
}

// GenerateLoadBalancerName - generate the VPC load balancer name from the cluster ID and Kube service
func (c *CloudVpc) GenerateLoadBalancerName(service *v1.Service) string {
	return GenerateLoadBalancerName(service, c.Config.ClusterID)
}

// GenerateLoadBalancerName - generate the VPC load balancer name from the cluster ID and Kube service
func GenerateLoadBalancerName(service *v1.Service, clusterID string) string {
	serviceLbName := service.ObjectMeta.Annotations[serviceAnnotationLbName]
	if serviceLbName != "" {
		return serviceLbName
	}
	serviceID := strings.ReplaceAll(string(service.ObjectMeta.UID), "-", "")
	lbName := VpcLbNamePrefix + "-" + clusterID + "-" + serviceID
	if service.Spec.LoadBalancerClass != nil {
		prefix := *service.Spec.LoadBalancerClass
		lbName = prefix + "-" + clusterID + "-" + serviceID
	}
	// Limit the LB name to 63 characters
	if len(lbName) > 63 {
		lbName = lbName[:63]
	}
	return lbName
}

// getEventMessage based on the status that was passed in
func (c *CloudVpc) getEventMessage(status string) string {
	switch status {
	case vpcLbStatusOfflineFailed:
		return "The VPC load balancer that routes requests to this Kubernetes LoadBalancer service is offline. For troubleshooting steps, see <https://ibm.biz/vpc-lb-ts>"
	case vpcLbStatusOfflineMaintenancePending:
		return "The VPC load balancer that routes requests to this Kubernetes LoadBalancer service is under maintenance."
	case vpcLbStatusOfflineNotFound:
		return "The VPC load balancer that routes requests to this Kubernetes LoadBalancer service was not found. The VPC load balancer resource may have failed to create or may have been renamed or deleted."
	default:
		return fmt.Sprintf("The VPC load balancer that routes requests to this Kubernetes LoadBalancer service is currently %s.", status)
	}
}

// GetLoadBalancer - called by cloud provider to retrieve status of the load balancer
func (c *CloudVpc) GetLoadBalancer(lbName string, service *v1.Service) (*v1.LoadBalancerStatus, bool, error) {
	// Check to see if the VPC load balancer exists
	lb, err := c.FindLoadBalancer(lbName, service)
	if err != nil {
		errString := fmt.Sprintf("Failed getting LoadBalancer: %v", err)
		klog.Errorf(errString)
		return nil, false, c.recordServiceWarningEvent(service, gettingCloudLoadBalancerFailed, lbName, errString)
	}

	// The load balancer was not found
	if lb == nil {
		klog.Infof("Load balancer %v not found", lbName)
		return nil, false, nil
	}

	// Write details of the load balancer to the log
	klog.Infof(lb.GetSummary())

	// If the VPC load balancer is not Ready, return the hostname from the service or blank
	if !lb.IsReady() {
		klog.Warningf("LoadBalancer %s for service %s is busy: %s", lbName, c.getServiceName(service), lb.GetStatus())
		var lbStatus *v1.LoadBalancerStatus
		if service.Status.LoadBalancer.Ingress != nil {
			lbStatus = c.GetLoadBalancerStatus(service, lb)
		} else {
			lbStatus = &v1.LoadBalancerStatus{}
		}
		return lbStatus, true, nil
	}

	// Return success
	lbStatus := c.GetLoadBalancerStatus(service, lb)
	klog.Infof("LoadBalancer %s for service %s has status: %+v", lbName, c.getServiceName(service), *lbStatus)
	return lbStatus, true, nil
}

// MonitorLoadBalancers - accepts a list of services (of all types), verifies that each Kubernetes load balancer service
// has a corresponding VPC load balancer object, and creates Kubernetes events based on the load balancer's status.
// `status` is a map from a load balancer's unique Service ID to its status.
// This persists load balancer status between consecutive monitor calls.
func (c *CloudVpc) MonitorLoadBalancers(services *v1.ServiceList, status map[string]string) {
	// Verify we were passed a list of Kube services
	if services == nil {
		klog.Infof("No Load Balancers to monitor, returning")
		return
	}
	// Retrieve list of VPC LBs for the current cluster
	lbMap, vpcMap, err := c.GatherLoadBalancers(services)
	if err != nil {
		klog.Errorf("Failed retrieving VPC LBs: %v", err)
		return
	}
	// Sort LB names so that monitor thread output is consistent each 5 min display
	lbNames := []string{}
	for name := range lbMap {
		lbNames = append(lbNames, name)
	}
	sort.Strings(lbNames)

	// Verify that we have a VPC LB for each of the Kube LB services
	for _, lbName := range lbNames {
		service := lbMap[lbName]
		serviceID := string(service.ObjectMeta.UID)
		oldStatus := status[serviceID]
		vpcLB, exists := vpcMap[lbName]
		if exists {
			if vpcLB.IsReady() {
				klog.Infof("VPC LB: %s Service:%s", vpcLB.GetSummary(), c.getServiceName(service))
			} else {
				klog.Warningf("VPC LB: %s Service:%s", vpcLB.GetSummary(), c.getServiceName(service))
			}
			// Store the new status so its available to the next call to VpcMonitorLoadBalancers()
			newStatus := vpcLB.GetStatus()
			status[serviceID] = newStatus

			// If the current state of the LB is online/active
			if newStatus == vpcLbStatusOnlineActive {
				if oldStatus != vpcLbStatusOnlineActive {
					// If the status of the VPC load balancer transitioned to 'online/active' --> NORMAL EVENT.
					c.recordServiceNormalEvent(service, lbName, c.getEventMessage(newStatus))
				}
				// Move on to the next LB service
				continue
			}

			// If the status of the VPC load balancer is not 'online/active', record warning event if status has not changed since last we checked
			if oldStatus == newStatus {
				_ = c.recordServiceWarningEvent(
					service, verifyingCloudLoadBalancerFailed, lbName, c.getEventMessage(newStatus)) // #nosec G104 error is always returned
			}

			// Move on to the next LB service
			continue
		}

		// There is no VPC LB for the current Kubernetes load balancer.  Update the status to: "offline/not_found"
		klog.Warningf("VPC LB not found for service %s %s", c.getServiceName(service), serviceID)
		newStatus := vpcLbStatusOfflineNotFound
		status[serviceID] = newStatus
		if oldStatus == newStatus {
			_ = c.recordServiceWarningEvent(
				service, verifyingCloudLoadBalancerFailed, lbName, c.getEventMessage(newStatus)) // #nosec G104 error is always returned
		}
	}
}

// recordServiceNormalEvent logs a VPC load balancer service event
func (c *CloudVpc) recordServiceNormalEvent(lbService *v1.Service, lbName, eventMessage string) {
	if c.Recorder != nil {
		message := fmt.Sprintf("Event on cloud load balancer %v for service %v with UID %v: %v",
			lbName, types.NamespacedName{Namespace: lbService.ObjectMeta.Namespace, Name: lbService.ObjectMeta.Name}, lbService.ObjectMeta.UID, eventMessage)
		c.Recorder.Event(lbService, v1.EventTypeNormal, "CloudVPCLoadBalancerNormalEvent", message)
	}
}

// recordServiceWarningEvent logs a VPC load balancer service warning
// event and returns an error representing the event.
func (c *CloudVpc) recordServiceWarningEvent(lbService *v1.Service, reason, lbName, errorMessage string) error {
	message := fmt.Sprintf("Error on cloud load balancer %v for service %v with UID %v: %v",
		lbName, types.NamespacedName{Namespace: lbService.ObjectMeta.Namespace, Name: lbService.ObjectMeta.Name}, lbService.ObjectMeta.UID, errorMessage)
	if c.Recorder != nil {
		c.Recorder.Event(lbService, v1.EventTypeWarning, reason, message)
	}
	return errors.New(message)
}
