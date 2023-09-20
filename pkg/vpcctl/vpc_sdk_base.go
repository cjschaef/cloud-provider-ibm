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
	"sort"
	"strconv"
	"strings"

	"github.com/go-openapi/strfmt"
	v1 "k8s.io/api/core/v1"
)

// CloudVpcSdk interface for SDK operations
type CloudVpcSdk interface {
	CreateLoadBalancer(lbName string, nodeList, poolList, subnetList []string, options *ServiceOptions) (*VpcLoadBalancer, error)
	CreateLoadBalancerListener(lbID, poolName, poolID string, options *ServiceOptions) (*VpcLoadBalancerListener, error)
	CreateLoadBalancerPool(lbID, poolName string, nodeList []string, options *ServiceOptions) (*VpcLoadBalancerPool, error)
	CreateLoadBalancerPoolMember(lbID, poolName, poolID, nodeID string, options *ServiceOptions) (*VpcLoadBalancerPoolMember, error)
	CreateSecurityGroupRule(secGroupID, direction, protocol string, portMin, portMax int, remoteSG string) (*VpcSecurityGroupRule, error)
	DeleteLoadBalancer(lbID string, options *ServiceOptions) error
	DeleteLoadBalancerListener(lbID, listenerID string) error
	DeleteLoadBalancerPool(lbID, poolID string) error
	DeleteLoadBalancerPoolMember(lbID, poolID, memberID string) error
	DeleteSecurityGroupRule(secGroupID, ruleID string) error
	DeleteServiceRegistration(serviceCRN string) error
	FindLoadBalancer(nameID string, options *ServiceOptions) (*VpcLoadBalancer, error)
	GetLoadBalancer(lbID string) (*VpcLoadBalancer, error)
	GetSecurityGroup(secGroupID string) (*VpcSecurityGroup, error)
	GetSubnet(subnetID string) (*VpcSubnet, error)
	GetVPC(vpcID string) (*Vpc, error)
	ListNetworkACLs() ([]*VpcNetworkACL, error)
	ListLoadBalancers() ([]*VpcLoadBalancer, error)
	ListLoadBalancerListeners(lbID string) ([]*VpcLoadBalancerListener, error)
	ListLoadBalancerPools(lbID string) ([]*VpcLoadBalancerPool, error)
	ListLoadBalancerPoolMembers(lbID, poolID string) ([]*VpcLoadBalancerPoolMember, error)
	ListSecurityGroups(vpcID string) ([]*VpcSecurityGroup, error)
	ListServiceRegistrations() ([]*VpcServiceRegistration, error)
	ListSubnets() ([]*VpcSubnet, error)
	ListVPCs() ([]*Vpc, error)
	ReplaceLoadBalancerPoolMembers(lbID, poolName, poolID string, nodeList []string, options *ServiceOptions) ([]*VpcLoadBalancerPoolMember, error)
	UpdateLoadBalancer(lbID string, updateList, nodeList, poolList []string, options *ServiceOptions) error
	UpdateLoadBalancerListener(lbID, listenerID string, options *ServiceOptions) (*VpcLoadBalancerListener, error)
	UpdateLoadBalancerPool(lbID, newPoolName string, existingPool *VpcLoadBalancerPool, options *ServiceOptions) (*VpcLoadBalancerPool, error)
	UpdateLoadBalancerSubnets(lbID string, subnetList []string, options *ServiceOptions) (*VpcLoadBalancer, error)
}

// NewVpcSdkProvider - name of SDK interface
var NewVpcSdkProvider = NewVpcSdkGen2

// NewCloudVpcSdk - return the correct set of SDK library routines
func NewCloudVpcSdk(c *ConfigVpc) (CloudVpcSdk, error) {
	switch c.ProviderType {
	case VpcProviderTypeGen2:
		return NewVpcSdkProvider(c)
	case VpcProviderTypeFake:
		return NewVpcSdkFake()
	default:
		return nil, fmt.Errorf("Invalid VPC ProviderType: %s", c.ProviderType)
	}
}

// VpcPoolNameFields - Structure for dealing with parts of the VPC pool name
type VpcPoolNameFields struct {
	Protocol string
	PortMin  int
	PortMax  int
	NodePort int
}

// isPortRange - returns if the pool name is a port range
func (poolName *VpcPoolNameFields) isPortRange() bool {
	return poolName.PortMin != poolName.PortMax
}

// extractFieldsFromPoolName - pool name has format of <protocol>-<port>-<nodePort>
func extractFieldsFromPoolName(poolName string) (*VpcPoolNameFields, error) {
	protocol, portMin, portMax, nodePort, err := extractProtocolPortsFromPoolName(poolName)
	return &VpcPoolNameFields{protocol, portMin, portMax, nodePort}, err
}

// extractProtocolPortsFromPoolName - pool name has format of <protocol>-<port>-<nodePort>
func extractProtocolPortsFromPoolName(poolName string) (string, int, int, int, error) {
	pool := strings.Split(poolName, "-")
	if len(pool) != 3 {
		return "", -1, -1, -1, fmt.Errorf("Invalid pool name, format not <protocol>-<port>-<nodePort>: [%s]", poolName)
	}
	protocol := pool[0]
	portString := pool[1]
	nodePortString := pool[2]
	if protocol != "tcp" && protocol != "udp" {
		return "", -1, -1, -1, fmt.Errorf("Invalid protocol in pool name [%s], only tcp and udp supported", poolName)
	}
	var portMin int
	var portMax int
	var err error
	if strings.Contains(portString, "x") {
		// Port range : portString = "<portMin> x <portMax>"
		ports := strings.Split(portString, "x")
		portMin, err = strconv.Atoi(ports[0])
		if err != nil {
			return "", -1, -1, -1, err
		}
		portMax, err = strconv.Atoi(ports[1])
		if err != nil {
			return "", -1, -1, -1, err
		}
	} else {
		// Single port: portSting = "port"
		portMin, err = strconv.Atoi(portString)
		if err != nil {
			return "", -1, -1, -1, err
		}
		portMax = portMin
	}
	nodePort, err := strconv.Atoi(nodePortString)
	if err != nil {
		return "", -1, -1, -1, err
	}
	return protocol, portMin, portMax, nodePort, nil
}

// genLoadBalancerPoolName - generate the VPC pool name for a specific Kubernetes service port
func genLoadBalancerPoolName(kubePort v1.ServicePort, servicePortRange string) string {
	protocol := strings.ToLower(string(kubePort.Protocol))
	extPort := kubePort.Port
	portString := strconv.Itoa(int(extPort))
	nodePort := kubePort.NodePort
	if servicePortRange == "" {
		// No port range annotation
		return fmt.Sprintf("%s-%d-%d", protocol, extPort, nodePort)
	}
	for _, portRange := range strings.Split(servicePortRange, ",") {
		ports := strings.Split(portRange, "-")
		if portString == ports[0] {
			// Found a service port that matches the portMin of the current port range
			return fmt.Sprintf("%s-%sx%s-%d", protocol, ports[0], ports[1], nodePort)
		}
	}
	// Port in the spec does not match a port range
	return fmt.Sprintf("%s-%d-%d", protocol, extPort, nodePort)
}

// ServiceOptions - options from Kubernetes Load Balancer service and methods to access those fields
type ServiceOptions struct {
	annotations         map[string]string
	enabledFeatures     string
	healthCheckDelay    int
	healthCheckNodePort int
	healthCheckPath     string
	healthCheckPort     int
	healthCheckProtocol string
	healthCheckRetries  int
	healthCheckTimeout  int
	healthCheckUDP      int
	idleConnTimeout     int
	serviceName         string
	serviceType         string
	serviceUDP          bool
}

// newServiceOptions - return blank/empty service option
func newServiceOptions() *ServiceOptions {
	return &ServiceOptions{annotations: map[string]string{}}
}

// getServiceOptions - create service options from the Kubernetes service
func (c *CloudVpc) getServiceOptions(service *v1.Service) *ServiceOptions {
	if service == nil {
		return newServiceOptions()
	}
	return &ServiceOptions{
		annotations:         service.Annotations,
		enabledFeatures:     c.getServiceEnabledFeatures(service),
		healthCheckNodePort: c.getServiceHealthCheckNodePort(service),
		serviceName:         c.getServiceName(service),
		serviceType:         string(service.Spec.Type),
		serviceUDP:          c.isServiceUDP(service),
	}
}

// getHealthCheckDelay - retrieve the heath check delay setting
func (options *ServiceOptions) getHealthCheckDelay() int {
	return options.healthCheckDelay
}

// getHealthCheckNodePort - retrieve the health check node port value
//
//	 0  = externalTrafficPolicy: Cluster
//	>0  = externalTrafficPolicy: Local
func (options *ServiceOptions) getHealthCheckNodePort() int {
	return options.healthCheckNodePort
}

// getHealthCheckPath - retrieve the health check path to be used
func (options *ServiceOptions) getHealthCheckPath() string {
	return options.healthCheckPath
}

// getHealthCheckPort - retrieve the health check port to be used
func (options *ServiceOptions) getHealthCheckPort() int {
	return options.healthCheckPort
}

// getHealthCheckProtocol - retrieve the health check protocol to be used
func (options *ServiceOptions) getHealthCheckProtocol() string {
	return options.healthCheckProtocol
}

// getHealthCheckRetries - retrieve the heath check retries setting
func (options *ServiceOptions) getHealthCheckRetries() int {
	return options.healthCheckRetries
}

// getHealthCheckTimeout - retrieve the heath check timeout setting
func (options *ServiceOptions) getHealthCheckTimeout() int {
	return options.healthCheckTimeout
}

// getHealthCheckUDP - retrieve the node port to be used for UDP health checks
func (options *ServiceOptions) getHealthCheckUDP() int {
	return options.healthCheckUDP
}

// getIdleConnectionTimeout - retrieve the idle connection timeout setting
func (options *ServiceOptions) getIdleConnectionTimeout() int {
	return options.idleConnTimeout
}

// getSdnlbOption - retrieve the sdnlb option that was specified on the service
func (options *ServiceOptions) getSdnlbOption() string {
	switch {
	case options.isSdnlbPartner():
		return LoadBalancerOptionsSdnlbPartner
	case options.isSdnlbInternal():
		return LoadBalancerOptionsSdnlbInternal
	}
	return ""
}

// getServiceCRN - retrieve the vpc-service-crn annotation
func (options *ServiceOptions) getServiceCRN() string {
	return options.annotations[serviceAnnotationServiceCRN]
}

// getServiceType - retrieve the zone annotation
func (options *ServiceOptions) getServiceName() string {
	return options.serviceName
}

// getServiceSubnets - retrieve the vpc-subnets annotation
func (options *ServiceOptions) getServiceSubnets() string {
	return strings.ReplaceAll(options.annotations[serviceAnnotationSubnets], " ", "")
}

// getServiceType - retrieve the zone annotation
func (options *ServiceOptions) getServiceType() string {
	switch {
	case options.isNLB():
		return "nlb"
	case options.isSdnlb():
		return options.getSdnlbOption()
	case options.serviceType == string(v1.ServiceTypeNodePort):
		return "node-port"
	}
	return "alb"
}

// getServiceZone - retrieve the zone annotation
func (options *ServiceOptions) getServiceZone() string {
	return strings.ReplaceAll(options.annotations[serviceAnnotationZone], " ", "")
}

// isALB - return true if service is ALB
func (options *ServiceOptions) isALB() bool {
	return !options.isNLB() && !options.isSdnlb()
}

// isNLB - return true if service is NLB
func (options *ServiceOptions) isNLB() bool {
	return isVpcOptionEnabled(options.enabledFeatures, LoadBalancerOptionNLB)
}

// isProxyProtocol - return true if service has proxy-protocol enabled
func (options *ServiceOptions) isProxyProtocol() bool {
	return isVpcOptionEnabled(options.enabledFeatures, LoadBalancerOptionProxyProtocol)
}

// isPublic - return true if service is public LB
func (options *ServiceOptions) isPublic() bool {
	value := options.annotations[serviceAnnotationIPType]
	return value == "" || value == servicePublicLB
}

// isSdnlb - return true if service is sDNLB
func (options ServiceOptions) isSdnlb() bool {
	return options.isSdnlbInternal() || options.isSdnlbPartner()
}

// isSdnlbInternal - return true if service is internal sDNLB
func (options ServiceOptions) isSdnlbInternal() bool {
	return isVpcOptionEnabled(options.enabledFeatures, LoadBalancerOptionsSdnlbInternal)
}

// isSdnlbPartner - return true if service is partner sDNLB
func (options ServiceOptions) isSdnlbPartner() bool {
	return isVpcOptionEnabled(options.enabledFeatures, LoadBalancerOptionsSdnlbPartner)
}

// isUDP - retrieve true if a UDP port was specified on this service
func (options *ServiceOptions) isUDP() bool {
	return options.serviceUDP
}

// setHealthCheckDelay - set the heath check delay setting
func (options *ServiceOptions) setHealthCheckDelay(delay int) {
	options.healthCheckDelay = delay
}

// setHealthCheckPath - set the heath check path setting
func (options *ServiceOptions) setHealthCheckPath(path string) {
	options.healthCheckPath = path
}

// setHealthCheckPort - set the heath check port setting
func (options *ServiceOptions) setHealthCheckPort(port int) {
	options.healthCheckPort = port
}

// setHealthCheckProtocol - set the heath check protocol setting
func (options *ServiceOptions) setHealthCheckProtocol(protocol string) {
	options.healthCheckProtocol = protocol
}

// setHealthCheckRetries - set the heath check retries setting
func (options *ServiceOptions) setHealthCheckRetries(retries int) {
	options.healthCheckRetries = retries
}

// setHealthCheckTimeout - set the heath check timeout setting
func (options *ServiceOptions) setHealthCheckTimeout(timeout int) {
	options.healthCheckTimeout = timeout
}

// setHealthCheckUDP - set the heath check UDP port setting
func (options *ServiceOptions) setHealthCheckUDP(udpPort int) {
	options.healthCheckUDP = udpPort
}

// setIdleConnectionTimeout - set the idle connection timeout setting
func (options *ServiceOptions) setIdleConnectionTimeout(timeout int) {
	options.idleConnTimeout = timeout
}

// isVpcOptionEnabled - check to see if item string is in the comma separated list
func isVpcOptionEnabled(list, item string) bool {
	if list == "" {
		return false
	}
	for _, option := range strings.Split(list, ",") {
		if option == item {
			return true
		}
	}
	return false
}

// SafePointerBool - safely de-ref pointer to an bool
func SafePointerBool(ptr *bool) bool {
	if ptr == nil {
		return false
	}
	return *ptr
}

// SafePointerDate - safely de-ref pointer to an date object
func SafePointerDate(ptr *strfmt.DateTime) string {
	if ptr == nil {
		return "nil"
	}
	return fmt.Sprintf("%v", *ptr)
}

// SafePointerInt64 - safely de-ref pointer to an int64
func SafePointerInt64(ptr *int64) int64 {
	if ptr == nil {
		return 0
	}
	return *ptr
}

// SafePointerString - safely de-ref pointer to an string
func SafePointerString(ptr *string) string {
	if ptr == nil {
		return "nil"
	}
	return *ptr
}

// Constants associated with the LoadBalancer*.OperatingStatus property.
// The operating status of this load balancer.
const (
	LoadBalancerOperatingStatusOffline = "offline"
	LoadBalancerOperatingStatusOnline  = "online"
)

// Constants associated with the LoadBalancer*.ProvisioningStatus property.
// The provisioning status of this load balancer.
const (
	LoadBalancerProvisioningStatusActive             = "active"
	LoadBalancerProvisioningStatusCreatePending      = "create_pending"
	LoadBalancerProvisioningStatusDeletePending      = "delete_pending"
	LoadBalancerProvisioningStatusFailed             = "failed"
	LoadBalancerProvisioningStatusMaintenancePending = "maintenance_pending"
	LoadBalancerProvisioningStatusUpdatePending      = "update_pending"
)

// Constants associated with the LoadBalancer*.Protocol property.
// The listener protocol.
const (
	LoadBalancerProtocolHTTP  = "http"
	LoadBalancerProtocolHTTPS = "https"
	LoadBalancerProtocolTCP   = "tcp"
)

// Constants associated with the LoadBalancerPool.Algorithm property.
// The load balancing algorithm.
const (
	LoadBalancerAlgorithmLeastConnections   = "least_connections"
	LoadBalancerAlgorithmRoundRobin         = "round_robin"
	LoadBalancerAlgorithmWeightedRoundRobin = "weighted_round_robin"
)

// Constants associated with the LoadBalancerPool.ProxyProtocol property.
// The PROXY protocol setting for this pool:
// - `v1`: Enabled with version 1 (human-readable header format)
// - `v2`: Enabled with version 2 (binary header format)
// - `disabled`: Disabled
//
// Supported by load balancers in the `application` family (otherwise always `disabled`).
const (
	LoadBalancerProxyProtocolDisabled = "disabled"
	LoadBalancerProxyProtocolV1       = "v1"
	LoadBalancerProxyProtocolV2       = "v2"
)

// Constants associated with the LoadBalancerPoolSessionPersistence.Type property.
// The session persistence type.
const (
	LoadBalancerSessionPersistenceSourceIP = "source_ip"
)

// Constants that can control the behavior of the VPC LoadBalancer
const (
	LoadBalancerOptionProxyProtocol = "proxy-protocol"
	LoadBalancerOptionNLB           = "nlb"
	// LoadBalancerOptionLeastConnections / LoadBalancerOptionSessionAffinity are currently not supported
	// See issue: https://github.ibm.com/alchemy-containers/armada-network/issues/3470
	//
	// LoadBalancerOptionLeastConnections = "least-connections"
	// LoadBalancerOptionSessionAffinity  = "session-affinity"
)

// VpcObjectReference ...
type VpcObjectReference struct {
	// The unique identifier
	ID string

	// The unique user-defined name
	Name string
}

// VpcLoadBalancer ...
type VpcLoadBalancer struct {
	// Saved copy of the actual SDK object
	SdkObject interface{}

	// The date and time that this load balancer was created.
	// CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`
	CreatedAt string

	// The load balancer's CRN.
	// CRN *string `json:"crn" validate:"required"`

	// Fully qualified domain name assigned to this load balancer.
	// Hostname *string `json:"hostname" validate:"required"`
	Hostname string

	// The load balancer's canonical URL.
	// Href *string `json:"href" validate:"required"`

	// The unique identifier for this load balancer.
	// ID *string `json:"id" validate:"required"`
	ID string

	// The type of this load balancer, public or private.
	// IsPublic *bool `json:"is_public" validate:"required"`
	IsPublic bool

	// Indicates whether this load balancer is a service load balancer.
	// IsService *bool `json:"is_service" validate:"required"`
	IsService bool

	// The listeners of this load balancer.
	// Listeners []LoadBalancerListenerReference `json:"listeners" validate:"required"`
	ListenerIDs []string

	// The logging configuration for this load balancer.
	// Logging *LoadBalancerLogging `json:"logging" validate:"required"`

	// The unique user-defined name for this load balancer.
	// Name *string `json:"name" validate:"required"`
	Name string

	// The operating status of this load balancer.
	// OperatingStatus *string `json:"operating_status" validate:"required"`
	OperatingStatus string

	// The pools of this load balancer.
	// Pools []LoadBalancerPoolReference `json:"pools" validate:"required"`
	Pools []VpcObjectReference

	// The private IP addresses assigned to this load balancer.
	// PrivateIps []IP `json:"private_ips" validate:"required"`
	PrivateIps []string

	// The profile to use for this load balancer.
	// Profile *LoadBalancerProfileReference `json:"profile" validate:"required"`
	ProfileFamily string

	// The provisioning status of this load balancer.
	// ProvisioningStatus *string `json:"provisioning_status" validate:"required"`
	ProvisioningStatus string

	// The public IP addresses assigned to this load balancer. These are applicable only for public load balancers.
	// PublicIps []IP `json:"public_ips" validate:"required"`
	PublicIps []string

	// The resource group for this load balancer.
	// ResourceGroup *ResourceGroupReference `json:"resource_group" validate:"required"`
	ResourceGroup VpcObjectReference

	// The security groups targeting this load balancer.
	//
	// Applicable only for load balancers that support security groups.
	// SecurityGroups []SecurityGroupReference `json:"security_groups" validate:"required"`
	SecurityGroups []VpcObjectReference

	// Collection of service IP addresses for this load balancer.
	// ServiceIps []LoadBalancerServiceIPs `json:"service_ips,omitempty"`
	// Service IPs will be returned in the PrivateIps field

	// The subnets this load balancer is part of.
	// Subnets []SubnetReference `json:"subnets" validate:"required"`
	Subnets []VpcObjectReference

	// The VPC this load balancer belongs to. For load balancers that use subnets, this
	// is the VPC the subnets belong to.
	// Vpc *VPCReferenceNoName `json:"vpc,omitempty"`
	VpcID string
}

// GetStatus - returns the operational/provisioning status of the VPC load balancer as a string
func (lb *VpcLoadBalancer) GetStatus() string {
	return fmt.Sprintf("%s/%s", lb.OperatingStatus, lb.ProvisioningStatus)
}

// getSubnetIDs - returns list of subnet IDs associated with the VPC load balancer
func (lb *VpcLoadBalancer) getSubnetIDs() []string {
	subnetList := []string{}
	for _, subnet := range lb.Subnets {
		subnetList = append(subnetList, subnet.ID)
	}
	return subnetList
}

// GetSuccessString - returns a string indicating success of the LB creation
func (lb *VpcLoadBalancer) GetSuccessString() string {
	if lb.Hostname != "" {
		return lb.Hostname
	}
	return strings.Join(lb.PrivateIps, ",")
}

// GetSummary - returns a string containing key information about the VPC load balancer
func (lb *VpcLoadBalancer) GetSummary() string {
	poolList := []string{}
	for _, pool := range lb.Pools {
		poolList = append(poolList, pool.Name)
	}
	sort.Strings(poolList)
	poolNames := strings.Join(poolList, ",")
	privateIPs := strings.Join(lb.PrivateIps, ",")
	publicIPs := strings.Join(lb.PublicIps, ",")
	result := fmt.Sprintf("Name:%s ID:%s Status:%s", lb.Name, lb.ID, lb.GetStatus())
	// Don't return fields that have not been set
	if lb.Hostname != "" {
		result += fmt.Sprintf(" Hostname:%s", lb.Hostname)
	}
	if poolNames != "" {
		result += fmt.Sprintf(" Pools:%s", poolNames)
	}
	if privateIPs != "" {
		result += fmt.Sprintf(" Private:%s", privateIPs)
	}
	if publicIPs != "" {
		result += fmt.Sprintf(" Public:%s", publicIPs)
	}
	return result
}

// getVpcID - return the VPC ID associated with the VPC load balancer
func (lb *VpcLoadBalancer) getVpcID(vpcSubnets []*VpcSubnet) string {
	for _, lbSubnet := range lb.Subnets {
		for _, vpcSubnet := range vpcSubnets {
			if lbSubnet.ID == vpcSubnet.ID {
				return vpcSubnet.Vpc.ID
			}
		}
	}
	return ""
}

// getZones - return the Zone(s) associated with the VPC load balancer
func (lb *VpcLoadBalancer) getZones(vpcSubnets []*VpcSubnet) []string {
	zoneMap := map[string]bool{}
	for _, lbSubnet := range lb.Subnets {
		for _, vpcSubnet := range vpcSubnets {
			if lbSubnet.ID == vpcSubnet.ID {
				zoneMap[vpcSubnet.Zone] = true
			}
		}
	}
	zoneList := []string{}
	for zone := range zoneMap {
		zoneList = append(zoneList, zone)
	}
	sort.Strings(zoneList)
	return zoneList
}

// IsNLB - returns true of the load balancer is a Network Load Balancer
func (lb *VpcLoadBalancer) IsNLB() bool {
	return strings.EqualFold(lb.ProfileFamily, "network")
}

// IsReady - returns a flag indicating if the load balancer will allow additional operations to be done
func (lb *VpcLoadBalancer) IsReady() bool {
	return lb.OperatingStatus == LoadBalancerOperatingStatusOnline &&
		lb.ProvisioningStatus == LoadBalancerProvisioningStatusActive
}

// VpcLoadBalancerListener ...
type VpcLoadBalancerListener struct {
	// The certificate instance used for SSL termination. It is applicable only to `https`
	// protocol.
	// CertificateInstance *CertificateInstanceReference `json:"certificate_instance,omitempty"`

	// The connection limit of the listener.
	// ConnectionLimit *int64 `json:"connection_limit,omitempty"`
	ConnectionLimit int64

	// The date and time that this listener was created.
	// CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`

	// The default pool associated with the listener.
	// DefaultPool *LoadBalancerPoolReference `json:"default_pool,omitempty"`
	DefaultPool VpcObjectReference

	// The listener's canonical URL.
	// Href *string `json:"href" validate:"required"`

	// The idle connection timeout of the listener in seconds. This property will be present for load balancers in the
	// `application` family.
	// IdleConnTimeout *int64 `json:"idle_connection_timeout,omitempty"`
	IdleConnTimeout int64

	// The unique identifier for this load balancer listener.
	// ID *string `json:"id" validate:"required"`
	ID string

	// The list of policies of this listener.
	// Policies []LoadBalancerListenerPolicyReference `json:"policies,omitempty"`

	// The listener port number.
	// PortMin *int64 `json:"port" validate:"required"`
	PortMin int64

	// The listener port number.
	// PortMax *int64 `json:"port" validate:"required"`
	PortMax int64

	// The listener protocol.
	// Protocol *string `json:"protocol" validate:"required"`
	Protocol string

	// The provisioning status of this listener.
	// ProvisioningStatus *string `json:"provisioning_status" validate:"required"`
	ProvisioningStatus string
}

// VpcLoadBalancerPool ...
type VpcLoadBalancerPool struct {
	// The load balancing algorithm.
	// Algorithm *string `json:"algorithm" validate:"required"`
	Algorithm string

	// The date and time that this pool was created.
	// CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`

	// The health monitor of this pool.
	// HealthMonitor *LoadBalancerPoolHealthMonitor `json:"health_monitor" validate:"required"`
	HealthMonitor VpcLoadBalancerPoolHealthMonitor

	// The pool's canonical URL.
	// Href *string `json:"href" validate:"required"`

	// The unique identifier for this load balancer pool.
	// ID *string `json:"id" validate:"required"`
	ID string

	// The backend server members of the pool.
	// Members []LoadBalancerPoolMembersItem `json:"members,omitempty"`
	Members []*VpcLoadBalancerPoolMember

	// The user-defined name for this load balancer pool.
	// Name *string `json:"name" validate:"required"`
	Name string

	// The protocol used for this load balancer pool.
	//
	// The enumerated values for this property are expected to expand in the future. When processing this property, check
	// for and log unknown values. Optionally halt processing and surface the error, or bypass the pool on which the
	// unexpected property value was encountered.
	// Protocol *string `json:"protocol" validate:"required"`
	Protocol string

	// The provisioning status of this pool.
	// ProvisioningStatus *string `json:"provisioning_status" validate:"required"`
	ProvisioningStatus string

	// The PROXY protocol setting for this pool:
	// - `v1`: Enabled with version 1 (human-readable header format)
	// - `v2`: Enabled with version 2 (binary header format)
	// - `disabled`: Disabled
	//
	// Supported by load balancers in the `application` family (otherwise always `disabled`).
	// ProxyProtocol *string `json:"proxy_protocol" validate:"required"`
	ProxyProtocol string

	// The session persistence of this pool.
	// SessionPersistence *LoadBalancerPoolSessionPersistenceTemplate `json:"session_persistence,omitempty"`
	SessionPersistence string
}

// VpcLoadBalancerPoolHealthMonitor ...
type VpcLoadBalancerPoolHealthMonitor struct {
	// The health check interval in seconds. Interval must be greater than timeout value.
	// Delay *int64 `json:"delay" validate:"required"`
	Delay int64

	// The health check max retries.
	// MaxRetries *int64 `json:"max_retries" validate:"required"`
	MaxRetries int64

	// The health check port number. If specified, this overrides the ports specified in the server member resources.
	// Port *int64 `json:"port,omitempty"`
	Port int64

	// The health check timeout in seconds.
	// Timeout *int64 `json:"timeout" validate:"required"`
	Timeout int64

	// The protocol type of this load balancer pool health monitor.
	//
	// The enumerated values for this property are expected to expand in the future. When processing this property, check
	// for and log unknown values. Optionally halt processing and surface the error, or bypass the health monitor on which
	// the unexpected property value was encountered.
	// Type *string `json:"type" validate:"required"`
	Type string

	// The health check url. This is applicable only to `http` type of health monitor.
	// URLPath *string `json:"url_path,omitempty"`
	URLPath string
}

// VpcLoadBalancerPoolMember ...
type VpcLoadBalancerPoolMember struct {
	// The date and time that this member was created.
	// CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`

	// Health of the server member in the pool.
	// Health *string `json:"health" validate:"required"`
	Health string

	// The member's canonical URL.
	// Href *string `json:"href" validate:"required"`

	// The unique identifier for this load balancer pool member.
	// ID *string `json:"id" validate:"required"`
	ID string

	// The port number of the application running in the server member.
	// Port *int64 `json:"port" validate:"required"`
	Port int64

	// The provisioning status of this member.
	// ProvisioningStatus *string `json:"provisioning_status" validate:"required"`
	ProvisioningStatus string

	// The pool member target type.
	// TargetIPAddress *LoadBalancerMemberTarget.Address `json:"target" validate:"required"`
	TargetIPAddress string
	// TargetAddress *LoadBalancerMemberTarget.ID `json:"target" validate:"required"`
	TargetInstanceID string

	// Weight of the server member. This takes effect only when the load balancing algorithm of its belonging pool is
	// `weighted_round_robin`.
	// Weight *int64 `json:"weight,omitempty"`
	Weight int64
}

// VpcNetworkACL ...
type VpcNetworkACL struct {
	// Actual SDK object to support "full" dump of the object
	SdkObject interface{}

	// The date and time that the network ACL was created.
	// CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`
	CreatedAt string

	// The CRN for this network ACL.
	// CRN *string `json:"crn" validate:"required"`

	// The URL for this network ACL.
	// Href *string `json:"href" validate:"required"`

	// The unique identifier for this network ACL.
	// ID *string `json:"id" validate:"required"`
	ID string

	// The user-defined name for this network ACL.
	// Name *string `json:"name" validate:"required"`
	Name string

	// The resource group for this network ACL.
	// ResourceGroup *ResourceGroupReference `json:"resource_group" validate:"required"`
	ResourceGroup VpcObjectReference

	// The ordered rules for this network ACL. If no rules exist, all traffic will be denied.
	// Rules []NetworkACLRuleItemIntf `json:"rules" validate:"required"`
	Rules []VpcNetworkACLRule

	// The subnets to which this network ACL is attached.
	// Subnets []SubnetReference `json:"subnets" validate:"required"`

	// The VPC this security group is a part of.
	// Vpc *VPCReference `json:"vpc" validate:"required"`
	Vpc VpcObjectReference
}

// VpcNetworkACLRule ...
type VpcNetworkACLRule struct {
	// Actual SDK object to support "full" dump of the object
	SdkObject interface{}
}

// VpcSecurityGroup ...
type VpcSecurityGroup struct {
	// Actual SDK object to support "full" dump of the object
	SdkObject interface{}

	// The date and time that this security group was created.
	// CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`
	CreatedAt string

	// The security group's CRN.
	// Crn *string `json:"crn" validate:"required"`

	// The security group's canonical URL.
	// Href *string `json:"href" validate:"required"`

	// The unique identifier for this security group.
	// ID *string `json:"id" validate:"required"`
	ID string

	// The user-defined name for this security group. Names must be unique within the VPC the security group resides in.
	// Name *string `json:"name" validate:"required"`
	Name string

	// Collection of references to network interfaces.
	// NetworkInterfaces []NetworkInterfaceReference `json:"network_interfaces" validate:"required"`
	// NetworkInterfaces []string

	// The resource group for this security group.
	// ResourceGroup *ResourceGroupReference `json:"resource_group" validate:"required"`
	ResourceGroup VpcObjectReference

	// Collection of references to rules for this security group. If no rules exist, all traffic will be denied.
	// Rules []SecurityGroupRuleIntf `json:"rules" validate:"required"`
	Rules []VpcSecurityGroupRule

	// The targets for this security group.
	// Targets []SecurityGroupTargetReferenceIntf `json:"targets" validate:"required"`
	Targets []VpcSecurityGroupTarget

	// The VPC this security group is a part of.
	// Vpc *VPCReference `json:"vpc" validate:"required"`
	Vpc VpcObjectReference
}

// VpcSecurityGroupRule ...
type VpcSecurityGroupRule struct {
	// Saved copy of the actual SDK object
	SdkObject interface{}

	// The direction of traffic to enforce, either `inbound` or `outbound`.
	// Direction *string `json:"direction" validate:"required"`
	Direction string

	// The URL for this security group rule.
	// Href *string `json:"href" validate:"required"`

	// The unique identifier for this security group rule.
	// ID *string `json:"id" validate:"required"`
	ID string

	// The IP version to enforce. The format of `remote.address` or `remote.cidr_block` must match this property, if they
	// are used. Alternatively, if `remote` references a security group, then this rule only applies to IP addresses
	// (network interfaces) in that group matching this IP version.
	// IPVersion *string `json:"ip_version,omitempty"`
	IPVersion string

	// The protocol to enforce.
	// Protocol *string `json:"protocol,omitempty"`
	Protocol string

	// The IP addresses or security groups from which this rule will allow traffic (or to
	// which, for outbound rules). Can be specified as an IP address, a CIDR block, or a
	// security group. If omitted, a CIDR block of `0.0.0.0/0` will be used to allow traffic
	// from any source (or to any source, for outbound rules).
	// Remote SecurityGroupRuleRemotePrototypeIntf `json:"remote,omitempty"`
	Remote VpcSecurityGroupRuleRemote

	// The ICMP traffic code to allow.
	// Code *int64 `json:"code,omitempty"`

	// The ICMP traffic type to allow.
	// Type *int64 `json:"type,omitempty"`

	// The inclusive upper bound of TCP/UDP port range.
	// PortMax *int64 `json:"port_max,omitempty"`
	PortMax int64

	// The inclusive lower bound of TCP/UDP port range.
	// PortMin *int64 `json:"port_min,omitempty"`
	PortMin int64
}

// Constants associated with the SecurityGroupRule.Direction property.
// The direction of traffic to enforce, either `inbound` or `outbound`.
const (
	SecurityGroupRuleDirectionInbound  = "inbound"
	SecurityGroupRuleDirectionOutbound = "outbound"
)

// Constants associated with the SecurityGroupRule.IPVersion property.
// The IP version to enforce. The format of `remote.address` or `remote.cidr_block` must match this property, if they
// are used. Alternatively, if `remote` references a security group, then this rule only applies to IP addresses
// (network interfaces) in that group matching this IP version.
const (
	SecurityGroupRuleIPVersionIpv4 = "ipv4"
)

// Constants associated with the SecurityGroupRule.Protocol property.
// The protocol to enforce.
const (
	SecurityGroupRuleProtocolALL  = "all"
	SecurityGroupRuleProtocolICMP = "icmp"
	SecurityGroupRuleProtocolTCP  = "tcp"
	SecurityGroupRuleProtocolUDP  = "udp"
)

// allowsTraffic - returns true if the current rule allows the specified traffic
func (rule *VpcSecurityGroupRule) allowsTraffic(direction, protocol string, portMin, portMax int) bool {
	return rule.Direction == direction &&
		rule.Protocol == protocol &&
		rule.PortMin <= int64(portMin) &&
		rule.PortMax >= int64(portMax)
}

// display - returns string of the key rule information
func (rule *VpcSecurityGroupRule) display() string {
	return fmt.Sprintf("{ ID:%s Direction:%s Protocol:%s Ports:%d-%d }", rule.ID, rule.Direction, rule.Protocol, rule.PortMin, rule.PortMax)
}

// insidePortRange - returns true if the current rule in contained within the specified port range
func (rule *VpcSecurityGroupRule) insidePortRange(direction, protocol string, portMin, portMax int) bool {
	return rule.Direction == direction &&
		rule.Protocol == protocol &&
		rule.PortMin >= int64(portMin) &&
		rule.PortMax <= int64(portMax)
}

// matchesPorts - returns true if the current rule matches the specified parameters
func (rule *VpcSecurityGroupRule) matchesPorts(direction, protocol string, portMin, portMax int) bool {
	return rule.Direction == direction &&
		rule.Protocol == protocol &&
		rule.PortMin == int64(portMin) &&
		rule.PortMax == int64(portMax)
}

// VpcSecurityGroupRuleRemote ...
type VpcSecurityGroupRuleRemote struct {
	// The IP address.
	//
	// This property may add support for IPv6 addresses in the future. When processing a value in this property, verify
	// that the address is in an expected format. If it is not, log an error. Optionally halt processing and surface the
	// error, or bypass the resource on which the unexpected IP address format was encountered.
	// Address *string `json:"address,omitempty"`
	Address string

	// The CIDR block. This property may add support for IPv6 CIDR blocks in the future. When processing a value in this
	// property, verify that the CIDR block is in an expected format. If it is not, log an error. Optionally halt
	// processing and surface the error, or bypass the resource on which the unexpected CIDR block format was encountered.
	// CIDRBlock *string `json:"cidr_block,omitempty"`
	CIDRBlock string

	// The security group's CRN.
	// CRN *string `json:"crn,omitempty"`

	// If present, this property indicates the referenced resource has been deleted, and provides
	// some supplementary information.
	// Deleted *SecurityGroupReferenceDeleted `json:"deleted,omitempty"`

	// The security group's canonical URL.
	// Href *string `json:"href,omitempty"`

	// The unique identifier for this security group.
	// ID *string `json:"id,omitempty"`
	ID string

	// The name for this security group. The name is unique across all security groups for the VPC.
	// Name *string `json:"name,omitempty"`
	Name string
}

// VpcSecurityGroupTarget ...
type VpcSecurityGroupTarget struct {
	// Saved copy of the actual SDK object
	SdkObject interface{}
}

// VpcServiceRegistration ...
type VpcServiceRegistration struct {
	// Saved copy of the actual SDK object
	SdkObject interface{}

	// Whether the IBM catalog has been given approval to publish an IBM catalog object corresponding to the `service_crn`
	// of this service registration.
	// ApprovedForPublication *bool `json:"approved_for_publication" validate:"required"`
	ApprovedForPublication bool

	// The date and time that the service registration was created.
	// CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`
	CreatedAt string

	// The number of endpoint gateways using this service registration.
	// EndpointGatewaysCount *int64 `json:"endpoint_gateways_count" validate:"required"`
	EndpointGatewaysCount int64

	// An array of endpoints per region for this service registration.
	// Endpoints [][]IBMServiceRegistrationZoneEndpoint `json:"endpoints" validate:"required"`
	Endpoints []string

	// The URL for this service registration.
	// Href *string `json:"href" validate:"required"`

	// The unique identifier for this service registration.
	// ID *string `json:"id" validate:"required"`
	ID string

	// The lifecycle state of the service registration.
	// LifecycleState *string `json:"lifecycle_state" validate:"required"`
	LifecycleState string

	// The unique user-defined name for this service registration.
	// Name *string `json:"name" validate:"required"`
	Name string

	// The origin type of this service.
	//   - `cos`: service endpoint is cloud object storage
	//   - `cse`: service endpoint is reached through a cloud service endpoint
	//   - `vpc`: service endpoint is VPC-native.
	// OriginType *string `json:"origin_type" validate:"required"`
	OriginType string

	// An array of non-overlapping port ranges for this service registration.
	// Ports []IBMServiceRegistrationPortRange `json:"ports,omitempty"`
	Ports []string

	// The resource type.
	// ResourceType *string `json:"resource_type" validate:"required"`
	ResourceType string

	// The CRN for this service.
	// ServiceCrn *string `json:"service_crn" validate:"required"`
	ServiceCrn string

	// Indicates whether this service has zonal affinity. If `true`, and `origin_type` is
	// `vpc`, then traffic to the service from a VPC zone will favor service endpoints in the same zone. If `false`, or
	// `origin_type` is not `vpc`, then traffic will be load balanced across all service zones.
	// ZonalAffinity *bool `json:"zonal_affinity" validate:"required"`
	ZonalAffinity bool
}

// VpcSubnet ...
type VpcSubnet struct {
	// Saved copy of the actual SDK object
	SdkObject interface{}

	// The number of IPv4 addresses in this subnet that are not in-use, and have not been reserved by the user or the
	// provider.
	// AvailableIpv4AddressCount *int64 `json:"available_ipv4_address_count" validate:"required"`
	AvailableIpv4AddressCount int64

	// The date and time that the subnet was created.
	// CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`
	CreatedAt string

	// The CRN for this subnet.
	// CRN *string `json:"crn" validate:"required"`

	// The URL for this subnet.
	// Href *string `json:"href" validate:"required"`

	// The unique identifier for this subnet.
	// ID *string `json:"id" validate:"required"`
	ID string

	// The IP version(s) supported by this subnet.
	// IPVersion *string `json:"ip_version" validate:"required"`
	IPVersion string

	// The IPv4 range of the subnet, expressed in CIDR format.
	// Ipv4CIDRBlock *string `json:"ipv4_cidr_block,omitempty"`
	Ipv4CidrBlock string

	// The user-defined name for this subnet.
	// Name *string `json:"name" validate:"required"`
	Name string

	// The network ACL for this subnet.
	// NetworkACL *NetworkACLReference `json:"network_acl" validate:"required"`
	NetworkACL VpcObjectReference

	// The public gateway to handle internet bound traffic for this subnet.
	// PublicGateway *PublicGatewayReference `json:"public_gateway,omitempty"`
	PublicGateway VpcObjectReference

	// The resource group for this subnet.
	// ResourceGroup *ResourceGroupReference `json:"resource_group" validate:"required"`
	ResourceGroup VpcObjectReference

	// The status of the subnet.
	// Status *string `json:"status" validate:"required"`
	Status string

	// The total number of IPv4 addresses in this subnet.
	//
	// Note: This is calculated as 2<sup>(32 − prefix length)</sup>. For example, the prefix length `/24` gives:<br>
	// 2<sup>(32 − 24)</sup> = 2<sup>8</sup> = 256 addresses.
	// TotalIpv4AddressCount *int64 `json:"total_ipv4_address_count" validate:"required"`
	TotalIpv4AddressCount int64

	// The VPC this subnet is a part of.
	// VPC *VPCReference `json:"vpc" validate:"required"`
	Vpc VpcObjectReference

	// The zone this subnet resides in.
	// Zone *ZoneReference `json:"zone" validate:"required"`
	Zone string
}

// Vpc ...
type Vpc struct {
	// Actual SDK object to support "full" dump of the object
	SdkObject interface{}

	// Indicates whether this VPC is connected to Classic Infrastructure. If true, this VPC's resources have private
	// network connectivity to the account's Classic Infrastructure resources. Only one VPC, per region, may be connected
	// in this way. This value is set at creation and subsequently immutable.
	// ClassicAccess *bool `json:"classic_access" validate:"required"`
	ClassicAccess bool

	// The date and time that the VPC was created.
	// CreatedAt *strfmt.DateTime `json:"created_at" validate:"required"`
	CreatedAt string

	// The CRN for this VPC.
	// Crn *string `json:"crn" validate:"required"`

	// Array of CSE ([Cloud Service Endpoint](https://cloud.ibm.com/docs/resources?topic=resources-service-endpoints))
	// source IP addresses for the VPC. The VPC will have one CSE source IP address per zone.
	// CseSourceIps []VPCCSESourceIP `json:"cse_source_ips,omitempty"`
	CseSourceIPs []string

	// The default network ACL to use for subnets created in this VPC.
	// DefaultNetworkAcl *NetworkACLReference `json:"default_network_acl" validate:"required"`
	DefaultNetworkACL VpcObjectReference

	// The default routing table to use for subnets created in this VPC.
	// DefaultRoutingTable *RoutingTableReference `json:"default_routing_table" validate:"required"`

	// The default security group to use for network interfaces created in this VPC.
	// DefaultSecurityGroup *SecurityGroupReference `json:"default_security_group" validate:"required"`
	DefaultSecurityGroup VpcObjectReference

	// The URL for this VPC.
	// Href *string `json:"href" validate:"required"`

	// The unique identifier for this VPC.
	// ID *string `json:"id" validate:"required"`
	ID string

	// The user-defined name for this VPC.
	// Name *string `json:"name" validate:"required"`
	Name string

	// The resource group for this VPC.
	// ResourceGroup *ResourceGroupReference `json:"resource_group" validate:"required"`
	ResourceGroup VpcObjectReference

	// The status of this VPC.
	// Status *string `json:"status" validate:"required"`
	Status string
}

// Constants associated with the VPC.Status property.
// The status of this VPC.
const (
	VPCStatusAvailable = "available"
	VPCStatusDeleting  = "deleting"
	VPCStatusFailed    = "failed"
	VPCStatusPending   = "pending"
)
