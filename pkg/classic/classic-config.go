/*******************************************************************************
* IBM Cloud Kubernetes Service, 5737-D43
* (C) Copyright IBM Corp. 2017, 2023 All Rights Reserved.
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

package classic

import (
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

// CloudConfig is the ibm cloud provider config data.
type CloudConfig struct {
	Application     string // Name of the application to use as a label for the load balancer deployment
	CalicoDatastore string // The Calico datastore type: "ETCD" or "KDD"
	ConfigFilePath  string // The Kubernetes config file path
	Image           string // Name of the image to use for the load balancer deployment
	VlanIPConfigMap string // Name of the VLAN IP config map in the kube-system or ibm-system namespace
}

// Cloud is the ibm cloud provider implementation.
type Cloud struct {
	KubeClient clientset.Interface
	Config     *CloudConfig
	Recorder   *CloudEventRecorder
}

const (
	ProviderName = "ibm"
)

func NewCloud(kubeClient kubernetes.Interface, config *CloudConfig, recorder record.EventRecorder) *Cloud {
	return &Cloud{
		KubeClient: kubeClient,
		Config:     config,
		Recorder:   &CloudEventRecorder{Name: ProviderName, Recorder: recorder}}
}

// SetInformers - Configure watch/informers
func (c *Cloud) SetInformers(informerFactory informers.SharedInformerFactory) {
	endpointInformer := informerFactory.Core().V1().Endpoints().Informer()
	endpointInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: c.handleEndpointUpdate,
	})
}
