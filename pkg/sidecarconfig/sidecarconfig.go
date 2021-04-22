/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package sidecarconfig

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"text/template"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/salesforce/generic-sidecar-injector/pkg/mutationconfig"
	"github.com/salesforce/generic-sidecar-injector/pkg/templates"
	"github.com/salesforce/generic-sidecar-injector/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	defaultVolumes = []corev1.Volume{
		{
			Name: "sidecar-lifecycle",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	}

	defaultVolumeMounts = []corev1.VolumeMount{
		{
			Name:      "sidecar-lifecycle",
			MountPath: "/var/run/sidecar-lifecycle",
		},
	}
)

// SidecarConfig encapsulates sidecar related config
type SidecarConfig struct {
	InitContainers []corev1.Container   `yaml:"initContainers"`
	Containers     []corev1.Container   `yaml:"containers"`
	Volumes        []corev1.Volume      `yaml:"volumes"`
	VolumeMounts   []corev1.VolumeMount `yaml:"volumeMounts"`
}

// NewSidecarConfig constructor for MutationConfigs
func NewSidecarConfig(sidecarConfigFile []byte) (*SidecarConfig, error) {
	config, err := parse(sidecarConfigFile)
	if err != nil {
		return nil, errors.Errorf("api=NewMutatingConfig, reason=parse, sidecarConfigFile=%q, err=%v", sidecarConfigFile, err)
	}
	return config, nil
}

// parse parses side car config file
func parse(configFile []byte) (*SidecarConfig, error) {
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(configFile))

	c := &SidecarConfig{}
	if err := yaml.Unmarshal(configFile, &c); err != nil {
		return nil, err
	}

	return c, nil
}

// NewPerMutationConfig creates a new SidecarConfig corresponding to a provided MutationConfig.
// The resources in the new SidecarConfig are copies of the originals and can be safely mutated.
func (sidecarConfig *SidecarConfig) NewPerMutationConfig(m mutationconfig.MutationConfig) *SidecarConfig {
	s := &SidecarConfig{}

	// parse out the init containers
	for _, i := range sidecarConfig.InitContainers {
		if contains(m.InitContainers, i.Name) {
			iCopy := i.DeepCopy()
			s.InitContainers = append(s.InitContainers, *iCopy)
		}
	}

	// parse out the containers
	for _, c := range sidecarConfig.Containers {
		if contains(m.Containers, c.Name) {
			cCopy := c.DeepCopy()
			s.Containers = append(s.Containers, *cCopy)
		}
	}

	// parse out the volumes
	for _, v := range sidecarConfig.Volumes {
		if contains(m.Volumes, v.Name) {
			vCopy := v.DeepCopy()
			s.Volumes = append(s.Volumes, *vCopy)
		}
	}

	// parse out the volumeMounts
	for _, vm := range sidecarConfig.VolumeMounts {
		if contains(m.VolumeMounts, vm.Name) {
			vmCopy := vm.DeepCopy()
			s.VolumeMounts = append(s.VolumeMounts, *vmCopy)
		}
	}

	return s
}

// AddSidecarLifecycleDefaults adds the standard Sidecar Lifecycle Volume and VolumeMounts.
func (sidecarConfig *SidecarConfig) AddSidecarLifecycleDefaults() {
	// Add defaults
	for i := range sidecarConfig.Containers {
		sidecarConfig.Containers[i].VolumeMounts = util.MergeVolumeMounts(sidecarConfig.Containers[i].VolumeMounts, defaultVolumeMounts)
	}
	sidecarConfig.VolumeMounts = util.MergeVolumeMounts(sidecarConfig.VolumeMounts, defaultVolumeMounts)
	sidecarConfig.Volumes = util.MergeVolumes(sidecarConfig.Volumes, defaultVolumes)
}

// ParseVolumeMountAnnotations looks for the configured volumeMount annotations in the provided MutationConfig.
// Unmarshal and add them to this SidecarConfig.
func (sidecarConfig *SidecarConfig) ParseVolumeMountAnnotations(annotations map[string]string, m mutationconfig.MutationConfig) error {
	tmpMounts := make([]corev1.VolumeMount, 0)
	for _, a := range m.AnnotationConfig.VolumeMounts {
		key := util.GetAnnotation(m.AnnotationNamespace, a.Name)
		value, ok := annotations[key]
		if !ok {
			// annotation does not exist, ignore and continue
			continue
		}

		if err := json.Unmarshal([]byte(value), &tmpMounts); err != nil {
			return errors.Errorf("reason=json.Unmarshal, key=%s, value=%s, err=%v", key, value, err)
		}

		mounts := make([]corev1.VolumeMount, len(tmpMounts))

		for i, vm := range tmpMounts {
			vm.DeepCopyInto(&mounts[i])
		}

		for i, ic := range sidecarConfig.InitContainers {
			if contains(a.InitContainerRefs, ic.Name) {
				// reference by index so that the append operation lives beyond the scope of the loop
				sidecarConfig.InitContainers[i].VolumeMounts = append(ic.VolumeMounts, mounts...)
			}
		}

		for i, c := range sidecarConfig.Containers {
			if contains(a.ContainerRefs, c.Name) {
				sidecarConfig.Containers[i].VolumeMounts = append(c.VolumeMounts, mounts...)
			}
		}

	}

	return nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// RenderTemplate takes a restricted pod struct, sidecarTemplate and fill in templated variables
func RenderTemplate(pod corev1.Pod, sidecarConfigTemplate *template.Template) (*SidecarConfig, error) {
	var tempBuffer strings.Builder
	err := sidecarConfigTemplate.Execute(&tempBuffer, pod)
	if err != nil {
		return nil, err
	}
	sidecarConfig, err := NewSidecarConfig([]byte(tempBuffer.String()))
	if err != nil {
		return nil, err
	}
	return sidecarConfig, nil
}

// TemplateSanityCheck ensures given template has valid templated field
func TemplateSanityCheck(sidecarConfigTemplate *template.Template) error {
	const annotationValueAsYaml = `
some:
- yaml
- array
with:
  yaml: object`

	dummyPod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"rsyslog.k8s-integration.sfdc.com/test-volume-mounts": "test",
				"rsyslog.k8s-integration.sfdc.com/log-volume-mounts":  "test",
				"vault.k8s-integration.sfdc.com/vaultRole":            "test",
				"vault.k8s-integration.sfdc.com/config":               annotationValueAsYaml,
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "test",
		},
	}
	_, err := RenderTemplate(dummyPod, sidecarConfigTemplate)
	return err
}

func SidecarTemplateExtraFuncs() template.FuncMap {
	return template.FuncMap{
		"fromYaml": templates.FromYAML,
	}
}
