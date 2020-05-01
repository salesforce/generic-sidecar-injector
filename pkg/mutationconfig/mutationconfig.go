/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package mutationconfig

import (
	"io/ioutil"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// MutationConfigs encapsulates set of mutation configs
type MutationConfigs struct {
	MutationConfigs []MutationConfig `yaml:"mutationConfigs,flow"`
}

// MutationConfig encapsulates a single mutation config
type MutationConfig struct {
	Name                                  string           `yaml:"name"`
	AnnotationNamespace                   string           `yaml:"annotationNamespace"`
	AnnotationTrigger                     string           `yaml:"annotationTrigger"`
	AnnotationConfig                      annotationConfig `yaml:"annotationConfig,flow"`
	InitContainersBeforePodInitContainers []string         `yaml:"initContainersBeforePodInitContainers,omitempty,flow"`
	InitContainers                        []string         `yaml:"initContainers,flow"`
	Containers                            []string         `yaml:"containers,flow"`
	Volumes                               []string         `yaml:"volumes,flow"`
	VolumeMounts                          []string         `yaml:"volumeMounts,flow"`
	IgnoreNamespaces                      []string         `yaml:"ignoreNamespaces,flow"`
	WhitelistNamespaces                   []string         `yaml:"whitelistNamespaces,flow"`
	ImplementsSidecarLifecycle            bool             `yaml:"implementsSidecarLifecycle,omitempty,flow"`
}

type annotationConfig struct {
	VolumeMounts []volumeMountAnnotation `yaml:"volumeMounts,flow"`
}

type volumeMountAnnotation struct {
	Name              string   `yaml:"name,flow"`
	InitContainerRefs []string `yaml:"initContainerRefs,flow"`
	ContainerRefs     []string `yaml:"containerRefs,flow"`
}

// NewMutatingConfigs constructor for MutationConfigs
func NewMutatingConfigs(mutationConfigsFile string) (*MutationConfigs, error) {
	config, err := parse(mutationConfigsFile)
	if err != nil {
		return nil, errors.Errorf("api=NewMutatingConfig, reason=parse, mutationConfigsFile=%q, err=%v", mutationConfigsFile, err)
	}
	return config, nil
}

// parse parses mutation configs
func parse(configFilePath string) (config *MutationConfigs, err error) {
	configFile, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}
	c := &MutationConfigs{}
	err = yaml.Unmarshal(configFile, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}
