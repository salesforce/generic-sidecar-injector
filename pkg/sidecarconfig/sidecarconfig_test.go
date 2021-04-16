/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package sidecarconfig

import (
	"encoding/json"
	"io/ioutil"
	"testing"
	"text/template"

	"github.com/salesforce/generic-sidecar-injector/pkg/mutationconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	sidecarConfigFile     = "../../testdata/sidecarconfigs.yaml"
	mutationConfigFile    = "../../testdata/mutationconfigs.yaml"
	mutationConfigFileBad = "../../testdata/mutationconfigs_bad.yaml"
	keymakerResultFile    = "../../testdata/result/keymaker"
	keymakerBadResultFile = "../../testdata/result/keymaker_bad"
	maddogResultFile      = "../../testdata/result/maddog"
)

var (
	scf []byte
	pod corev1.Pod
	tpl *template.Template
)

func init() {
	scf, _ = ioutil.ReadFile(sidecarConfigFile)
	pod = corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"vault.k8s-integration.sfdc.com/role": "hello",
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "world",
		},
	}
	tpl, _ = template.New("test").Delims("{%", "%}").Parse(string(scf))
}

func TestLoadConfig(t *testing.T) {
	s, err := RenderTemplate(pod, tpl)
	require.NoError(t, err)
	assert.Equal(t, s.InitContainers[0].Name, "ca-populator")
	assert.Equal(t, s.Volumes[12].Name, "aws-iam-credentials")
	assert.Equal(t, s.Containers[2].Name, "rsyslog-test-sidecar")
	assert.Equal(t, s.VolumeMounts[2].Name, "clientcert")
	assert.Len(t, s.InitContainers, 8)
	assert.Len(t, s.Volumes, 13)
	assert.Len(t, s.Containers, 6)
	assert.Len(t, s.VolumeMounts, 7)
}

func TestNewPerMutationConfig(t *testing.T) {
	mc, err := mutationconfig.NewMutatingConfigs(mutationConfigFile)
	assert.NoError(t, err)

	sc, err := RenderTemplate(pod, tpl)
	require.NoError(t, err)

	// Validate keymaker config
	s := sc.NewPerMutationConfig(mc.MutationConfigs[0])
	sb, _ := json.Marshal(s)
	b, err := ioutil.ReadFile(keymakerResultFile)
	assert.NoError(t, err)
	assert.Equal(t, string(b), string(sb))

	// Validate maddog config
	s = sc.NewPerMutationConfig(mc.MutationConfigs[1])
	sb, _ = json.Marshal(s)
	b, err = ioutil.ReadFile(maddogResultFile)
	assert.NoError(t, err)
	assert.Equal(t, string(b), string(sb))
}

func TestBadNewPerMutationConfig(t *testing.T) {
	mc, err := mutationconfig.NewMutatingConfigs(mutationConfigFileBad)
	assert.NoError(t, err)

	sc, err := RenderTemplate(pod, tpl)
	require.NoError(t, err)

	// Validate bad keymaker config
	s := sc.NewPerMutationConfig(mc.MutationConfigs[0])
	sb, _ := json.Marshal(s)

	b, err := ioutil.ReadFile(keymakerBadResultFile)
	assert.NoError(t, err)
	assert.Equal(t, string(b), string(sb))

	b, err = ioutil.ReadFile(keymakerResultFile)
	assert.NoError(t, err)
	assert.NotEqual(t, string(b), string(sb))
}

func TestAddSidecarLifecycleDefaults(t *testing.T) {
	mc, err := mutationconfig.NewMutatingConfigs(mutationConfigFile)
	assert.NoError(t, err)

	sc, err := RenderTemplate(pod, tpl)
	require.NoError(t, err)

	// Validate simple config
	s := sc.NewPerMutationConfig(mc.MutationConfigs[4])
	s.AddSidecarLifecycleDefaults()

	assert.Len(t, s.Containers, 1)
	assert.Len(t, s.Volumes, 1)
	assert.Equal(t, "sidecar-lifecycle", s.Volumes[0].Name)
	assert.Len(t, s.Containers[0].VolumeMounts, 1)
	assert.Equal(t, "sidecar-lifecycle", s.Containers[0].VolumeMounts[0].Name)
	assert.Len(t, s.VolumeMounts, 1)
}

func TestRenderTemplate(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"test-annotation-key": "hello",
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "world",
		},
	}
	tpl, _ := template.New("test").Delims("{%", "%}").Parse("volumes:\n- name: test-volume \n  secret: \n   secretName: {% index .Annotations \"test-annotation-key\"  %}-{% .Spec.ServiceAccountName %}")
	rendered, err := RenderTemplate(pod, tpl)
	require.NoError(t, err)
	assert.Equal(t, "hello-world", rendered.Volumes[0].Secret.SecretName)
}

func TestTemplateSanityCheck(t *testing.T) {
	goodTpl, _ := template.New("goodTest").Funcs(SidecarTemplateExtraFuncs()).Delims("{%", "%}").Parse("volumes:\n- name: test-volume \n  secret: \n   secretName: {% index .Annotations \"test-annotation-key\"  %}-{% .Spec.ServiceAccountName %}")
	assert.NoError(t, TemplateSanityCheck(goodTpl))
	badTpl, _ := template.New("badTest").Funcs(SidecarTemplateExtraFuncs()).Delims("{%", "%}").Parse("volumes:\n- name: test-volume \n  secret: \n   secretName: {% .bad %}")
	assert.Error(t, TemplateSanityCheck(badTpl))

	yamlTpl, _ := template.New("yamlTest").Funcs(SidecarTemplateExtraFuncs()).Delims("{%", "%}").Parse("volumes:\n- name: test-volume \n  secret: \n   secretName: {% with $yaml := (index .Annotations \"vault.k8s-integration.sfdc.com/config\") | fromYaml -%}{%- $yaml.with.yaml -%}-{%- index $yaml.some 0 -%}{%- end -%}")
	assert.NoError(t, TemplateSanityCheck(yamlTpl))
}
