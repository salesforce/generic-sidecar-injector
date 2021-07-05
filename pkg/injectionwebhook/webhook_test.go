/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package injectionwebhook

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"

	"github.com/salesforce/generic-sidecar-injector/pkg/injectionwebhook/config"
	"github.com/salesforce/generic-sidecar-injector/pkg/mutationconfig"
	"github.com/salesforce/generic-sidecar-injector/pkg/sidecarconfig"
	"github.com/salesforce/generic-sidecar-injector/pkg/util"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	sidecarConfigFile         = "../../testdata/sidecarconfigs.yaml"
	mutationConfigFile        = "../../testdata/mutationconfigs.yaml"
	admissionReviewFile       = "../../testdata/admissionreview.json"
	admissionReviewResultFile = "../../testdata/result/admissionresponse"
)

var (
	ar  v1.AdmissionReview
	pod corev1.Pod

	sct *template.Template
	mc  *mutationconfig.MutationConfigs
)

func init() {
	sct, _ = template.New(filepath.Base(sidecarConfigFile)).Delims(util.TemplateLeftDelimiter, util.TemplateRightDelimiter).ParseFiles(sidecarConfigFile)
	mc, _ = mutationconfig.NewMutatingConfigs(mutationConfigFile)

	data, _ := ioutil.ReadFile(admissionReviewFile)
	_, _, _ = deserializer.Decode(data, nil, &ar)

	req := ar.Request
	json.Unmarshal(req.Object.Raw, &pod)
}

// Return a patch as a newline-delimited "op path value(omitIfNil)".
// Easily check what's being added/removed when the test fails.
func toHumanReadablePatch(patchString []byte) string {
	var patches []patchOperation
	_ = json.Unmarshal(patchString, &patches)
	var formatted []string
	for _, p := range patches {
		if reflect.ValueOf(p.Value).Kind() == reflect.Map {
			formatted = append(formatted, fmt.Sprintf("%s %s %s", p.Op, p.Path, p.Value.(map[string]interface{})["name"].(string)))
		} else if reflect.ValueOf(p.Value).Kind() == reflect.String {
			formatted = append(formatted, fmt.Sprintf("%s %s %s", p.Op, p.Path, p.Value.(string)))
		} else {
			formatted = append(formatted, fmt.Sprintf("%s %s", p.Op, p.Path))
		}
	}
	return strings.Join(formatted, "\n")
}

// Do a mutation round given a Pod, a set of MutationConfigs, and expected Status.
func doTestMutate(t *testing.T, pod corev1.Pod, mutationConfigs []mutationconfig.MutationConfig, expectStatus mutationStatus) (*corev1.Pod, error) {
	whsvr := &WebhookServer{
		config: &config.WebhookConfig{
			SidecarConfigFile:  sidecarConfigFile,
			MutationConfigFile: mutationConfigFile,
		},
		sidecarConfigTemplate: sct,
		mutatingConfig:        mc,
	}
	sc, err := sidecarconfig.RenderTemplate(pod, sct)
	if err != nil {
		return nil, err
	}
	statusForMutations, patches, err := whsvr.mutatePod("default", &pod, mutationConfigs, sc)
	// Check statusForMutations before returning error from mutatePod
	assert.Equal(t, len(mutationConfigs), len(statusForMutations))
	for _, status := range statusForMutations {
		assert.Equal(t, expectStatus, status)
	}
	if err != nil {
		return nil, err
	}
	var mutatedPod *corev1.Pod
	mutatedPod, err = applyPatches(&pod, patches)
	assert.NoErrorf(t, err, "applyPatches err=%v", err)

	return mutatedPod, nil
}

func doTestMutateAndExpectSuccess(t *testing.T, pod corev1.Pod, mutationConfigs []mutationconfig.MutationConfig) *corev1.Pod {
	mutatedPod, _ := doTestMutate(t, pod, mutationConfigs, succeededMutation)
	return mutatedPod
}

func doTestMutateAndExpectError(t *testing.T, pod corev1.Pod, mutationConfigs []mutationconfig.MutationConfig) error {
	_, err := doTestMutate(t, pod, mutationConfigs, failedMutation)
	return err
}

func TestMutate(t *testing.T) {
	whsvr := &WebhookServer{
		config: &config.WebhookConfig{
			SidecarConfigFile:  sidecarConfigFile,
			MutationConfigFile: mutationConfigFile,
		},
		sidecarConfigTemplate: sct,
		mutatingConfig:        mc,
	}
	admissionResponse, statusForMutations := whsvr.mutate(&ar)

	data, _ := ioutil.ReadFile(admissionReviewResultFile)
	assert.Equal(t, string(data), string(admissionResponse.Patch),
		fmt.Sprintf("## EXPECTED ##\n%s\n\n## ACTUAL ##\n%s", toHumanReadablePatch(data), toHumanReadablePatch(admissionResponse.Patch)))
	assert.Len(t, statusForMutations, 6)
	for key, val := range statusForMutations {
		if strings.HasPrefix(key, "keymaker") || strings.HasPrefix(key, "madkub") {
			assert.Equal(t, succeededMutation, val)
		} else {
			assert.Equal(t, skippedMutation, val)
		}
	}
}

func TestIsShortRunningWorkload(t *testing.T) {
	var shortRunningWorkloadTests = []struct {
		pod            *corev1.Pod
		isShortRunning bool
	}{
		{

			&corev1.Pod{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyOnFailure,
				},
			},
			true,
		},
		{
			&corev1.Pod{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
				},
			},
			true,
		},
		{
			&corev1.Pod{
				Spec: corev1.PodSpec{
					RestartPolicy: "Never",
				},
			},
			true,
		},
		{
			&corev1.Pod{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyAlways,
				},
			},
			false,
		},
		{

			&corev1.Pod{
				Spec: corev1.PodSpec{
					RestartPolicy: "Always",
				},
			},
			false,
		},
	}

	for _, w := range shortRunningWorkloadTests {
		assert.Equal(t, w.isShortRunning, isShortRunningWorkload(w.pod))
	}
}

func TestDefaultsAreInjectedToJobPod(t *testing.T) {
	// It's a mostly-empty Pod with a non-Always RestartPolicy!
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"simple.k8s-integration.sfdc.com/inject": "enabled",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "container",
				},
			},
			RestartPolicy: corev1.RestartPolicyOnFailure,
		},
	}

	// Simple mutation config
	m4 := mc.MutationConfigs[4]
	mutatedPod := doTestMutateAndExpectSuccess(t, pod, []mutationconfig.MutationConfig{m4})

	// Should be 1 default Volume
	assert.Len(t, mutatedPod.Spec.Volumes, 1)
	assert.Equal(t, "sidecar-lifecycle", mutatedPod.Spec.Volumes[0].Name)
	assert.Len(t, mutatedPod.Spec.Containers[0].VolumeMounts, 1)
	// And 1 default VolumeMount in the original Container
	assert.Equal(t, "sidecar-lifecycle", mutatedPod.Spec.Containers[0].VolumeMounts[0].Name)
	assert.Equal(t, "/var/run/sidecar-lifecycle", mutatedPod.Spec.Containers[0].VolumeMounts[0].MountPath)

	// There should be 1 additional injected sidecar
	assert.Len(t, mutatedPod.Spec.Containers, 2)
	// And it should also have a default VolumeMount
	assert.Len(t, mutatedPod.Spec.Containers[1].VolumeMounts, 1)
	assert.Equal(t, "sidecar-lifecycle", mutatedPod.Spec.Containers[1].VolumeMounts[0].Name)
	assert.Equal(t, "/var/run/sidecar-lifecycle", mutatedPod.Spec.Containers[1].VolumeMounts[0].MountPath)
}

func TestDefaultsAreOverridable(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"simple.k8s-integration.sfdc.com/inject": "enabled",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "container",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "sidecar-lifecycle",
							MountPath: "/override/sidecar-lifecycle",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "sidecar-lifecycle",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{},
					},
				},
			},
			RestartPolicy: corev1.RestartPolicyOnFailure,
		},
	}

	// noop mutation config
	m4 := mc.MutationConfigs[4]
	mutatedPod := doTestMutateAndExpectSuccess(t, pod, []mutationconfig.MutationConfig{m4})

	assert.Len(t, mutatedPod.Spec.Volumes, 1)
	assert.Equal(t, "sidecar-lifecycle", mutatedPod.Spec.Volumes[0].Name)
	assert.Len(t, mutatedPod.Spec.Containers[0].VolumeMounts, 1)
	assert.Equal(t, "sidecar-lifecycle", mutatedPod.Spec.Containers[0].VolumeMounts[0].Name)
	assert.Equal(t, "/override/sidecar-lifecycle", mutatedPod.Spec.Containers[0].VolumeMounts[0].MountPath)
}

func TestMutationRequired(t *testing.T) {
	whsvr := &WebhookServer{
		config: &config.WebhookConfig{
			SidecarConfigFile:  sidecarConfigFile,
			MutationConfigFile: mutationConfigFile,
		},
		sidecarConfigTemplate: sct,
		mutatingConfig:        mc,
	}

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"keymaker.k8s-integration.sfdc.com/inject": "false",
				"madkub.k8s-integration.sfdc.com/inject":   "true",
				"vault.k8s-integration.sfdc.com/inject":    "enabled",
			},
		},
	}

	// Test keymaker injection required should be false when annotation says false
	m0 := mc.MutationConfigs[0]
	assert.False(t, whsvr.mutationRequired(&m0, "default", &pod))

	// Test madkub injection required should be true when annotation says true
	m1 := mc.MutationConfigs[1]
	assert.True(t, whsvr.mutationRequired(&m1, "default", &pod))

	// Test vault injection required should be true when annotation says enabled
	m3 := mc.MutationConfigs[3]
	assert.True(t, whsvr.mutationRequired(&m3, "default", &pod))
}

func TestMutatePodWithTemplatedConfig(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"vault.k8s-integration.sfdc.com/inject": "enabled",
				"vault.k8s-integration.sfdc.com/role":   "superSecretVaultRole",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "container",
				},
			},
			InitContainers: []corev1.Container{
				{
					Name: "init-container",
				},
			},
			ServiceAccountName: "secretServiceAccountName",
			RestartPolicy:      corev1.RestartPolicyAlways,
		},
	}

	m := mc.MutationConfigs[3]
	mutatedPod := doTestMutateAndExpectSuccess(t, pod, []mutationconfig.MutationConfig{m})

	assert.Equal(t, "container", mutatedPod.Spec.Containers[0].Name)
	assert.Equal(t, "vault-agent", mutatedPod.Spec.Containers[1].Name)
	assert.Equal(t, "init-container", mutatedPod.Spec.InitContainers[0].Name)
	assert.Equal(t, "vault-agent-init", mutatedPod.Spec.InitContainers[1].Name)
	assert.Equal(t, "vault-token", mutatedPod.Spec.Volumes[0].Name)
	assert.Equal(t, "aws-iam-secretServiceAccountName", mutatedPod.Spec.Volumes[3].Secret.SecretName)
	assert.Equal(t, "superSecretVaultRole", mutatedPod.Spec.Containers[1].Env[0].Value)
}

func TestMutatePodRsyslog(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"rsyslog.k8s-integration.sfdc.com/inject": "enabled",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "container",
				},
			},
			InitContainers: []corev1.Container{
				{
					Name: "init-container",
				},
			},
			RestartPolicy: corev1.RestartPolicyAlways,
		},
	}

	m := mc.MutationConfigs[2]
	mutatedPod := doTestMutateAndExpectSuccess(t, pod, []mutationconfig.MutationConfig{m})

	assert.Equal(t, "container", mutatedPod.Spec.Containers[0].Name)
	assert.Equal(t, "rsyslog-sidecar", mutatedPod.Spec.Containers[1].Name)
	assert.Equal(t, "init-container", mutatedPod.Spec.InitContainers[0].Name)
	assert.Equal(t, "rsyslog-spool-vol", mutatedPod.Spec.Volumes[0].Name)
}

// Make sure multiple injections properly patch the Pod and do not overwrite each other
func TestMutatePodTwoInjections(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"rsyslog.k8s-integration.sfdc.com/inject": "enabled",
				"madkub.k8s-integration.sfdc.com/inject":  "enabled",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "container",
				},
			},
			RestartPolicy: corev1.RestartPolicyAlways,
		},
	}

	m1 := mc.MutationConfigs[1]
	m2 := mc.MutationConfigs[2]
	mutatedPod := doTestMutateAndExpectSuccess(t, pod, []mutationconfig.MutationConfig{m1, m2})

	// 1 original + 2 rsyslog + 1 madkub
	assert.Len(t, mutatedPod.Spec.Containers, 4)
	// 0 original + 1 rsyslog + 2 madkub
	assert.Len(t, mutatedPod.Spec.InitContainers, 3)
	// 0 original + 3 rsyslog + 5 madkub
	assert.Len(t, mutatedPod.Spec.Volumes, 8)
}

func TestMutatePodWithNonAlwaysRestartPolicy(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"madkub.k8s-integration.sfdc.com/inject": "enabled",
			},
		},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{
					Name: "init-container",
				},
			},
			Containers: []corev1.Container{
				{
					Name: "container",
				},
			},
			RestartPolicy: corev1.RestartPolicyOnFailure,
		},
	}

	// Grab the madkub mutationconfigs
	m := mc.MutationConfigs[1]
	mutatedPod := doTestMutateAndExpectSuccess(t, pod, []mutationconfig.MutationConfig{m})

	// 1 original + 0 madkub, RestartPolicy = OnFailure should skip sidecar container injection
	assert.Len(t, mutatedPod.Spec.Containers, 1)
	// 1 original + 2 madkub
	assert.Len(t, mutatedPod.Spec.InitContainers, 3)
}

func TestMutatePodWithVolumeMountAnnotations(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"rsyslog.k8s-integration.sfdc.com/inject": "enabled",
				"rsyslog.k8s-integration.sfdc.com/log-volume-mounts": `
				[
					{
						"name": "log-volume",
						"mountPath": "/logs"
					}
				]`,
				"rsyslog.k8s-integration.sfdc.com/test-volume-mounts": `
				[
					{
						"name": "test-volume",
						"mountPath": "/test-path"
					}
				]`,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "container",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "log-volume",
							MountPath: "/app-logs",
						},
					},
				},
			},
			InitContainers: []corev1.Container{
				{
					Name: "init-container",
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "log-volume",
				},
				{
					Name: "test-volume",
				},
			},
			RestartPolicy: corev1.RestartPolicyAlways,
		},
	}

	m := mc.MutationConfigs[2]
	mutatedPod := doTestMutateAndExpectSuccess(t, pod, []mutationconfig.MutationConfig{m})

	// 1st sidecar has 2 existing mounts + 2 configured
	assert.Len(t, mutatedPod.Spec.Containers[1].VolumeMounts, 4)
	assert.Equal(t, "rsyslog-sidecar", mutatedPod.Spec.Containers[1].Name)
	assert.Equal(t, "rsyslog-spool-vol", mutatedPod.Spec.Containers[1].VolumeMounts[0].Name)
	assert.Equal(t, "rsyslog-conf-gen", mutatedPod.Spec.Containers[1].VolumeMounts[1].Name)
	assert.Equal(t, "log-volume", mutatedPod.Spec.Containers[1].VolumeMounts[2].Name)
	assert.Equal(t, "test-volume", mutatedPod.Spec.Containers[1].VolumeMounts[3].Name)
	assert.Equal(t, "/logs", mutatedPod.Spec.Containers[1].VolumeMounts[2].MountPath)

	// 2nd sidecar has 0 existing mounts + 1 configured
	assert.Equal(t, "test-volume", mutatedPod.Spec.Containers[2].VolumeMounts[0].Name)
	// init has 2 existing mounts
	assert.Equal(t, "test-volume", mutatedPod.Spec.InitContainers[1].VolumeMounts[2].Name)
}

func TestMutatePodWithBadVolumeMountAnnotations(t *testing.T) {
	// Missing a curly bracket
	badPod1 := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"rsyslog.k8s-integration.sfdc.com/inject": "enabled",
				"rsyslog.k8s-integration.sfdc.com/test-volume-mounts": `
				[	
						"name": "test-volume",
						"mountPath": "/test-path"
					}
				]`,
			},
		},
	}

	m := mc.MutationConfigs[2]
	err := doTestMutateAndExpectError(t, badPod1, []mutationconfig.MutationConfig{m})

	assert.Error(t, err)

	// not an array
	badPod2 := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"rsyslog.k8s-integration.sfdc.com/inject": "enabled",
				"rsyslog.k8s-integration.sfdc.com/test-volume-mounts": `
					{
						"name": "test-volume",
						"mountPath": "/test-path"
					}`,
			},
		},
	}

	err = doTestMutateAndExpectError(t, badPod2, []mutationconfig.MutationConfig{m})

	assert.Error(t, err)
}

func TestMutateWithInitBeforePodInit(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"vaultReverse.k8s-integration.sfdc.com/inject": "enabled",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "container",
				},
			},
			InitContainers: []corev1.Container{
				{
					Name: "init-container",
				},
			},
			ServiceAccountName: "secretServiceAccountName",
			RestartPolicy:      corev1.RestartPolicyAlways,
		},
	}

	m := mc.MutationConfigs[5]
	mutatedPod := doTestMutateAndExpectSuccess(t, pod, []mutationconfig.MutationConfig{m})
	// consul-template-init is listed before pod's initContainers because of this line in mutationConfig:
	// initContainersBeforePodInitContainers: ["consul-template-init"]
	assert.Len(t, mutatedPod.Spec.InitContainers, 3)
	assert.Equal(t, "consul-template-init", mutatedPod.Spec.InitContainers[0].Name)
	assert.Equal(t, "init-container", mutatedPod.Spec.InitContainers[1].Name)
	assert.Equal(t, "vault-agent-init", mutatedPod.Spec.InitContainers[2].Name)
	assert.Equal(t, m.VolumeMounts[0], mutatedPod.Spec.InitContainers[1].VolumeMounts[0].Name)
}

func TestHealthz(t *testing.T) {
	// Arrange
	wc := &config.WebhookConfig{}
	whs := NewWebhookServer(wc, sct, mc, nil)
	req := httptest.NewRequest("POST", "http://localhost:9999/mutate", strings.NewReader("OK"))
	req.Header.Add("Content-Type", "application/json")
	respWriter := httptest.NewRecorder()

	// Act
	whs.healthz(respWriter, req)

	// Assert
	assert.Equal(t, http.StatusOK, respWriter.Code)
}

func TestGetInitContainersBeforeAfterPodInitContainers(t *testing.T) {
	scf, _ := ioutil.ReadFile(sidecarConfigFile)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"vaultReverse.k8s-integration.sfdc.com/inject": "enabled",
			},
		},
	}
	tpl, _ := template.New("test").Delims("{%", "%}").Parse(string(scf))
	sc, err := sidecarconfig.RenderTemplate(pod, tpl)
	require.NoError(t, err)
	m := mc.MutationConfigs[5]
	s := sc.NewPerMutationConfig(m)
	initsBefore, initsAfter := getInitContainers(m.InitContainersBeforePodInitContainers, s.InitContainers)
	assert.Len(t, initsBefore, 1)
	assert.Len(t, initsAfter, 1)
	assert.Equal(t, "consul-template-init", initsBefore[0].Name)
	assert.Equal(t, "vault-agent-init", initsAfter[0].Name)
}
