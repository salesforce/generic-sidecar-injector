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
	"strings"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/golang/glog"
	"github.com/pkg/errors"

	corev1 "k8s.io/api/core/v1"
)

//TODO: Use shared operation function in service mesh webhook

const (
	admissionWebhookVolumeNameKey = "svcaccount"
	clientCertMountPath           = "/etc/identity/client"
	clientCertMountName           = "clientcert"
	serverCertMountPath           = "/etc/identity/server"
	serverCertMountName           = "servercert"
	secretMountPath               = "/secrets/serviceaccount"
	secretMountName               = "svcaccount"
)

const (
	// jsonPatchAdd json field for add
	jsonPatchAdd string = "add"
	// jsonPatchRemove json field for remove
	jsonPatchRemove string = "remove"
	// jsonPatchReplace json field for replace
	jsonPatchReplace string = "replace"
	// jsonPatchMove json field for move
	jsonPatchMove string = "move"
	// jsonPatchCopy json field for copy
	jsonPatchCopy string = "copy"
	// jsonPatchTest json field for test
	jsonPatchTest string = "test"
)

// Modify defines a modification on a Container
type Modify func(*corev1.Container)

func modifyContainers(containers []corev1.Container, basePath string, modify Modify) (patch []patchOperation) {
	// jsonPatch `remove` is applied sequentially. Remove items in reverse
	// order to avoid renumbering indices.
	for i := len(containers) - 1; i >= 0; i-- {
		glog.Infof("container being removed %v", containers[i])
		patch = append(patch, removeContainer(i, basePath)...)
		modify(&containers[i])
		glog.Infof("container being added %v", containers[i])
		patch = append(patch, addContainer(containers[i], basePath)...)
	}
	return patch
}

func replaceImage(index int, newImage string) (patch []patchOperation) {
	patch = append(patch, patchOperation{
		Op:    jsonPatchReplace,
		Path:  fmt.Sprintf("/spec/containers/%d/image", index),
		Value: newImage,
	})
	return patch
}

func modifyInitContainers(containers []corev1.Container, basePath string, modify Modify) (patch []patchOperation) {
	// jsonPatch `remove` is applied sequentially.
	var tempPatch []patchOperation
	for i := len(containers) - 1; i >= 0; i-- {
		glog.Infof("container being removed %v", containers[i])
		patch = append(patch, removeContainer(i, basePath)...)
		modify(&containers[i])
		glog.Infof("container being added %v", containers[i])
		tempPatch = append(tempPatch, addContainer(containers[i], basePath)...)

	}

	// But we can not append patches to init container the same way as remove as that will
	// reverse the order of init container execution. Thus we add them back in reverse
	for i := len(tempPatch) - 1; i >= 0; i-- {
		patch = append(patch, tempPatch[i])
	}
	return patch
}

func removeContainer(containerIndex int, basePath string) (patch []patchOperation) {
	patch = append(patch, patchOperation{
		Op:    jsonPatchRemove,
		Path:  fmt.Sprintf("%v/%v", basePath, containerIndex),
		Value: nil,
	})
	return patch
}

func addContainer(container corev1.Container, basePath string) (patch []patchOperation) {
	var value interface{}
	var path = basePath + "/-"
	value = container
	patch = append(patch, patchOperation{
		Op:    jsonPatchAdd,
		Path:  path,
		Value: value,
	})
	return patch
}

func addContainers(target, added []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path += "/-"
		}
		patch = append(patch, patchOperation{
			Op:    jsonPatchAdd,
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addVolumes(target, added []corev1.Volume, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    jsonPatchAdd,
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func updateAnnotations(target, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		escapedKey := escapeJSONPointer(key)
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:    jsonPatchAdd,
				Path:  "/metadata/annotations/" + escapedKey,
				Value: value,
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    jsonPatchReplace,
				Path:  "/metadata/annotations/" + escapedKey,
				Value: value,
			})
		}
	}
	return patch
}

// escapeJSONPointer https://tools.ietf.org/html/rfc6902
func escapeJSONPointer(value string) string {
	result := strings.Replace(value, "~", "~0", -1)
	result = strings.Replace(result, "/", "~1", -1)
	return result
}

// Given a pod and a set of json patches, compute the resulting pod definition.
// If more than one mutation is applied to a pod, the caller should use this function
// to ensure that their view of the pod is consistent with patches applied in the same
// transaction.
func applyPatches(pod *corev1.Pod, patches []patchOperation) (*corev1.Pod, error) {
	podJSON, err := json.Marshal(pod)
	if err != nil {
		return nil, errors.Errorf("failed to marshal original pod: %v", err)
	}

	patchJSON, err := json.Marshal(patches)
	if err != nil {
		return nil, errors.Errorf("failed to marshal patches: %v", err)
	}

	p, err := jsonpatch.DecodePatch(patchJSON)
	if err != nil {
		return nil, errors.Errorf("failed to decode patches: %v", err)
	}

	modifiedPodJSON, err := p.Apply(podJSON)
	if err != nil {
		return nil, errors.Errorf("failed to apply patches: %v", err)
	}

	modifiedPod := &corev1.Pod{}
	if err := json.Unmarshal(modifiedPodJSON, modifiedPod); err != nil {
		return nil, errors.Errorf("failed to unmarshal modified pod: %v", err)
	}

	return modifiedPod, nil
}
