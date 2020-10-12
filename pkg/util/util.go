/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package util

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

const (
	// TemplateLeftDelimiter is left delimeter for sidecar config
	TemplateLeftDelimiter = "{%"
	// TemplateRightDelimiter is right delimeter for sidecar config
	TemplateRightDelimiter = "%}"
)

// GetAnnotation formats a fully qualified annotation  from a prefix and a name.
// For example, with prefix "annotation.io" and name "key", it returns "annotation.io/key".
func GetAnnotation(prefix string, name string) string {
	// TODO validation on prefix/name? K8s has some restrictions on what are valid annotations.
	// See https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/.
	return fmt.Sprintf("%s/%s", prefix, name)
}

// MergeVolumes merges target with added, but only if a Volume does not exist in target.
func MergeVolumes(target, added []corev1.Volume) []corev1.Volume {
	return append(target, DeDuplicateVolumes(target, added)...)
}

// MergeVolumeMounts merges target with added, but only if a Volume does not exist in target.
func MergeVolumeMounts(target, added []corev1.VolumeMount) []corev1.VolumeMount {
	return append(target, DeDuplicateVolumeMounts(target, added)...)
}

// DeDuplicateVolumes returns all or some of added only if they do not already exist in target
func DeDuplicateVolumes(target, added []corev1.Volume) []corev1.Volume {
	var uniqueVolumes []corev1.Volume
	targetNames := map[string]bool{}
	for _, v := range target {
		targetNames[v.Name] = true
	}
	for _, add := range added {
		if _, exists := targetNames[add.Name]; !exists {
			uniqueVolumes = append(uniqueVolumes, add)
		}
	}
	return uniqueVolumes
}

// DeDuplicateVolumeMounts returns all or some of added only if they do not already exist in target
func DeDuplicateVolumeMounts(target, added []corev1.VolumeMount) []corev1.VolumeMount {
	var uniqueVolumeMounts []corev1.VolumeMount
	targetNames := map[string]bool{}
	for _, vm := range target {
		targetNames[vm.Name] = true
	}
	for _, add := range added {
		if _, exists := targetNames[add.Name]; !exists {
			uniqueVolumeMounts = append(uniqueVolumeMounts, add)
		}
	}
	return uniqueVolumeMounts
}
