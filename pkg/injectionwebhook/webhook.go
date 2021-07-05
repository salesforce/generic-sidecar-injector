/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package injectionwebhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"text/template"

	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/salesforce/generic-sidecar-injector/pkg/injectionwebhook/config"
	"github.com/salesforce/generic-sidecar-injector/pkg/metrics"
	"github.com/salesforce/generic-sidecar-injector/pkg/mutationconfig"
	"github.com/salesforce/generic-sidecar-injector/pkg/sidecarconfig"
	"github.com/salesforce/generic-sidecar-injector/pkg/util"

	"k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	// https://github.com/kubernetes/kubernetes/issues/57982
	defaulter = runtime.ObjectDefaulter(runtimeScheme)
)

var ignoredSystemNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

type mutationStatus int

const (
	failedMutation    mutationStatus = 0
	skippedMutation   mutationStatus = 1
	succeededMutation mutationStatus = 2
)

const (
	annotationStatusKey      = "status"
	annotationStatusInjected = "injected"

	injectionStatusSkipped = "skipped"
	injectionStatusFailure = "failure"
	injectionStatusSuccess = "success"
)

func init() {
	// AddToScheme is a global function that registers this API group & version to a scheme
	_ = admissionregistrationv1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	_ = corev1.AddToScheme(runtimeScheme)
}

// WebhookServer encapsulates webhook server related fields
type WebhookServer struct {
	tlsServer             *http.Server
	httpServer            *http.Server
	config                *config.WebhookConfig
	sidecarConfigTemplate *template.Template
	mutatingConfig        *mutationconfig.MutationConfigs
	certificateReloader   util.CertificateReloader
}

// NewWebhookServer is a constructor for webhookServer
func NewWebhookServer(
	config *config.WebhookConfig,
	sidecarConfigTemplate *template.Template,
	mutationConfig *mutationconfig.MutationConfigs,
	certificateReloader util.CertificateReloader,
) *WebhookServer {
	srv := &WebhookServer{
		config:                config,
		sidecarConfigTemplate: sidecarConfigTemplate,
		mutatingConfig:        mutationConfig,
		certificateReloader:   certificateReloader,
	}
	return srv
}

// mutate method for mutation webhook
func (whsvr *WebhookServer) mutate(ar *v1.AdmissionReview) (admissionResponse *v1.AdmissionResponse, statusForMutations map[string]mutationStatus) {
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		glog.Errorf("api=mutate, reason=json.Unmarshal, message=invalid raw object, err=%v", err)
		return &v1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}, nil
	}

	glog.Errorf("api=mutate, message=new AdmissionReview, Kind=%v, Namespace=%v, Name=%v (%v), UID=%v, patchOperation=%v, UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	sidecarConfig, err := sidecarconfig.RenderTemplate(corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: pod.Annotations,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: pod.Spec.ServiceAccountName,
		},
	}, whsvr.sidecarConfigTemplate)
	if err != nil {
		glog.Errorf("api=mutate, reason=sidecarconfig.RenderTemplate, message=failed to render from template, err=%v", err)
		return &v1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}, nil
	}

	// Workaround: https://github.com/kubernetes/kubernetes/issues/57982
	// Example: if you add an initContainer to a pod, you have to set fields that ought to have system-applied defaults.
	whsvr.applyDefaultsWorkaround(sidecarConfig.Containers, sidecarConfig.InitContainers, sidecarConfig.Volumes)

	statusForMutations, patchOperation, err := whsvr.mutatePod(ar.Request.Namespace, &pod, whsvr.mutatingConfig.MutationConfigs, sidecarConfig)
	if err != nil {
		glog.Errorf("api=mutate, reason=whsvr.mutatePod, message=failed to mutate, err=%v", err)
		setAllStatusesToFailed(statusForMutations)

		return &v1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}, statusForMutations
	}

	patchBytes, err := json.Marshal(patchOperation)
	if err != nil {
		setAllStatusesToFailed(statusForMutations)

		return &v1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}, statusForMutations
	}

	glog.Infof("api=mutate, message=creating new AdmissionResponse, patch=%v\n", string(patchBytes))
	return &v1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1.PatchType {
			pt := v1.PatchTypeJSONPatch
			return &pt
		}(),
	}, statusForMutations
}

// serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("api=serve, message=invalid Content-Type expect `application/json`, contentType=%s ", contentType)
		http.Error(w, "invalid Content-Type expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Errorf("api=serve, message=empty body received, contentType=%s, headers=%s", contentType, r.Header)
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	glog.Infof("api=serve, message=incoming request, body=%s", body)
	var admissionResponse *v1.AdmissionResponse
	var statusForMutations map[string]mutationStatus
	ar := v1.AdmissionReview{}
	_, gvk, err := deserializer.Decode(body, nil, &ar)
	if err != nil {
		glog.Errorf("api=serve, reason=deserializer.Decode, message=cannot decode body, err=%v", err)
		admissionResponse = &v1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse, statusForMutations = whsvr.mutate(&ar)
	}

	admissionReview := v1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		admissionReview.SetGroupVersionKind(*gvk)
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		setAllStatusesToFailed(statusForMutations)

		glog.Errorf("api=serve, reason=json.Marshal, message=could not encode response, err=%v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("api=serve, message=ready to write response")
	if _, err := w.Write(resp); err != nil {
		setAllStatusesToFailed(statusForMutations)

		glog.Errorf("api=serve, reason=w.Write, message=could not write response, err=%v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}

	if statusForMutations != nil {
		for m, s := range statusForMutations {
			switch s {
			case failedMutation:
				metrics.CountInjection(m, injectionStatusFailure)
			case skippedMutation:
				metrics.CountInjection(m, injectionStatusSkipped)
			case succeededMutation:
				metrics.CountInjection(m, injectionStatusSuccess)
			}
		}
	}
}

// healthz implements a health check, useful for k8s liveness and readiness probes.
func (whsvr *WebhookServer) healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// Start starts webhook server
func (whsvr *WebhookServer) Start() (chan bool, chan bool, error) {
	config := whsvr.config
	var tlsConfig *tls.Config
	isTLS := whsvr.certificateReloader != nil
	if isTLS {
		err := whsvr.certificateReloader.Start()
		if err != nil {
			glog.Errorf("api=Start, reason=certReloader.Start, certFilePath=%q, keyFilePath=%q, caFilePath=%q, err=%v", config.CertFilePath, config.KeyFilePath, config.CaFilePath, err)
			return nil, nil, errors.Errorf("api=Start, reason=certReloader.Start, certFilePath=%q, keyFilePath=%q, caFilePath=%q, err=%v", config.CertFilePath, config.KeyFilePath, config.CaFilePath, err)
		}

		tlsConfig = &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return whsvr.certificateReloader.GetCertificate()
			},
		}
		if !config.AllowDeprecatedTLSConfig {
			tlsConfig.MinVersion = tls.VersionTLS12
			tlsConfig.CipherSuites = []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			}
			tlsConfig.PreferServerCipherSuites = true
		}

		if config.CaFilePath != "" {
			caCert, err := ioutil.ReadFile(config.CaFilePath)
			if err != nil {
				glog.Errorf("api=Start, reason=ioutil.ReadFile, caFilePath=%q, err=%v", config.CaFilePath, err)
				return nil, nil, errors.Errorf("api=Start, reason=ioutil.ReadFile, caFilePath=%q, err=%v", config.CaFilePath, err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}
	}

	// Define routing for requests to the server.
	router := http.NewServeMux()
	router.HandleFunc("/mutate", metrics.GetHTTPMetricHandler("mutate", http.HandlerFunc(whsvr.serve)).ServeHTTP)
	router.HandleFunc("/healthz", metrics.GetHTTPMetricHandler("healthz", http.HandlerFunc(whsvr.healthz)).ServeHTTP)
	router.HandleFunc("/metrics", metrics.GetHTTPMetricHandler("metrics", promhttp.Handler()).ServeHTTP)

	// We create two servers: one that serves https requests, and another that serves http requests only.
	whsvr.tlsServer = &http.Server{
		Addr:      fmt.Sprintf(":%v", config.TLSPort),
		TLSConfig: tlsConfig,
	}
	whsvr.tlsServer.Handler = router

	// Channel to indicate when the server stopped listening for some reason
	doneListeningTLSChannel := make(chan bool)

	// start webhook server in new routine
	go func() {
		if isTLS {
			if err := whsvr.tlsServer.ListenAndServeTLS("", ""); err != nil {
				glog.Errorf("failed to listen and serve webhook server: %v", err)
			}
			doneListeningTLSChannel <- true
		}
	}()

	whsvr.httpServer = &http.Server{
		Addr: fmt.Sprintf(":%v", config.HTTPPort),
	}

	whsvr.httpServer.Handler = router

	// Channel to indicate when the server stopped listening for some reason
	doneListeningHTTPChannel := make(chan bool)

	go func() {
		if err := whsvr.httpServer.ListenAndServe(); err != nil {
			glog.Errorf("failed to listen and serve webhook HTTP server: %v", err)
		}
		doneListeningHTTPChannel <- true
	}()

	return doneListeningTLSChannel, doneListeningHTTPChannel, nil
}

// Stop stops webhook server
func (whsvr *WebhookServer) Stop() {
	glog.Infof("api=Stop, reason='shutting down webhook server gracefully...'")
	whsvr.tlsServer.Shutdown(context.Background())
	whsvr.httpServer.Shutdown(context.Background())
	if whsvr.certificateReloader.IsRunning() {
		whsvr.certificateReloader.Stop()
	}
}

// applyDefaultsWorkaround for https://github.com/kubernetes/kubernetes/issues/57982
func (whsvr *WebhookServer) applyDefaultsWorkaround(containers []corev1.Container, initContainers []corev1.Container, volumes []corev1.Volume) {
	defaulter.Default(&corev1.Pod{
		Spec: corev1.PodSpec{
			Containers:     containers,
			InitContainers: initContainers,
			Volumes:        volumes,
		},
	})
}

// mutationRequired checks whether the target resource need to be mutated
func (whsvr *WebhookServer) mutationRequired(m *mutationconfig.MutationConfig, requestNamespace string, pod *corev1.Pod) bool {
	// skip special kubernetes system namespaces
	for _, namespace := range ignoredSystemNamespaces {
		if requestNamespace == namespace {
			glog.Infof("api=mutationRequired, message=skip mutation for pod in a system namespace, pod=%s, namespace=%v", pod.GenerateName, requestNamespace)
			return false
		}
	}

	// skip ignored namespaces defined by mutation config
	for _, namespace := range m.IgnoreNamespaces {
		if requestNamespace == namespace {
			glog.Infof("api=mutationRequired, message=skip mutation for pod in special namespace, pod=%s, namespace=%v", pod.GenerateName, requestNamespace)
			return false
		}
	}

	annotations := pod.GetAnnotations()
	if annotations == nil {
		glog.Infof("api=mutationRequired, message=skip mutation for pod with no annotations, pod=%s, namespace =%s", pod.GenerateName, requestNamespace)
		return false
	}

	// if the annotation trigger is not found return false
	triggerKey := util.GetAnnotation(m.AnnotationNamespace, m.AnnotationTrigger)
	triggerValue, ok := annotations[triggerKey]
	if !ok {
		glog.Infof("api=mutationRequired, message=skip mutation for pod with no annotation trigger, pod=%s, namespace=%s, annotationTriggerKey=%s", pod.GenerateName, requestNamespace, triggerKey)
		return false
	}

	// if annotation trigger value is not set to true or equivalent
	if triggerValue != "true" && triggerValue != "enabled" {
		glog.Infof("api=mutationRequired, message=skip mutation for pod where annotation trigger is not set to true or equivalent, pod=%s, namespace=%s, annotationTriggerKey=%s, annotationTriggerValue=%s", pod.GenerateName, requestNamespace, triggerKey, triggerValue)
		return false
	}

	// finally if the pod is injected return false
	statusKey := util.GetAnnotation(m.AnnotationNamespace, annotationStatusKey)
	status := annotations[statusKey]
	//don't inject again, if already injected
	if strings.ToLower(status) == annotationStatusInjected {
		glog.Infof("api=mutationRequired, message=skip mutation for pod with existing injection, pod=%s, namespace=%s", pod.GenerateName, requestNamespace)
		return false
	}

	return true

}

// Pods with a restartPolicy that is not "Always" are usually some type of Job.
// See https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-lifetime.
func isShortRunningWorkload(pod *corev1.Pod) bool {
	return pod.Spec.RestartPolicy != corev1.RestartPolicyAlways
}

// Create a patch that adds the resources defined in the mutationConfig to a pod.
// Care must be taken to keep the pod consistent with the changes that are made, so that multiple mutations work correctly.
// If 2 mutations are computed, the 2nd set of patches must start with the result of the 1st.
func (whsvr *WebhookServer) createPatches(pod *corev1.Pod, mutationConfig *mutationconfig.MutationConfig, sidecarConfig *sidecarconfig.SidecarConfig) []patchOperation {
	var patches []patchOperation

	// Add lifecycle defaults if we're looking a Pod running as a Job AND this injection runs sidecars for Jobs
	addSidecarLifecycleDefaults := isShortRunningWorkload(pod) && mutationConfig.ImplementsSidecarLifecycle

	if addSidecarLifecycleDefaults {
		sidecarConfig.AddSidecarLifecycleDefaults()
	}

	// Modify Containers first removes all containers, add them back again with added volume mounts
	patches = append(patches, modifyContainers(pod.Spec.Containers, "/spec/containers", func(c *corev1.Container) {
		c.VolumeMounts = util.MergeVolumeMounts(c.VolumeMounts, sidecarConfig.VolumeMounts)
	})...)

	// Ditto for InitContainers
	patches = append(patches, modifyInitContainers(pod.Spec.InitContainers, "/spec/initContainers", func(c *corev1.Container) {
		c.VolumeMounts = util.MergeVolumeMounts(c.VolumeMounts, sidecarConfig.VolumeMounts)
	})...)

	// Adding initContainers, keep the pod consistent with the patch
	initsBefore, initsAfter := getInitContainers(mutationConfig.InitContainersBeforePodInitContainers, sidecarConfig.InitContainers)
	patches = append(addContainers(pod.Spec.InitContainers, initsBefore, "/spec/initContainers"), patches...)
	pod.Spec.InitContainers = append(initsBefore, pod.Spec.InitContainers...)
	patches = append(patches, addContainers(pod.Spec.InitContainers, initsAfter, "/spec/initContainers")...)
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, initsAfter...)

	// Inject sidecar containers if we're NOT looking at a Pod OR this injection runs sidecars for Jobs
	// A long-running sidecar Container can cause the Job to never complete,
	// so do not inject sidecars into these Pods unless it is explicity overridden
	injectSidecars := !isShortRunningWorkload(pod) || mutationConfig.ImplementsSidecarLifecycle

	if injectSidecars {
		// Add sidecar Containers, keep the pod consistent with the patch
		patches = append(patches, addContainers(pod.Spec.Containers, sidecarConfig.Containers, "/spec/containers")...)
		pod.Spec.Containers = append(pod.Spec.Containers, sidecarConfig.Containers...)
	}

	// Add Volumes, keep the pod consistent with the patch
	volumes := util.DeDuplicateVolumes(pod.Spec.Volumes, sidecarConfig.Volumes)
	patches = append(patches, addVolumes(pod.Spec.Volumes, volumes, "/spec/volumes")...)
	pod.Spec.Volumes = append(pod.Spec.Volumes, volumes...)

	// Update annotations with status, keep the pod consistent with the patch
	annotations := make(map[string]string)
	statusKey := util.GetAnnotation(mutationConfig.AnnotationNamespace, annotationStatusKey)
	annotations[statusKey] = annotationStatusInjected
	patches = append(patches, updateAnnotations(pod.Annotations, annotations)...)
	pod.Annotations[statusKey] = annotationStatusInjected

	return patches
}

func (whsvr *WebhookServer) mutatePod(requestNamespace string, pod *corev1.Pod, mutationConfigs []mutationconfig.MutationConfig, sidecarConfig *sidecarconfig.SidecarConfig) (map[string]mutationStatus, []patchOperation, error) {
	// Take a copy of the the pod so that we do not mutate the caller's version
	podView := pod.DeepCopy()
	statusForMutation := make(map[string]mutationStatus)
	var patches []patchOperation
	for _, m := range mutationConfigs {
		glog.Infof("api=mutatePod, message=processing mutation request, mutationConfig=%s", m.Name)

		// determine whether to perform mutation
		required := whsvr.mutationRequired(&m, requestNamespace, podView)
		if !required {
			glog.Infof("api=mutatePod, message=skipping mutation due to policy check, namespace=%s, pod=%s", requestNamespace, podView.GenerateName)
			statusForMutation[m.AnnotationNamespace] = skippedMutation
			continue
		}

		s := sidecarConfig.NewPerMutationConfig(m)
		if err := s.ParseVolumeMountAnnotations(pod.ObjectMeta.GetAnnotations(), m); err != nil {
			glog.Errorf("api=mutatePod, reason=s.ParseVolumeMountAnnotations, message=failed to parse volumeMount annotations, err=%q", err)
			statusForMutation[m.AnnotationNamespace] = failedMutation
			return statusForMutation, nil, err
		}

		mutationPatches := whsvr.createPatches(podView, &m, s)

		statusForMutation[m.AnnotationNamespace] = succeededMutation
		patches = append(patches, mutationPatches...)
	}
	return statusForMutation, patches, nil
}

func setAllStatusesToFailed(statusForMutations map[string]mutationStatus) {
	if statusForMutations != nil {
		for mutationConfig := range statusForMutations {
			statusForMutations[mutationConfig] = failedMutation
		}
	}
}

func getInitContainers(initsBeforeNames []string, allInits []corev1.Container) ([]corev1.Container, []corev1.Container) {
	var initsAfter, initsBefore []corev1.Container
	m := make(map[string]bool)
	for _, i := range initsBeforeNames {
		m[i] = true
	}

	for _, i := range allInits {
		if m[i.Name] {
			biCopy := i.DeepCopy()
			initsBefore = append(initsBefore, *biCopy)
		} else {
			aiCopy := i.DeepCopy()
			initsAfter = append(initsAfter, *aiCopy)
		}
	}
	return initsBefore, initsAfter
}
