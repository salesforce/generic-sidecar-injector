/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package metrics

import (
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	codeLabelName    = "code"
	methodLabelName  = "method"
	handlerLabelName = "handler"
)

var (
	gitHash                string
	gitTag                 string
	webhookInjectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "webhook_injections_total",
			Help: "A count of total mutations/injections into a resource",
		},
		[]string{"prefix", "status"},
	)

	httpRequestsInFlight = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "webhook_http_requests_in_flight",
			Help: "A gauge of requests currently being served by the wrapped handler",
		})

	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "webhook_http_requests_total",
			Help: "A count of total HTTP requests",
		},
		[]string{codeLabelName, methodLabelName, handlerLabelName},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "webhook_http_request_duration_seconds",
			Help:    "A histogram of HTTP request latencies",
			Buckets: []float64{.001, .01, .05, .1, .5, 1, 5},
		},
		[]string{codeLabelName, methodLabelName, handlerLabelName},
	)

	httpResponseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "webhook_http_request_response_size_bytes",
			Help:    "A histogram of response sizes for requests",
			Buckets: []float64{100, 200, 500, 1000, 1500, 5000, 10000},
		},
		[]string{codeLabelName, methodLabelName, handlerLabelName},
	)
)

func init() {
	prometheus.MustRegister(webhookInjectionsTotal, httpRequestsInFlight, httpRequestsTotal, httpRequestDuration, httpResponseSize)
}

// PromHTTPHandler contains the HTTP handler and handler name for an endpoint
type PromHTTPHandler struct {
	handler     http.Handler
	handlerName string
}

func (p *PromHTTPHandler) withInFlight() *PromHTTPHandler {
	p.handler = promhttp.InstrumentHandlerInFlight(httpRequestsInFlight, p.handler)
	return p
}

func (p *PromHTTPHandler) withDuration() *PromHTTPHandler {
	curriedHTTPRequestDuration := httpRequestDuration.MustCurryWith(prometheus.Labels{handlerLabelName: p.handlerName})
	p.handler = promhttp.InstrumentHandlerDuration(curriedHTTPRequestDuration, p.handler)
	return p
}

func (p *PromHTTPHandler) withCounter() *PromHTTPHandler {
	curriedHTTPRequestsTotal := httpRequestsTotal.MustCurryWith(prometheus.Labels{handlerLabelName: p.handlerName})
	p.handler = promhttp.InstrumentHandlerCounter(curriedHTTPRequestsTotal, p.handler)
	return p
}

func (p *PromHTTPHandler) withResponseSize() *PromHTTPHandler {
	curriedHTTPResponseSize := httpResponseSize.MustCurryWith(prometheus.Labels{handlerLabelName: p.handlerName})
	p.handler = promhttp.InstrumentHandlerResponseSize(curriedHTTPResponseSize, p.handler)
	return p
}

// GetHTTPMetricHandler wraps the provided HTTP handler with Prometheus metrics wrappers
func GetHTTPMetricHandler(handlerName string, handler http.Handler) http.Handler {
	p := PromHTTPHandler{handler: handler, handlerName: handlerName}
	return p.withInFlight().withCounter().withDuration().withResponseSize().handler
}

// CountInjection increments the webhookInjectionsTotal metric with the given name and status labels
func CountInjection(prefix, status string) {
	webhookInjectionsTotal.With(prometheus.Labels{"prefix": prefix, "status": status}).Inc()
}

// WebhookBuildInfo emits a constant metric of 1 with build info tags such as
// gitHash, gitTag and additional tags passed through `--build-info-metrics` flag
func WebhookBuildInfo(buildInfoLabels string) {
	labels, labelMaps := getBuildInfoLabels(buildInfoLabels)
	webhookBuildInfo := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "webhook_build_info",
			Help: "A constant metric set to 1 with webhook's build info",
		},
		labels,
	)
	prometheus.MustRegister(webhookBuildInfo)
	webhookBuildInfo.With(labelMaps).Set(1)
}

// getBuildInfoMetrics returns a string slice of all tags, and a map of tag and value pairs as prometheus Labels
func getBuildInfoLabels(buildInfoLabels string) ([]string, prometheus.Labels) {
	labels := []string{"gitHash", "gitTag"}
	m := make(prometheus.Labels)

	m["gitHash"] = gitHash
	m["gitTag"] = gitTag

	if len(buildInfoLabels) > 0 {
		customMetrics := strings.Split(buildInfoLabels, ",")
		for _, c := range customMetrics {
			p := strings.Split(c, "=")
			labels = append(labels, p[0])
			m[p[0]] = p[1]
		}
	}
	return labels, m
}
