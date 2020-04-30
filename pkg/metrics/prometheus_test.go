package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestGetBuildInfoMetrics(t *testing.T) {
	buildInfoLabels := "chartVersion=0.0.14,userLabel1=val1,userLabel2=val2"
	expectedKeys := []string{"gitHash", "gitTag", "chartVersion", "userLabel1", "userLabel2"}
	expectedLabels := prometheus.Labels{"gitHash": gitHash, "gitTag": gitTag, "chartVersion": "0.0.14",
		"userLabel1": "val1", "userLabel2": "val2"}
	k, l := getBuildInfoLabels(buildInfoLabels)
	assert.Equal(t, expectedKeys, k)
	assert.Equal(t, expectedLabels, l)
}
