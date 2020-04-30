/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package config

import (
	"github.com/golang/glog"
	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
	"github.com/salesforce/generic-sidecar-injector/pkg/metrics"
)

// WebhookConfig is the configuration parameters for the madkubinjectionwebhook
type WebhookConfig struct {
	TLSPort            string `long:"port" default:"443" description:"Webhook server port for mutate endpoint"`
	HTTPPort           string `long:"http-port" default:"17773" description:"Webhook server http port for metrics and healthz endpoints"`
	CertFilePath       string `long:"cert-file-path" description:"File containing the x509 Certificate for HTTPS"`
	KeyFilePath        string `long:"key-file-path" description:"File containing the x509 private key"`
	CaFilePath         string `long:"ca-file-path" required:"false" description:"File containing the CA cert"`
	SidecarConfigFile  string `long:"sidecar-config-file" description:"File containing the sidecar container configuration"`
	MutationConfigFile string `long:"mutation-config-file" description:"File containing the mutation configuration"`
	LogLevel           string `short:"v" long:"log-level" default:"0" description:"Logging level"`
	Environment        string `short:"e" long:"environment" default:"prod" description:"Environment we are running. local or prod"`
	BuildInfoLabels    string `long:"build-info-labels" required:"false" description:"Additional build info metric labels"`
}

// NewWebhookConfig is a constructor for WebhookConfig
func NewWebhookConfig() (*WebhookConfig, error) {
	config, err := parse()
	if err != nil {
		return nil, errors.Errorf("api=NewWebhookConfig, reason=parse, err=%v", err)
	}
	return config, nil
}

// parse the args and environment to fill the ClientConfig
func parse() (*WebhookConfig, error) {
	c := &WebhookConfig{}
	parser := flags.NewParser(c, flags.HelpFlag|flags.PrintErrors|flags.PassDoubleDash|flags.IgnoreUnknown)
	_, err := parser.Parse()

	if err != nil {
		glog.Errorf("api=Parse, err=%v", err)
		return nil, err
	}

	// Emit build info metric
	metrics.WebhookBuildInfo(c.BuildInfoLabels)

	return c, nil
}
