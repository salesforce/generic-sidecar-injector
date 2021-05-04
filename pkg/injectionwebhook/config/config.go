/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package config

import (
	"flag"

	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
)

// WebhookConfig is the configuration parameters for the sidecar injector
type WebhookConfig struct {
	TLSPort            int    `long:"port" default:"443" required:"false" description:"webhook server port for mutate endpoint"`
	HTTPPort           int    `long:"http-port" default:"17773" required:"false" description:"webhook server http port for metrics and healthz endpoints"`
	CertFilePath       string `long:"cert-file-path" required:"true" description:"file containing the x509 Certificate for HTTPS"`
	KeyFilePath        string `long:"key-file-path" required:"true" description:"file containing the x509 private key"`
	CaFilePath         string `long:"ca-file-path" required:"false" description:"file containing the CA cert"`
	SidecarConfigFile  string `long:"sidecar-config-file" required:"true" description:"file containing the sidecar container configuration"`
	MutationConfigFile string `long:"mutation-config-file" required:"true" description:"file containing the mutation configuration"`
	BuildInfoLabels    string `long:"build-info-labels" required:"false" description:"additional build info metric labels"`

	// Flag to permit fallback to old, insecure TLS configurations.
	AllowDeprecatedTLSConfig bool `long:"allow-deprecated-tls-config" required:"false" description:"permits use of deprecated TLS configuration (TLS 1.0/1.1, weak ciphers)"`
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
	extraArgs, err := parser.Parse()
	if err != nil {
		return nil, errors.Errorf("api=parse, err=%v", err)
	}
	// Parse any extra args for dependent packages that use "flag" (e.g., glog).
	flag.CommandLine.Parse(extraArgs)
	return c, nil
}
