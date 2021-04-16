/*
 * Copyright (c) 2020, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */

package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/template"
	"time"

	"github.com/golang/glog"
	"github.com/jessevdk/go-flags"
	"github.com/salesforce/generic-sidecar-injector/pkg/injectionwebhook"
	"github.com/salesforce/generic-sidecar-injector/pkg/injectionwebhook/config"
	"github.com/salesforce/generic-sidecar-injector/pkg/metrics"
	"github.com/salesforce/generic-sidecar-injector/pkg/mutationconfig"
	"github.com/salesforce/generic-sidecar-injector/pkg/sidecarconfig"
	"github.com/salesforce/generic-sidecar-injector/pkg/util"
	"github.com/spf13/afero"
)

const (
	successExitCode = 0
	errorExitCode   = 1
)

func main() {
	webhookConfig, err := config.NewWebhookConfig()
	if err != nil {
		glog.Errorf("api=main, reason=config.NewWebhookConfig, err=%v", err)
		os.Exit(errorExitCode)
	}
	if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
		os.Exit(successExitCode)
	}

	if webhookConfig.BuildInfoLabels != "" {
		metrics.WebhookBuildInfo(webhookConfig.BuildInfoLabels)
	}

	// Sanity check for templateFile. Eligible fields https://salesforce.quip.com/pEW6A6AtpwRc
	// TODO: move above doc to git wiki
	sidecarConfigTemplate, err := template.New(filepath.Base(webhookConfig.SidecarConfigFile)).Delims(util.TemplateLeftDelimiter, util.TemplateRightDelimiter).ParseFiles(webhookConfig.SidecarConfigFile)
	if err != nil {
		glog.Errorf("api=main, reason=template.New, file=%q, err=%v", webhookConfig.SidecarConfigFile, err)
		os.Exit(errorExitCode)
	}

	err = sidecarconfig.TemplateSanityCheck(sidecarConfigTemplate)
	if err != nil {
		glog.Errorf("api=main, reason=sidecarconfig.TemplateSanityCheck, message=template may contain ineligible fields, err=%v", err)
		os.Exit(errorExitCode)
	}

	mutationConfigs, err := mutationconfig.NewMutatingConfigs(webhookConfig.MutationConfigFile)
	if err != nil {
		glog.Errorf("api=main, reason=mutationconfig.NewMutatingConfig, file=%q, err=%v", webhookConfig.MutationConfigFile, err)
		os.Exit(errorExitCode)
	}

	fs := afero.NewOsFs()
	certReloader := util.NewCertificatePKIReloaderFull(fs, webhookConfig.CertFilePath, webhookConfig.KeyFilePath, time.Minute*15)

	whsrv := injectionwebhook.NewWebhookServer(webhookConfig, sidecarConfigTemplate, mutationConfigs, certReloader)
	if err != nil {
		glog.Errorf("api=main, reason=injectionwebhook.NewWebhookServer, err=%v", err)
		os.Exit(errorExitCode)
	}
	doneListeningTLSChannel, doneListeningHTTPChannel, err := whsrv.Start()
	if err != nil {
		glog.Errorf("api=main, reason=whsrv.Start, err=%v", err)
		os.Exit(errorExitCode)
	}

	// listening OS shutdown signal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	stopped := false
	// Wait until we receive either a termination signal, or the server stops by itself for some reason
	select {
	case signal := <-signalChan:
		{
			glog.Infof("Received a termination signal. SIG=%s", signal)
		}
	case stopped = <-doneListeningTLSChannel:
		{
			glog.Warning("TLS Server has stopped on it's own... exiting.")
		}
	case stopped = <-doneListeningHTTPChannel:
		{
			glog.Warning("HTTP Server has stopped on it's own... exiting.")
		}
	}

	if !stopped {
		whsrv.Stop()
	}

	glog.Info("Webhook server exited successfully.")
	os.Exit(successExitCode)
}
