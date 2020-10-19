# A Generic framework for Writing Mutating Webhook Admission Controllers.


[![Build Status](https://travis-ci.org/salesforce/generic-sidecar-injector.svg?branch=master)](https://travis-ci.org/salesforce/generic-sidecar-injector)
[![Go Report Card](https://goreportcard.com/badge/github.com/salesforce/generic-sidecar-injector)](https://goreportcard.com/report/github.com/salesforce/generic-sidecar-injector)

Many kubernetes users have started using mutating admission controllers to inject sidecars.
These sidecars are used for different purposes like logging, service mesh, monitoring, getting
certificates, secret decryption, etc. Its most likely that all of these functions are being
maintained by different teams. Its also most likely that each of these teams is writing the 
same code for mutating admission controllers, same unit tests and similar helm charts. In order
to avoid duplication and improve collaboration, we are introducing this framework.

Generic Sidecar Injector is a framework that allows you to inject sidecars(aka containers), 
initcontainers, volumes and volume mounts in a very config driven way that will solve most 
sidecar injection needs without requiring code change.


## How to run tests
    make 
    
## Build a docker image
    make docker

## Documentation

### Configuration

The framework divides the configuration into two parts.

1. What needs to be injected , aka the sidecar configuration
2. A list of mutations, aka the mutation configuration


The mutating webhook takes the following arguments:-

```
/mutating-webhook/mutating-webhook
 --sidecar-config-file=/config/sidecarconfig.yaml
 --mutation-config-file=/config/mutationconfig.yaml
 --cert-file-path=/etc/identity/server/certificates/server.pem
 --key-file-path=/etc/identity/server/keys/server-key.pem
```

#### Sidecar Configs

--sidecar-config-file is a list of initcontainers, containers and volumes to inject. The container 
and volume yamls are exactly the same as the K8s container and volume format.


```
initContainers:
    - name: rsyslog-init
      image: blah
      command: ["bash", "-c"]
      env:
      - name: LOG_TYPES_JSON
        valueFrom:
          fieldRef:
            apiVersion: v1
            fieldPath: metadata.annotations['rsyslog.k8s-integration.sfdc.com/log-configs']
containers:
    - name: rsyslog-sidecar
volumes:
    - name: rsyslog-spool-vol
```        

#### Mutation Configs

--mutation-config-file is a list of mutations that need to be performed by the Mutating Webhook. All the 
mutations belong to the same team. Each mutation consists of a trigger in the form of an annotation and
a list of injections performed in response to the annotation trigger.


Its in the following format:-

```
mutationConfigs:
  - name: "rsyslog-file-tailer"
    annotationNamespace: "rsyslog.k8s-integration.sfdc.com"
    annotationTrigger: "inject"
    annotationConfig:
      volumeMounts:
        - name: "volume-mounts"
          containerRefs: ["rsyslog-sidecar"]
    initContainersBeforePodInitContainers: ["vault-init"]
    initContainers: ["rsyslog-init", "vault-init"]
    containers: ["rsyslog-sidecar"]
    volumes: ["rsyslog-spool-vol", "rsyslog-conf-tpl", "rsyslog-conf-gen"]
    volumeMounts: []
    ignoreNamespaces: []

```

##### Meaning of different terms

`annotationNamespace`: Every Mutating webhook only looks at annotations within a namespace that it owns. In 
the above  example, the mutating webhook only looks at the annotations that begin with rsyslog.k8s-integration.sfdc.com

`annotationTrigger`:  The injection is only triggered if the kPod has the following annotation  
rsyslog.k8s-integration.sfdc.com/inject present

`initContainersBeforePodInitContainers`: This is a list of init containers to inject before all other init containers

`initContainers`:  This is a list of init containers to inject when the annotation is present on 
the pod. The name of the initContainers should match an init container in the -sidecar-config-file

`containers`: This is a list of containers to inject when the annotation is present on the pod. The 
name of the containers should match a container in the -sidecar-config-file

`volumes`: This is a list of volumes to inject when the annotation is present on the pod. The name 
of the volumes should match a volume in the -sidecar-config-file

`annotationConfig`: This is a way of dynamically injecting configuration in the injected containers 
which is only known at the pod creation time. Currently it only supports injecting volumeMounts into the injected containers.
This will soon be DEPRECATED.

#### Dynamic Configuration of Injected Containers

DEPRECATED, will soon be removed, since the same functionality can be achieved by templating.

```
annotationConfig:
    volumeMounts:
    - name: "volume-mounts"
      containerRefs: ["rsyslog-sidecar"]
```

In the above mutationConfig example, it is instructing the Mutation Webhook to look for an annotation called 
volume-mounts and use the value of that annotation to configure a volumeMount inside the container rsyslog-sidecar 
which is present in the sidecar configuration.

The annotation value has configuration for what volume to mount and its mountPath inside the container rsyslog-sidecar.

Here is the corresponding annotation to expect on the pod. This annotation assumes that the volume “logs” already exists in the Pod.


```
rsyslog.k8s-integration.sfdc.com/volume-mounts: >
        [
            {
                "name": "logs",
                "mountPath": "/logs"
            }
        ]
```


#### Passing Configuration to Injected Containers as Environment Variables

Sometimes you need to pass large configuration to the injected containers. One way to do this is by annotations.

In the Pod, pass an annotation with the required config as follows:-

```
rsyslog.k8s-integration.sfdc.com/log-configs: >
        [
            {
                "id": "log1",
                "source_type": "test:test",
                "paths": ["/logs/log1.log"],
                "multiline_option": "REGEX",
                "start_regex": "^[[:digit:]]{14}\\\\.[[:digit:]]{6}"
            }
        ]
```

In the injected container create an environment variable that references this annotation as the source of the value for that environment variable.

```
env:
      - name: LOG_TYPES_JSON
        valueFrom:
          fieldRef:
            apiVersion: v1
            fieldPath: metadata.annotations['rsyslog.k8s-integration.sfdc.com/log-configs']
            
```


#### Example Pod Annotation to that goes with above examples

```
# Example pod with rsyslog injection and configuration annotations.
apiVersion: v1
kind: Pod
metadata:
  name: rsyslog-inject-example
  namespace: test-injection
  annotations:
    rsyslog.k8s-integration.sfdc.com/inject: enabled
    rsyslog.k8s-integration.sfdc.com/volume-mounts: >
        [
            {
                "name": "logs",
                "mountPath": "/logs"
            }
        ]
    rsyslog.k8s-integration.sfdc.com/log-configs: >
        [
            {
                "id": "log1",
                "source_type": "test:test",
                "paths": ["/logs/log1.log"],
            }
        ]
spec:
  containers:
  - name: app
    image: someimage:17
    command: ['sh', '-c', 'while true; do echo -e "20190904013510.766000 [INFO ] log line 1\nline 2\nline 3" >> /logs/log1.log; sleep 10; done']
  volumes:
    - name: logs
      emptyDir: {}
```



#### Templating of Sidecar Configuration

The framework supports golang templating in the sidecar configs. This means certain parts of the injected container 
can be derived at runtime from the pod in which the injection needs to happen. 

For e.g.  lets say your container has a secret whose name is derived from the service account name of the pod. You 
sidecar config can look like this :-

```
volumes:
  - name: foo
    secret:
       ### This templated field will come from the pod manifest passed to the mutating webhook controller
       secretName: aws-iam-{% .Spec.ServiceAccountName %}
  
```

Similarly lets say you want to populate an environment variable in the injected container, where the value of the 
environment variable comes from an annotation in the pod.

```

- name: VAULT_ROLE
  ### This templated field will come from the pod manifest passed to the mutating webhook controller
  value: {% index .Annotations "vault.k8s-integration.sfdc.com/role" %}
```