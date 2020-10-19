# Step by Step Instructions to Install and try the examples

## Assumptions
- a Kubernetes cluster is available and KUBECONFIG is correct configured
- kubectl cli is installed
- Helm v3 is installed

## Steps 

### Create a namespace for cert-manager

```
kubectl create ns cert-manager
```

### Generate a CA pair

- generate a keypair using openssl

```
openssl genrsa -out ca.key 2048
- export COMMON_NAME=sidecarinjector.sidecarinjector.svc
- openssl req -x509 -new -nodes -key ca.key -subj "/CN=${COMMON_NAME}" -days 3650 -reqexts v3_req -extensions v3_ca -out ca.crt -config /usr/local/etc/openssl/openssl.cnf
```
- store the keypair in a Kubernetes secret

```
kubectl create secret tls ca-key-pair    --cert=ca.crt    --key=ca.key    --namespace=cert-manager
```

### Install Cert-Manager 

- Install Cert-Manager using Helm

```
helm install   cert-manager jetstack/cert-manager   --namespace cert-manager   --version v1.0.3 --set installCRDs=true
```

### Install Generic Sidecar Injector

- Label the cert-manager namespace so that injection is disabled

```
kubectl label ns cert-manager sidecar-injection=disabled
```

- Clone the repo 

```
git clone git@github.com:salesforce/generic-sidecar-injector.git
```

- Install Generic Sidecar injector using Helm

```
helm install helm/sidecarinjector/  --generate-name
kubectl get pods -n sidecarinjector
```

### Verify sidecar injector functionality

- Try some examples

```
cd helm/examples
kubectl apply -f pod.yaml
kubectl get pods 
```

- verify the pod has a new container injected called simple-sidecar

```
 kubectl get po -o jsonpath='{range .items[*]}{"pod: "}{.metadata.name}{"\n"}{range .spec.containers[*]}{"\tname: "}{.name}{"\n"}{end}'
pod: busybox
```

### Cleanup
- list helm releases

```
helm list
```

- delete the helm release for sidecar

```
helm delete sidecarinjector-1602990110
```

- delete the helm release for the Cert Manager

```
helm --namespace cert-manager delete cert-manager
```

- delete the busybox pod

```
kubectl delete pod busybox1
```
