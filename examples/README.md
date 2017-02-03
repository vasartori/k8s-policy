# Examples

This directory contains the following manifest file for deploying the 
Calico policy controller.  

This manifest is expected to work for most cases, but is not necessarily intended to be a "one size fits all" solution.

- `policy-controller.yaml`: A ReplicaSet which deploys the policy controller on top of Kubernetes.
- `thirdpartyresource-netpol.yaml`: A ThirdPartyResource used by Calico policy controller
- `netpol-rule.yaml`: A Policy with ingress and egress rules. Based on K8s example (https://kubernetes.io/docs/user-guide/networkpolicies/)
- `annotated-namespace.yaml`: A namespace annotated with ingress and egress blocked.