# Calico Policy Controller Configuration 

The config for this version are a little bit diferent from master.

1 - You need create a thirdpartyresource on k8s. We have examples in [examples](examples/README.md)

2 - If you have choosen to customize this thirdpartyresource, you'll need set this environment variables:

*RESOURCE_TYPE_NETWORK_POLICY* => 'Kind' name of your rules. Default value: Netpolicy. 
See in [examples](examples/README.md)

*THIRDPARTYRESOURCE* => Name of your thirdpartyresource. Default value: netpolicy.calico.int

*THIRDPARTYRESOURCE_VERSION* => Version of thirdpartyresource. Default value: v1

The rest of configuration, can be viewed on [main Calico documentation](http://docs.projectcalico.org/master/reference/policy-controller/configuration).

