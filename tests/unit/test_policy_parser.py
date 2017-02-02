# Copyright 2015 Tigera, Inc
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import unittest

from mock import patch, MagicMock, ANY, call
from nose.tools import assert_equal, assert_false, assert_raises
from nose_parameterized import parameterized
from pycalico.datastore_datatypes import Rule, Rules

from policy_parser import *

"""
Specifications for NetworkPolicies and the expected set of
Calico rules that should be generated as a result.
"""
# An empty NetworkPolicy.
network_policy_empty = {"kind": "networkpolicy",
                        "apiversion": "net.beta.kubernetes.io",
                        "metadata": {"namespace": "ns",
                                     "name": "test-policy"},
                        "spec": {}}
network_policy_empty_result = []

# Ingress NetworkPolicy with only ports defined.
ports = [{"port": 80, "protocol": "TCP"},
         {"port": 443, "protocol": "UDP"}]
spec = {"ingress": [{"ports": ports}]}
ingress_network_policy_ports = {"kind": "networkpolicy",
                                "apiversion": "net.beta.kubernetes.io",
                                "metadata": {"namespace": "ns",
                                             "name": "test-policy"},
                                "spec": spec}
ingress_network_policy_ports_result = [
    Rule(action="allow", dst_ports=[80], protocol="tcp"),
    Rule(action="allow", dst_ports=[443], protocol="udp")
]

# Egress NetworkPolicy with only ports defined.
ports = [{"port": 80, "protocol": "TCP"},
         {"port": 443, "protocol": "UDP"}]
spec = {"egress": [{"ports": ports}]}
egress_network_policy_ports = {"kind": "networkpolicy",
                               "apiversion": "net.beta.kubernetes.io",
                               "metadata": {"namespace": "ns",
                                            "name": "test-policy"},
                               "spec": spec}
egress_network_policy_ports_result = [
    Rule(action="allow", dst_ports=[80], protocol="tcp"),
    Rule(action="allow", dst_ports=[443], protocol="udp")
]

# Ingress NetworkPolicy with only pods defined by labels.
froms = [{"podSelector": {"matchLabels": {"role": "diags", "tier": "db"}}}]
spec = {"ingress": [{"from": froms}]}
ingress_network_policy_froms = {"kind": "networkpolicy",
                                "apiversion": "net.beta.kubernetes.io",
                                "metadata": {"namespace": "ns",
                                             "name": "test-policy"},
                                "spec": spec}
ingress_network_policy_froms_result = [
    Rule(action="allow",
         src_selector="tier == 'db' && role == 'diags' && calico/k8s_ns == 'ns'")
]

# Egress NetworkPolicy with only pods defined by labels.
froms = [{"podSelector": {"matchLabels": {"role": "diags", "tier": "db"}}}]
spec = {"egress": [{"from": froms}]}
egress_network_policy_froms = {"kind": "networkpolicy",
                               "apiversion": "net.beta.kubernetes.io",
                               "metadata": {"namespace": "ns",
                                            "name": "test-policy"},
                               "spec": spec}
egress_network_policy_froms_result = [
    Rule(action="allow",
         src_selector="tier == 'db' && role == 'diags' && calico/k8s_ns == 'ns'")
]

# Ingress NetworkPolicy with ports and pods defined by labels.
froms = [{"podSelector": {"matchLabels": {"role": "diags", "tier": "db"}}}]
ports = [{"port": 80, "protocol": "TCP"},
         {"port": 443, "protocol": "UDP"}]
spec = {"ingress": [{"from": froms, "ports": ports}]}
ingress_network_policy_both = {"kind": "networkpolicy",
                               "apiversion": "net.beta.kubernetes.io",
                               "metadata": {"namespace": "ns",
                                            "name": "test-policy"},
                               "spec": spec}
ingress_network_policy_both_result = [
    Rule(action="allow",
         src_selector="tier == 'db' && role == 'diags' && calico/k8s_ns == 'ns'",
         dst_ports=[80], protocol="tcp"),
    Rule(action="allow",
         src_selector="tier == 'db' && role == 'diags' && calico/k8s_ns == 'ns'",
         dst_ports=[443], protocol="udp")
]

# Egress NetworkPolicy with ports and pods defined by labels.
froms = [{"podSelector": {"matchLabels": {"role": "diags", "tier": "db"}}}]
ports = [{"port": 80, "protocol": "TCP"},
         {"port": 443, "protocol": "UDP"}]
spec = {"egress": [{"from": froms, "ports": ports}]}
egress_network_policy_both = {"kind": "networkpolicy",
                              "apiversion": "net.beta.kubernetes.io",
                              "metadata": {"namespace": "ns",
                                           "name": "test-policy"},
                              "spec": spec}
egress_network_policy_both_result = [
    Rule(action="allow",
         src_selector="tier == 'db' && role == 'diags' && calico/k8s_ns == 'ns'",
         dst_ports=[80], protocol="tcp"),
    Rule(action="allow",
         src_selector="tier == 'db' && role == 'diags' && calico/k8s_ns == 'ns'",
         dst_ports=[443], protocol="udp")
]

# Ingress NetworkPolicy with pods and namespaces defined by labels.
froms = [{"namespaceSelector": {"matchLabels": {"role": "prod"}}},
         {"podSelector": {"matchLabels": {"tier": "db"}}}]
spec = {"ingress": [{"from": froms}]}
ingress_network_policy_from_pods_ns = {"kind": "networkpolicy",
                                       "apiversion": "net.beta.kubernetes.io",
                                       "metadata": {"namespace": "ns",
                                                    "name": "test-policy"},
                                       "spec": spec}
ingress_network_policy_from_pods_ns_result = [
    Rule(action="allow", src_selector="k8s_ns/label/role == 'prod'"),
    Rule(action="allow", src_selector="tier == 'db' && calico/k8s_ns == 'ns'")
]

# Egress NetworkPolicy with pods and namespaces defined by labels.
froms = [{"namespaceSelector": {"matchLabels": {"role": "prod"}}},
         {"podSelector": {"matchLabels": {"tier": "db"}}}]
spec = {"egress": [{"from": froms}]}
egress_network_policy_from_pods_ns = {"kind": "networkpolicy",
                                      "apiversion": "net.beta.kubernetes.io",
                                      "metadata": {"namespace": "ns",
                                                   "name": "test-policy"},
                                      "spec": spec}
egress_network_policy_from_pods_ns_result = [
    Rule(action="allow", src_selector="k8s_ns/label/role == 'prod'"),
    Rule(action="allow", src_selector="tier == 'db' && calico/k8s_ns == 'ns'")
]

# Ingress NetworkPolicy with pods and namespaces defined by expressions.
froms = [{"namespaceSelector": {"matchExpressions": [{"key": "role",
                                                      "operator": "NotIn",
                                                      "values": ["prod",
                                                                 "staging"]}]}},
         {"podSelector": {"matchExpressions": [{"key": "tier",
                                                "operator": "In",
                                                "values": ["db"]}]}}]
spec = {"ingress": [{"from": froms}]}
ingress_network_policy_from_pods_ns_expr = {"kind": "networkpolicy",
                                            "apiversion": "net.beta.kubernetes.io",
                                            "metadata": {"namespace": "ns",
                                                         "name": "test-policy"},
                                            "spec": spec}
ingress_network_policy_from_pods_ns_expr_result = [
    Rule(action="allow",
         src_selector="k8s_ns/label/role not in { \"prod\", \"staging\" }"),
    Rule(action="allow",
         src_selector="tier in { \"db\" } && calico/k8s_ns == 'ns'")
]

# Egress NetworkPolicy with pods and namespaces defined by expressions.
froms = [{"namespaceSelector": {"matchExpressions": [{"key": "role",
                                                      "operator": "NotIn",
                                                      "values": ["prod",
                                                                 "staging"]}]}},
         {"podSelector": {"matchExpressions": [{"key": "tier",
                                                "operator": "In",
                                                "values": ["db"]}]}}]
spec = {"egress": [{"from": froms}]}
egress_network_policy_from_pods_ns_expr = {"kind": "networkpolicy",
                                           "apiversion": "net.beta.kubernetes.io",
                                           "metadata": {"namespace": "ns",
                                                        "name": "test-policy"},
                                           "spec": spec}

egress_network_policy_from_pods_ns_expr_result = [
    Rule(action="allow",
         src_selector="k8s_ns/label/role not in { \"prod\", \"staging\" }"),
    Rule(action="allow",
         src_selector="tier in { \"db\" } && calico/k8s_ns == 'ns'")
]

# Ingress NetworkPolicy all pods and all namespaces.
froms = [{"namespaceSelector": None},
         {"podSelector": None}]
spec = {"ingress": [{"from": froms}]}
ingress_network_policy_from_all = {"kind": "networkpolicy",
                                   "apiversion": "net.beta.kubernetes.io",
                                   "metadata": {"namespace": "ns",
                                                "name": "test-policy"},
                                   "spec": spec}
ingress_network_policy_from_all_result = [
    Rule(action="allow", src_selector="has(calico/k8s_ns)"),
    Rule(action="allow", src_selector="calico/k8s_ns == 'ns'")
]

# Egress NetworkPolicy all pods and all namespaces.
froms = [{"namespaceSelector": None},
         {"podSelector": None}]
spec = {"egress": [{"from": froms}]}
egress_network_policy_from_all = {"kind": "networkpolicy",
                                  "apiversion": "net.beta.kubernetes.io",
                                  "metadata": {"namespace": "ns",
                                               "name": "test-policy"},
                                  "spec": spec}
egress_network_policy_from_all_result = [
    Rule(action="allow", src_selector="has(calico/k8s_ns)"),
    Rule(action="allow", src_selector="calico/k8s_ns == 'ns'")
]

# Ingress Invalid: Cannot declare both namespaces and pods in same from.
froms = [{"namespaceSelector": None, "podSelector": None}]
spec = {"ingress": [{"from": froms}]}
ingress_network_policy_invalid_both = {"kind": "networkpolicy",
                                       "apiversion": "net.beta.kubernetes.io",
                                       "metadata": {"namespace": "ns",
                                                    "name": "test-policy"},
                                       "spec": spec}
ingress_network_policy_invalid_both_result = PolicyError

# Egress Invalid: Cannot declare both namespaces and pods in same from.
froms = [{"namespaceSelector": None, "podSelector": None}]
spec = {"egress": [{"from": froms}]}
egress_network_policy_invalid_both = {"kind": "networkpolicy",
                               "apiversion": "net.beta.kubernetes.io",
                               "metadata": {"namespace": "ns",
                                            "name": "test-policy"},
                               "spec": spec}
egress_network_policy_invalid_both_result = PolicyError

# Ingress No ingress rules - should allow all.
spec = {"ingress": [None]}
ingress_network_policy_empty_rule = {"kind": "networkpolicy",
                                     "apiversion": "net.beta.kubernetes.io",
                                     "metadata": {"namespace": "ns",
                                                  "name": "test-policy"},
                                     "spec": spec}
ingress_network_policy_empty_rule_result = [Rule(action="allow")]

# No egress rules - should allow all.
spec = {"egress": [None]}
egress_network_policy_empty_rule = {"kind": "networkpolicy",
                                    "apiversion": "net.beta.kubernetes.io",
                                    "metadata": {"namespace": "ns",
                                                 "name": "test-policy"},
                                    "spec": spec}
egress_network_policy_empty_rule_result = [Rule(action="allow")]

# Ingress NetworkPolicy with podSelector defined by expressions.
ports = [{"port": 80, "protocol": "TCP"}]
selector = {"matchExpressions": [{"key": "name", "operator": "Exists"},
                                 {"key": "date", "operator": "DoesNotExist"}]}
spec = {"ingress": [{"ports": ports}], "podSelector": selector}
ingress_network_policy_pod_sel_expr = {"kind": "networkpolicy",
                                       "apiversion": "net.beta.kubernetes.io",
                                       "metadata": {"namespace": "ns",
                                                    "name": "test-policy"},
                                       "spec": spec}
ingress_network_policy_pod_sel_expr_result = "calico/k8s_ns == 'ns' && has(name) && ! has(date)"

# NetworkPolicy with podSelector defined by expressions.
ports = [{"port": 80, "protocol": "TCP"}]
selector = {"matchExpressions": [{"key": "name", "operator": "Exists"},
                                 {"key": "date", "operator": "DoesNotExist"}]}
spec = {"egress": [{"ports": ports}], "podSelector": selector}
egress_network_policy_pod_sel_expr = {"kind": "networkpolicy",
                                      "apiversion": "net.beta.kubernetes.io",
                                      "metadata": {"namespace": "ns",
                                                   "name": "test-policy"},
                                      "spec": spec}
egress_network_policy_pod_sel_expr_result = "calico/k8s_ns == 'ns' && has(name) && ! has(date)"

# Ingress NetworkPolicy with podSelector defined by invalid expression.
ports = [{"port": 80, "protocol": "TCP"}]
selector = {"matchExpressions": [{"key": "name",
                                  "operator": "SoundsLike",
                                  "values": ["alice", "bob"]}]}
spec = {"ingress": [{"ports": ports}], "podSelector": selector}
ingress_network_policy_invalid_op = {"kind": "networkpolicy",
                                     "apiversion": "net.beta.kubernetes.io",
                                     "metadata": {"namespace": "ns",
                                                  "name": "test-policy"},
                                     "spec": spec}
ingress_network_policy_invalid_op_result = PolicyError

# Egress NetworkPolicy with podSelector defined by invalid expression.
ports = [{"port": 80, "protocol": "TCP"}]
selector = {"matchExpressions": [{"key": "name",
                                  "operator": "SoundsLike",
                                  "values": ["alice", "bob"]}]}
spec = {"egress": [{"ports": ports}], "podSelector": selector}
egress_network_policy_invalid_op = {"kind": "networkpolicy",
                                    "apiversion": "net.beta.kubernetes.io",
                                    "metadata": {"namespace": "ns",
                                                 "name": "test-policy"},
                                    "spec": spec}
egress_network_policy_invalid_op_result = PolicyError


class PolicyParserTest(unittest.TestCase):
    """
    Test class for PolicyParser class.
    """

    @parameterized.expand([
        (network_policy_empty, network_policy_empty_result),
        (ingress_network_policy_ports, ingress_network_policy_ports_result),
        (ingress_network_policy_froms, ingress_network_policy_froms_result),
        (ingress_network_policy_both, ingress_network_policy_both_result),
        (ingress_network_policy_from_pods_ns,
         ingress_network_policy_from_pods_ns_result),
        (ingress_network_policy_from_pods_ns_expr,
         ingress_network_policy_from_pods_ns_expr_result),
        (ingress_network_policy_from_all,
         ingress_network_policy_from_all_result),
        (ingress_network_policy_invalid_both,
         ingress_network_policy_invalid_both_result),
        (ingress_network_policy_empty_rule,
         ingress_network_policy_empty_rule_result)
    ])
    def test_parse_ingress_policy(self, policy, expected):
        # Parse it.
        self.parser = PolicyParser(policy)

        # If expected result is an exception, try to catch it.
        try:
            rules = self.parser.calculate_inbound_rules()
        except Exception, e:
            if isinstance(e, expected):
                pass
            else:
                raise
        else:
            assert_equal(sorted(rules), sorted(expected))

    @parameterized.expand([
        (egress_network_policy_ports, egress_network_policy_ports_result),
        (egress_network_policy_froms, egress_network_policy_froms_result),
        (egress_network_policy_both, egress_network_policy_both_result),
        (egress_network_policy_from_pods_ns,
         egress_network_policy_from_pods_ns_result),
        (egress_network_policy_from_pods_ns_expr,
         egress_network_policy_from_pods_ns_expr_result),
        (egress_network_policy_from_all,
         egress_network_policy_from_all_result),
        (egress_network_policy_invalid_both,
         egress_network_policy_invalid_both_result),
        (egress_network_policy_empty_rule,
         egress_network_policy_empty_rule_result)
    ])
    def test_parse_egress_policy(self, policy, expected):
        # Parse it.
        self.parser = PolicyParser(policy)

        # If expected result is an exception, try to catch it.
        try:
            rules = self.parser.calculate_outbound_rules()
        except Exception, e:
            if isinstance(e, expected):
                pass
            else:
                raise
        else:
            assert_equal(sorted(rules), sorted(expected))

    @parameterized.expand([
        (ingress_network_policy_pod_sel_expr,
         ingress_network_policy_pod_sel_expr_result),
        (ingress_network_policy_invalid_op,
         ingress_network_policy_invalid_op_result)
    ])
    def test_pod_selector(self, policy, expected):
        # Parse it.
        self.parser = PolicyParser(policy)

        # If expected result is an exception, try to catch it.
        try:
            selector = self.parser.calculate_pod_selector()
        except Exception, e:
            if isinstance(e, expected):
                pass
            else:
                raise
        else:
            assert_equal(selector, expected)
