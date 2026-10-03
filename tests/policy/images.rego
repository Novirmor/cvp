# Production images must be digest-pinned. Mutable tags are rejected for
# repository-authored workloads; the :latest tag is rejected everywhere,
# including exempted bootstrap namespaces.
package main

import rego.v1

deny contains sprintf("%s: container %q uses the forbidden :latest tag", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	some c in all_containers(input)
	endswith(object.get(c, "image", ""), ":latest")
}

deny contains sprintf("%s: container %q image must be pinned by digest", [workload_ref(input), c.name]) if {
	input.kind in workload_kinds
	not object.get(input.metadata, "namespace", "") in digest_exempt_namespaces
	some c in all_containers(input)
	not regex.match(`@sha256:[0-9a-f]{64}$`, object.get(c, "image", ""))
}
