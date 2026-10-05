# Shared helpers for the cluster manifest policy tests. conftest evaluates
# every rendered document as `input` and reports every `deny` message.
# The rules implement the M5 security baseline from PLAN.md; independent
# counterexamples are exercised by scripts/test-cluster-policy.
package main

import rego.v1

as_object(value) := value if {
	is_object(value)
} else := {}

as_array(value) := value if {
	is_array(value)
} else := []

object_field(obj, key) := as_object(object.get(as_object(obj), key, {}))

array_field(obj, key) := as_array(object.get(as_object(obj), key, []))

workload_kinds := {"Pod", "PodTemplate", "Deployment", "ReplicaSet", "ReplicationController", "StatefulSet", "DaemonSet", "Job", "CronJob"}

vendored_flux_images := {
	"helm-controller": "ghcr.io/fluxcd/helm-controller:v1.2.0",
	"image-automation-controller": "ghcr.io/fluxcd/image-automation-controller:v0.40.0",
	"image-reflector-controller": "ghcr.io/fluxcd/image-reflector-controller:v0.34.0",
	"kustomize-controller": "ghcr.io/fluxcd/kustomize-controller:v1.5.1",
	"notification-controller": "ghcr.io/fluxcd/notification-controller:v1.5.0",
	"source-controller": "ghcr.io/fluxcd/source-controller:v1.5.0",
}

vendored_flux_container(obj, c) if {
	obj.apiVersion == "apps/v1"
	obj.kind == "Deployment"
	obj.metadata.namespace == "flux-system"
	c.name == "manager"
	c.image == vendored_flux_images[obj.metadata.name]
	c in obj.spec.template.spec.containers
}

effective_security(obj, c, key, fallback) := object.get(
	object_field(c, "securityContext"),
	key,
	object.get(object_field(pod_spec(obj), "securityContext"), key, fallback),
)

pod_spec(obj) := object_field(obj, "spec") if {
	obj.kind == "Pod"
}

pod_spec(obj) := object_field(object_field(object_field(obj, "spec"), "template"), "spec") if {
	obj.kind in {"Deployment", "ReplicaSet", "ReplicationController", "StatefulSet", "DaemonSet", "Job"}
}

pod_spec(obj) := object_field(object_field(obj, "template"), "spec") if {
	obj.kind == "PodTemplate"
}

pod_spec(obj) := object_field(object_field(object_field(object_field(object_field(obj, "spec"), "jobTemplate"), "spec"), "template"), "spec") if {
	obj.kind == "CronJob"
}

all_containers(obj) := cs if {
	spec := pod_spec(obj)
	cs := array.concat(
		array.concat(array_field(spec, "containers"), array_field(spec, "initContainers")),
		array_field(spec, "ephemeralContainers"),
	)
}

workload_ref(obj) := sprintf("%s/%s in namespace %s", [
	object.get(as_object(obj), "kind", "?"),
	object.get(object_field(obj, "metadata"), "name", "?"),
	object.get(object_field(obj, "metadata"), "namespace", "default"),
])

deny contains sprintf("%s: unsupported pod-template kind", [workload_ref(input)]) if {
	not input.kind in workload_kinds
	input.spec.template.spec
}

deny contains sprintf("%s: unsupported job-template kind", [workload_ref(input)]) if {
	not input.kind in workload_kinds
	input.spec.jobTemplate.spec.template.spec
}
