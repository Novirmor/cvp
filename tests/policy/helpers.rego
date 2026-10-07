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

# Vendored Flux controllers are tag-pinned by the committed install manifest,
# not digest-pinned like application images. The exemption matches the image
# repository so Renovate digest-pinning (or a version bump) of these
# controllers cannot break policy evaluation; :latest stays forbidden for them
# too (see images.rego).
vendored_flux_repositories := {
	"ghcr.io/fluxcd/helm-controller",
	"ghcr.io/fluxcd/image-automation-controller",
	"ghcr.io/fluxcd/image-reflector-controller",
	"ghcr.io/fluxcd/kustomize-controller",
	"ghcr.io/fluxcd/notification-controller",
	"ghcr.io/fluxcd/source-controller",
}

image_repository(image) := regex.replace(
	regex.replace(image, `@.*$`, ""),
	`:[^:/]+$`,
	"",
)

vendored_flux_container(obj, c) if {
	obj.apiVersion == "apps/v1"
	obj.kind == "Deployment"
	obj.metadata.namespace == "flux-system"
	c.name == "manager"
	image_repository(c.image) in vendored_flux_repositories
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
