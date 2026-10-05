package main

import rego.v1

sops_ciphertext(value) if {
	is_string(value)
	regex.match(`^ENC\[AES256_GCM,data:[A-Za-z0-9+/=]*,iv:[A-Za-z0-9+/=]+,tag:[A-Za-z0-9+/=]+,type:str\]$`, value)
}

secret_documents contains document if {
	walk(input, [_, document])
	is_object(document)
	document.kind == "Secret"
}

deny contains "resource list wrappers are forbidden; use separate manifest documents" if {
	walk(input, [_, document])
	is_object(document)
	is_string(document.kind)
	endswith(document.kind, "List")
}

secret_payload(document) if {
	some section in {"data", "stringData"}
	count(object.get(document, section, {})) > 0
}

deny contains sprintf("%s: Secret metadata must be a map", [workload_ref(document)]) if {
	some document in secret_documents
	not is_object(object.get(document, "metadata", null))
}

deny contains sprintf("%s: Secret %s must be a map", [workload_ref(document), section]) if {
	some document in secret_documents
	some section in {"data", "stringData"}
	not is_object(object.get(document, section, {}))
}

valid_sops_metadata(document) if {
	sops_ciphertext(document.sops.mac)
	document.sops.encrypted_regex == "^(data|stringData)$"
	count(document.sops.age) > 0
	every recipient in document.sops.age {
		regex.match(`^age1[0-9a-z]+$`, recipient.recipient)
		startswith(recipient.enc, "-----BEGIN AGE ENCRYPTED FILE-----")
		contains(recipient.enc, "-----END AGE ENCRYPTED FILE-----")
	}
}

deny contains sprintf("%s: Secret payload requires SOPS age metadata", [workload_ref(document)]) if {
	some document in secret_documents
	secret_payload(document)
	not valid_sops_metadata(document)
}

deny contains sprintf("%s: Secret %s.%s must be SOPS encrypted", [workload_ref(document), section, key]) if {
	some document in secret_documents
	some section in {"data", "stringData"}
	some key, value in object.get(document, section, {})
	not sops_ciphertext(value)
}

deny contains "secretGenerator is forbidden; reference an encrypted SOPS Secret manifest" if {
	count(object.get(input, "secretGenerator", [])) > 0
}

deny contains "SecretGenerator is forbidden; reference an encrypted SOPS Secret manifest" if {
	input.kind == "SecretGenerator"
}
