#!/usr/bin/env python3
import base64
import binascii
import ipaddress
import json
import posixpath
import re
import sys


class ValidationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def validate_topology(data, allow_empty=False):
    groups = data["groups"]
    hosts = data["hosts"]
    members = {}
    for group in ("wireguard", "k3s_servers", "k3s_agents", "ingress"):
        names = groups.get(group, [])
        require(isinstance(names, list) and all(isinstance(name, str) for name in names),
                "inventory groups must contain host names")
        require(len(names) == len(set(names)), "inventory groups must not contain duplicate hosts")
        members[group] = set(names)
    mesh = members["wireguard"]
    servers = members["k3s_servers"]
    agents = members["k3s_agents"]
    ingress = members["ingress"]
    require(not servers & agents and servers | agents == mesh,
            "k3s_servers and k3s_agents must exclusively and completely partition wireguard")
    require(ingress <= mesh, "ingress must be a subset of wireguard")
    if not mesh and allow_empty:
        return
    require(bool(mesh), "topology requires a nonempty wireguard inventory")
    require(len(ingress) == 1, "topology requires exactly one ingress frontend")
    require(bool(servers), "topology requires at least one server")
    init = []
    addresses = set()
    networks = set()
    public_keys = set()
    shared = {key: set() for key in (
        "k3s_cluster_init_host", "k3s_server_host", "k3s_datastore", "k3s_default_local_storage_path")}
    reserved = {"cvp.io/bootstrap", "cvp.io/bootstrap-quarantine"}
    ingress_labels = {
        "cvp.io/ingress": "true",
        "svccontroller.k3s.cattle.io/enablelb": "true",
        "svccontroller.k3s.cattle.io/lbpool": "public",
    }
    for name in sorted(mesh):
        host = hosts[name]
        require(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", name) is not None
                and host.get("node_name") == name, "node_name must match a valid inventory host name")
        require(host.get("k3s_role") == ("server" if name in servers else "agent"),
                "k3s_role must match the exclusive server/agent group")
        require(type(host.get("k3s_server_init")) is bool, "k3s_server_init must be an explicit boolean")
        if host["k3s_server_init"]:
            require(name in servers, "only a server may have k3s_server_init=true")
            init.append(name)
        for key in shared:
            value = host.get(key)
            require(isinstance(value, str) and bool(value), key + " must be explicitly configured")
            shared[key].add(value)
        require(host.get("wireguard_peers_group") == "wireguard",
                "wireguard_peers_group must select the complete wireguard mesh")
        address = host.get("wireguard_address")
        require(isinstance(address, str), "wireguard_address must be a bare IPv4 address")
        try:
            ip = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError:
            raise ValidationError("wireguard_address must be a valid bare IPv4 address") from None
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        require(not (ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local
                     or ip.is_reserved or int(ip) >> 24 == 0)
                and ip not in (network.network_address, network.broadcast_address),
                "wireguard_address must be usable unicast on its /24")
        require(address not in addresses, "wireguard_address must be unique")
        addresses.add(address)
        networks.add(network)
        public_key = host.get("wireguard_public_key")
        require(isinstance(public_key, str), "wireguard_public_key must be canonical base64 for 32 bytes")
        try:
            decoded = base64.b64decode(public_key, validate=True)
        except (ValueError, binascii.Error):
            raise ValidationError("wireguard_public_key must be canonical base64 for 32 bytes") from None
        require(len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == public_key,
                "wireguard_public_key must be canonical base64 for 32 bytes")
        require(public_key not in public_keys, "wireguard_public_key must be unique")
        public_keys.add(public_key)
        for key in ("k3s_node_labels", "k3s_node_taints"):
            flags = host.get(key)
            require(isinstance(flags, list) and all(isinstance(flag, str) for flag in flags),
                    key + " must be a list of strings")
            keys = [re.split("[=:]", flag, maxsplit=1)[0] for flag in flags]
            require(len(keys) == len(set(keys)), key + " must not contain duplicate keys")
            require(not reserved.intersection(keys), "bootstrap quarantine tags are reserved for rendered configuration")
            require("cvp.io/role" not in keys, "cvp.io/role must be derived from k3s_role")
        labels = {}
        for label in host["k3s_node_labels"]:
            key, _, value = label.partition("=")
            labels[key] = value
        if name in ingress:
            require(all(labels.get(key) == value for key, value in ingress_labels.items()),
                    "ingress node must declare cvp.io/ingress=true, "
                    "svccontroller.k3s.cattle.io/enablelb=true and svccontroller.k3s.cattle.io/lbpool=public")
        else:
            require(labels.get("cvp.io/ingress") in (None, "false")
                    and not (ingress_labels.keys() - {"cvp.io/ingress"}).intersection(labels),
                    "non-ingress nodes must omit ServiceLB placement labels and omit cvp.io/ingress or set it to false")
        require(type(host.get("storage_enabled")) is bool, "storage_enabled must be boolean")
        path = host["k3s_default_local_storage_path"]
        require(path.startswith("/") and path != "/" and posixpath.normpath(path) == path,
                "k3s_default_local_storage_path must be a canonical absolute directory")
        if host["storage_enabled"]:
            require(host.get("storage_mountpoint") == path,
                    "storage_mountpoint must match k3s_default_local_storage_path on storage-enabled nodes")
    require(len(init) == 1, "topology requires exactly one k3s_server_init=true server")
    require(len(networks) == 1, "wireguard addresses must share one /24 mesh")
    for key, values in shared.items():
        require(len(values) == 1, key + " must be consistent across all mesh nodes")
    require(shared["k3s_cluster_init_host"] == {init[0]},
            "k3s_cluster_init_host must name the unique init server")
    require(next(iter(shared["k3s_server_host"])) in servers, "k3s_server_host must name a server")
    datastore = next(iter(shared["k3s_datastore"]))
    require(datastore in ("etcd", "sqlite"), "k3s_datastore must be etcd or sqlite")
    require(datastore != "sqlite" or len(servers) == 1, "sqlite requires exactly one server")


def validate_onboard_intent(data, target, confirmation):
    validate_topology(data)
    require(isinstance(target, str) and target in data["groups"]["wireguard"],
            "cvp_onboard_node must name one inventory mesh node")
    require(isinstance(confirmation, str), "cvp_onboard_server_confirm must be a string")
    host = data["hosts"][target]
    require(not host["k3s_server_init"], "onboarding must not initialize a control plane")
    if host["k3s_role"] == "server":
        require(confirmation == target, "a new server requires cvp_onboard_server_confirm equal to cvp_onboard_node")
    else:
        require(confirmation == "", "an agent must not carry a server confirmation")
    require(host["k3s_server_host"] != target, "onboarding requires an existing designated server")


def validate_onboard(data, target, confirmation, nodes):
    validate_onboard_intent(data, target, confirmation)
    require(isinstance(nodes, list), "cluster API must return a Node list")
    expected = set(data["groups"]["wireguard"])
    actual = {}
    server_labels = {"node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master",
                     "node-role.kubernetes.io/etcd"}
    for node in nodes:
        metadata = node["metadata"]
        name = metadata["name"]
        require(name in expected, "cluster contains an unexpected node or unconfirmed server")
        require(name not in actual, "cluster API returned duplicate node names")
        actual[name] = node
        require(not metadata.get("deletionTimestamp"), "cluster contains a terminating inventory node")
        labels = metadata.get("labels", {})
        server = bool(server_labels.intersection(labels))
        host = data["hosts"][name]
        require(server == (host["k3s_role"] == "server"), "cluster node role differs from inventory")
        require(not server or bool((server_labels - {"node-role.kubernetes.io/etcd"}).intersection(labels)),
                "inventory servers must be initialized control-plane nodes")
        require("cvp.io/role" not in labels
                or labels["cvp.io/role"] == ("control-plane" if server else "agent"),
                "cluster cvp.io/role differs from inventory")
        addresses = [entry["address"] for entry in node.get("status", {}).get("addresses", [])
                     if entry.get("type") == "InternalIP"]
        ipv4 = [address for address in addresses if ipaddress.ip_address(address).version == 4]
        require(ipv4 == [host["wireguard_address"]], "cluster node InternalIP differs from inventory mesh address")
        if name != target:
            ready = [condition for condition in node.get("status", {}).get("conditions", [])
                     if condition.get("type") == "Ready"]
            require(len(ready) == 1 and ready[0].get("status") == "True",
                    "all existing inventory nodes must be Ready before onboarding")
    require(expected - {target} <= actual.keys(),
            "cluster is missing an existing inventory node or an unconfirmed server")


def main():
    try:
        payload = json.load(sys.stdin)
        mode = sys.argv[1]
        data = payload["topology"]
        if mode == "topology":
            validate_topology(data, payload.get("allow_empty") is True)
        elif mode == "onboard-intent":
            validate_onboard_intent(data, payload.get("target"), payload.get("server_confirmation", ""))
        elif mode == "onboard":
            validate_onboard(data, payload.get("target"), payload.get("server_confirmation", ""), payload["nodes"])
        else:
            raise ValidationError("unknown validation mode")
    except ValidationError as error:
        print(str(error), file=sys.stderr)
        return 1
    except ValueError:
        print("invalid topology or API input", file=sys.stderr)
        return 1
    except (KeyError, TypeError, IndexError, AttributeError):
        print("incomplete or malformed topology or API input", file=sys.stderr)
        return 1
    print("validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
