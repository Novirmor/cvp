#!/usr/bin/env python3
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ansible/roles/wireguard/files/cvp-wireguard-state"


def identity(kind):
    return os.stat("/proc/self/ns/" + kind).st_ino


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def isolated(guard):
    require(identity("user") != guard["user"] and identity("net") != guard["net"], "Namespace isolation failed")
    require(Path("/proc/self/uid_map").read_text().split() == ["0", str(guard["uid"]), "1"], "Unexpected uid mapping")
    with open("/proc/self/ns/net", "rb") as stream:
        owner = fcntl.ioctl(stream.fileno(), 0xB701)
    try:
        require(os.fstat(owner).st_ino == identity("user"), "Network namespace has another owner")
    finally:
        os.close(owner)


def sandbox():
    guard = json.loads(os.environ["CVP_WG_TEST_GUARD"])
    isolated(guard)

    def run(*argv, stdin=None, success=True):
        isolated(guard)
        result = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=30)
        require((result.returncode == 0) == success, f"Unexpected exit for {argv[0]}: {result.stderr}")
        return result.stdout

    require([link["ifname"] for link in json.loads(run("ip", "-j", "link"))] == ["lo"], "Unexpected inherited interfaces")
    with tempfile.TemporaryDirectory(prefix="cvp-wg-dataplane-") as directory:
        work = Path(directory)
        config, record = work / "wg0.conf", work / "record.json"
        private = run("wg", "genkey").strip()
        peer = run("wg", "pubkey", stdin=run("wg", "genkey")).strip()

        def write_config(key=private, endpoint="198.51.100.2:51820"):
            config.write_text(f"[Interface]\nAddress = 192.0.2.1/24\nListenPort = 51820\nMTU = 1420\n"
                              f"PrivateKey = {key}\nSaveConfig = false\n[Peer]\nPublicKey = {peer}\n"
                              f"AllowedIPs = 192.0.2.2/32\nEndpoint = {endpoint}\nPersistentKeepalive = 25\n")
            config.chmod(0o600)

        def helper(action, success=True):
            return run(sys.executable, "-B", "-c", 'import runpy, sys; runpy.run_path(sys.argv.pop(1))["main"]()',
                       str(HELPER), action, "--interface", "wg0", "--config", str(config),
                       "--record", str(record), "--temp-dir", directory, success=success)

        write_config()
        require(not json.loads(helper("inspect"))["present"], "Fresh interface incorrectly detected")
        run("ip", "link", "add", "wg0", "type", "wireguard")
        index = json.loads(run("ip", "-j", "link", "show", "dev", "wg0"))[0]["ifindex"]
        require(json.loads(helper("apply"))["changed"], "Fresh interface was not configured")
        helper("verify")
        require(not json.loads(helper("apply"))["changed"], "Unchanged reconciliation is not idempotent")
        require(record.stat().st_mode & 0o777 == 0o600, "Activation record is not private")

        interface_only = config.read_text().split("[Peer]", 1)[0]
        config.write_text(interface_only)
        helper("apply")
        helper("verify")
        require(not run("wg", "show", "wg0", "peers").strip(), "No-peer mesh retained a retired peer")
        run("ip", "route", "del", "192.0.2.0/24", "dev", "wg0")
        before = run("wg", "show", "wg0", "dump"), record.read_bytes()
        for action in ("inspect", "verify", "apply"):
            helper(action, success=False)
            require(before == (run("wg", "show", "wg0", "dump"), record.read_bytes()),
                    "No-peer missing-route fence mutated WireGuard state")
        run("ip", "route", "add", "192.0.2.0/24", "dev", "wg0", "proto", "kernel", "scope", "link", "src", "192.0.2.1")
        helper("verify")
        run("ip", "link", "set", "wg0", "down")
        before = run("wg", "show", "wg0", "dump"), record.read_bytes(), run("ip", "-4", "-j", "route", "show", "table", "all")
        require(json.loads(helper("inspect")) == {"present": True, "matches": False}, "Down no-peer interface was reported healthy")
        helper("verify", success=False)
        require(before == (run("wg", "show", "wg0", "dump"), record.read_bytes(),
                           run("ip", "-4", "-j", "route", "show", "table", "all")),
                "Down-interface inspection or verification mutated state")
        require(json.loads(helper("apply"))["changed"], "Down interface did not recover in place")
        helper("verify")
        require(json.loads(run("ip", "-j", "link", "show", "dev", "wg0"))[0]["ifindex"] == index,
                "Down no-peer recovery replaced the interface")
        write_config()
        helper("apply")
        helper("verify")

        run("ip", "route", "del", "192.0.2.0/24", "dev", "wg0")
        before = run("wg", "show", "wg0", "dump"), record.read_bytes(), run("ip", "-4", "-j", "route", "show", "table", "all")
        for action in ("inspect", "verify", "apply"):
            helper(action, success=False)
            require(before == (run("wg", "show", "wg0", "dump"), record.read_bytes(),
                               run("ip", "-4", "-j", "route", "show", "table", "all")),
                    "Missing-route rejection mutated WireGuard or routing state")
        run("ip", "route", "add", "192.0.2.0/24", "dev", "wg0", "proto", "kernel", "scope", "link", "src", "192.0.2.1")
        helper("verify")
        run("ip", "link", "add", "external", "type", "dummy")
        run("ip", "link", "set", "external", "up")
        for extra in (("ip", "route", "add", "192.0.2.2/32", "dev", "external"),
                      ("ip", "route", "add", "192.0.2.2/32", "dev", "external", "table", "100")):
            run(*extra)
            if extra[-1] == "100":
                run("ip", "rule", "add", "priority", "100", "to", "192.0.2.2/32", "table", "100")
            before = run("wg", "show", "wg0", "dump"), record.read_bytes(), run("ip", "-4", "-j", "route", "show", "table", "all")
            for action in ("inspect", "verify", "apply"):
                helper(action, success=False)
                require(before == (run("wg", "show", "wg0", "dump"), record.read_bytes(),
                                   run("ip", "-4", "-j", "route", "show", "table", "all")),
                        "Competing-route rejection mutated WireGuard or unrelated routing state")
            if extra[-1] == "100":
                run("ip", "rule", "del", "priority", "100")
            run(*extra[:2], "del", *extra[3:])
            helper("verify")
        require(not json.loads(helper("apply"))["changed"], "Route recovery changed healthy WireGuard state")

        second_peer = run("wg", "pubkey", stdin=run("wg", "genkey")).strip()
        config.write_text(config.read_text() + f"[Peer]\nPublicKey = {second_peer}\nAllowedIPs = 192.0.2.3/32\n")
        helper("apply")
        helper("verify")
        require(second_peer in run("wg", "show", "wg0", "peers"), "New inventory peer was not installed")
        write_config()
        helper("apply")
        helper("verify")
        require(second_peer not in run("wg", "show", "wg0", "peers"), "Retired inventory peer survived")
        config.write_text(config.read_text().replace("PersistentKeepalive = 25\n", ""))
        helper("apply")
        helper("verify")
        require("off" in run("wg", "show", "wg0", "persistent-keepalive"), "Omitted keepalive did not disable prior value")
        write_config()
        helper("apply")
        helper("verify")
        foreign_record = work / ".cvp-old-interface-live.json"
        foreign_record.write_text("{}")
        helper("inspect", success=False)
        foreign_record.unlink()

        run("wg", "set", "wg0", "peer", peer, "endpoint", "198.51.100.99:40000")
        require(not json.loads(helper("apply"))["changed"], "Authenticated endpoint roaming was overwritten")
        run("wg", "set", "wg0", "listen-port", "51999", "fwmark", "123", "peer", peer,
            "allowed-ips", "192.0.2.99/32", "persistent-keepalive", "0")
        unexpected_key = work / "unexpected-key"
        unexpected_key.write_text(run("wg", "genkey"))
        unexpected_key.chmod(0o600)
        run("wg", "set", "wg0", "private-key", str(unexpected_key), "peer", peer,
            "preshared-key", str(unexpected_key))
        rogue = run("wg", "pubkey", stdin=run("wg", "genkey")).strip()
        run("wg", "set", "wg0", "peer", rogue, "allowed-ips", "192.0.2.100/32")
        run("ip", "address", "del", "192.0.2.1/24", "dev", "wg0")
        run("ip", "address", "add", "192.0.2.10/24", "dev", "wg0")
        run("ip", "link", "set", "wg0", "mtu", "1300", "down")
        before = run("wg", "show", "wg0", "dump"), record.read_bytes()
        helper("verify", success=False)
        require(before == (run("wg", "show", "wg0", "dump"), record.read_bytes()), "Verification mutated state")
        helper("apply")
        helper("verify")
        require("198.51.100.99:40000" in run("wg", "show", "wg0", "endpoints"), "Drift repair lost roaming endpoint")
        require(rogue not in run("wg", "show", "wg0", "peers"), "Unexpected peer survived")

        old_path = os.environ["PATH"]
        real_wg = shutil.which("wg")
        bin_directory = work / "bin"
        bin_directory.mkdir()
        failing_wg = bin_directory / "wg"
        failing_wg.write_text(f"#!{sys.executable}\nimport os, sys\n"
                              "if sys.argv[1] == 'syncconf': sys.exit(7)\n"
                              f"os.execv({real_wg!r}, [{real_wg!r}, *sys.argv[1:]])\n")
        failing_wg.chmod(0o700)
        run("ip", "link", "set", "wg0", "mtu", "1300")
        os.environ["PATH"] = str(bin_directory) + os.pathsep + old_path
        try:
            helper("apply", success=False)
            require(json.loads(record.read_text())["fingerprint"] == "", "Failed syncconf retained success evidence")
            require(not list(work.glob("cvp-wg-sync-*")), "Failed syncconf leaked a secret file")
        finally:
            os.environ["PATH"] = old_path
        helper("apply")
        helper("verify")
        require("198.51.100.99:40000" in run("wg", "show", "wg0", "endpoints"), "Retry lost roaming endpoint intent")

        rotated = run("wg", "genkey").strip()
        write_config(key=rotated, endpoint="198.51.100.3:51821")
        helper("verify", success=False)
        helper("apply")
        helper("verify")
        require(run("wg", "show", "wg0", "public-key").strip() == run("wg", "pubkey", stdin=rotated).strip(), "Key rotation failed")
        require("198.51.100.3:51821" in run("wg", "show", "wg0", "endpoints"), "Changed endpoint intent was ignored")
        require(json.loads(run("ip", "-j", "link", "show", "dev", "wg0"))[0]["ifindex"] == index,
                "Reconciliation replaced the interface")
        config.write_text(config.read_text().replace("192.0.2.1/24", "192.0.2.10/24"))
        before = run("wg", "show", "wg0", "dump"), record.read_bytes()
        helper("inspect", success=False)
        helper("apply", success=False)
        require(before == (run("wg", "show", "wg0", "dump"), record.read_bytes()), "Identity migration was not fenced")
        write_config(key=rotated, endpoint="198.51.100.3:51821")
        config.write_text(config.read_text().replace("192.0.2.2/32", "203.0.113.2/32"))
        helper("inspect", success=False)
        write_config(key=rotated, endpoint="198.51.100.3:51821")
        config.write_text(config.read_text().replace(peer, "invalid-key"))
        before = run("wg", "show", "wg0", "dump")
        helper("apply", success=False)
        require(run("wg", "show", "wg0", "dump") == before, "Invalid peer data mutated the interface")
        require(not list(work.glob("cvp-wg-sync-*")), "Secret sync files were not removed")
        print("PASS: real WireGuard syncconf, rotation, peer/address/MTU/port drift, mesh/peer/policy route fences, roaming, read-only verification, stable ifindex")


def main():
    if sys.argv[1:] == ["--sandbox"]:
        sandbox()
        return
    require(not sys.argv[1:] and os.getuid() > 0 and os.getuid() == os.geteuid(), "Run without sudo/root or extra arguments")
    for binary in ("wg", "wg-quick", "ip", "unshare"):
        require(shutil.which(binary), "Required test tool missing: " + binary)
    guard = {"uid": os.getuid(), "user": identity("user"), "net": identity("net")}
    result = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "--", sys.executable, "-B", __file__, "--sandbox"],
                            env=os.environ | {"CVP_WG_TEST_GUARD": json.dumps(guard)}, timeout=120)
    require(identity("user") == guard["user"] and identity("net") == guard["net"], "Launcher namespace changed")
    require(result.returncode == 0, "Isolated WireGuard kernel checks failed")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
