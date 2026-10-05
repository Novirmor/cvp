from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


PROBE_TIMEOUT = 15
ZERO_SCAN_TIMEOUT = 300


class UnsafeStorage(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise UnsafeStorage(message)


class System:
    def run(self, argv, accepted=(0,), timeout=PROBE_TIMEOUT):
        try:
            result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise UnsafeStorage(f"Storage inspection timed out after {timeout}s: {argv[0]}; prepare slow devices outside this role") from error
        require(result.returncode in accepted, f"Storage inspection failed: {argv[0]} (rc={result.returncode})")
        return result.returncode, result.stdout, result.stderr

    def device(self, path):
        canonical = os.path.realpath(path, strict=True)
        info = os.stat(canonical)
        require(stat.S_ISBLK(info.st_mode), "The storage target must be a block device")
        require(canonical.startswith("/dev/"), "The resolved storage target must be under /dev")
        return canonical, f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"

    def directory(self, path):
        require(os.path.realpath(path) == path, "The storage mountpoint and its ancestors must not be symlinks")
        for component in (Path(path), *Path(path).parents):
            try:
                info = component.stat()
            except FileNotFoundError:
                continue
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    "Storage directory ancestry must be root-owned directories without group/other write access")
        try:
            info = os.stat(path)
        except FileNotFoundError:
            return {"exists": False, "populated": False}
        require(stat.S_ISDIR(info.st_mode), "The storage mountpoint must be a directory")
        with os.scandir(path) as entries:
            populated = next(entries, None) is not None
        return {"exists": True, "populated": populated}

    def holders(self, device_number):
        return list(Path("/sys/dev/block", device_number, "holders").iterdir())

    @contextmanager
    def exclusive(self, device, number):
        descriptor = os.open(device, os.O_RDONLY | os.O_EXCL | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISBLK(info.st_mode)
                    and f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}" == number,
                    "Device identity changed during inspection")
            yield
        finally:
            os.close(descriptor)

    def swap_device(self, path, kind):
        if kind == "partition":
            return self.device(path)[1]
        require(kind == "file", "Unknown active swap type")
        info = os.stat(path)
        require(stat.S_ISREG(info.st_mode), "Active swap file cannot be identified")
        return f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"


def read_json(system, argv, key):
    _, output, errors = system.run(argv)
    require(not errors.strip(), f"Inconclusive storage inspection: {argv[0]}")
    try:
        value = json.loads(output)[key]
    except (ValueError, KeyError, TypeError) as error:
        raise UnsafeStorage(f"Invalid storage inspection output: {argv[0]}") from error
    require(isinstance(value, list), f"Missing storage inspection list: {key}")
    require(all(isinstance(item, dict) for item in value), f"Invalid storage inspection entries: {key}")
    return value


def parse_swaps(output):
    require(all(character in ("\n", "\t") or (ord(character) >= 32 and ord(character) != 127)
                for character in output), "Unescaped control character in swapon raw output")
    swaps = []
    names = set()
    for line in output.splitlines():
        match = re.fullmatch(r"((?:[^\\\s]|\\x[0-9a-fA-F]{2})+)[ \t]+(file|partition)", line)
        if match is None:
            raise UnsafeStorage("Malformed swapon raw output")
        encoded, kind = match.groups()
        name = os.fsdecode(re.sub(
            rb"\\x([0-9a-fA-F]{2})",
            lambda value: bytes([int(value[1], 16)]),
            os.fsencode(encoded),
        ))
        require(name.startswith("/") and "\x00" not in name and name not in names,
                "Active swap paths must be absolute, unique, and free of NUL bytes")
        names.add(name)
        swaps.append({"name": name, "type": kind})
    return swaps


def read_swaps(system):
    _, output, errors = system.run(["/usr/sbin/swapon", "--show=NAME,TYPE", "--raw", "--noheadings"])
    require(not errors.strip(), "Inconclusive active swap inspection")
    return parse_swaps(output)


def export_values(output):
    values = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        require(separator and key and key not in values, "Invalid or ambiguous blkid result")
        values[key] = value
    return values


def valid_uuid(value):
    return isinstance(value, str) and re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value
    ) is not None


def validate(config):
    require(config.get("action") in ("preflight", "verify"), "Unknown storage inspection action")
    require(isinstance(config.get("host"), str) and bool(config["host"]), "Inventory host identity is required")
    for field in ("device", "mountpoint", "filesystem", "mount_options", "directory_mode", "format_confirmation"):
        require(isinstance(config.get(field), str), f"storage {field} must be a string")
        require(not any(ord(character) < 32 for character in config[field]), f"Invalid storage {field}")
    path = config["mountpoint"]
    require(path.startswith("/") and os.path.normpath(path) == path, "Use a normalized absolute storage mountpoint")
    require(len(Path(path).parts) >= 3, "Refusing a root or top-level storage mountpoint")
    require(path not in ("/var/lib", "/var/lib/rancher", "/var/lib/rancher/k3s"), "Refusing a system data directory as storage")
    require(not any(path == prefix or path.startswith(prefix + "/") for prefix in (
        "/etc", "/usr", "/boot", "/dev", "/proc", "/sys", "/run", "/root", "/home",
        "/tmp", "/var/tmp", "/var/log", "/var/cache", "/var/spool",
    )), "Refusing a system directory as storage")
    require(not config["device"] or config["device"].startswith("/dev/"), "storage_device must be an absolute /dev path")
    require(config["filesystem"] in ("ext4", "xfs"), "Managed storage supports ext4 or existing XFS only")
    mode = config["directory_mode"]
    require(re.fullmatch(r"0?[0-7]{3}", mode), "storage_directory_mode must be an octal permission string")
    require(int(mode, 8) & 0o700 == 0o700 and not int(mode, 8) & 0o022, "The storage directory needs owner rwx and must not be group/other writable")
    options = config["mount_options"].split(",")
    require(bool(options) and all(option in {
        "defaults", "rw", "noatime", "relatime", "strictatime", "nodiratime",
        "nodev", "nosuid", "noexec", "discard", "lazytime", "sync", "async", "errors=remount-ro",
    } for option in options), "Unsupported storage mount options")
    require(config["filesystem"] == "ext4" or "errors=remount-ro" not in options, "errors=remount-ro is an ext4-only mount option")
    for field in ("manage_device", "allow_format"):
        require(isinstance(config.get(field), bool), f"storage {field} must be boolean")


def inspect(config, system):
    validate(config)
    mountpoint = config["mountpoint"]
    directory = system.directory(mountpoint)
    report = {
        "device": "", "uuid": "", "filesystem": "", "needs_format": False,
        "mountpoint_exists": directory["exists"], "mounted": False,
    }
    if not config["device"]:
        if config["action"] == "verify":
            require(directory["exists"], "The directory-backed storage path does not exist")
        return report

    device, number = system.device(config["device"])
    devices = read_json(system, [
        "/usr/bin/lsblk", "--json", "--bytes", "--paths", "--list", "--output",
        "NAME,KNAME,PKNAME,TYPE,MAJ:MIN,SIZE,RO,FSTYPE,UUID,WWN,SERIAL,PARTUUID,START",
    ], "blockdevices")
    candidates = [item for item in devices if item.get("maj:min") == number]
    require(len(candidates) == 1, "The target must have one unambiguous lsblk identity")
    node = candidates[0]
    require(node.get("name") == device, "lsblk disagrees with the resolved device path")
    require(node.get("type") in ("disk", "part"), "Only a physical disk or partition is supported; mappings require manual preparation")
    require(isinstance(node.get("ro"), (bool, int)) and node["ro"] == 0, "The storage device is read-only or its state is unknown")
    size = node.get("size")
    require(isinstance(size, int) and not isinstance(size, bool) and size >= 16 * 1024 * 1024, "Missing or insufficient device capacity")
    for option, expected in (("--getsize64", str(size)), ("--getro", "0")):
        _, output, errors = system.run(["/usr/sbin/blockdev", option, device])
        require(not errors.strip() and output.strip() == expected, "Device size/read-only probes disagree")

    name = Path(device).name
    require(not any(item.get("pkname") and Path(item["pkname"]).name == name for item in devices),
            "The target has partitions or dependent devices; refusing whole-device management")
    physical = node
    if node["type"] == "part":
        parent = node.get("pkname")
        require(isinstance(parent, str) and bool(parent), "Partition parent is unknown")
        parents = [item for item in devices if Path(item.get("name", "")).name == Path(parent).name]
        require(len(parents) == 1 and parents[0].get("type") == "disk", "Partition parent must be an identifiable physical disk")
        physical = parents[0]
        require(isinstance(node.get("start"), int) and not isinstance(node["start"], bool)
                and node["start"] > 0, "Partition geometry is unknown")
        require(isinstance(physical.get("size"), int) and node["start"] * 512 + size <= physical["size"], "Partition bounds or parent capacity are unknown")
        start, end = node["start"] * 512, node["start"] * 512 + size
        for sibling in devices:
            if sibling is node or not sibling.get("pkname") or Path(sibling["pkname"]).name != Path(parent).name:
                continue
            require(sibling.get("type") == "part" and isinstance(sibling.get("start"), int)
                    and isinstance(sibling.get("size"), int) and sibling["start"] > 0 and sibling["size"] > 0,
                    "Sibling partition geometry is incomplete")
            sibling_start = sibling["start"] * 512
            sibling_end = sibling_start + sibling["size"]
            require(sibling_end <= physical["size"] and (end <= sibling_start or sibling_end <= start),
                    "Overlapping or out-of-bounds partitions require manual preparation")
        require(isinstance(physical.get("ro"), (bool, int)) and physical["ro"] == 0, "Partition parent is read-only or unknown")
        require(system.device(physical["name"])[1] == physical.get("maj:min"), "Partition parent identity is inconsistent")
        for option, expected in (("--getsize64", str(physical["size"])), ("--getro", "0")):
            _, output, errors = system.run(["/usr/sbin/blockdev", option, physical["name"]])
            require(not errors.strip() and output.strip() == expected, "Partition parent probes disagree")
    for item in (node,) if physical is node else (node, physical):
        identifier = item.get("maj:min")
        require(isinstance(identifier, str) and re.fullmatch(r"\d+:\d+", identifier), "Missing kernel device identity")
        require(not system.holders(identifier), "The device or its parent has holders; stop and dismantle mappings explicitly")

    swaps = read_swaps(system)
    for swap in swaps:
        require(isinstance(swap.get("name"), str), "Active swap identity is incomplete")
        require(system.swap_device(swap["name"], swap.get("type")) != number, "The target backs active swap")

    mounts = read_json(system, [
        "/usr/bin/findmnt", "--json", "--list", "--output", "TARGET,SOURCE,FSTYPE,UUID,MAJ:MIN,FSROOT,OPTIONS",
    ], "filesystems")
    require(any(item.get("target") == "/" for item in mounts), "The mount table is incomplete")
    for item in mounts:
        require(isinstance(item.get("target"), str) and item["target"].startswith("/")
                and isinstance(item.get("maj:min"), str) and re.fullmatch(r"\d+:\d+", item["maj:min"]), "Incomplete mount identity")
        require(not item["target"].startswith(mountpoint + "/"), "Nested mounts require an explicit storage migration")
    exact = [item for item in mounts if item["target"] == mountpoint]
    require(len(exact) <= 1, "Stacked mounts at the storage mountpoint are not supported")
    if exact:
        require(directory["exists"], "The mountpoint disappeared during inspection")
        require(exact[0]["maj:min"] == number and exact[0].get("fsroot") == "/", "The mountpoint is backed by another device or a bind-mounted subdirectory")
        require("rw" in exact[0].get("options", "").split(","), "The storage filesystem is not mounted read-write")
    for item in mounts:
        if item["maj:min"] == number and item not in exact:
            require(bool(exact) and isinstance(item.get("fsroot"), str) and item["fsroot"].startswith("/") and item["fsroot"] != "/",
                    "The device is mounted elsewhere; refuse to adopt or format it")
        if physical is not node and item["maj:min"] == physical.get("maj:min"):
            raise UnsafeStorage("The partition's whole parent device is mounted")
    if not exact:
        require(not directory["populated"], "Refusing to mount over a populated directory; quiesce and migrate data explicitly")

    signatures = read_json(system, [
        "/usr/sbin/wipefs", "--no-act", "--json", "--output", "TYPE,UUID,OFFSET", device,
    ], "signatures")
    rc, output, errors = system.run(["/usr/sbin/blkid", "-p", "-o", "export", device], accepted=(0, 2))
    require(not errors.strip(), "blkid did not conclusively inspect the device")
    values = export_values(output)
    report.update(device=device, device_number=number, size=size, mounted=bool(exact))
    if "TYPE" in values:
        filesystem, uuid = values["TYPE"], values.get("UUID", "")
        require(rc == 0 and filesystem == config["filesystem"] and valid_uuid(uuid), "Existing filesystem type/UUID does not match storage intent")
        require(values.get("USAGE") == "filesystem", "The detected signature is not an ordinary filesystem")
        require(bool(signatures) and all(
            item.get("type") == filesystem and isinstance(item.get("uuid"), str)
            and item["uuid"].lower() == uuid.lower() and item.get("offset")
            for item in signatures
        ), "Filesystem signatures disagree or additional signatures exist")
        require(node.get("fstype") in (None, "", filesystem), "Cached and probed filesystem types disagree")
        require(not node.get("uuid") or node["uuid"].lower() == uuid.lower(), "Cached and probed UUIDs disagree")
        _, output, errors = system.run(["/usr/sbin/blkid", "-c", "/dev/null", "-t", f"UUID={uuid}", "-o", "device"])
        matches = output.splitlines()
        require(not errors.strip() and len(matches) == 1 and system.device(matches[0]) == (device, number), "The filesystem UUID is not uniquely assigned to the intended device")
        if exact:
            require(exact[0].get("fstype") == filesystem and isinstance(exact[0].get("uuid"), str)
                    and exact[0]["uuid"].lower() == uuid.lower(), "Mounted UUID/filesystem differs from the intended device")
        report.update(filesystem=filesystem, uuid=uuid.lower())
    else:
        require(not signatures and not node.get("fstype") and not node.get("uuid"), "Unrecognized or inconsistent on-disk signatures; refusing formatting")
        require((rc == 2 and not values) or (
            rc == 0 and node["type"] == "part" and bool(values)
            and any(key.startswith("PART_ENTRY_") for key in values)
            and all(key.startswith("PART_ENTRY_") or (key == "DEVNAME" and value == device)
                    for key, value in values.items())
        ), "Missing filesystem identification is not a conclusive blank-device result")
        require(not exact, "A mounted device cannot be formatted")
        require(config["action"] != "verify", "The intended device has no filesystem")
        require(config["filesystem"] == "ext4", "Automatic formatting supports ext4 only; prepare other filesystems explicitly")
        identifiers = {key: str(physical.get(key) or "").strip() for key in ("wwn", "serial")}
        identifiers = {key: value for key, value in identifiers.items() if value.lower() not in ("", "0", "unknown", "none") and value.lower().strip("0x:- ")}
        require(bool(identifiers), "Formatting requires a physical disk serial or WWN")
        require(not any(item is not physical and item.get("type") == "disk"
                        and any(str(item.get(key) or "").strip() == value for key, value in identifiers.items())
                        for item in devices), "Physical disk identifiers are not unique")
        identity = {
            "host": config["host"], "device": device, "device_number": number,
            "size": size, "physical_size": physical.get("size"), "identifiers": identifiers,
            "partition_start": node.get("start"), "partition_uuid": node.get("partuuid"),
        }
        fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        report.update(needs_format=True, format_confirmation=f"{config['host']}:{device}:{fingerprint}")
    if config["action"] == "verify":
        require(bool(exact), "The intended device is not mounted at the storage mountpoint")
    return report


def preflight(config, system=None):
    system = system or System()
    report = inspect(config, system)
    if report["device"] and not report["mounted"]:
        with system.exclusive(report["device"], report["device_number"]):
            if report["needs_format"]:
                require(config["manage_device"] and config["allow_format"]
                        and config["format_confirmation"] == report["format_confirmation"],
                        "Formatting requires both opt-ins and storage_format_confirmation=" + report["format_confirmation"])
                rc, _, errors = system.run([
                    "/usr/bin/cmp", "--silent", "--bytes", str(report["size"]), report["device"], "/dev/zero",
                ], accepted=(0, 1, 2), timeout=ZERO_SCAN_TIMEOUT)
                require(rc == 0 and not errors.strip(), "The entire format candidate must be readable and all-zero; erase/migrate nonempty devices outside this role")
    return report


if __name__ == "__main__":
    try:
        print(json.dumps(preflight(json.load(sys.stdin))))
    except (OSError, ValueError, TypeError, KeyError) as error:
        sys.exit(f"Storage safety gate: {error}")
