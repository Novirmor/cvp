#!/usr/bin/env python3
from contextlib import contextmanager
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

try:
    import yaml
except ImportError:
    executable = shutil.which("ansible-playbook")
    if __name__ != "__main__" or not executable or os.environ.get("CVP_STORAGE_TEST_ANSIBLE_PYTHON"):
        raise
    with Path(executable).resolve().open() as stream:
        shebang = stream.readline().strip()
    if not shebang.startswith("#!/"):
        raise RuntimeError("ansible-playbook must use an absolute Python shebang")
    interpreter = shlex.split(shebang[2:])
    if not Path(interpreter[0]).name.startswith("python"):
        raise RuntimeError("ansible-playbook must use its pinned Python interpreter directly")
    os.environ["CVP_STORAGE_TEST_ANSIBLE_PYTHON"] = "1"
    os.execv(interpreter[0], [*interpreter, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "ansible/roles/storage"
SPEC = importlib.util.spec_from_file_location("cvp_storage_safety", ROLE / "files/storage_safety.py")
assert SPEC is not None and SPEC.loader is not None
SAFETY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SAFETY)
UUID = "12345678-1234-1234-1234-123456789abc"
OTHER_UUID = "87654321-4321-4321-4321-cba987654321"
SIZE = 64 * 1024 * 1024
MOUNTPOINT = "/var/lib/rancher/k3s/storage"


def config():
    return {
        "action": "preflight", "host": "storage-test", "device": "/dev/disk/by-id/fixture",
        "mountpoint": MOUNTPOINT, "filesystem": "ext4", "mount_options": "defaults,noatime",
        "directory_mode": "0750", "manage_device": False, "allow_format": False,
        "format_confirmation": "",
    }


def fixture(filesystem: str | None = "ext4", mounted=False):
    state = {
        "nodes": [{
            "name": "/dev/sdb", "kname": "/dev/sdb", "pkname": None, "type": "disk",
            "maj:min": "8:16", "size": SIZE, "ro": False, "fstype": None, "uuid": None,
            "wwn": "0x123456789abcdef", "serial": "disk-fixture-A", "partuuid": None, "start": None,
        }],
        "directory": {"exists": True, "populated": False},
        "mounts": [{"target": "/", "source": "/dev/sda1", "fstype": "ext4", "uuid": OTHER_UUID,
                    "maj:min": "8:1", "fsroot": "/", "options": "rw,relatime"}],
        "aliases": {"/dev/disk/by-id/fixture": "/dev/sdb"}, "holders": {}, "swaps": [],
        "swap_files": {}, "overrides": {}, "events": [], "zero_rc": 0,
    }
    set_filesystem(state, filesystem)
    if mounted:
        mount(state)
    return state


def set_filesystem(state, filesystem):
    node = state["nodes"][0]
    node["fstype"] = filesystem
    node["uuid"] = UUID if filesystem else None
    state["signatures"] = [{"type": filesystem, "uuid": UUID, "offset": "0x438"}] if filesystem else []
    state["blkid"] = {
        "rc": 0 if filesystem else 2,
        "stdout": f"DEVNAME={node['name']}\nTYPE={filesystem}\nUUID={UUID}\nUSAGE=filesystem\n" if filesystem else "",
        "stderr": "",
    }
    state["uuid_devices"] = [node["name"]] if filesystem else []


def mount(state):
    node = state["nodes"][0]
    state["mounts"] = [row for row in state["mounts"] if row["target"] != MOUNTPOINT]
    state["mounts"].append({
        "target": MOUNTPOINT, "source": node["name"], "fstype": node["fstype"],
        "uuid": state.get("mount_result_uuid", node["uuid"]), "maj:min": node["maj:min"],
        "fsroot": "/", "options": "rw,noatime",
    })
    state["directory"]["exists"] = True


class FakeSystem:
    def __init__(self, state):
        self.state = state
        self.calls = []

    def device(self, path):
        name = self.state["aliases"].get(path, path)
        nodes = [node for node in self.state["nodes"] if node["name"] == name]
        SAFETY.require(len(nodes) == 1, "Synthetic device missing or ambiguous")
        SAFETY.require(not self.state.get("regular_file"), "The storage target must be a block device")
        return name, nodes[0]["maj:min"]

    def directory(self, path):
        if self.state.get("directory_error"):
            raise OSError("Synthetic directory inspection failed")
        return self.state["directory"]

    def holders(self, number):
        if self.state.get("holders_error"):
            raise OSError("Synthetic holders inspection failed")
        return self.state["holders"].get(number, [])

    @contextmanager
    def exclusive(self, device, number):
        if self.state.get("busy"):
            raise OSError("Synthetic device is exclusively held or mounted in another namespace")
        yield

    def swap_device(self, path, kind):
        if kind == "partition":
            return self.device(path)[1]
        SAFETY.require(kind == "file" and path in self.state["swap_files"], "Synthetic swap inspection failed")
        return self.state["swap_files"][path]

    def run(self, argv, accepted=(0,), timeout=SAFETY.PROBE_TIMEOUT):
        self.calls.append(argv)
        tool = Path(argv[0]).name
        key = tool
        if tool in ("blkid", "blockdev"):
            key += ":" + argv[1]
        if self.state.get("timeout_tool") == key:
            with mock.patch.object(SAFETY.subprocess, "run", side_effect=subprocess.TimeoutExpired(argv, timeout)):
                return SAFETY.System().run(argv, accepted=accepted, timeout=timeout)
        result = self.state["overrides"].get(key)
        if result is None:
            output = ""
            if tool == "lsblk":
                output = json.dumps({"blockdevices": self.state["nodes"]})
            elif tool == "blockdev":
                node = next(node for node in self.state["nodes"] if node["name"] == argv[-1])
                output = str(node["size"] if argv[1] == "--getsize64" else int(node["ro"])) + "\n"
            elif tool == "swapon":
                assert argv == ["/usr/sbin/swapon", "--show=NAME,TYPE", "--raw", "--noheadings"], argv
                output = "".join(
                    "".join(f"\\x{byte:02x}" if byte <= 32 or byte >= 127 or byte == 92 else chr(byte)
                            for byte in os.fsencode(swap["name"])) + " " + swap["type"] + "\n"
                    for swap in self.state["swaps"]
                )
            elif tool == "findmnt":
                output = json.dumps({"filesystems": self.state["mounts"]})
            elif tool == "wipefs":
                output = json.dumps({"signatures": self.state["signatures"]})
            elif key == "blkid:-p":
                result = self.state["blkid"]
            elif key == "blkid:-c":
                output = "\n".join(self.state["uuid_devices"]) + "\n"
            elif tool == "cmp":
                result = {"rc": self.state["zero_rc"], "stdout": "", "stderr": ""}
            else:
                raise AssertionError(f"Unmocked command: {argv}")
            if result is None:
                result = {"rc": 0, "stdout": output, "stderr": ""}
        SAFETY.require(result["rc"] in accepted, f"Synthetic {key} failed (rc={result['rc']})")
        return result["rc"], result["stdout"], result["stderr"]


def approve(state, cfg):
    evidence = SAFETY.inspect(cfg, FakeSystem(state))
    cfg.update(manage_device=True, allow_format=True, format_confirmation=evidence["format_confirmation"])


class StorageInspectorTests(unittest.TestCase):
    def test_real_hanging_probe_is_killed_with_a_diagnostic(self):
        started = time.monotonic()
        with self.assertRaisesRegex(SAFETY.UnsafeStorage, 'timed out after 0.1s'):
            SAFETY.System().run([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=0.1)
        self.assertLess(time.monotonic() - started, 3)

    def test_probe_and_whole_device_scan_use_distinct_finite_budgets(self):
        state, cfg = fixture(None), config()
        approve(state, cfg)
        system = FakeSystem(state)
        original = system.run
        calls = []
        def run(argv, accepted=(0,), timeout=SAFETY.PROBE_TIMEOUT):
            calls.append((Path(argv[0]).name, timeout))
            return original(argv, accepted=accepted, timeout=timeout)
        system.run = run
        SAFETY.preflight(cfg, system)
        self.assertTrue(calls)
        self.assertIn(('cmp', SAFETY.ZERO_SCAN_TIMEOUT), calls)
        self.assertTrue(all(0 < budget <= 300 for _, budget in calls))
        self.assertTrue(all(budget == SAFETY.PROBE_TIMEOUT for tool, budget in calls if tool != 'cmp'))
        with mock.patch.object(SAFETY.subprocess, 'run', return_value=subprocess.CompletedProcess(['probe'], 0, '', '')) as process:
            SAFETY.System().run(['probe'])
            self.assertEqual(process.call_args.kwargs['timeout'], SAFETY.PROBE_TIMEOUT)

    @unittest.skipUnless(os.access("/usr/sbin/swapon", os.X_OK), "swapon is unavailable")
    def test_real_readonly_swapon_command_format(self):
        rows = SAFETY.read_swaps(SAFETY.System())
        self.assertIsInstance(rows, list)
        for row in rows:
            self.assertTrue(row["name"].startswith("/"))
            self.assertIn(row["type"], ("file", "partition"))

    def test_swap_raw_escaping_and_strict_parsing(self):
        output = (
            r"/dev/sdb partition" + "\n"
            + r"/swap\x20file\x09tab\x0anewline\x5cbackslash file" + "\n"
            + r"/literal\x5cx20 file" + "\n"
            + r"/swap-\xc3\xa9 file" + "\n"
        )
        self.assertEqual(SAFETY.parse_swaps(output), [
            {"name": "/dev/sdb", "type": "partition"},
            {"name": "/swap file\ttab\nnewline\\backslash", "type": "file"},
            {"name": r"/literal\x20", "type": "file"},
            {"name": "/swap-é", "type": "file"},
        ])
        self.assertEqual(SAFETY.parse_swaps(""), [])
        for invalid in (
            "NAME TYPE\n", "\n", "/swap file extra\n", "relative file\n",
            r"/swap\xZZ file", r"/swap\040file file", r"/swap\x00 file",
            "/dev/sdb disk\n", "/swap file\n/swap file\n", "/swap file\ntruncated",
            "/swap file\v/dev/sdb partition\n", "/swap\x1b file\n",
        ):
            with self.subTest(output=invalid), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.parse_swaps(invalid)

    def test_escaped_swap_file_still_blocks_its_backing_device(self):
        state = fixture()
        name = "/swap file\ttab\nnewline\\literal"
        state["swaps"] = [{"name": name, "type": "file"}]
        state["swap_files"][name] = "8:16"
        with self.assertRaisesRegex(SAFETY.UnsafeStorage, "active swap"):
            SAFETY.preflight(config(), FakeSystem(state))

    def test_existing_filesystem_adoption_and_live_pvc_bind_mount(self):
        for mounted in (False, True):
            state = fixture(mounted=mounted)
            if mounted:
                state["directory"]["populated"] = True
                bind = copy.deepcopy(state["mounts"][-1])
                bind.update(target="/var/lib/kubelet/pods/fixture/volumes/pvc", fsroot="/pvc-fixture")
                state["mounts"].append(bind)
            report = SAFETY.preflight(config(), FakeSystem(state))
            self.assertFalse(report["needs_format"])
            self.assertEqual(report["uuid"], UUID)
            self.assertEqual(report["mounted"], mounted)

    def test_existing_xfs_is_adopted_without_formatting(self):
        cfg = config()
        cfg["filesystem"] = "xfs"
        report = SAFETY.preflight(cfg, FakeSystem(fixture("xfs")))
        self.assertEqual(report["filesystem"], "xfs")

    def test_blank_device_requires_both_flags_and_bound_confirmation(self):
        state, cfg = fixture(None), config()
        with self.assertRaisesRegex(SAFETY.UnsafeStorage, "storage_format_confirmation=storage-test:/dev/sdb:"):
            SAFETY.preflight(cfg, FakeSystem(state))
        approve(state, cfg)
        for field, bad in (("manage_device", False), ("allow_format", False),
                           ("format_confirmation", "yes"), ("host", "another-host")):
            invalid = dict(cfg, **{field: bad})
            with self.subTest(field=field), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(invalid, FakeSystem(state))
        inspector = FakeSystem(state)
        self.assertTrue(SAFETY.preflight(cfg, inspector)["needs_format"])
        self.assertIn(["/usr/bin/cmp", "--silent", "--bytes", str(SIZE), "/dev/sdb", "/dev/zero"], inspector.calls)
        for field, value in (("serial", "another-disk"), ("size", SIZE * 2)):
            changed = copy.deepcopy(state)
            changed["nodes"][0][field] = value
            with self.subTest(field=field), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(cfg, FakeSystem(changed))

    def test_whole_device_nonzero_content_and_read_errors_refuse_format(self):
        state, cfg = fixture(None), config()
        approve(state, cfg)
        for code in (1, 2):
            state["zero_rc"] = code
            with self.subTest(code=code), self.assertRaisesRegex(SAFETY.UnsafeStorage, "all-zero"):
                SAFETY.preflight(cfg, FakeSystem(state))

    def test_missing_duplicate_physical_identity_and_busy_devices_refuse(self):
        no_identity = fixture(None)
        no_identity["nodes"][0].update(serial=None, wwn=None)
        duplicate = fixture(None)
        other = copy.deepcopy(duplicate["nodes"][0])
        other.update(name="/dev/sdc", kname="/dev/sdc")
        other["maj:min"] = "8:32"
        duplicate["nodes"].append(other)
        for state in (no_identity, duplicate):
            with self.subTest(state=state), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(config(), FakeSystem(state))
        for filesystem in (None, "ext4"):
            state = fixture(filesystem)
            state["busy"] = True
            with self.subTest(filesystem=filesystem), self.assertRaises(OSError):
                SAFETY.preflight(config(), FakeSystem(state))

    def test_probe_failures_never_become_format_permission(self):
        for key in ("lsblk", "blockdev:--getsize64", "blockdev:--getro", "swapon", "findmnt", "wipefs", "blkid:-p"):
            for code in (1, 4, 8, 127):
                state, cfg = fixture(None), config()
                approve(state, cfg)
                state["overrides"][key] = {"rc": code, "stdout": "", "stderr": "probe failed"}
                system = FakeSystem(state)
                with self.subTest(key=key, code=code), self.assertRaises(SAFETY.UnsafeStorage):
                    SAFETY.preflight(cfg, system)
                self.assertFalse(any(Path(call[0]).name == "cmp" for call in system.calls))
        for result in (
            {"rc": 2, "stdout": "", "stderr": "I/O error"},
            {"rc": 0, "stdout": "", "stderr": ""},
            {"rc": 2, "stdout": "TYPE=ext4\n", "stderr": ""},
        ):
            state = fixture(None)
            state["blkid"] = result
            with self.subTest(result=result), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(config(), FakeSystem(state))

    def test_incomplete_inspections_fail_closed(self):
        for key, output in (("lsblk", "{}"), ("findmnt", '{"filesystems":[]}'),
                            ("wipefs", "not-json"), ("swapon", 'NAME TYPE\n')):
            state = fixture()
            state["overrides"][key] = {"rc": 0, "stdout": output, "stderr": ""}
            with self.subTest(key=key), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(config(), FakeSystem(state))
        for field in ("holders_error", "directory_error"):
            state = fixture()
            state[field] = True
            with self.subTest(field=field), self.assertRaises(OSError):
                SAFETY.preflight(config(), FakeSystem(state))

    def test_partition_table_unknown_and_conflicting_signatures_refuse(self):
        for signature in ("gpt", "dos", "LVM2_member", "linux_raid_member", "crypto_LUKS", "swap"):
            state = fixture(None)
            state["signatures"] = [{"type": signature, "uuid": None, "offset": "0x200"}]
            with self.subTest(signature=signature), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(config(), FakeSystem(state))
        state = fixture()
        state["signatures"].append({"type": "swap", "uuid": OTHER_UUID, "offset": "0x1000"})
        with self.assertRaises(SAFETY.UnsafeStorage):
            SAFETY.preflight(config(), FakeSystem(state))

    def test_filesystem_uuid_type_and_uniqueness(self):
        states = []
        mismatch = fixture("xfs")
        states.append(mismatch)
        no_uuid = fixture()
        no_uuid["blkid"]["stdout"] = "TYPE=ext4\nUSAGE=filesystem\n"
        states.append(no_uuid)
        duplicate = fixture()
        duplicate["uuid_devices"].append("/dev/sdc")
        states.append(duplicate)
        cached = fixture()
        cached["nodes"][0]["uuid"] = OTHER_UUID
        states.append(cached)
        for state in states:
            with self.subTest(state=state), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(config(), FakeSystem(state))

    def test_populated_mount_conflicts_and_nested_mounts_fail_before_format(self):
        for kind in ("populated", "conflicting", "nested", "mounted_elsewhere", "bind_root"):
            state = fixture(None)
            if kind == "populated":
                state["directory"]["populated"] = True
            else:
                row = copy.deepcopy(state["mounts"][0])
                row["target"] = MOUNTPOINT
                if kind == "nested":
                    row["target"] += "/nested"
                if kind in ("mounted_elsewhere", "bind_root"):
                    row["maj:min"] = "8:16"
                    row["target"] = "/mnt/other" if kind == "mounted_elsewhere" else MOUNTPOINT
                    row["fsroot"] = "/subdirectory" if kind == "bind_root" else "/"
                state["mounts"].append(row)
            with self.subTest(kind=kind), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(config(), FakeSystem(state))

    def test_device_kind_partitions_holders_swap_and_readonly(self):
        states = []
        for kind in ("loop", "lvm", "crypt", "raid1"):
            state = fixture(None)
            state["nodes"][0]["type"] = kind
            states.append(state)
        for field in ("ro", "regular_file"):
            state = fixture(None)
            (state["nodes"][0] if field == "ro" else state)[field] = True
            states.append(state)
        child = fixture(None)
        child["nodes"].append({"name": "/dev/sdb1", "pkname": "/dev/sdb", "maj:min": "8:17"})
        states.append(child)
        held = fixture(None)
        held["holders"]["8:16"] = ["dm-0"]
        states.append(held)
        swap = fixture(None)
        swap["swaps"] = [{"name": "/dev/sdb", "type": "partition"}]
        states.append(swap)
        swap_file = fixture()
        swap_file["swaps"] = [{"name": "/swapfile", "type": "file"}]
        swap_file["swap_files"]["/swapfile"] = "8:16"
        states.append(swap_file)
        for state in states:
            with self.subTest(state=state), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(config(), FakeSystem(state))

    def test_partition_identity_geometry_and_parent_holders(self):
        state, cfg = fixture(None), config()
        parent = copy.deepcopy(state["nodes"][0])
        parent["size"] = SIZE * 2
        node = state["nodes"][0]
        node.update(name="/dev/sdb1", kname="/dev/sdb1", type="part", pkname="/dev/sdb",
                    start=2048, partuuid=OTHER_UUID)
        node["maj:min"] = "8:17"
        state["nodes"].append(parent)
        state["aliases"][cfg["device"]] = "/dev/sdb1"
        state["blkid"] = {"rc": 0, "stdout": f"DEVNAME=/dev/sdb1\nPART_ENTRY_UUID={OTHER_UUID}\n", "stderr": ""}
        approve(state, cfg)
        self.assertTrue(SAFETY.preflight(cfg, FakeSystem(state))["needs_format"])
        sibling = copy.deepcopy(node)
        sibling.update(name="/dev/sdb2", kname="/dev/sdb2", start=4096)
        sibling["maj:min"] = "8:18"
        state["nodes"].append(sibling)
        with self.assertRaisesRegex(SAFETY.UnsafeStorage, "Overlapping"):
            SAFETY.preflight(cfg, FakeSystem(state))
        state["nodes"].pop()
        state["holders"]["8:16"] = ["dm-0"]
        with self.assertRaises(SAFETY.UnsafeStorage):
            SAFETY.preflight(cfg, FakeSystem(state))

    def test_verify_requires_exact_desired_uuid_and_filesystem(self):
        cfg = dict(config(), action="verify")
        self.assertEqual(SAFETY.preflight(cfg, FakeSystem(fixture(mounted=True)))["uuid"], UUID)
        for field, value in (("uuid", OTHER_UUID), ("fstype", "xfs"), ("maj:min", "8:32")):
            state = fixture(mounted=True)
            state["mounts"][-1][field] = value
            with self.subTest(field=field), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(cfg, FakeSystem(state))
        with self.assertRaises(SAFETY.UnsafeStorage):
            SAFETY.preflight(cfg, FakeSystem(fixture(mounted=False)))

    def test_directory_mode_and_directory_only_verification(self):
        for path in ("/", "/var/lib", "/etc/ssh", "/mnt/../etc", "relative"):
            with self.subTest(path=path), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(dict(config(), mountpoint=path), FakeSystem(fixture()))
        for mode in ("banana", "0777", "4750", "0000"):
            with self.subTest(mode=mode), self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.preflight(dict(config(), directory_mode=mode), FakeSystem(fixture()))
        cfg = dict(config(), device="", action="verify")
        state = fixture()
        state["directory"]["populated"] = True
        system = FakeSystem(state)
        SAFETY.preflight(cfg, system)
        self.assertEqual(system.calls, [])
        state["directory"]["exists"] = False
        with self.assertRaises(SAFETY.UnsafeStorage):
            SAFETY.preflight(cfg, system)

    def test_real_files_and_directory_symlinks_are_rejected_readonly(self):
        with tempfile.TemporaryDirectory(prefix="cvp-storage-stat-") as directory:
            root = Path(directory)
            regular = root / "not-a-device"
            regular.write_text("preserve")
            with self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.System().device(str(regular))
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(SAFETY.UnsafeStorage):
                SAFETY.System().directory(str(alias / "missing"))
            with self.assertRaisesRegex(SAFETY.UnsafeStorage, "ancestry"):
                SAFETY.System().directory(str(root / "missing"))
            self.assertEqual(regular.read_text(), "preserve")


def mock_module_main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(argument_spec={
        "argv": {"type": "list", "elements": "str", "default": []},
        "stdin": {"type": "str", "default": ""},
        "operation": {"type": "str", "default": ""},
        "parameters": {"type": "dict", "default": {}},
    }, supports_check_mode=True)
    path = Path(os.environ["CVP_STORAGE_TEST_STATE"])
    state = json.loads(path.read_text())
    argv = module.params["argv"]
    try:
        if argv and argv[0] == "timeout":
            assert argv[:4] == ['timeout', '--kill-after=5s', '600s', '/usr/bin/python3'], argv
            cfg = json.loads(module.params["stdin"])
            state["events"].append("inspect:" + cfg["action"])
            report = SAFETY.preflight(cfg, FakeSystem(state))
            state["last_report"] = report
            path.write_text(json.dumps(state))
            module.exit_json(changed=False, rc=0, stdout=json.dumps(report), stderr="")
        if argv:
            assert argv == ["/usr/sbin/mkfs.ext4", state["nodes"][0]["name"]], argv
            assert state["last_report"]["needs_format"]
            state["events"].append("mutate:format")
            set_filesystem(state, "ext4")
        else:
            operation = module.params["operation"]
            assert operation in ("file", "mount"), operation
            state["events"].append("mutate:" + operation)
            if operation == "mount":
                assert module.params["parameters"]["src"] == "UUID=" + UUID
                assert module.params["parameters"]["fstype"] == state["nodes"][0]["fstype"]
                mount(state)
            else:
                state["directory"]["exists"] = True
        path.write_text(json.dumps(state))
        module.exit_json(changed=True, rc=0, stdout="", stderr="")
    except (OSError, ValueError, TypeError, KeyError, AssertionError) as error:
        path.write_text(json.dumps(state))
        module.fail_json(msg=str(error), rc=1, stdout="", stderr=str(error))


def mock_tasks(value, real_files=False):
    if isinstance(value, list):
        return [mock_tasks(item, real_files=real_files) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key == "ansible.builtin.command":
            result["cvp_storage_mock"] = item
        elif key == "ansible.builtin.file" and real_files:
            result[key] = item | {'path': '{{ storage_test_directory }}',
                                  'owner': str(os.getuid()), 'group': str(os.getgid())}
        elif key in ("ansible.builtin.file", "ansible.posix.mount"):
            result["cvp_storage_mock"] = {"operation": key.rsplit(".", 1)[-1], "parameters": item}
        else:
            if key.startswith("ansible."):
                assert key in {"ansible.builtin.assert", "ansible.builtin.set_fact", "ansible.builtin.include_tasks"}, key
            result[key] = mock_tasks(item, real_files=real_files)
    return result


class StorageRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="cvp-storage-ansible-")
        cls.work = Path(cls.temporary.name)
        role = cls.work / "roles/storage"
        for subdirectory in ("tasks", "defaults", "files"):
            (role / subdirectory).mkdir(parents=True)
        for source in (ROLE / "tasks").glob("*.yml"):
            (role / "tasks" / source.name).write_text(yaml.safe_dump(mock_tasks(yaml.safe_load(source.read_text()))))
        (role / "defaults/main.yml").write_bytes((ROLE / "defaults/main.yml").read_bytes())
        (role / "files/storage_safety.py").write_bytes((ROLE / "files/storage_safety.py").read_bytes())
        library = cls.work / "library"
        library.mkdir()
        (library / "cvp_storage_mock.py").write_text(
            "#!/usr/bin/python3\nimport importlib.util, sys\n"
            "from ansible.module_utils.basic import AnsibleModule\n"
            "sys.dont_write_bytecode = True\n"
            f"spec = importlib.util.spec_from_file_location('cvp_storage_tests', {str(Path(__file__).resolve())!r})\n"
            "module = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(module)\nmodule.mock_module_main()\n"
        )
        (cls.work / "ansible.cfg").write_text(
            f"[defaults]\nroles_path={cls.work / 'roles'}\nlibrary={library}\n"
            f"local_tmp={cls.work / 'controller'}\nremote_tmp={cls.work / 'remote'}\n"
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_role(self, state, cfg=None, *, success=True, check=False, verify=False, real_files=False):
        cfg = cfg or config()
        for source in (ROLE / 'tasks').glob('*.yml'):
            (self.work / 'roles/storage/tasks' / source.name).write_text(
                yaml.safe_dump(mock_tasks(yaml.safe_load(source.read_text()), real_files=real_files)))
        state_file = self.work / "state.json"
        state_file.write_text(json.dumps(state))
        variables = {
            "ansible_connection": "local", "ansible_become": False, "ansible_python_interpreter": sys.executable,
            "storage_device": cfg["device"], "storage_mountpoint": cfg["mountpoint"],
            "storage_filesystem": cfg["filesystem"], "storage_mount_options": cfg["mount_options"],
            "storage_directory_mode": cfg["directory_mode"], "storage_manage_device": cfg["manage_device"],
            "storage_allow_format": cfg["allow_format"], "storage_format_confirmation": cfg["format_confirmation"],
        }
        if real_files:
            variables['storage_test_directory'] = str(self.work / 'directory-backed')
        play = {"name": "Synthetic storage safety", "hosts": "storage-test", "gather_facts": False, "vars": variables}
        if verify:
            verification = yaml.safe_load((ROOT / "ansible/playbooks/verify.yml").read_text())
            tasks = [task for section in verification for task in section.get("tasks", [])
                     if task.get("ansible.builtin.include_role", {}).get("name") == "storage"]
            self.assertEqual(len(tasks), 1)
            self.assertEqual(tasks[0]["ansible.builtin.include_role"]["tasks_from"], "verify")
            play["tasks"] = tasks
        else:
            play["roles"] = ["storage"]
        playbook = self.work / "play.yml"
        playbook.write_text(yaml.safe_dump([play]))
        env = {key: value for key, value in os.environ.items() if not key.startswith(("ANSIBLE_", "CVP_"))}
        env.update(ANSIBLE_CONFIG=str(self.work / "ansible.cfg"), CVP_STORAGE_TEST_STATE=str(state_file),
                   PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(
            ["ansible-playbook", "-i", "storage-test,", str(playbook), *(["--check"] if check else [])],
            env=env, text=True, capture_output=True, timeout=90,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.last_result = result
        return json.loads(state_file.read_text())["events"]

    def test_approved_blank_format_then_verified_mount(self):
        state, cfg = fixture(None), config()
        state["directory"]["exists"] = False
        approve(state, cfg)
        events = self.run_role(state, cfg)
        self.assertEqual(events, ["inspect:preflight", "mutate:format", "inspect:preflight",
                                  "mutate:file", "mutate:mount", "inspect:verify", "mutate:file"])

    def test_existing_fs_is_never_formatted_and_check_mode_never_mutates(self):
        events = self.run_role(fixture())
        self.assertNotIn("mutate:format", events)
        self.assertEqual(events[0], "inspect:preflight")
        self.assertLess(events.index("inspect:verify"), events.index("mutate:file"))
        state, cfg = fixture(None), config()
        approve(state, cfg)
        self.assertEqual(self.run_role(state, cfg, check=True), ["inspect:preflight"])

    def test_failures_precede_all_managed_mutations(self):
        for kind in ("no-confirmation", "populated", "conflicting-mount", "probe-error", "nonzero-data"):
            state, cfg = fixture(None), config()
            if kind == "populated":
                state["directory"]["populated"] = True
            elif kind == "conflicting-mount":
                other = copy.deepcopy(state["mounts"][0])
                other["target"] = MOUNTPOINT
                state["mounts"].append(other)
            elif kind == "probe-error":
                state["blkid"].update(rc=2, stderr="I/O error")
            elif kind == "nonzero-data":
                approve(state, cfg)
                state["zero_rc"] = 1
            with self.subTest(kind=kind):
                self.assertEqual(self.run_role(state, cfg, success=False), ["inspect:preflight"])

    def test_wrong_post_mount_identity_stops_before_permissions(self):
        state = fixture()
        state["mount_result_uuid"] = OTHER_UUID
        events = self.run_role(state, success=False)
        self.assertEqual(events, ["inspect:preflight", "inspect:preflight", "mutate:mount", "inspect:verify"])

    def test_existing_directory_permissions_converge_and_check_mode_previews(self):
        directory = self.work / 'directory-backed'
        directory.mkdir(mode=0o755)
        sentinel = directory / 'existing-volume-data'
        sentinel.write_text('preserve')
        cfg = dict(config(), device='')
        state = fixture()
        state['directory']['populated'] = True
        self.run_role(state, cfg, check=True, real_files=True)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
        self.assertIn('changed=1', self.last_result.stdout)
        self.run_role(state, cfg, real_files=True)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o750)
        self.assertIn('changed=1', self.last_result.stdout)
        self.run_role(state, cfg, real_files=True)
        self.assertIn('changed=0', self.last_result.stdout)
        cfg['directory_mode'] = '0700'
        self.run_role(state, cfg, real_files=True)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_probe_and_scan_timeouts_block_mutations_even_in_check_mode(self):
        for tool in ('lsblk', 'blockdev:--getsize64', 'swapon', 'findmnt', 'wipefs', 'blkid:-p', 'cmp'):
            for check in (False, True):
                state, cfg = fixture(None), config()
                approve(state, cfg)
                state['timeout_tool'] = tool
                with self.subTest(tool=tool, check=check):
                    self.assertEqual(self.run_role(state, cfg, success=False, check=check), ['inspect:preflight'])
                    self.assertIn('timed out', self.last_result.stdout)

    def test_verification_playbook_storage_section_is_readonly_and_identity_aware(self):
        self.assertEqual(self.run_role(fixture(mounted=True), verify=True), ["inspect:verify"])
        state = fixture(mounted=True)
        state["mounts"][-1]["uuid"] = OTHER_UUID
        self.assertEqual(self.run_role(state, verify=True, success=False), ["inspect:verify"])


if __name__ == "__main__":
    unittest.main()
