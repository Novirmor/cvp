#!/usr/bin/env python3
"""Create and maintain instance repositories that run this platform.

An instance repository holds one operator's platform: its inventory, its Flux
entry point, its applications and encrypted secrets. It pins this platform to
exactly one release through platform.lock — one version and one commit shared
by every channel: the installed cvp.platform Ansible collection (which carries
the roles, playbooks, operator scripts, Flux cluster layers, and OpenTofu
roots), the copied taskfile, and Flux's pinned cvp-platform Git source. There
is no git submodule; a fresh clone runs `task platform-install` to materialize
the locked release into collections/.

new      Create an instance repository next to (not inside) this one.
install  Fetch the locked platform release and install it (collection, pinned
         third-party collections, copied taskfile).
check    Verify the lock, the installed collection, the copied taskfile, and
         the Flux pins all agree.
validate check + render every cluster layer from the locked tree + inventory.
upgrade  Move the lock to another platform release and reinstall.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "templates/instance"
VERSION = (ROOT / "VERSION").read_text().strip()
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
COMMIT = re.compile(r"[0-9a-f]{40}")
PLATFORM_SOURCE = "cvp-platform"
COLLECTION_REL = Path("collections/ansible_collections/cvp/platform")
# Flux bootstrap files the instance carries verbatim from its pinned platform.
COPIED = ("cluster/flux-system/gotk-components.yaml", "cluster/flux-system/namespace.yaml",
          "cluster/flux-system/sync.yaml")
# Platform layers Flux reconciles from the pinned platform commit.
PLATFORM_LAYERS = ("policy", "infrastructure", "data", "operations")


class InstanceError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise InstanceError(message)


def git(directory, *args, check=True, allow_file=False):
    command = ["git", *(["-c", "protocol.file.allow=always"] if allow_file else []),
               "-C", str(directory), *args]
    result = subprocess.run(command, text=True, capture_output=True)
    if check and result.returncode:
        raise InstanceError(f"git {' '.join(args[:3])} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def say(message):
    print(message, flush=True)


def run(argv, cwd=None, env=None):
    result = subprocess.run(argv, cwd=cwd, env=env)
    require(result.returncode == 0, f"{Path(argv[0]).name} {' '.join(map(str, argv[1:3]))} failed")


# --- the lock ---------------------------------------------------------------

def write_lock(root, version, commit, url):
    (root / "platform.lock").write_text(
        f"# The single platform pin. Every channel must serve exactly this release.\n"
        f"version {version}\n"
        f"commit {commit}\n"
        f"url {url}\n"
    )


def read_lock(root):
    values = {}
    for line in (root / "platform.lock").read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        key, separator, value = line.partition(" ")
        require(separator and key in {"version", "commit", "url"} and value,
                "platform.lock must contain version, commit, and url lines")
        values[key] = value
    require(set(values) == {"version", "commit", "url"}, "platform.lock is incomplete")
    return values


# --- rendering ---------------------------------------------------------------

def platform_source(url, commit):
    require(re.fullmatch(r"https://[^\s@]+", url) is not None,
            "the platform URL must be a public https:// Git URL Flux can fetch without credentials")
    require(COMMIT.fullmatch(commit) is not None, "the platform pin must be a full 40-character commit")
    return f"""---
# The platform this instance runs. Flux fetches its cluster layers from exactly
# this commit, which must equal the commit in platform.lock and the installed
# collection (`task platform-upgrade` updates both; `task validate` checks they agree).
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: {PLATFORM_SOURCE}
  namespace: flux-system
spec:
  suspend: false
  interval: 10m
  url: {url}
  ref:
    commit: {commit}
"""


def reconciliation(platform_text):
    """The platform's reconciliation graph, with platform layers from the pinned source."""
    documents = [part for part in platform_text.split("\n---\n") if part.strip()]
    rendered = []
    for document in documents:
        body = document.removeprefix("---\n")
        match = re.search(r"(?m)^  name: (\S+)$", body)
        if match is None:
            raise InstanceError("cannot repoint reconciliation.yaml: a document has no "
                                "two-space-indented metadata.name")
        name = match.group(1)
        if name in PLATFORM_LAYERS:
            body, count = re.subn(r"(?m)^(    kind: GitRepository\n    name: )flux-system$",
                                  rf"\g<1>{PLATFORM_SOURCE}", body)
            require(count == 1, f"cannot repoint the {name} reconciler at the platform source")
        rendered.append(body.rstrip() + "\n")
    header = ("---\n# Platform layers (policy, infrastructure, data, operations) come from the pinned\n"
              f"# {PLATFORM_SOURCE} source; apps come from this repository (flux-system source).\n")
    return header + "---\n".join(rendered)


def source(url):
    return f"""---
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: flux-system
  namespace: flux-system
spec:
  suspend: false
  interval: 1m
  ref:
    branch: main
  secretRef:
    name: flux-system
  url: {url}
"""


def render_tree(destination, name, platform_url, repo_url, commit, tree):
    for path in sorted(TEMPLATE.rglob("*")):
        if path.is_dir():
            continue
        target = destination / path.relative_to(TEMPLATE)
        target.parent.mkdir(parents=True, exist_ok=True)
        text = path.read_text().replace("__NAME__", name).replace("__PLATFORM_URL__", platform_url)
        target.write_text(text)
        target.chmod(path.stat().st_mode & 0o777)
    for relative in COPIED:
        shutil.copyfile(tree / relative, destination / relative)
    flux = destination / "cluster/flux-system"
    (flux / "source.yaml").write_text(source(repo_url))
    (flux / "platform-source.yaml").write_text(platform_source(platform_url, commit))
    (flux / "reconciliation.yaml").write_text(
        reconciliation((tree / "cluster/flux-system/reconciliation.yaml").read_text()))
    shutil.copytree(tree / "cluster/apps", destination / "cluster/apps")
    shutil.copytree(tree / "examples/instance/inventory", destination / "inventory", dirs_exist_ok=True)
    shutil.copyfile(tree / "cluster/.sops.yaml.example", destination / "cluster/.sops.yaml.example")
    shutil.copyfile(tree / "mise.toml", destination / "mise.toml")


# --- installation ------------------------------------------------------------

def fetch_tree(url, commit, destination, *, allow_file=False):
    """Materialize the platform tree at exactly `commit` (a commit, tag, or
    branch) from `url`, leaving the worktree at FETCH_HEAD."""
    require(not destination.exists() or not any(destination.iterdir()), "fetch destination is not empty")
    destination.mkdir(parents=True, exist_ok=True)
    if allow_file or not re.fullmatch(r"https://[^\s@]+", url):
        git(destination, "init", "-q", allow_file=True)
        git(destination, "remote", "add", "origin", url)
        git(destination, "fetch", "-q", "--no-tags", "origin", commit, allow_file=True)
    else:
        run(["git", "clone", "-q", "--no-checkout", url, str(destination)])
        git(destination, "fetch", "-q", "--no-tags", "origin", commit)
    git(destination, "checkout", "-q", "FETCH_HEAD")
    return destination


def install(root, lock, tree):
    """Install the locked release: collection, third-party pins, copied taskfile."""
    state = root / ".platform-state"
    shutil.rmtree(state, ignore_errors=True)
    (state / "dist").mkdir(parents=True)
    say(f"==> building the cvp.platform collection from {lock['commit'][:12]}")
    run([sys.executable, "-B", str(tree / "scripts/build-collection"),
         "--output", str(state / "dist"), "--commit", lock["commit"]], cwd=tree)
    tarball = state / "dist" / f"cvp-platform-{lock['version']}.tar.gz"
    require(tarball.is_file(), "the collection build did not produce the locked version's tarball")
    say("==> installing the collection and the pinned third-party collections")
    collections = root / "collections"
    run(["ansible-galaxy", "collection", "install", str(tarball), "-p", str(collections), "--force"])
    run(["ansible-galaxy", "collection", "install", "-r", str(tree / "ansible/requirements.yml"),
         "-p", str(collections), "--force"])
    installed = root / COLLECTION_REL
    require((installed / "PLATFORM_COMMIT").is_file(), "the installed collection is missing its commit stamp")
    require((installed / "PLATFORM_VERSION").read_text().strip() == lock["version"],
            "the installed collection serves a different version than platform.lock")
    require((installed / "PLATFORM_COMMIT").read_text().strip() == lock["commit"],
            "the installed collection serves a different commit than platform.lock")
    (root / "tasks").mkdir(exist_ok=True)
    shutil.copyfile(installed / "tasks/ops.yml", root / "tasks/ops.yml")
    shutil.rmtree(state, ignore_errors=True)
    say(f"Installed cvp.platform {lock['version']} ({lock['commit'][:12]}) into collections/.")


# --- commands ----------------------------------------------------------------

def cmd_new(args):
    destination = Path(args.destination).resolve()
    require(destination != ROOT and ROOT not in destination.parents and destination not in ROOT.parents,
            "create the instance outside the platform repository")
    require(not destination.exists() or not any(destination.iterdir()), f"{destination} is not empty")
    name = args.name or destination.name
    require(NAME.fullmatch(name) is not None, "the instance name must be lowercase letters, digits, and hyphens")
    commit = git(ROOT, "rev-parse", "HEAD")
    if git(ROOT, "status", "--porcelain"):
        say("note: the platform working tree has uncommitted changes; the instance pins the last commit "
            f"({commit[:12]}) only")
    platform_url = args.platform_url
    repo_url = args.repo_url or "ssh://git@example.invalid/repository.git"
    lock = {"version": VERSION, "commit": commit, "url": platform_url}

    destination.mkdir(parents=True, exist_ok=True)
    say(f"==> installing the platform collection at {commit[:12]}")
    install(destination, lock, ROOT)
    render_tree(destination, name, platform_url, repo_url, commit, ROOT)
    write_lock(destination, VERSION, commit, platform_url)
    git(destination, "init", "-q", "-b", "main")
    git(destination, "add", "-A")
    # Commit as the operator when Git knows them; otherwise as a neutral placeholder.
    identity = [] if git(destination, "config", "user.email", check=False) else [
        "-c", "user.name=cvp", "-c", "user.email=cvp@example.invalid"]
    git(destination, *identity, "commit", "-q", "-m", f"chore: create instance {name} from platform {commit[:12]}")
    say(f"\nCreated {destination} (instance {name}, platform {VERSION} at {commit[:12]}).")
    say("Next:")
    say(f"  cd {destination} && mise install && task validate")
    say("  task init        # set up the first host")
    if not args.repo_url:
        say("  Set cluster/flux-system/source.yaml to this repository's Git URL before bootstrapping Flux.")
    return 0


def instance_root():
    root = Path(os.environ.get("CVP_INSTANCE_DIR") or Path.cwd()).resolve()
    require((root / "platform.lock").is_file() and (root / "cluster/flux-system").is_dir(),
            f"{root} is not an instance repository (expected platform.lock and cluster/flux-system/)")
    return root


def pinned(root):
    text = (root / "cluster/flux-system/platform-source.yaml").read_text()
    match = re.search(r"(?m)^    commit: ([0-9a-f]{40})$", text)
    if match is None:
        raise InstanceError("platform-source.yaml must pin spec.ref.commit to a full commit")
    url = re.search(r"(?m)^  url: (\S+)$", text)
    return match.group(1), url.group(1) if url else ""


def cmd_check(args):
    root = instance_root()
    lock = read_lock(root)
    require(not (root / ".gitmodules").exists(), "this instance predates platform.lock; recreate it")
    installed = root / COLLECTION_REL
    problems = []
    if not (installed / "PLATFORM_COMMIT").is_file():
        problems.append("the cvp.platform collection is not installed; run task platform-install")
    else:
        for file, key in (("PLATFORM_VERSION", "version"), ("PLATFORM_COMMIT", "commit")):
            value = (installed / file).read_text().strip()
            if value != lock[key]:
                problems.append(f"the installed collection serves {key} {value} but platform.lock pins "
                                f"{lock[key]}; run task platform-install")
    if (root / "tasks/ops.yml").is_file() and (installed / "tasks/ops.yml").is_file() \
            and (root / "tasks/ops.yml").read_bytes() != (installed / "tasks/ops.yml").read_bytes():
        problems.append("tasks/ops.yml differs from the installed platform's taskfile "
                        "(run task platform-install)")
    commit, url = pinned(root)
    if commit != lock["commit"]:
        problems.append(f"the Flux platform pin {commit[:12]} differs from platform.lock {lock['commit'][:12]}")
    if url and url != lock["url"]:
        problems.append(f"the Flux platform URL {url!r} differs from platform.lock {lock['url']!r}")
    for relative in COPIED:
        if not (installed / relative).is_file() or \
                (root / relative).read_bytes() != (installed / relative).read_bytes():
            problems.append(f"{relative} differs from the locked platform copy (run task platform-upgrade)")
    if (installed / "cluster/flux-system/reconciliation.yaml").is_file():
        expected = reconciliation((installed / "cluster/flux-system/reconciliation.yaml").read_text())
        if (root / "cluster/flux-system/reconciliation.yaml").read_text() != expected and not args.allow_custom_graph:
            problems.append("cluster/flux-system/reconciliation.yaml differs from the platform graph "
                            "(pass --allow-custom-graph if you changed it deliberately)")
    try:
        listed = subprocess.run(["uv", "tool", "list"], capture_output=True, text=True)
    except OSError:
        listed = None
    if listed is not None and listed.returncode == 0 and "cvp-platform" in listed.stdout:
        match = re.search(r"cvp-platform[^\n]*?v?(\d+\.\d+\.\d+)", listed.stdout)
        if match and match.group(1) != lock["version"]:
            problems.append(f"the cvp-platform CLI tool is v{match.group(1)} but platform.lock pins "
                            f"{lock['version']}; reinstall it with `uv tool install` from the locked tree")
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    require(not problems, "the instance does not match its pinned platform")
    say(f"Instance pinned to platform {lock['version']} at {lock['commit'][:12]}; collection, "
        "taskfile, and Flux source agree.")
    return 0


def cmd_validate(args):
    root = instance_root()
    cmd_check(args)
    installed = root / COLLECTION_REL
    say("==> validating cluster manifests with the pinned platform layers")
    run([sys.executable, "-B", str(installed / "scripts/cluster-manifest-inputs"), "validate",
         "--root", str(root / "cluster"), "--platform-root", str(installed)], cwd=root,
        env=dict(os.environ, CVP_PLATFORM_DIR=str(installed), CVP_COLLECTIONS_DIR=str(root / "collections")))
    env = dict(os.environ, ANSIBLE_CONFIG=str(installed / "ansible/ansible.cfg"),
               CVP_INSTANCE_DIR=str(root), CVP_PLATFORM_DIR=str(installed),
               CVP_COLLECTIONS_DIR=str(root / "collections"),
               ANSIBLE_COLLECTIONS_PATH=str(root / "collections"))
    inventory = ["-i", str(installed / "ansible/defaults/inventory.yml"), "-i", str(root / "inventory/hosts.yml")]
    listed = subprocess.run(["ansible-inventory", *inventory, "--list"], text=True, capture_output=True, env=env)
    require(listed.returncode == 0, f"cannot read the inventory: {listed.stderr.strip()[-300:]}")
    hosts = json.loads(listed.stdout).get("wireguard", {}).get("hosts", [])
    if not hosts:
        say("Inventory has no hosts yet; run `task init` to add the first one.")
        return 0
    say(f"==> validating the inventory ({len(hosts)} hosts, controller only)")
    run(["ansible-playbook", *inventory, str(installed / "ansible/playbooks/validate-inventory.yml")],
        cwd=root, env=env)
    return 0


def cmd_install(args):
    root = instance_root()
    lock = read_lock(root)
    with tempfile.TemporaryDirectory(prefix="cvp-platform-tree-") as directory:
        tree = Path(directory) / "platform"
        if args.tree:
            fetch_tree(str(Path(args.tree).resolve()), lock["commit"], tree, allow_file=True)
        else:
            fetch_tree(lock["url"], lock["commit"], tree)
        install(root, lock, tree)
    return 0


def cmd_upgrade(args):
    root = instance_root()
    old = read_lock(root)
    require(not git(root, "status", "--porcelain"), "commit or stash instance changes before upgrading")
    with tempfile.TemporaryDirectory(prefix="cvp-platform-tree-") as directory:
        tree = Path(directory) / "platform"
        if args.tree:
            fetch_tree(str(Path(args.tree).resolve()), args.ref, tree, allow_file=True)
        else:
            fetch_tree(old["url"], args.ref, tree)
        commit = git(tree, "rev-parse", "FETCH_HEAD")
        require(COMMIT.fullmatch(commit) is not None, "the platform ref did not resolve to a commit")
        version = git(tree, "show", f"{commit}:VERSION")
        lock = {"version": version, "commit": commit, "url": old["url"]}
        install(root, lock, tree)
        installed = root / COLLECTION_REL
        for relative in COPIED:
            shutil.copyfile(installed / relative, root / relative)
        (root / "cluster/flux-system/platform-source.yaml").write_text(platform_source(old["url"], commit))
        (root / "cluster/flux-system/reconciliation.yaml").write_text(
            reconciliation((installed / "cluster/flux-system/reconciliation.yaml").read_text()))
        shutil.copyfile(installed / "tasks/ops.yml", root / "tasks/ops.yml")
        shutil.copyfile(tree / "mise.toml", root / "mise.toml")
        write_lock(root, version, commit, old["url"])
    say(f"Platform {old['version']} ({old['commit'][:12]}) -> {version} ({commit[:12]}). Review `git diff`, "
        "read the platform CHANGELOG, run `mise install && task validate`, then commit and push; "
        "Flux follows the new pin.")
    return 0


def parser():
    root = argparse.ArgumentParser(prog="cvp-instance", description=__doc__,
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = root.add_subparsers(dest="command", required=True)
    new = commands.add_parser("new", help="create an instance repository")
    new.add_argument("destination")
    new.add_argument("--name", help="instance name (default: the directory name)")
    new.add_argument("--platform-url", required=True,
                     help="public https Git URL of this platform, used by clones and by Flux")
    new.add_argument("--repo-url", help="the instance repository's own Git URL for Flux (ssh://git@github.com/...)")
    new.set_defaults(func=cmd_new)
    install = commands.add_parser("install", help="install the locked platform release")
    install.add_argument("--tree", help="build from this platform checkout instead of the lock URL")
    install.set_defaults(func=cmd_install)
    check = commands.add_parser("check", help="verify the platform pin")
    check.add_argument("--allow-custom-graph", action="store_true")
    check.set_defaults(func=cmd_check)
    validate = commands.add_parser("validate", help="check the pin, cluster manifests, and inventory")
    validate.add_argument("--allow-custom-graph", action="store_true")
    validate.set_defaults(func=cmd_validate)
    upgrade = commands.add_parser("upgrade", help="move to another platform release")
    upgrade.add_argument("ref", help="platform tag, branch, or commit")
    upgrade.add_argument("--tree", help="fetch from this platform checkout instead of the lock URL")
    upgrade.set_defaults(func=cmd_upgrade)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except (InstanceError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
