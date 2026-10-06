#!/usr/bin/env python3
"""Create and maintain instance repositories that run this platform.

An instance repository holds one operator's platform: its inventory, its Flux
entry point, its applications and encrypted secrets. It includes this
platform as a git submodule at `platform/`, pinned to one commit, and Flux
pulls the platform's cluster layers from that same commit.

new      Create an instance repository next to (not inside) this one.
check    Verify the pin, the submodule, and the copied Flux files agree.
upgrade  Move the submodule to another platform release and refresh the pin.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "templates/instance"
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
COMMIT = re.compile(r"[0-9a-f]{40}")
PLATFORM_SOURCE = "cvp-platform"
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
    command = ["git", *(["-c", "protocol.file.allow=always"] if allow_file else []), "-C", str(directory), *args]
    result = subprocess.run(command, text=True, capture_output=True)
    if check and result.returncode:
        raise InstanceError(f"git {' '.join(args[:3])} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def say(message):
    print(message, flush=True)


# --- rendering ---------------------------------------------------------------

def platform_source(url, commit):
    require(re.fullmatch(r"https://[^\s@]+", url) is not None,
            "the platform URL must be a public https:// Git URL Flux can fetch without credentials")
    require(COMMIT.fullmatch(commit) is not None, "the platform pin must be a full 40-character commit")
    return f"""---
# The platform this instance runs. Flux fetches its cluster layers from exactly
# this commit, which must equal the platform/ submodule commit
# (`task platform-upgrade` updates both; `task validate` checks they agree).
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
        name = re.search(r"(?m)^  name: (\S+)$", body).group(1)
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


def render_tree(destination, name, platform_url, repo_url, commit, platform_dir):
    for path in sorted(TEMPLATE.rglob("*")):
        if path.is_dir():
            continue
        target = destination / path.relative_to(TEMPLATE)
        target.parent.mkdir(parents=True, exist_ok=True)
        text = path.read_text().replace("__NAME__", name).replace("__PLATFORM_URL__", platform_url)
        target.write_text(text)
        target.chmod(path.stat().st_mode & 0o777)
    for relative in COPIED:
        shutil.copyfile(platform_dir / relative, destination / relative)
    flux = destination / "cluster/flux-system"
    (flux / "source.yaml").write_text(source(repo_url))
    (flux / "platform-source.yaml").write_text(platform_source(platform_url, commit))
    (flux / "reconciliation.yaml").write_text(
        reconciliation((platform_dir / "cluster/flux-system/reconciliation.yaml").read_text()))
    shutil.copytree(platform_dir / "cluster/apps", destination / "cluster/apps")
    shutil.copytree(platform_dir / "examples/instance/inventory", destination / "inventory", dirs_exist_ok=True)
    shutil.copyfile(platform_dir / "cluster/.sops.yaml.example", destination / "cluster/.sops.yaml.example")
    shutil.copyfile(platform_dir / "mise.toml", destination / "mise.toml")


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

    destination.mkdir(parents=True, exist_ok=True)
    git(destination, "init", "-q", "-b", "main")
    say(f"==> adding the platform submodule at {commit[:12]}")
    git(destination, "submodule", "add", "-q", args.platform_source or str(ROOT), "platform", allow_file=True)
    git(destination / "platform", "checkout", "-q", commit)
    # Clones use the public URL; this checkout keeps whatever source it was added from.
    git(destination, "config", "-f", ".gitmodules", "submodule.platform.url", platform_url)
    render_tree(destination, name, platform_url, repo_url, commit, destination / "platform")
    git(destination, "add", "-A")
    git(destination, "-c", "user.name=cvp", "-c", "user.email=cvp@example.invalid",
        "commit", "-q", "-m", f"chore: create instance {name} from platform {commit[:12]}")
    say(f"\nCreated {destination} (instance {name}, platform {commit[:12]}).")
    say("Next:")
    say(f"  cd {destination} && mise install && task validate")
    say("  task init        # set up the first host")
    if not args.repo_url:
        say("  Set cluster/flux-system/source.yaml to this repository's Git URL before bootstrapping Flux.")
    return 0


def instance_root():
    root = Path(os.environ.get("CVP_INSTANCE_DIR") or Path.cwd()).resolve()
    require((root / "platform").is_dir() and (root / "cluster/flux-system").is_dir(),
            f"{root} is not an instance repository (expected platform/ and cluster/flux-system/)")
    return root


def pinned(root):
    text = (root / "cluster/flux-system/platform-source.yaml").read_text()
    match = re.search(r"(?m)^    commit: ([0-9a-f]{40})$", text)
    require(match is not None, "platform-source.yaml must pin spec.ref.commit to a full commit")
    url = re.search(r"(?m)^  url: (\S+)$", text)
    return match.group(1), url.group(1) if url else ""


def cmd_check(args):
    root = instance_root()
    commit, url = pinned(root)
    recorded = git(root, "ls-tree", "HEAD", "platform", check=False).split()
    checkout = git(root / "platform", "rev-parse", "HEAD")
    problems = []
    if checkout != commit:
        problems.append(f"platform/ is at {checkout[:12]} but Flux is pinned to {commit[:12]}")
    if recorded and recorded[2] != commit:
        problems.append(f"the committed submodule pointer {recorded[2][:12]} differs from the pin {commit[:12]}")
    modules = git(root, "config", "-f", ".gitmodules", "submodule.platform.url", check=False)
    if modules != url:
        problems.append(f".gitmodules URL {modules!r} differs from the Flux platform URL {url!r}")
    for relative in COPIED:
        if (root / relative).read_bytes() != (root / "platform" / relative).read_bytes():
            problems.append(f"{relative} differs from the pinned platform copy (run task platform-upgrade)")
    expected = reconciliation((root / "platform/cluster/flux-system/reconciliation.yaml").read_text())
    if (root / "cluster/flux-system/reconciliation.yaml").read_text() != expected and not args.allow_custom_graph:
        problems.append("cluster/flux-system/reconciliation.yaml differs from the platform graph "
                        "(pass --allow-custom-graph if you changed it deliberately)")
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    require(not problems, "the instance does not match its pinned platform")
    say(f"Instance pinned to platform {commit[:12]}; submodule, Flux source, and copied files agree.")
    return 0


def cmd_validate(args):
    root = instance_root()
    cmd_check(args)
    say("==> validating cluster manifests with the pinned platform layers")
    run([sys.executable, "-B", str(ROOT / "scripts/cluster-manifest-inputs"), "validate",
         "--root", str(root / "cluster"), "--platform-root", str(root / "platform")], cwd=root)
    env = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / "ansible/ansible.cfg"), CVP_INSTANCE_DIR=str(root))
    inventory = ["-i", str(ROOT / "ansible/defaults/inventory.yml"), "-i", str(root / "inventory/hosts.yml")]
    listed = subprocess.run(["ansible-inventory", *inventory, "--list"], text=True, capture_output=True, env=env)
    require(listed.returncode == 0, f"cannot read the inventory: {listed.stderr.strip()[-300:]}")
    hosts = json.loads(listed.stdout).get("wireguard", {}).get("hosts", [])
    if not hosts:
        say("Inventory has no hosts yet; run `task init` to add the first one.")
        return 0
    say(f"==> validating the inventory ({len(hosts)} hosts, controller only)")
    run(["ansible-playbook", *inventory, str(ROOT / "ansible/playbooks/validate-inventory.yml")], cwd=root, env=env)
    return 0


def run(argv, cwd=None, env=None):
    result = subprocess.run(argv, cwd=cwd, env=env)
    require(result.returncode == 0, f"{Path(argv[0]).name} {' '.join(map(str, argv[1:3]))} failed")


def cmd_upgrade(args):
    root = instance_root()
    old, url = pinned(root)
    require(not git(root, "status", "--porcelain"), "commit or stash instance changes before upgrading")
    git(root / "platform", "fetch", "-q", "--tags", "origin")
    commit = git(root / "platform", "rev-parse", f"{args.ref}^{{commit}}")
    git(root / "platform", "checkout", "-q", commit)
    platform = root / "platform"
    for relative in COPIED:
        shutil.copyfile(platform / relative, root / relative)
    (root / "cluster/flux-system/platform-source.yaml").write_text(platform_source(url, commit))
    (root / "cluster/flux-system/reconciliation.yaml").write_text(
        reconciliation((platform / "cluster/flux-system/reconciliation.yaml").read_text()))
    shutil.copyfile(platform / "mise.toml", root / "mise.toml")
    say(f"Platform {old[:12]} -> {commit[:12]}. Review `git diff`, read the platform CHANGELOG, run")
    say("`mise install && task validate`, then commit and push; Flux follows the new pin.")
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
    new.add_argument("--platform-source", help="where to clone the submodule from now (default: this checkout)")
    new.add_argument("--repo-url", help="the instance repository's own Git URL for Flux (ssh://git@github.com/...)")
    new.set_defaults(func=cmd_new)
    check = commands.add_parser("check", help="verify the platform pin")
    check.add_argument("--allow-custom-graph", action="store_true")
    check.set_defaults(func=cmd_check)
    validate = commands.add_parser("validate", help="check the pin, cluster manifests, and inventory")
    validate.add_argument("--allow-custom-graph", action="store_true")
    validate.set_defaults(func=cmd_validate)
    upgrade = commands.add_parser("upgrade", help="move to another platform release")
    upgrade.add_argument("ref", help="platform tag, branch, or commit")
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
