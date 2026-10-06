#!/bin/sh
# Prepare a freshly installed Debian host for Ansible. `task node-bootstrap`
# copies this script to the host over SSH and runs it as root:
#
#   sh cvp-node-bootstrap.sh '<operator SSH public key>'
#
# It installs Python, sudo, SSH, and host-probe tools, then creates the `ops`
# operator with that key and passwordless sudo, exactly as
# ansible/playbooks/bootstrap-access.yml would. It changes no network policy.
set -eu

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

[ "$#" -eq 1 ] || fail "usage: $0 '<operator SSH public key>'"
key="$1"
case "$key" in
  *"
"*) fail "the public key must be a single line" ;;
esac
printf '%s\n' "$key" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+={0,2}( [^[:cntrl:]]*)?$' ||
  fail "not an approved SSH public key type"
[ "$(id -u)" -eq 0 ] || fail "run as root"
if [ ! -x /usr/bin/apt-get ] || ! grep -Eq '^ID=debian$' /etc/os-release; then
  fail "this bootstrap supports Debian only"
fi

printf '==> installing Python, sudo, SSH, and host-probe tools\n'
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-apt sudo kmod procps openssh-server

printf '==> creating the ops operator\n'
if ! id ops >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --groups sudo ops
else
  usermod --append --groups sudo ops
fi
home="$(getent passwd ops | cut -d: -f6)"
install -d -m 0700 -o ops -g ops "$home/.ssh"
keys="$home/.ssh/authorized_keys"
touch "$keys"
grep -qxF "$key" "$keys" || printf '%s\n' "$key" >> "$keys"
chown ops:ops "$keys"
chmod 0600 "$keys"

sudoers="$(mktemp /etc/sudoers.d/.ops.XXXXXX)"
printf 'ops ALL=(ALL:ALL) NOPASSWD:ALL\n' > "$sudoers"
chmod 0440 "$sudoers"
visudo -cf "$sudoers" >/dev/null || { rm -f "$sudoers"; fail "sudoers validation failed"; }
mv "$sudoers" /etc/sudoers.d/ops

systemctl enable --now ssh >/dev/null 2>&1 || systemctl enable --now sshd >/dev/null

printf '==> host key fingerprints\n'
for file in /etc/ssh/ssh_host_*_key.pub; do
  ssh-keygen -lf "$file"
done
printf 'Bootstrap complete: ops can log in with the supplied key and use sudo.\n'
