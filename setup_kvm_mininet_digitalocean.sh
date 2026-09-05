#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export VGUARD_PUBLIC_IPV4="${VGUARD_PUBLIC_IPV4:-157.230.118.251}"
export VGUARD_PRIVATE_IPV4="${VGUARD_PRIVATE_IPV4:-10.114.0.3}"
export VGUARD_PUBLIC_IPV6="${VGUARD_PUBLIC_IPV6:-2a03:b0c0:3:f0:0:2:7de2:9000}"
export VGUARD_KVM_VM_NAME="${VGUARD_KVM_VM_NAME:-vguard-kvm-test}"
export VGUARD_KVM_GATEWAY="${VGUARD_KVM_GATEWAY:-192.168.122.1}"
export VGUARD_KVM_VM_IP="${VGUARD_KVM_VM_IP:-192.168.122.54}"

sudo apt update
sudo apt install -y python3-venv python3-pip curl iptables \
  mininet openvswitch-switch libnetfilter-queue-dev libnfnetlink-dev \
  qemu-kvm libvirt-daemon-system libvirt-clients virtinst cloud-image-utils cpu-checker

python3 -m venv .venv
. .venv/bin/activate
pip install --no-cache-dir -r requirements.txt

sudo systemctl enable --now libvirtd || true
sudo virsh net-start default || true
sudo virsh net-autostart default || true

cat <<INFO

v-Guard KVM/Mininet dependencies are ready.
Public IPv4 : ${VGUARD_PUBLIC_IPV4}
Private IPv4: ${VGUARD_PRIVATE_IPV4}
Public IPv6 : ${VGUARD_PUBLIC_IPV6}
KVM gateway : ${VGUARD_KVM_GATEWAY}

Manual Mininet run:
  sudo .venv/bin/python mininet_vguard_lab.py --project-dir $(pwd) --python $(pwd)/.venv/bin/python --reset-logs

Dashboard Run Mininet button:
  # The button is active by default. Mininet requires root/sudo on the API host.
  export VGUARD_LAB_PYTHON=$(pwd)/.venv/bin/python
  # Optional safety kill switch:
  # export VGUARD_DISABLE_LAB_RUN=1
  # restart dashboard API after changing env vars
INFO
