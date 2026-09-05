# v-Guard KVM / Mininet DigitalOcean Lab Runbook

This package is configured for the deployment host:

- Public IPv4: `157.230.118.251`
- Private IPv4: `10.114.0.3`
- Public IPv6: `2a03:b0c0:3:f0:0:2:7de2:9000`
- Honeypot/test service: `0.0.0.0:8081`
- Libvirt/KVM gateway: `192.168.122.1`
- Demo KVM VM: `vguard-kvm-test`
- Demo KVM VM IP fallback: `192.168.122.54`

## 1. Install lab dependencies

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip curl iptables \
  mininet openvswitch-switch libnetfilter-queue-dev libnfnetlink-dev \
  qemu-kvm libvirt-daemon-system libvirt-clients virtinst cloud-image-utils cpu-checker
```

## 2. Prepare Python environment

```bash
cd /root/V-Guard
python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir -r requirements.txt
```

## 3. Verify KVM support

```bash
sudo kvm-ok || true
ls -l /dev/kvm
sudo systemctl enable --now libvirtd
sudo virsh net-start default || true
sudo virsh net-autostart default || true
ip addr show virbr0
```

Expected gateway: `192.168.122.1`.

## 4. Create or verify the lightweight VM

```bash
sudo virsh list --all
sudo virsh domstate vguard-kvm-test || true
sudo virsh net-dhcp-leases default || true
```

If the VM already exists and is running, the dashboard reads it automatically. If not, create a small CirrOS VM with libvirt/virt-install according to your host image path.

## 5. Verify VM → honeypot traffic

From the VM console:

```bash
wget -O- http://192.168.122.1:8081/
wget -O- 'http://192.168.122.1:8081/?url=http://169.254.169.254/latest/meta-data' || true
wget -O- "http://192.168.122.1:8081/login?user=admin%27%20or%201%3D1--" || true
```

Normal HTTP touch should be logged as `HONEYPOT_HTTP_TOUCH` with source `192.168.122.54`. Suspicious SSRF/SQLi requests may be blocked or time out when DPI/NFQUEUE is active.

## 6. Run Mininet validation

Manual safe command:

```bash
sudo .venv/bin/python mininet_vguard_lab.py --project-dir /root/V-Guard --python /root/V-Guard/.venv/bin/python --reset-logs
```

Dashboard button command:

```bash
export VGUARD_LAB_PYTHON=/root/V-Guard/.venv/bin/python
# optional safety kill switch: export VGUARD_DISABLE_LAB_RUN=1
# restart dashboard API after setting env vars
```

Then open **KVM Lab → Run Mininet**. The button returns visible status/output in the UI. It runs directly when the API process is root; otherwise it tries `sudo -n` and prints the exact sudo/root error in the UI.

## 7. Expected dashboard evidence

The KVM Lab page should show:

- `KVM Acceleration: /dev/kvm OK`
- `VM State: vguard-kvm-test / running`
- `VM IP: 192.168.122.54`
- `Gateway: 192.168.122.1`
- `Honeypot Event: HONEYPOT_HTTP_TOUCH`
- `SSRF Blocked`, `SQLi Blocked`, `XSS Blocked` counters from Mininet/DPI logs

The backend reads live checks first and uses `kvm_evidence_snapshot.json` as a stable fallback so the dashboard remains presentable during demos.
