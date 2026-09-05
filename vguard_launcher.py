import os
import sys
import time
import ctypes
import socket
import webbrowser
import subprocess
from pathlib import Path
import tkinter as tk
from tkinter import messagebox


BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "launcher_logs"
LOG_DIR.mkdir(exist_ok=True)

PYTHON_EXE = sys.executable

PORTS_TO_KILL = [5000, 8081, 2222]
SCRIPT_NAMES = ["dashboard_api.py", "honeypot.py", "dpi_engine.py"]

SERVICES = [
    {
        "key": "dashboard",
        "name": "Dashboard API",
        "script": "dashboard_api.py",
        "ports": [5000],
        "url": "http://127.0.0.1:5000",
    },
    {
        "key": "honeypot",
        "name": "Honeypot",
        "script": "honeypot.py",
        "ports": [8081, 2222],
        "url": None,
    },
    {
        "key": "dpi",
        "name": "DPI / IDS / IPS Engine",
        "script": "dpi_engine.py",
        "ports": [],
        "url": None,
    },
]


def is_windows():
    return os.name == "nt"


def is_admin():
    if not is_windows():
        try:
            return os.geteuid() == 0
        except Exception:
            return False

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    if not is_windows():
        messagebox.showwarning("Admin Required", "Run this launcher with sudo/root.")
        return

    try:
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            str(BASE_DIR),
            1
        )
        sys.exit(0)
    except Exception as exc:
        messagebox.showerror("Admin Start Failed", str(exc))


def run_cmd(args, timeout=8):
    try:
        completed = subprocess.run(
            args,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except Exception as exc:
        return -1, "", str(exc)


def run_powershell(script, timeout=12):
    return run_cmd([
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script
    ], timeout=timeout)


def get_pids_by_port(port):
    pids = set()

    if not is_windows():
        return pids

    code, out, err = run_cmd(["netstat", "-ano", "-p", "tcp"], timeout=8)
    if code != 0 and not out:
        return pids

    needle1 = f":{port} "
    needle2 = f":{port}\t"

    for line in out.splitlines():
        raw = line.strip()
        upper = raw.upper()

        if "LISTENING" not in upper:
            continue

        if needle1 not in raw and needle2 not in raw:
            continue

        parts = raw.split()
        if not parts:
            continue

        pid_raw = parts[-1]
        if pid_raw.isdigit():
            pids.add(int(pid_raw))

    return pids


def kill_pid(pid):
    if not pid:
        return False, "Invalid PID"

    if is_windows():
        code, out, err = run_cmd(["taskkill", "/F", "/T", "/PID", str(pid)], timeout=8)
        ok = code == 0 or "SUCCESS" in out.upper()
        return ok, out or err

    try:
        os.kill(int(pid), 9)
        return True, "Killed"
    except Exception as exc:
        return False, str(exc)


def kill_by_ports(ports):
    killed = []
    errors = []

    for port in ports:
        pids = get_pids_by_port(port)

        for pid in pids:
            ok, msg = kill_pid(pid)
            if ok:
                killed.append(f"port {port} -> PID {pid}")
            else:
                errors.append(f"port {port} -> PID {pid}: {msg}")

    return killed, errors


def kill_by_script_names(script_names):
    killed = []
    errors = []

    if not is_windows():
        # Basic Linux/macOS fallback
        for script in script_names:
            code, out, err = run_cmd(["pkill", "-f", script], timeout=5)
            if code == 0:
                killed.append(script)
            elif err:
                errors.append(f"{script}: {err}")
        return killed, errors

    # Strong PowerShell method: only kill python processes whose commandline contains our script names.
    escaped_scripts = ",".join([f"'{s}'" for s in script_names])
    ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
$scripts = @({escaped_scripts})
$killed = @()
foreach ($s in $scripts) {{
  $procs = Get-CimInstance Win32_Process | Where-Object {{
    $_.CommandLine -and $_.CommandLine.ToLower().Contains($s.ToLower())
  }}
  foreach ($p in $procs) {{
    try {{
      Stop-Process -Id $p.ProcessId -Force
      $killed += "$s -> PID $($p.ProcessId)"
    }} catch {{
      Write-Output "ERR $s -> PID $($p.ProcessId): $($_.Exception.Message)"
    }}
  }}
}}
$killed | ForEach-Object {{ Write-Output $_ }}
"""
    code, out, err = run_powershell(ps, timeout=12)

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("ERR "):
            errors.append(line)
        else:
            killed.append(line)

    if err:
        errors.append(err)

    return killed, errors


def is_port_open(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.25)
    try:
        result = s.connect_ex(("127.0.0.1", port))
        return result == 0
    except Exception:
        return False
    finally:
        s.close()


class VGuardLauncher(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("v-Guard Control Center")
        self.geometry("840x620")
        self.minsize(760, 560)
        self.configure(bg="#0f172a")

        self.processes = {}
        self.status_labels = {}
        self.port_labels = {}

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.build_ui()
        self.refresh_status_loop()

    def build_ui(self):
        header = tk.Frame(self, bg="#1e293b", padx=18, pady=16)
        header.pack(fill="x")

        title = tk.Label(
            header,
            text="v-Guard Control Center",
            bg="#1e293b",
            fg="#38bdf8",
            font=("Arial", 20, "bold")
        )
        title.pack(side="left")

        admin_text = "ADMIN" if is_admin() else "NORMAL"
        admin_color = "#22c55e" if is_admin() else "#ef4444"

        self.admin_label = tk.Label(
            header,
            text=f"Mode: {admin_text}",
            bg="#1e293b",
            fg=admin_color,
            font=("Arial", 11, "bold")
        )
        self.admin_label.pack(side="right")

        body = tk.Frame(self, bg="#0f172a", padx=24, pady=22)
        body.pack(fill="both", expand=True)

        info = tk.Label(
            body,
            text=(
                "Start/Stop all v-Guard services from one place.\n"
                "Force Kill closes ports 5000, 8081 and 2222, plus stale dashboard/honeypot/dpi Python processes.\n"
                "If Force Kill cannot close a port, run this launcher as Administrator."
            ),
            bg="#0f172a",
            fg="#94a3b8",
            justify="left",
            font=("Arial", 10)
        )
        info.pack(anchor="w", pady=(0, 18))

        service_box = tk.Frame(body, bg="#1e293b", padx=18, pady=14)
        service_box.pack(fill="x")

        header_row = tk.Frame(service_box, bg="#1e293b")
        header_row.pack(fill="x", pady=(0, 8))
        for text, width in [("Service", 28), ("Script", 10), ("Ports", 20), ("Status", 14)]:
            tk.Label(
                header_row, text=text, bg="#1e293b", fg="#94a3b8",
                width=width, anchor="w", font=("Arial", 9, "bold")
            ).pack(side="left")

        for service in SERVICES:
            row = tk.Frame(service_box, bg="#1e293b")
            row.pack(fill="x", pady=7)

            tk.Label(
                row, text=service["name"], bg="#1e293b", fg="#f8fafc",
                width=28, anchor="w", font=("Arial", 11, "bold")
            ).pack(side="left")

            script_status = "OK" if (BASE_DIR / service["script"]).exists() else "MISSING"
            script_color = "#22c55e" if script_status == "OK" else "#ef4444"

            tk.Label(
                row, text=script_status, bg="#1e293b", fg=script_color,
                width=10, anchor="w", font=("Arial", 10, "bold")
            ).pack(side="left")

            ports_text = ", ".join(str(p) for p in service["ports"]) if service["ports"] else "-"
            ports_lbl = tk.Label(
                row, text=f"Ports: {ports_text}", bg="#1e293b", fg="#94a3b8",
                width=20, anchor="w", font=("Arial", 10, "bold")
            )
            ports_lbl.pack(side="left")
            self.port_labels[service["key"]] = ports_lbl

            status = tk.Label(
                row, text="STOPPED", bg="#1e293b", fg="#ef4444",
                width=14, anchor="w", font=("Arial", 10, "bold")
            )
            status.pack(side="left")
            self.status_labels[service["key"]] = status

        controls = tk.Frame(body, bg="#0f172a", pady=20)
        controls.pack(fill="x")

        buttons = [
            ("Start All", "#22c55e", self.start_all),
            ("Stop All", "#ef4444", self.stop_all),
            ("Force Kill v-Guard", "#ef4444", self.force_kill_all),
            ("Open Dashboard", "#38bdf8", self.open_dashboard),
            ("Restart as Admin", "#f59e0b", relaunch_as_admin),
            ("Open Logs Folder", "#a855f7", self.open_logs_folder),
            ("Clear Auth Ban File", "#64748b", self.clear_auth_ban_file),
            ("Check Ports", "#334155", self.check_ports_now),
        ]

        for idx, (text, color, cmd) in enumerate(buttons):
            btn = self.make_button(controls, text, color, cmd)
            btn.grid(row=idx // 4, column=idx % 4, padx=6, pady=6, sticky="ew")

        for i in range(4):
            controls.grid_columnconfigure(i, weight=1)

        output_box = tk.Frame(body, bg="#020617", padx=14, pady=12)
        output_box.pack(fill="both", expand=True)

        tk.Label(
            output_box,
            text="Launcher Output",
            bg="#020617",
            fg="#38bdf8",
            font=("Consolas", 11, "bold")
        ).pack(anchor="w")

        self.output = tk.Text(
            output_box,
            bg="#020617",
            fg="#f8fafc",
            insertbackground="#f8fafc",
            height=14,
            relief="flat",
            font=("Consolas", 10),
            wrap="word"
        )
        self.output.pack(fill="both", expand=True, pady=(8, 0))

        self.write_output("Ready.")
        self.write_output(f"Project folder: {BASE_DIR}")
        self.write_output(f"Log folder: {LOG_DIR}")

    def make_button(self, parent, text, color, command):
        fg = "#020617" if color in ["#22c55e", "#38bdf8", "#f59e0b"] else "#ffffff"
        return tk.Button(
            parent, text=text, command=command, bg=color, fg=fg,
            activebackground=color, activeforeground="#ffffff",
            relief="flat", padx=12, pady=12,
            font=("Arial", 9, "bold"), cursor="hand2"
        )

    def write_output(self, text):
        timestamp = time.strftime("%H:%M:%S")
        self.output.insert("end", f"[{timestamp}] {text}\n")
        self.output.see("end")

    def start_service(self, service):
        key = service["key"]
        script_path = BASE_DIR / service["script"]

        if key in self.processes and self.processes[key].poll() is None:
            self.write_output(f"{service['name']} already running.")
            return

        if not script_path.exists():
            self.write_output(f"ERROR: {service['script']} not found.")
            return

        log_file = LOG_DIR / f"{key}.log"
        log_handle = open(log_file, "a", encoding="utf-8", errors="ignore")

        creationflags = subprocess.CREATE_NO_WINDOW if is_windows() else 0

        try:
            proc = subprocess.Popen(
                [PYTHON_EXE, str(script_path)],
                cwd=str(BASE_DIR),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=creationflags
            )

            self.processes[key] = proc
            self.write_output(f"Started {service['name']} | PID: {proc.pid} | Log: {log_file}")

        except Exception as exc:
            self.write_output(f"FAILED to start {service['name']}: {exc}")

    def start_all(self):
        if not is_admin():
            answer = messagebox.askyesno(
                "Administrator Recommended",
                (
                    "DPI/firewall operations and Force Kill work best as Administrator.\n\n"
                    "Restart launcher as Administrator now?"
                )
            )
            if answer:
                relaunch_as_admin()
                return

        self.force_kill_all(silent=True)

        for service in SERVICES:
            self.start_service(service)

        self.after(1800, self.open_dashboard)

    def stop_service(self, key, proc):
        if proc.poll() is not None:
            return

        ok, msg = kill_pid(proc.pid)
        if ok:
            self.write_output(f"Stopped {key} | PID: {proc.pid}")
        else:
            self.write_output(f"FAILED to stop {key} | PID: {proc.pid}: {msg}")

    def stop_all(self):
        for key, proc in list(self.processes.items()):
            self.stop_service(key, proc)

        self.processes.clear()

        # Also remove stale processes/ports started by previous launchers or manual CMD windows.
        self.force_kill_all(silent=True)
        self.refresh_status_once()

    def force_kill_all(self, silent=False):
        if not silent:
            self.write_output("Force Kill started...")

        killed_ports, port_errors = kill_by_ports(PORTS_TO_KILL)
        killed_scripts, script_errors = kill_by_script_names(SCRIPT_NAMES)

        for item in killed_ports:
            self.write_output(f"Killed by port: {item}")

        for item in killed_scripts:
            self.write_output(f"Killed by script: {item}")

        for err in port_errors + script_errors:
            self.write_output(f"Kill warning/error: {err}")

        time.sleep(0.4)
        self.refresh_status_once()

        still_open = [p for p in PORTS_TO_KILL if is_port_open(p)]

        if still_open:
            self.write_output(f"Ports still open: {still_open}")
            if not is_admin():
                self.write_output("You are in NORMAL mode. Run as Administrator and press Force Kill again.")
        else:
            self.write_output("Force Kill completed. Ports are closed.")

    def open_dashboard(self):
        webbrowser.open("http://127.0.0.1:5000/login")
        self.write_output("Opening login: http://127.0.0.1:5000/login")

    def open_logs_folder(self):
        if is_windows():
            os.startfile(str(LOG_DIR))
        else:
            subprocess.Popen(["xdg-open", str(LOG_DIR)])
        self.write_output("Opening launcher_logs folder.")

    def clear_auth_ban_file(self):
        path = BASE_DIR / "vguard_auth_security.json"

        if not path.exists():
            messagebox.showinfo("Auth Ban", "vguard_auth_security.json already does not exist.")
            return

        answer = messagebox.askyesno(
            "Clear Auth Ban",
            "Delete vguard_auth_security.json?\nThis clears login attempt lockouts."
        )

        if not answer:
            return

        try:
            path.unlink()
            self.write_output("vguard_auth_security.json removed.")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def check_ports_now(self):
        for port in PORTS_TO_KILL:
            pids = get_pids_by_port(port)
            open_text = "OPEN" if is_port_open(port) else "CLOSED"
            pid_text = ", ".join(str(p) for p in sorted(pids)) if pids else "-"
            self.write_output(f"Port {port}: {open_text} | PID(s): {pid_text}")

    def refresh_status_once(self):
        for service in SERVICES:
            key = service["key"]
            proc = self.processes.get(key)
            proc_running = proc and proc.poll() is None

            ports = service.get("ports", [])
            port_open = any(is_port_open(p) for p in ports) if ports else proc_running

            if proc_running or port_open:
                self.status_labels[key].config(text="RUNNING", fg="#22c55e")
            else:
                self.status_labels[key].config(text="STOPPED", fg="#ef4444")

    def refresh_status_loop(self):
        self.refresh_status_once()
        self.after(1000, self.refresh_status_loop)

    def on_close(self):
        answer = messagebox.askyesnocancel(
            "v-Guard",
            (
                "Close launcher?\n\n"
                "Yes  = stop/kill all v-Guard services and exit\n"
                "No   = exit launcher only, services may keep running\n"
                "Cancel = return"
            )
        )

        if answer is None:
            return

        if answer is True:
            self.stop_all()

        self.destroy()


if __name__ == "__main__":
    app = VGuardLauncher()
    app.mainloop()
