import socket
import threading
import json
import datetime
import os
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


# ============================================================
# v-Guard Honeypot Module
#
# Fake HTTP Admin Panel + Fake SSH Service
#
# Purpose:
# - Detect suspicious interaction with decoy services.
# - Send structured intelligence logs to vguard_logs.json.
# - Apply safe auto-ban for HIGH/CRITICAL honeypot probes.
# - Firewall blocking is best-effort and is also visible in the dashboard ban list.
# ============================================================


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "vguard_logs.json")

try:
    from ban_manager import is_ban_active, get_active_ban, register_security_event_for_autoban
except Exception:
    is_ban_active = None
    get_active_ban = None
    register_security_event_for_autoban = None


# ============================================================
# Utility
# ============================================================

def current_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def classify_http_honeypot_event(path):
    """
    HTTP honeypot temasını basit risk kategorilerine ayırır.
    Bu sınıflandırma ban yapmaz; dashboard/AI için daha zengin log üretir.
    """
    decoded_path = urllib.parse.unquote(path).lower()

    if any(sig in decoded_path for sig in [
        "union select",
        "select * from",
        "or 1=1",
        "drop table",
        "--",
        "xp_cmdshell"
    ]):
        return "HONEYPOT_SQLI_PROBE", "HIGH"

    if any(sig in decoded_path for sig in [
        "<script>",
        "javascript:",
        "onerror=",
        "onload=",
        "document.cookie"
    ]):
        return "HONEYPOT_XSS_PROBE", "HIGH"

    if any(sig in decoded_path for sig in [
        "../",
        "..\\",
        "/etc/passwd",
        "boot.ini"
    ]):
        return "HONEYPOT_PATH_TRAVERSAL_PROBE", "HIGH"

    if any(sig in decoded_path for sig in [
        "169.254.169.254",
        "metadata.google.internal",
        "metadata/instance",
        "latest/meta-data",
        "169.254.170.2",
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "10.114.0.3",
        "file://",
        "gopher://"
    ]):
        return "HONEYPOT_SSRF_PROBE", "HIGH"

    if any(sig in decoded_path for sig in [
        "admin",
        "login",
        "wp-admin",
        "phpmyadmin",
        "manager",
        "config",
        ".env"
    ]):
        return "HONEYPOT_ADMIN_PROBE", "MEDIUM"

    return "HONEYPOT_HTTP_TOUCH", "LOW"


def save_to_log(
    source_ip,
    dst_port,
    protocol,
    event_type,
    severity,
    info,
    payload="",
    action="LOG_ONLY"
):
    """
    Honeypot'a temas eden bağlantıları v-Guard dashboard loglarına yazar.
    """
    log_entry = {
        "timestamp": current_timestamp(),
        "source": source_ip,
        "destination": f"127.0.0.1:{dst_port}",
        "protocol": protocol,
        "type": event_type,
        "severity": severity,
        "action": action,
        "module": "HONEYPOT",
        "info": info,
        "payload": payload
    }

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            json.dump(log_entry, f, ensure_ascii=False)
            f.write("\n")

    except Exception as e:
        print(f"\n[!] DOSYAYA YAZMA HATASI: {e}")

    # Auto-ban dangerous web/SSH probes.
    # Loopback is skipped inside ban_manager so local simulator tests cannot lock the host.
    if register_security_event_for_autoban:
        try:
            result = register_security_event_for_autoban(
                source_ip,
                severity=severity,
                event_type=event_type,
                info=info,
            )
            if result.get("banned"):
                log_entry["action"] = "AUTO_BAN"
                log_entry["verdict"] = "BAN_AND_DROP"
                log_entry["auto_ban_reason"] = result.get("reason")
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    json.dump({
                        "timestamp": current_timestamp(),
                        "source": source_ip,
                        "destination": f"127.0.0.1:{dst_port}",
                        "protocol": protocol,
                        "type": "AUTO_BAN_APPLIED",
                        "severity": "CRITICAL" if str(severity).upper() == "CRITICAL" else "HIGH",
                        "action": "AUTO_BAN",
                        "module": "BAN_MANAGER",
                        "verdict": "BAN_AND_DROP",
                        "info": result.get("reason"),
                        "payload": payload,
                    }, f, ensure_ascii=False)
                    f.write("\n")
        except Exception as e:
            print(f"\n[!] AUTO-BAN HATASI: {e}")

    print(f"\n[HONEYPOT] {severity} | {source_ip} -> {info}")


# ============================================================
# Fake HTTP Admin Panel - Port 8081
# ============================================================

class HoneypotHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]

        if is_ban_active and is_ban_active(client_ip):
            ban = get_active_ban(client_ip) if get_active_ban else {}
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><body style='background:#000;color:#f00;font-family:monospace;'><h1>Blocked by v-Guard</h1><p>{(ban or {}).get('reason','Active IP ban')}</p></body></html>".encode("utf-8"))
            return

        requested_path = self.path

        event_type, severity = classify_http_honeypot_event(requested_path)

        info = f"Sahte HTTP admin servisinde GET denemesi: {requested_path}"
        payload = (
            f"GET {requested_path} HTTP/1.1\n"
            f"Host: {self.headers.get('Host', '-')}\n"
            f"User-Agent: {self.headers.get('User-Agent', '-')}"
        )

        save_to_log(
            source_ip=client_ip,
            dst_port=8081,
            protocol="HTTP",
            event_type=event_type,
            severity=severity,
            info=info,
            payload=payload,
            action="LOG_ONLY"
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        fake_html = """
        <html>
            <head>
                <title>Admin Panel</title>
            </head>
            <body style="background:#000; color:#0f0; font-family:monospace;">
                <h1>v-Guard: Unauthorized Access Detected</h1>
                <p>Your IP address has been logged.</p>
            </body>
        </html>
        """

        self.wfile.write(fake_html.encode("utf-8"))

    def do_POST(self):
        client_ip = self.client_address[0]

        if is_ban_active and is_ban_active(client_ip):
            ban = get_active_ban(client_ip) if get_active_ban else {}
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"<html><body style='background:#000;color:#f00;font-family:monospace;'><h1>Blocked by v-Guard</h1><p>{(ban or {}).get('reason','Active IP ban')}</p></body></html>".encode("utf-8"))
            return

        requested_path = self.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_body = ""

        if content_length > 0:
            try:
                post_body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
            except Exception:
                post_body = "[Unreadable POST body]"

        event_type, severity = classify_http_honeypot_event(requested_path + " " + post_body)

        if severity == "LOW":
            severity = "MEDIUM"

        info = f"Sahte HTTP admin servisinde POST denemesi: {requested_path}"
        payload = (
            f"POST {requested_path} HTTP/1.1\n"
            f"Host: {self.headers.get('Host', '-')}\n"
            f"User-Agent: {self.headers.get('User-Agent', '-')}\n\n"
            f"{post_body}"
        )

        save_to_log(
            source_ip=client_ip,
            dst_port=8081,
            protocol="HTTP",
            event_type=event_type,
            severity=severity,
            info=info,
            payload=payload,
            action="LOG_ONLY"
        )

        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        fake_html = """
        <html>
            <body style="background:#000; color:#f00; font-family:monospace;">
                <h1>Access Denied</h1>
                <p>Unauthorized login attempt recorded.</p>
            </body>
        </html>
        """

        self.wfile.write(fake_html.encode("utf-8"))

    def log_message(self, format, *args):
        # Default HTTP server access loglarını kapatıyoruz.
        return


def start_http_honeypot():
    server = None

    try:
        server = HTTPServer(("0.0.0.0", 8081), HoneypotHTTPHandler)
        print("[*] Sahte HTTP Admin Honeypot aktif: 0.0.0.0:8081")
        server.serve_forever()

    except OSError as e:
        print(f"[!] HTTP Honeypot başlatılamadı. Port 8081 kullanımda olabilir: {e}")

    except Exception as e:
        print(f"[!] HTTP Honeypot hatası: {e}")

    finally:
        if server:
            server.server_close()


# ============================================================
# Fake SSH Service - Port 2222
# ============================================================

def start_ssh_honeypot():
    print("[*] Sahte SSH Honeypot aktif: 0.0.0.0:2222")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", 2222))
        server.listen(5)

        while True:
            client = None

            try:
                client, addr = server.accept()
                client_ip = addr[0]

                if is_ban_active and is_ban_active(client_ip):
                    try:
                        client.send(b"Blocked by v-Guard IP ban policy.\r\n")
                    finally:
                        client.close()
                    continue

                fake_banner = b"SSH-2.0-OpenSSH_8.4p1 Debian-5\r\n"
                client.send(fake_banner)

                received_data = client.recv(1024)
                payload = received_data.decode("utf-8", errors="ignore")

                save_to_log(
                    source_ip=client_ip,
                    dst_port=2222,
                    protocol="SSH",
                    event_type="HONEYPOT_SSH_PROBE",
                    severity="HIGH",
                    info="Sahte SSH servisine bağlantı denemesi.",
                    payload=payload,
                    action="LOG_ONLY"
                )

                client.send(b"Access denied.\r\n")

            except Exception as e:
                print(f"[!] SSH bağlantı işleme hatası: {e}")

            finally:
                if client:
                    try:
                        client.close()
                    except Exception:
                        pass

    except OSError as e:
        print(f"[!] SSH Honeypot başlatılamadı. Port 2222 kullanımda olabilir: {e}")

    except Exception as e:
        print(f"[!] SSH Honeypot hatası: {e}")

    finally:
        try:
            server.close()
        except Exception:
            pass


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    print("[*] v-Guard Dual Honeypot Sistemi Başlatılıyor...\n")
    print("[*] Modüller:")
    print("    - Fake HTTP Admin Panel : 0.0.0.0:8081")
    print("    - Fake SSH Service      : 0.0.0.0:2222")
    print(f"[*] Log dosyası: {LOG_FILE}")

    http_thread = threading.Thread(target=start_http_honeypot, daemon=True)
    ssh_thread = threading.Thread(target=start_ssh_honeypot, daemon=True)

    http_thread.start()
    ssh_thread.start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Honeypot kapatılıyor...")