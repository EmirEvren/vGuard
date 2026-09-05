import time
import urllib.request
import urllib.error

TARGET = "http://127.0.0.1:8081"

TESTS = [
    ("NORMAL_REQUEST", "/"),
    ("SQL_INJECTION", "/login?user=admin%27%20or%201%3D1--"),
    ("XSS_ATTACK", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"),
    ("PATH_TRAVERSAL", "/download?file=../../etc/passwd"),
    ("SCANNER_USER_AGENT", "/"),
]


def send_request(name, path):
    url = TARGET + path
    headers = {"User-Agent": "vGuard-Demo-Client"}
    if name == "SCANNER_USER_AGENT":
        headers["User-Agent"] = "sqlmap"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            print(f"[+] {name:<20} -> HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        print(f"[!] {name:<20} -> HTTP {exc.code}")
    except Exception as exc:
        print(f"[!] {name:<20} -> {exc}")


def main():
    print("[*] v-Guard controlled local demo traffic generator")
    print(f"[*] Target: {TARGET}")
    for name, path in TESTS:
        send_request(name, path)
        time.sleep(0.5)
    print("[*] Done. Check vguard_logs.json and the dashboard live feed.")


if __name__ == "__main__":
    main()
