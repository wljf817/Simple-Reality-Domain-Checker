#!/usr/bin/env python3
import argparse
import html as html_lib
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


USER_AGENT = "domain-checker/1.0"
DEFAULT_TIMEOUT = 10
ITDOG_CHINA_LINE = "1,2,3"
ITDOG_AUTH_TOKEN = "token_20230313000136kwyktxb0tgspm00yo5"
ITDOG_DISPLAY_LIMIT = 5
ITDOG_DEFAULT_TIMEOUT = 15
ITDOG_FAST_MIN_RESULTS = 20
ITDOG_IDLE_EARLY_STOP_SECONDS = 3
THEORETICAL_CN_TO_US_MIN_MS = 120
ITDOG_PREFERRED_NODES = [
    ("上海", "电信"),
    ("广州", "移动"),
    ("北京", "联通"),
    ("深圳", "电信"),
    ("成都", "联通"),
]
ITDOG_LINE_LABEL = {
    "1": "电信",
    "2": "联通",
    "3": "移动",
    "5": "海外",
}
CDN_CNAME_HINTS = {
    "Cloudflare": ["cloudflare"],
    "Akamai": ["akamai", "edgesuite", "edgekey"],
    "CloudFront": ["cloudfront.net"],
    "Fastly": ["fastly.net", "fastlylb.net"],
    "Alibaba Cloud CDN": ["alikunlun", "alicdn", "kunlun"],
    "Tencent Cloud CDN": ["tcdn", "dnspod", "dnsv1.com"],
    "Qiniu CDN": ["qiniucdn", "qbox.me"],
    "BunnyCDN": ["b-cdn.net", "bunnycdn"],
    "StackPath": ["stackpathdns", "netdna", "hwcdn"],
    "Gcore": ["gcore", "gcdn"],
}
CDN_HEADER_HINTS = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "server:cloudflare"],
    "CloudFront": ["x-amz-cf-pop", "x-amz-cf-id", "cloudfront"],
    "Fastly": ["x-fastly-request-id", "fastly"],
    "Akamai": ["akamai-grn", "x-akamai"],
    "Alibaba Cloud CDN": ["x-swift-cachetime", "x-cache-l2", "x-oss-cdn-auth"],
    "Tencent Cloud CDN": ["x-nws-log-uuid", "x-tencent-cache"],
    "BunnyCDN": ["bunnycdn"],
}

COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_CYAN = "\033[36m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_RED = "\033[31m"
COLOR_BLUE = "\033[34m"
COLOR_MAGENTA = "\033[35m"
COLOR_GRAY = "\033[90m"


def should_enable_color() -> bool:
    force = os.environ.get("FORCE_COLOR", "").strip().lower()
    if force in {"1", "true", "yes", "on"}:
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


COLOR_ENABLED = should_enable_color()


def colorize(text: str, color: str) -> str:
    if not COLOR_ENABLED:
        return text
    return f"{color}{text}{COLOR_RESET}"


@dataclass
class CheckResult:
    ok: bool
    detail: str
    level: Optional[str] = None

    def __post_init__(self) -> None:
        if self.level is None:
            self.level = "pass" if self.ok else "fail"
            return

        normalized = str(self.level).strip().lower()
        if normalized not in {"pass", "warn", "fail"}:
            normalized = "pass" if self.ok else "fail"
        if not self.ok:
            normalized = "fail"
        self.level = normalized


def get_status_label(result: CheckResult) -> str:
    if not result.ok or result.level == "fail":
        return "FAIL"
    if result.level == "warn":
        return "WARN"
    return "PASS"


def colorize_status(status: str) -> str:
    if status == "PASS":
        return colorize(status, COLOR_GREEN)
    if status == "WARN":
        return colorize(status, COLOR_YELLOW)
    if status == "FAIL":
        return colorize(status, COLOR_RED)
    return status


CHECK_NAME_COLORS = {
    "CDN 检测": COLOR_MAGENTA,
    "TLS 握手时间": COLOR_BLUE,
    "TLS1.3": COLOR_CYAN,
    "X25519": COLOR_CYAN,
    "HTTP/2 (H2)": COLOR_CYAN,
    "SNI 匹配": COLOR_CYAN,
    "ITDOG 中国 Ping": COLOR_MAGENTA,
}


def colorize_check_name(name: str) -> str:
    color = CHECK_NAME_COLORS.get(name, COLOR_CYAN)
    return colorize(name, f"{COLOR_BOLD}{color}")


def print_section(title: str) -> None:
    print("")
    print(colorize(f"[{title}]", COLOR_CYAN))


def print_check_item(name: str, result: CheckResult) -> str:
    status = get_status_label(result)
    print(f"- {colorize_check_name(name)}: [{colorize_status(status)}]")
    print(f"  {colorize('详情', COLOR_GRAY)}: {result.detail}")
    return status


def normalize_domain(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("域名不能为空")

    parsed = urllib.parse.urlparse(value if "://" in value else f"https://{value}")
    if not parsed.hostname:
        raise ValueError(f"无法解析域名: {value}")
    return parsed.hostname.lower()


def resolve_final_domain(domain: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[str, str]:
    start_url = f"https://{domain}"

    insecure_ctx = ssl.create_default_context()
    insecure_ctx.check_hostname = False
    insecure_ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=insecure_ctx),
    )
    req = urllib.request.Request(start_url, headers={"User-Agent": USER_AGENT})

    with opener.open(req, timeout=timeout) as resp:
        final_url = resp.geturl()

    parsed = urllib.parse.urlparse(final_url)
    if not parsed.hostname:
        raise RuntimeError(f"跳转后 URL 无法解析域名: {final_url}")
    return parsed.hostname.lower(), final_url


def open_tls_socket(
    domain: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    tls13_only: bool = False,
    alpn: Optional[list] = None,
    ecdh_curve: Optional[str] = None,
    verify_cert: bool = False,
) -> ssl.SSLSocket:
    if verify_cert:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        # 能力检测不依赖本机 CA 链，避免环境缺少根证书导致误判。
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if tls13_only:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    if alpn:
        ctx.set_alpn_protocols(alpn)

    if ecdh_curve:
        ctx.set_ecdh_curve(ecdh_curve)

    raw = socket.create_connection((domain, 443), timeout=timeout)
    try:
        tls_sock = ctx.wrap_socket(raw, server_hostname=domain)
    except Exception:
        raw.close()
        raise
    return tls_sock


def check_tls13(domain: str) -> CheckResult:
    try:
        with open_tls_socket(domain, tls13_only=True) as s:
            version = s.version()
            if version == "TLSv1.3":
                return CheckResult(True, "支持 TLS1.3")
            return CheckResult(False, f"握手成功但版本为 {version}")
    except Exception as exc:
        return CheckResult(False, f"TLS1.3 握手失败: {exc}")


def check_x25519(domain: str) -> CheckResult:
    try:
        with open_tls_socket(domain, tls13_only=True, ecdh_curve="X25519") as _:
            return CheckResult(True, "支持 X25519（仅提供 X25519 仍可握手）")
    except Exception as exc:
        msg = str(exc).lower()
        if "unknown group" in msg or "unknown elliptic curve" in msg:
            return check_x25519_via_openssl(domain)
        return CheckResult(False, f"X25519 检查失败: {exc}")


def check_x25519_via_openssl(domain: str) -> CheckResult:
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{domain}:443",
        "-servername",
        domain,
        "-tls1_3",
        "-groups",
        "X25519",
    ]
    try:
        proc = subprocess.run(
            cmd,
            input="",
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        return CheckResult(False, "本机不支持 Python X25519 检测，且未找到 openssl 命令")
    except subprocess.TimeoutExpired:
        return CheckResult(False, "openssl 检查 X25519 超时")
    except Exception as exc:
        return CheckResult(False, f"openssl 检查 X25519 失败: {exc}")

    output = f"{proc.stdout}\n{proc.stderr}"
    if "Server Temp Key" in output and "X25519" in output:
        return CheckResult(True, "支持 X25519（openssl 协商成功）")
    return CheckResult(False, "不支持 X25519（openssl 未协商到 X25519）")


def check_http2(domain: str) -> CheckResult:
    try:
        with open_tls_socket(domain, alpn=["h2", "http/1.1"]) as s:
            selected = s.selected_alpn_protocol()
            if selected == "h2":
                return CheckResult(True, "支持 HTTP/2 (ALPN=h2)")
            return CheckResult(False, f"不支持 HTTP/2，ALPN 协商结果: {selected}")
    except Exception as exc:
        return CheckResult(False, f"HTTP/2 检查失败: {exc}")


def check_sni_match(domain: str) -> CheckResult:
    try:
        with open_tls_socket(domain) as s:
            der = s.getpeercert(binary_form=True)
            if not der:
                return CheckResult(False, "未获取到服务端证书")
            cert = decode_der_cert(der)
            match_hostname = getattr(ssl, "match_hostname", None)
            if callable(match_hostname):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    match_hostname(cert, domain)
            else:
                match_hostname_fallback(cert, domain)
            return CheckResult(True, "证书与 SNI/域名匹配")
    except Exception as exc:
        return CheckResult(False, f"SNI/证书匹配失败: {exc}")


def decode_der_cert(der: bytes) -> dict:
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(ssl.DER_cert_to_PEM_cert(der))
        cert_file = f.name
    try:
        return ssl._ssl._test_decode_cert(cert_file)
    finally:
        os.unlink(cert_file)


def dnsname_match(pattern: str, hostname: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if "*" not in pattern:
        return pattern == hostname

    # 仅支持左侧单标签通配符，如 *.example.com
    if pattern.startswith("*.") and pattern.count("*") == 1:
        suffix = pattern[1:]
        if not hostname.endswith(suffix):
            return False
        left = hostname[: -len(suffix)]
        return bool(left) and "." not in left
    return False


def match_hostname_fallback(cert: dict, hostname: str) -> None:
    san = cert.get("subjectAltName", ()) or ()
    dns_names = [str(v) for k, v in san if str(k).upper() == "DNS"]
    if dns_names:
        if any(dnsname_match(name, hostname) for name in dns_names):
            return
        raise ValueError(f"hostname '{hostname}' not in SAN: {dns_names}")

    subject = cert.get("subject", ()) or ()
    common_names: List[str] = []
    for rdn in subject:
        for key, value in rdn:
            if str(key).lower() == "commonname":
                common_names.append(str(value))

    if common_names and any(dnsname_match(name, hostname) for name in common_names):
        return

    if common_names:
        raise ValueError(f"hostname '{hostname}' not in CN: {common_names}")
    raise ValueError("证书中未找到 SAN/CN 可用于主机名匹配")


def check_tls_handshake_time(
    domain: str,
    *,
    samples: int = 3,
    timeout: int = DEFAULT_TIMEOUT,
) -> CheckResult:
    timings: List[Tuple[float, float, float]] = []
    versions = set()
    errors = []

    for _ in range(max(1, samples)):
        raw = None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            start = time.perf_counter()
            raw = socket.create_connection((domain, 443), timeout=timeout)
            tcp_done = time.perf_counter()
            with ctx.wrap_socket(raw, server_hostname=domain) as tls_sock:
                tls_done = time.perf_counter()
                versions.add(tls_sock.version() or "unknown")
            raw = None

            timings.append(
                (
                    (tcp_done - start) * 1000,
                    (tls_done - tcp_done) * 1000,
                    (tls_done - start) * 1000,
                )
            )
        except Exception as exc:
            errors.append(str(exc))
        finally:
            if raw is not None:
                try:
                    raw.close()
                except Exception:
                    pass

    if not timings:
        detail = errors[0] if errors else "未知错误"
        return CheckResult(False, f"TLS 握手时间测量失败: {detail}")

    avg_tcp = sum(x[0] for x in timings) / len(timings)
    avg_tls = sum(x[1] for x in timings) / len(timings)
    avg_total = sum(x[2] for x in timings) / len(timings)
    best_total = min(x[2] for x in timings)
    ver_text = ",".join(sorted(versions)) if versions else "unknown"
    return CheckResult(
        True,
        (
            f"平均 {avg_total:.1f}ms（TCP {avg_tcp:.1f}ms + TLS {avg_tls:.1f}ms），"
            f"最快 {best_total:.1f}ms，协议 {ver_text}"
        ),
    )


def build_insecure_https_opener() -> urllib.request.OpenerDirector:
    insecure_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_ctx.check_hostname = False
    insecure_ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=insecure_ctx),
    )


def get_cname_candidates(domain: str) -> List[str]:
    candidates = set()
    try:
        _, aliases, _ = socket.gethostbyname_ex(domain)
        for alias in aliases:
            if alias and alias.lower() != domain.lower():
                candidates.add(alias.rstrip("."))
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["nslookup", "-type=CNAME", domain],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        text = f"{proc.stdout}\n{proc.stderr}"
        for cname in re.findall(r"canonical name\s*=\s*([^\s]+)", text, flags=re.I):
            cname = cname.rstrip(".")
            if cname and cname.lower() != domain.lower():
                candidates.add(cname)
    except Exception:
        pass

    return sorted(candidates)


def get_https_headers(domain: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, str]:
    opener = build_insecure_https_opener()
    req = urllib.request.Request(
        f"https://{domain}/",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {k.lower(): str(v) for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return {k.lower(): str(v) for k, v in exc.headers.items()}


def check_cdn(domain: str) -> CheckResult:
    cname_list = get_cname_candidates(domain)
    headers: Dict[str, str] = {}
    header_error = None
    try:
        headers = get_https_headers(domain)
    except Exception as exc:
        header_error = str(exc)

    provider_reasons: Dict[str, set] = {}

    for cname in cname_list:
        low = cname.lower()
        for provider, patterns in CDN_CNAME_HINTS.items():
            for p in patterns:
                if p in low:
                    provider_reasons.setdefault(provider, set()).add(f"CNAME={cname}")
                    break

    for hk, hv in headers.items():
        line = f"{hk}:{hv}".lower().replace(" ", "")
        for provider, markers in CDN_HEADER_HINTS.items():
            for marker in markers:
                if marker in hk or marker in line:
                    provider_reasons.setdefault(provider, set()).add(f"Header={hk}")
                    break

    if provider_reasons:
        providers = sorted(
            provider_reasons.keys(),
            key=lambda k: (-len(provider_reasons[k]), k),
        )
        top_reasons = list(provider_reasons[providers[0]])[:3]
        return CheckResult(
            True,
            f"疑似使用 CDN：{', '.join(providers)}（依据: {', '.join(top_reasons)}）",
            level="warn",
        )

    if cname_list or headers:
        note = "未发现明显 CDN 特征（可能直连源站或特征被隐藏）"
        if header_error and not headers:
            note += f"，Header 检测异常: {header_error}"
        return CheckResult(True, note)

    if header_error:
        return CheckResult(False, f"CDN 检查失败: {header_error}")
    return CheckResult(False, "CDN 检查失败: 未获取到 DNS/HTTP 信息")


def fetch_itdog_task_page(domain: str, *, line: str, timeout: int) -> str:
    url = f"https://www.itdog.cn/ping/{domain}"
    data = urllib.parse.urlencode(
        {
            "button_click": "yes",
            "line": line,
            "dns_server_type": "isp",
            "dns_server": "",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    opener = build_insecure_https_opener()
    with opener.open(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "ignore")


def parse_itdog_task_info(html_text: str) -> Tuple[str, str]:
    wss_match = re.search(r"var\s+wss_url='([^']+)'", html_text)
    task_match = re.search(r"var\s+task_id='([^']+)'", html_text)
    if not wss_match or not task_match:
        raise RuntimeError("ITDOG 页面未返回 websocket 任务信息")
    return wss_match.group(1), task_match.group(1)


def parse_itdog_nodes(html_text: str) -> Dict[int, Dict[str, str]]:
    nodes: Dict[int, Dict[str, str]] = {}
    row_re = re.compile(
        r'<tr\s+class="node_tr"\s+node="(?P<node>\d+)"\s+node_type="(?P<node_type>\d+)"[^>]*>(?P<body>.*?)</tr>',
        re.S,
    )
    for row in row_re.finditer(html_text):
        node_id = int(row.group("node"))
        node_type = row.group("node_type")
        body = row.group("body")
        td_match = re.search(r'<td\s+class="text-left"[^>]*>(.*?)</td>', body, re.S)
        if not td_match:
            continue
        name_text = re.sub(r"<[^>]+>", " ", td_match.group(1))
        name_text = html_lib.unescape(name_text)
        name_text = re.sub(r"\s+", " ", name_text).strip()
        nodes[node_id] = {
            "name": name_text,
            "line_code": node_type,
            "line_label": ITDOG_LINE_LABEL.get(node_type, f"线路{node_type}"),
        }
    return nodes


def pick_itdog_target_node_ids(node_map: Dict[int, Dict[str, str]]) -> List[int]:
    targets: List[int] = []
    used = set()
    for city, carrier in ITDOG_PREFERRED_NODES:
        for node_id in sorted(node_map.keys()):
            if node_id in used:
                continue
            info = node_map[node_id]
            name = str(info.get("name", ""))
            line_label = str(info.get("line_label", ""))
            if city in name and (carrier in name or carrier == line_label):
                targets.append(node_id)
                used.add(node_id)
                break
    return targets


def collect_itdog_ws_results(
    wss_url: str,
    task_id: str,
    timeout: int,
    *,
    target_node_ids: Optional[List[int]] = None,
    min_results: int = ITDOG_FAST_MIN_RESULTS,
    idle_seconds: int = ITDOG_IDLE_EARLY_STOP_SECONDS,
    min_target_hits: int = 3,
) -> Dict[str, Any]:
    target_ids = sorted({int(x) for x in (target_node_ids or []) if int(x) > 0})
    min_results = max(ITDOG_DISPLAY_LIMIT, int(min_results))
    idle_seconds = max(1, int(idle_seconds))
    min_target_hits = max(0, int(min_target_hits))

    node_script = r"""
const crypto = require("crypto");
const [wssUrl, taskId, timeoutSec, authToken, minResultsArg, idleSecArg, minTargetHitsArg, targetNodeIdsJson] = process.argv.slice(1);
const timeoutMs = Math.max(1, parseInt(timeoutSec, 10) || 45) * 1000;
const minResults = Math.max(1, parseInt(minResultsArg, 10) || 20);
const idleMs = Math.max(500, (parseFloat(idleSecArg) || 3) * 1000);
const minTargetHits = Math.max(0, parseInt(minTargetHitsArg, 10) || 0);
const taskToken = crypto.createHash("md5").update(taskId + authToken).digest("hex").slice(8, 24);
let targetNodeIds = [];
try {
  targetNodeIds = JSON.parse(targetNodeIdsJson || "[]");
  if (!Array.isArray(targetNodeIds)) targetNodeIds = [];
} catch (_) {
  targetNodeIds = [];
}
const targetSet = new Set(targetNodeIds.map((x) => String(x)));
const out = {
  ok: false,
  finished: false,
  early_stop: false,
  early_reason: null,
  messages: 0,
  results: {},
  node_errors: [],
  error: null
};
let ws = null;
let done = false;
let timer = null;
let idleTimer = null;
let lastProgressAt = Date.now();
let WebSocketImpl = globalThis.WebSocket;
if (!WebSocketImpl) {
  try {
    WebSocketImpl = require("ws");
  } catch (e) {
    out.error = "当前 Node 运行时不支持全局 WebSocket，且未安装 ws 模块。请升级 Node 或安装 ws（npm i ws）";
    process.stdout.write(JSON.stringify(out));
    process.exit(0);
  }
}

function finish() {
  if (done) return;
  done = true;
  if (timer) clearTimeout(timer);
  if (idleTimer) clearInterval(idleTimer);
  out.ok = out.finished || Object.keys(out.results).length > 0;
  process.stdout.write(JSON.stringify(out), () => {
    try { if (ws) ws.close(); } catch (_) {}
    process.exit(0);
  });
}

function haveEnoughTargetNodes() {
  if (!targetSet.size || minTargetHits <= 0) return true;
  let hits = 0;
  for (const nodeId of targetSet) {
    if (nodeId in out.results) hits += 1;
    if (hits >= Math.min(minTargetHits, targetSet.size)) return true;
  }
  return false;
}

function maybeEarlyStop(reason) {
  const got = Object.keys(out.results).length;
  if (got < minResults) return false;
  if (!haveEnoughTargetNodes()) return false;
  out.early_stop = true;
  out.early_reason = reason;
  finish();
  return true;
}

try {
  ws = new WebSocketImpl(wssUrl, {
    headers: {
      Origin: "https://www.itdog.cn",
      "User-Agent": "Mozilla/5.0"
    }
  });
} catch (e) {
  out.error = String(e);
  finish();
}

timer = setTimeout(() => {
  if (!out.error) out.error = "timeout";
  finish();
}, timeoutMs);

idleTimer = setInterval(() => {
  const idleFor = Date.now() - lastProgressAt;
  if (idleFor >= idleMs) {
    maybeEarlyStop("idle");
  }
}, 500);

ws.onopen = () => {
  try {
    ws.send(JSON.stringify({ task_id: taskId, task_token: taskToken }));
  } catch (e) {
    out.error = String(e);
    clearTimeout(timer);
    finish();
  }
};

ws.onmessage = (event) => {
  let obj;
  try {
    obj = JSON.parse(event.data.toString());
  } catch (_) {
    return;
  }
  out.messages += 1;
  if (obj.type === "node_error") {
    if (obj.node_id !== undefined && obj.node_id !== null) {
      out.node_errors.push(Number(obj.node_id));
    }
    return;
  }
  if (obj.type === "finished") {
    out.finished = true;
    finish();
    return;
  }
  if (obj.node_id !== undefined && obj.result !== undefined) {
    out.results[String(obj.node_id)] = obj;
    lastProgressAt = Date.now();
    maybeEarlyStop("enough_results");
  }
};

ws.onerror = () => {
  if (!out.error) out.error = "websocket_error";
};

ws.onclose = () => {
  if (!done) {
    finish();
  }
};
"""
    try:
        proc = subprocess.run(
            [
                "node",
                "-e",
                node_script,
                wss_url,
                task_id,
                str(timeout),
                ITDOG_AUTH_TOKEN,
                str(min_results),
                str(idle_seconds),
                str(min_target_hits),
                json.dumps(target_ids),
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 8,
            check=False,
        )
    except FileNotFoundError:
        return {
            "ok": False,
            "finished": False,
            "messages": 0,
            "results": {},
            "node_errors": [],
            "error": "未找到 node，无法连接 ITDOG websocket",
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "finished": False,
            "messages": 0,
            "results": {},
            "node_errors": [],
            "error": "连接 ITDOG websocket 超时",
        }
    except Exception as exc:
        return {
            "ok": False,
            "finished": False,
            "messages": 0,
            "results": {},
            "node_errors": [],
            "error": f"执行 node websocket 采集失败: {exc}",
        }

    stdout = (proc.stdout or "").strip()
    if not stdout:
        err = (proc.stderr or "").strip()
        return {
            "ok": False,
            "finished": False,
            "messages": 0,
            "results": {},
            "node_errors": [],
            "error": f"ITDOG websocket 无输出: {err}",
        }

    try:
        return json.loads(stdout.splitlines()[-1])
    except Exception as exc:
        return {
            "ok": False,
            "finished": False,
            "messages": 0,
            "results": {},
            "node_errors": [],
            "error": f"解析 ITDOG websocket 结果失败: {exc}",
        }


def fetch_itdog_china_ping(
    domain: str, timeout: int = ITDOG_DEFAULT_TIMEOUT
) -> Tuple[CheckResult, List[str]]:
    try:
        task_html = fetch_itdog_task_page(domain, line=ITDOG_CHINA_LINE, timeout=timeout)
        wss_url, task_id = parse_itdog_task_info(task_html)
        node_map = parse_itdog_nodes(task_html)
        target_node_ids = pick_itdog_target_node_ids(node_map)
        min_results = max(ITDOG_FAST_MIN_RESULTS, len(target_node_ids) + ITDOG_DISPLAY_LIMIT)
        ws_data = collect_itdog_ws_results(
            wss_url,
            task_id,
            timeout=timeout,
            target_node_ids=target_node_ids,
            min_results=min_results,
            idle_seconds=ITDOG_IDLE_EARLY_STOP_SECONDS,
            min_target_hits=min(3, len(target_node_ids)),
        )
    except Exception as exc:
        return CheckResult(False, f"ITDOG 请求失败: {exc}"), []

    raw_results = ws_data.get("results") or {}
    if not isinstance(raw_results, dict) or not raw_results:
        err = ws_data.get("error", "未收到可用节点结果")
        return CheckResult(False, f"ITDOG 无结果: {err}"), []

    records: List[Dict[str, Any]] = []
    for node_id_str, raw in raw_results.items():
        try:
            node_id = int(node_id_str)
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue

        line_code = str(raw.get("line", "")).strip()
        if line_code and line_code not in {"1", "2", "3"}:
            continue

        fallback = node_map.get(node_id, {})
        name = str(raw.get("name") or fallback.get("name") or f"node-{node_id}")
        if not line_code:
            line_code = str(fallback.get("line_code", ""))
        line_label = ITDOG_LINE_LABEL.get(line_code, fallback.get("line_label", "未知"))

        result_raw = str(raw.get("result", "")).strip()
        result_ms: Optional[int]
        if result_raw == "-1":
            result_ms = None
            rtt_text = "timeout"
        else:
            try:
                result_ms = int(result_raw)
                rtt_text = "<1ms" if result_ms == 0 else f"{result_ms}ms"
            except Exception:
                result_ms = None
                rtt_text = result_raw or "unknown"

        records.append(
            {
                "node_id": node_id,
                "name": name,
                "line_label": line_label,
                "result_ms": result_ms,
                "rtt_text": rtt_text,
            }
        )

    if not records:
        err = ws_data.get("error", "未得到中国节点结果")
        return CheckResult(False, f"ITDOG 无中国节点结果: {err}"), []

    records.sort(
        key=lambda x: (
            x["result_ms"] is None,
            x["result_ms"] if x["result_ms"] is not None else 999999,
            x["node_id"],
        )
    )

    ok_records = [x for x in records if x["result_ms"] is not None]
    timeout_num = len(records) - len(ok_records)
    warn_reasons: List[str] = []
    if ok_records:
        avg_ms = sum(x["result_ms"] for x in ok_records) / len(ok_records)
        best_ms = min(x["result_ms"] for x in ok_records)
        worst_ms = max(x["result_ms"] for x in ok_records)
        summary = (
            f"中国节点 {len(records)} 个，成功 {len(ok_records)}，超时 {timeout_num}，"
            f"平均 {avg_ms:.1f}ms，最快 {best_ms}ms，最慢 {worst_ms}ms"
        )
        if best_ms < THEORETICAL_CN_TO_US_MIN_MS:
            warn_reasons.append(
                f"最低时延 {best_ms}ms 低于中国直连美国理论下限 "
                f"{THEORETICAL_CN_TO_US_MIN_MS}ms，疑似存在国内 CDN"
            )
    else:
        summary = f"中国节点 {len(records)} 个，全部超时"

    if ws_data.get("early_stop"):
        summary += "（快速采样提前结束）"
    elif not ws_data.get("finished"):
        summary += "（未收到 finished，结果可能不完整）"
        warn_reasons.append("ITDOG 任务未收到 finished，结果可能不完整")

    selected_records: List[Dict[str, Any]] = []
    selected_node_ids = set()

    # 优先展示典型城市/运营商组合，不足再按时延由低到高补齐。
    for city, carrier in ITDOG_PREFERRED_NODES:
        for item in records:
            if item["node_id"] in selected_node_ids:
                continue
            if city not in item["name"]:
                continue
            if carrier in item["name"] or carrier == item["line_label"]:
                selected_records.append(item)
                selected_node_ids.add(item["node_id"])
                break
        if len(selected_records) >= ITDOG_DISPLAY_LIMIT:
            break

    if len(selected_records) < ITDOG_DISPLAY_LIMIT:
        for item in records:
            if item["node_id"] in selected_node_ids:
                continue
            selected_records.append(item)
            selected_node_ids.add(item["node_id"])
            if len(selected_records) >= ITDOG_DISPLAY_LIMIT:
                break

    show_num = len(selected_records)
    summary += f"；展示 {show_num} 个国内代表节点"
    if warn_reasons:
        summary += "；告警: " + "；".join(warn_reasons)

    lines = [
        f"{idx:03d}. [{item['line_label']}] {item['name']}: {item['rtt_text']}"
        for idx, item in enumerate(selected_records, start=1)
    ]
    level = "warn" if warn_reasons else "pass"
    return CheckResult(True, summary, level=level), lines


def run_checks(
    input_domain: str,
    *,
    skip_itdog: bool = False,
    itdog_timeout: int = ITDOG_DEFAULT_TIMEOUT,
    show_input_domain: bool = True,
) -> int:
    try:
        normalized = normalize_domain(input_domain)
    except Exception as exc:
        print(f"[错误] 输入不合法: {exc}")
        return 2

    print(colorize("========================================", COLOR_CYAN))
    print(colorize("域名检测报告", f"{COLOR_BOLD}{COLOR_CYAN}"))
    print(colorize("========================================", COLOR_CYAN))

    try:
        final_domain, final_url = resolve_final_domain(normalized)
    except Exception as exc:
        print(f"[错误] 获取跳转后域名失败: {exc}")
        return 2

    print_section("目标信息")
    if show_input_domain:
        print(f"- 输入域名: {normalized}")
    if final_domain != normalized:
        print(f"- 跳转检测: 检测到跨域名跳转 ({normalized} -> {final_domain})")
    else:
        print("- 跳转检测: 未检测到跨域名跳转")
    print(f"- 检测域名: {final_domain}")
    print(f"- 最终 URL: {final_url}")

    print_section("基础检查")

    checks = [
        ("CDN 检测", check_cdn(final_domain)),
        ("TLS 握手时间", check_tls_handshake_time(final_domain)),
        ("TLS1.3", check_tls13(final_domain)),
        ("X25519", check_x25519(final_domain)),
        ("HTTP/2 (H2)", check_http2(final_domain)),
        ("SNI 匹配", check_sni_match(final_domain)),
    ]

    warn_details: List[str] = []
    for name, result in checks:
        status = print_check_item(name, result)
        if status == "WARN":
            warn_details.append(f"{name}: {result.detail}")
        if not result.ok:
            print_section("结论")
            print(f"- 结果: {colorize('未通过', COLOR_RED)}")
            print(f"- 原因: {name}: {result.detail}")
            print("- 处理: 已跳过后续步骤")
            return 1

    if not skip_itdog:
        print_section("ITDOG 中国节点 Ping")
        itdog_result, itdog_lines = fetch_itdog_china_ping(final_domain, timeout=itdog_timeout)
        status = print_check_item("ITDOG 中国 Ping", itdog_result)
        if itdog_lines:
            print("  节点:")
            for line in itdog_lines:
                print(f"    {line}")
        else:
            print("  节点: 无")
        if status == "WARN":
            warn_details.append(f"ITDOG 中国 Ping: {itdog_result.detail}")
        if not itdog_result.ok:
            print_section("结论")
            print(f"- 结果: {colorize('未通过', COLOR_RED)}")
            print(f"- 原因: ITDOG 中国 Ping: {itdog_result.detail}")
            print("- 处理: 已跳过后续步骤")
            return 1

    print_section("结论")
    if warn_details:
        print(f"- 结果: {colorize('通过（有告警）', COLOR_YELLOW)}")
        print("- 告警详情:")
        for idx, detail in enumerate(warn_details, start=1):
            print(f"  {idx}. {detail}")
        return 0

    print(f"- 结果: {colorize('所有要求均通过', COLOR_GREEN)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "检查域名的跳转后目标是否满足 CDN 特征 / TLS 握手时间 / "
            "TLS1.3 / X25519 / HTTP2 / SNI 匹配"
        )
    )
    parser.add_argument("domain", nargs="?", help="要检测的域名，例如 example.com")
    parser.add_argument(
        "--skip-itdog",
        action="store_true",
        help="跳过 ITDOG 中国节点 Ping",
    )
    parser.add_argument(
        "--itdog-timeout",
        type=int,
        default=ITDOG_DEFAULT_TIMEOUT,
        help=f"ITDOG websocket 等待秒数（默认 {ITDOG_DEFAULT_TIMEOUT}）",
    )
    args = parser.parse_args()

    itdog_timeout = max(5, int(args.itdog_timeout))

    if args.domain:
        return run_checks(
            args.domain,
            skip_itdog=args.skip_itdog,
            itdog_timeout=itdog_timeout,
            show_input_domain=True,
        )

    while True:
        try:
            domain = input("请输入域名（q/quit/exit 或空行退出）: ").strip()
        except EOFError:
            print("")
            print("已退出")
            return 0

        if not domain:
            print("已退出")
            return 0
        if domain.lower() in {"q", "quit", "exit"}:
            print("已退出")
            return 0

        print("")
        run_checks(
            domain,
            skip_itdog=args.skip_itdog,
            itdog_timeout=itdog_timeout,
            show_input_domain=False,
        )
        print("")


if __name__ == "__main__":
    sys.exit(main())
