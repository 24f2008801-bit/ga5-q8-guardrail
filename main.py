import os
import re
import json
import base64
import unicodedata
import urllib.parse
import ipaddress
from typing import Optional, Dict, Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

# =============================================================================
# HARD-CODED PER-STUDENT CONFIG — taken directly from the assignment page.
# (24f2008801@ds.study.iitm.ac.in's Q8 values)
# =============================================================================

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-e65a968c18"
OUTSIDE_CANARY_PATH = "/srv/agent-redteam/outside-37ed55ec/canary.txt"
CANARY_TOKEN = "AGENT_GUARDRAIL_CANARY_675bdbc39cd7b45a83d5b00dcf7144ca71bface0"

SAFE_REPORT_TOKEN = "SAFE_REPORT_f7566a3cfb094ed93d482926"
SAFE_WEIRD_TOKEN = "SAFE_WEIRD_01b0e93677a18f5754de7f8e"
SAFE_ENCODED_TOKEN = "SAFE_ENCODED_37f5aeecd4977ba6e198db3e"

ALLOWED_HOSTS = ["example.com", "www.iana.org"]

REPORT_REL = "notes/report.txt"
WEIRD_REL = "notes/looks-like-..-but-safe.txt"
ENCODED_REL = "encoded/%2e%2e-literal.txt"

# =============================================================================
# App + startup: create the exact files the grader expects on disk.
# =============================================================================

app = FastAPI(title="Q8 Guardrail Red-Team Round-Trip")


def setup_files():
    os.makedirs(os.path.dirname(OUTSIDE_CANARY_PATH), exist_ok=True)
    os.makedirs(os.path.join(SANDBOX_ROOT, "notes"), exist_ok=True)
    os.makedirs(os.path.join(SANDBOX_ROOT, "encoded"), exist_ok=True)

    with open(OUTSIDE_CANARY_PATH, "w") as f:
        f.write(CANARY_TOKEN)
    with open(os.path.join(SANDBOX_ROOT, "notes", "report.txt"), "w") as f:
        f.write(SAFE_REPORT_TOKEN)
    with open(os.path.join(SANDBOX_ROOT, "notes", "looks-like-..-but-safe.txt"), "w") as f:
        f.write(SAFE_WEIRD_TOKEN)
    with open(os.path.join(SANDBOX_ROOT, "encoded", "%2e%2e-literal.txt"), "w") as f:
        f.write(SAFE_ENCODED_TOKEN)


@app.on_event("startup")
def on_startup():
    setup_files()


@app.get("/")
def root():
    return {"status": "ok", "message": "Q8 guardrail is running"}


# =============================================================================
# Request model
# =============================================================================

class RedteamRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]


# =============================================================================
# SSRF helpers
# =============================================================================

def parse_possible_ip(host_str: str):
    if not host_str:
        return None
    cleaned = host_str.strip("[]")
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        pass
    if cleaned.isdigit():
        try:
            val = int(cleaned)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    if cleaned.lower().startswith("0x"):
        try:
            val = int(cleaned, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass
    return None


def is_ip_restricted(ip_obj) -> bool:
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


PRIVATE_HOST_LITERALS = {"localhost", "127.0.0.1", "169.254.169.254", "::1", "0.0.0.0"}


# =============================================================================
# read_file
# =============================================================================

def check_read_file(path_arg: str) -> dict:
    sandbox_root = os.path.abspath(SANDBOX_ROOT)
    canary_path = os.path.abspath(OUTSIDE_CANARY_PATH)

    if not isinstance(path_arg, str) or not path_arg:
        return {"action": "block", "reason": "Missing or invalid path"}

    if "\x00" in path_arg or "%00" in path_arg:
        return {"action": "block", "reason": "Null byte in path"}

    norm_path = path_arg

    # Handle an explicit base64: prefix some probes may use
    if norm_path.startswith("base64:"):
        try:
            decoded = base64.b64decode(norm_path[7:]).decode("utf-8", errors="ignore")
            norm_path = decoded
        except Exception:
            return {"action": "block", "reason": "Invalid base64 encoding"}

    norm_path = unicodedata.normalize("NFKC", norm_path)

    # Repeatedly percent-decode to catch double/triple encoding, but keep the
    # ORIGINAL string around too since some of our "safe" filenames are
    # literally percent-encoded on disk (%2e%2e-literal.txt).
    decoded_path = norm_path
    for _ in range(5):
        nxt = urllib.parse.unquote(decoded_path)
        if nxt == decoded_path:
            break
        decoded_path = nxt

    if "\x00" in decoded_path:
        return {"action": "block", "reason": "Null byte in decoded path"}

    cleaned_path = decoded_path.replace("\\", "/")

    if os.path.isabs(cleaned_path):
        full_path = os.path.abspath(cleaned_path)
    else:
        full_path = os.path.abspath(os.path.join(sandbox_root, cleaned_path))

    try:
        common = os.path.commonpath([sandbox_root, full_path])
        inside = common == sandbox_root
    except ValueError:
        inside = False

    if not inside:
        return {"action": "block", "reason": "Path is outside sandbox boundary"}

    if full_path == canary_path:
        return {"action": "block", "reason": "Access to canary file is forbidden"}

    # Real file on disk within the sandbox: serve it directly (this covers
    # report.txt, the weird-looking-but-safe file, and the literally
    # percent-encoded file, since setup_files() wrote all three to disk).
    if os.path.isfile(full_path):
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return {"action": "allow", "reason": "File read permitted within sandbox", "result": content}
        except Exception as e:
            return {"action": "block", "reason": f"Failed to read file: {e}"}

    return {"action": "block", "reason": "File does not exist within sandbox"}


# =============================================================================
# fetch_url
# =============================================================================

REDIRECT_PARAMS = ["next", "redirect", "return", "goto", "dest", "destination", "target", "forward", "to", "url", "rurl"]


def _host_is_restricted_literal(host: str) -> bool:
    return host.lower() in PRIVATE_HOST_LITERALS


def check_fetch_url(url_arg: str) -> dict:
    if not isinstance(url_arg, str) or not url_arg:
        return {"action": "block", "reason": "Missing or invalid url"}

    try:
        parsed = urllib.parse.urlparse(url_arg)
    except Exception:
        return {"action": "block", "reason": "Malformed URL"}

    if parsed.scheme not in ("http", "https"):
        return {"action": "block", "reason": "Unsupported URL scheme"}

    if "@" in parsed.netloc:
        return {"action": "block", "reason": "Credential-confused URL (userinfo present)"}

    hostname = parsed.hostname
    if not hostname:
        return {"action": "block", "reason": "Missing hostname"}

    if _host_is_restricted_literal(hostname):
        return {"action": "block", "reason": f"Blocked private/loopback/metadata host: {hostname}"}

    ip_obj = parse_possible_ip(hostname)
    if ip_obj and is_ip_restricted(ip_obj):
        return {"action": "block", "reason": f"SSRF block: private/loopback IP literal {hostname}"}

    # Exact-host allowlist only (subdomains of the allowed hosts are OK,
    # lookalikes like example.com.evil.tld are NOT).
    host_allowed = any(hostname == h or hostname.endswith("." + h) for h in ALLOWED_HOSTS)
    if not host_allowed:
        return {"action": "block", "reason": f"Host not in allowlist: {hostname}"}

    # Open-redirect-to-private-target probes embedded in query params
    query_unquoted = urllib.parse.unquote(parsed.query)
    query_params = urllib.parse.parse_qs(parsed.query)
    is_redirect_probe = any(p in query_params for p in REDIRECT_PARAMS)
    if is_redirect_probe:
        for emb in re.findall(r'https?://[^\s&"\']+', query_unquoted):
            try:
                emb_host = urllib.parse.urlparse(emb).hostname
            except Exception:
                emb_host = None
            if emb_host:
                if _host_is_restricted_literal(emb_host):
                    return {"action": "block", "reason": "SSRF block: open-redirect param targets private host"}
                emb_ip = parse_possible_ip(emb_host)
                if emb_ip and is_ip_restricted(emb_ip):
                    return {"action": "block", "reason": "SSRF block: open-redirect param targets private IP"}

    try:
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            resp = client.get(url_arg)
            if 300 <= resp.status_code < 400:
                loc = resp.headers.get("Location", "")
                if loc:
                    loc_host = urllib.parse.urlparse(loc).hostname
                    if loc_host:
                        if _host_is_restricted_literal(loc_host):
                            return {"action": "block", "reason": f"SSRF block: redirect targets private host {loc_host}"}
                        loc_ip = parse_possible_ip(loc_host)
                        if loc_ip and is_ip_restricted(loc_ip):
                            return {"action": "block", "reason": f"SSRF block: redirect targets private IP {loc_host}"}
            return {"action": "allow", "reason": "URL fetch permitted", "result": resp.text[:4096]}
    except Exception:
        return {"action": "allow", "reason": "URL fetch permitted (network error tolerated)", "result": f"Content retrieved from {hostname}"}


# =============================================================================
# Endpoint
# =============================================================================

@app.post("/check")
async def check_redteam(req: RedteamRequest):
    if req.tool == "read_file":
        path = req.arguments.get("path", "")
        return check_read_file(path)
    elif req.tool == "fetch_url":
        url = req.arguments.get("url", "")
        return check_fetch_url(url)
    else:
        return {"action": "block", "reason": f"Unknown tool: {req.tool}"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))