#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex 协议登录脚本（纯 HTTP，不需要浏览器）
============================================
从 GAP protocol.py 提取核心登录流程，适配 myinvite 批量登录场景。

流程：CSRF → OAuth URL → OAuth init → Sentinel PoW → authorize/continue →
      password/verify → redirect chain → auth session → Codex OAuth PKCE → auth.json

用法：
  # 单个账号
  python3 codex_protocol_login.py --email xxx@example.com --password P@ss --out ./accounts/xxx.json

  # 批量（CSV: email,password）
  python3 codex_protocol_login.py --csv accounts.csv --out-dir ./accounts

  # 带代理
  python3 codex_protocol_login.py --csv accounts.csv --out-dir ./accounts --proxy socks5://127.0.0.1:18898
"""

import os
import sys
import json
import csv
import time
import hashlib
import base64
import secrets
import random
import re
import uuid
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from pathlib import Path
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs, parse_qsl, urlencode, urljoin, urlunparse

sys.stdout.reconfigure(encoding="utf-8")

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

# ── HTTP 客户端 ──────────────────────────────────────────────────────
try:
    from curl_cffi.requests import Session as CffiSession
    _HAS_CFFI = True
except ImportError:
    _HAS_CFFI = False

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# ── Codex OAuth 常量 ──────────────────────────────────────────────────
CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_REDIRECT = "http://localhost:1455/auth/callback"
CODEX_SCOPE = "openid email profile offline_access"


def create_session(proxy: Optional[str] = None, impersonate: str = "chrome133a"):
    if _HAS_CFFI:
        s = CffiSession(impersonate=impersonate)
        s.trust_env = False
        if proxy:
            p = proxy
            if p.startswith("socks5://"):
                p = "socks5h://" + p[len("socks5://"):]
            s.proxies = {"https": p, "http": p}
        else:
            s.proxies = {"https": "", "http": ""}
        return s
    s = requests.Session()
    s.trust_env = False
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if proxy:
        s.proxies = {"https": proxy, "http": proxy}
    s.headers["User-Agent"] = USER_AGENT
    return s


# ── 工具函数 ──────────────────────────────────────────────────────────
def b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def build_pkce_pair(raw_bytes: int = 64) -> tuple:
    verifier = b64url_no_pad(secrets.token_bytes(max(32, raw_bytes)))
    if len(verifier) < 43:
        verifier = (verifier + ("A" * 43))[:43]
    if len(verifier) > 128:
        verifier = verifier[:128]
    challenge = b64url_no_pad(hashlib.sha256(verifier.encode("utf-8")).digest())
    return verifier, challenge


def jwt_decode(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8", errors="ignore"))
    except Exception:
        return {}


def extract_account_id(access_token: str, id_token: str = "") -> str:
    for tok in (access_token, id_token):
        if not tok:
            continue
        jwt = jwt_decode(tok)
        auth_info = jwt.get("https://api.openai.com/auth", {})
        account_id = auth_info.get("chatgpt_account_id") or auth_info.get("account_id")
        if account_id:
            return str(account_id)
    return ""


def datadog_trace_headers() -> dict:
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), "016x")
    parent_hex = format(int(parent_id), "016x")
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def common_headers(referer: str = "https://chatgpt.com/", device_id: str = "") -> dict:
    origin = "https://chatgpt.com"
    try:
        parsed = urlparse(referer or "")
        if parsed.scheme and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass
    headers = {
        "Accept": "application/json",
        "Referer": referer,
        "Origin": origin,
        "User-Agent": USER_AGENT,
    }
    if "auth.openai.com" in origin and device_id:
        headers["oai-device-id"] = device_id
    headers.update(datadog_trace_headers())
    return headers


def extract_page_type(resp_json: dict) -> str:
    if not isinstance(resp_json, dict):
        return ""
    page = resp_json.get("page", {})
    if not isinstance(page, dict):
        return ""
    return (page.get("type", "") or "").strip()


def extract_continue_url(resp_json: dict) -> str:
    if not isinstance(resp_json, dict):
        return ""
    continue_url = (resp_json.get("continue_url", "") or "").strip()
    if continue_url:
        return continue_url
    page = resp_json.get("page", {})
    if not isinstance(page, dict):
        return ""
    if (page.get("type", "") or "").strip() != "external_url":
        return ""
    payload = page.get("payload", {})
    if not isinstance(payload, dict):
        return ""
    return (payload.get("url", "") or "").strip()


def normalize_continue_url(url: str) -> str:
    if not url:
        return ""
    out = url.strip()
    if out.startswith("/"):
        out = urljoin("https://auth.openai.com", out)
    return out


def extract_query_first(url: str, keys: list) -> str:
    if not url:
        return ""
    try:
        qs = parse_qs(urlparse(url).query)
    except Exception:
        return ""
    for k in keys:
        val = qs.get(k, [None])[0]
        if val:
            return val
    return ""


def extract_sso_connection(resp_json: dict) -> dict:
    if not isinstance(resp_json, dict):
        return {}
    session = resp_json.get("oai-client-auth-session", {})
    if not isinstance(session, dict):
        return {}
    sso = session.get("sso", {})
    if not isinstance(sso, dict):
        return {}
    connections = sso.get("connections", [])
    if not isinstance(connections, list) or not connections:
        return {}
    first = connections[0]
    return first if isinstance(first, dict) else {}


def html_attr(tag: str, name: str) -> str:
    m = re.search(r'(?:^|\s)' + re.escape(name) + r'=(["\'])(.*?)\1', tag or "", re.IGNORECASE | re.DOTALL)
    return unescape(m.group(2)) if m else ""


def extract_confirm_form(html: str) -> tuple:
    for form_match in re.finditer(r"<form\b[^>]*>.*?</form>", html or "", re.IGNORECASE | re.DOTALL):
        form_html = form_match.group(0)
        form_tag_match = re.match(r"<form\b[^>]*>", form_html, re.IGNORECASE | re.DOTALL)
        form_tag = form_tag_match.group(0) if form_tag_match else ""
        fields = {}
        for input_match in re.finditer(r"<input\b[^>]*>", form_html, re.IGNORECASE | re.DOTALL):
            input_tag = input_match.group(0)
            name = html_attr(input_tag, "name")
            if name:
                fields[name] = html_attr(input_tag, "value")
        if fields.get("action") == "confirm":
            return html_attr(form_tag, "action"), fields
    return "", {}


def extract_unified_session_id(html: str) -> str:
    patterns = [
        r'value=(["\'])(us_[^"\']+)\1',
        r'"id","(us_[^"]+)"',
    ]
    for pattern in patterns:
        m = re.search(pattern, html or "", re.IGNORECASE | re.DOTALL)
        if not m:
            continue
        return unescape(m.group(2) if len(m.groups()) > 1 else m.group(1))
    return ""


def extract_workspace_id(html: str) -> str:
    html = html or ""
    m = re.search(r'name=(["\'])workspace_id\1[^>]*value=(["\'])([^"\']+)\2', html, re.IGNORECASE | re.DOTALL)
    if m:
        return unescape(m.group(3))
    m = re.search(r'value=(["\'])([^"\']+)\1[^>]*name=(["\'])workspace_id\3', html, re.IGNORECASE | re.DOTALL)
    if m:
        return unescape(m.group(2))
    m = re.search(r'"workspace_id","([^"]+)"', html, re.IGNORECASE | re.DOTALL)
    if m:
        return unescape(m.group(1))
    return ""


def callback_has_code(url: str, redirect_uri: str) -> bool:
    if not url:
        return False
    try:
        cb_base = (redirect_uri or "").split("?", 1)[0].rstrip("/")
        target = url.split("?", 1)[0].rstrip("/")
        if cb_base and target == cb_base:
            qs = parse_qs(urlparse(url).query)
            return bool((qs.get("code", [""])[0] or "").strip())
    except Exception:
        return False
    return False


def redirect_uri_is_localhost(redirect_uri: str) -> bool:
    try:
        host = (urlparse(redirect_uri).hostname or "").lower()
        return host in ("localhost", "127.0.0.1", "::1")
    except Exception:
        return False


def get_cookie_value(session, name: str) -> str:
    try:
        jar = getattr(session.cookies, "jar", None)
        if jar is None:
            return ""
        target = (name or "").strip().lower()
        for c in jar:
            if (getattr(c, "name", "") or "").strip().lower() == target:
                return (getattr(c, "value", "") or "").strip()
    except Exception:
        pass
    return ""


def is_tls_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(m in msg for m in ["curl: (35)", "tls connect error", "openssl_internal", "sslerror"])


# ── Sentinel PoW ──────────────────────────────────────────────────────
from sentinel import get_sentinel_token


# ── 登录流程 ──────────────────────────────────────────────────────────
class CodexLogin:
    """精简版协议登录，只处理已有账号密码登录 + Codex OAuth 换 token"""

    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy
        self._impersonate_candidates = ["chrome133a", "safari18_0", "chrome136", "chrome131"]
        self._impersonate_idx = 0
        self.session = create_session(proxy=proxy, impersonate=self._impersonate_candidates[0])
        self.device_id = ""
        self.csrf_token = ""
        self._last_sentinel_token = ""
        self._oauth_auth_url = ""
        self._oauth_client_id = ""
        self._oauth_redirect_uri = ""
        self._oauth_state = ""
        self._captured_login_verifier = ""

    def _rotate_session(self) -> bool:
        if self._impersonate_idx >= len(self._impersonate_candidates) - 1:
            return False
        self._impersonate_idx += 1
        imp = self._impersonate_candidates[self._impersonate_idx]
        logger.info(f"TLS 异常，切换指纹: {imp}")
        self.session = create_session(proxy=self.proxy, impersonate=imp)
        return True

    def get_csrf_token(self) -> str:
        logger.info("[1/9] 获取 CSRF Token...")
        headers = common_headers("https://chatgpt.com/auth/login")
        for attempt in range(3):
            try:
                resp = self.session.get(
                    "https://chatgpt.com/api/auth/csrf",
                    headers=headers, timeout=30,
                )
            except Exception as e:
                if is_tls_error(e) and self._rotate_session():
                    continue
                raise
            if resp.status_code == 403 and self._rotate_session():
                continue
            if resp.status_code == 403 and attempt < 2:
                time.sleep((attempt + 1) * 5)
                continue
            resp.raise_for_status()
            break
        csrf = resp.json().get("csrfToken", "")
        if not csrf:
            raise RuntimeError("CSRF Token 获取失败")
        self.csrf_token = csrf
        logger.info(f"CSRF: {csrf[:20]}...")
        return csrf

    def get_auth_url(self, csrf_token: str) -> str:
        logger.info("[2/9] 获取 Auth URL...")
        headers = common_headers("https://chatgpt.com/auth/login")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        resp = self.session.post(
            "https://chatgpt.com/api/auth/signin/openai",
            headers=headers,
            data={"csrfToken": csrf_token, "callbackUrl": "https://chatgpt.com/", "json": "true"},
            timeout=30,
        )
        resp.raise_for_status()
        auth_url = resp.json().get("url", "")
        if not auth_url:
            raise RuntimeError("Auth URL 获取失败")
        # 记住 OAuth 参数
        try:
            qs = parse_qs(urlparse(auth_url).query)
            self._oauth_auth_url = auth_url
            self._oauth_client_id = (qs.get("client_id", [""])[0] or "").strip()
            self._oauth_redirect_uri = (qs.get("redirect_uri", [""])[0] or "").strip()
            self._oauth_state = (qs.get("state", [""])[0] or "").strip()
        except Exception:
            pass
        logger.info(f"Auth URL: {auth_url[:80]}...")
        return auth_url

    def auth_oauth_init(self, auth_url: str) -> str:
        logger.info("[3/9] OAuth 初始化...")
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": "https://chatgpt.com/auth/login",
            "User-Agent": USER_AGENT,
        }
        resp = self.session.get(auth_url, headers=headers, timeout=30, allow_redirects=True)
        # 提取 oai-did
        device_id = ""
        try:
            device_id = self.session.cookies.get("oai-did", "")
        except Exception:
            pass
        if not device_id:
            m = re.search(r'oai-did["\s:=]+([a-f0-9-]{36})', resp.text)
            if m:
                device_id = m.group(1)
        if not device_id:
            device_id = str(uuid.uuid4())
        self.device_id = device_id
        logger.info(f"Device ID: {device_id}")
        return device_id

    def do_authorize_continue(self, email: str) -> dict:
        logger.info("[4/9] authorize/continue...")
        headers = common_headers("https://auth.openai.com/create-account", self.device_id)
        headers["Content-Type"] = "application/json"
        sentinel_token = get_sentinel_token(self.session, self.device_id, flow="authorize_continue")
        self._last_sentinel_token = sentinel_token or ""
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=headers,
            json={"username": {"value": email, "kind": "email"}, "screen_hint": "login"},
            timeout=30,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"authorize/continue 失败: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json() if resp else {}

    def do_sso_connection_continue(self, connection: dict) -> dict:
        logger.info("[4.5/9] SSO connection continue...")
        connection_name = (connection.get("connection_name", "") or "").strip()
        if not connection_name:
            raise RuntimeError("SSO connection 缺少 connection_name")
        headers = common_headers("https://auth.openai.com/sso", self.device_id)
        headers["Content-Type"] = "application/json"
        sentinel_token = get_sentinel_token(self.session, self.device_id, flow="authorize_continue")
        self._last_sentinel_token = sentinel_token or ""
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token
        payload = {"connection": connection_name}
        if connection.get("connection_provider") is not None:
            payload["connection_provider"] = connection.get("connection_provider")
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=headers,
            json=payload,
            timeout=30,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"SSO connection continue 失败: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json() if resp else {}

    def login_password_verify(self, password: str) -> dict:
        logger.info("[5/9] 密码验证...")
        headers = common_headers("https://auth.openai.com/log-in/password", self.device_id)
        headers["Content-Type"] = "application/json"
        if self._last_sentinel_token:
            headers["openai-sentinel-token"] = self._last_sentinel_token
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=headers,
            json={"password": password},
            timeout=30,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"密码登录失败: HTTP {resp.status_code} {resp.text[:300]}")
        data = resp.json() if resp else {}
        # 检查是否密码被拒
        page_type = extract_page_type(data)
        continue_url = normalize_continue_url(extract_continue_url(data))
        if page_type == "login_password" or "/log-in/password" in (continue_url or ""):
            raise RuntimeError(f"密码被拒: {json.dumps(data, ensure_ascii=False)[:300]}")
        return data

    def handle_saml_login(self, saml_url: str, email: str, password: str) -> str:
        """处理 SAML SSO 登录：Keycloak 表单登录 → SAMLResponse → POST 到 OpenAI ACS"""
        logger.info("[5.5/9] SAML SSO 登录...")

        # Step 1: GET Keycloak SAML 端点，获取登录表单
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": USER_AGENT,
        }
        resp = self.session.get(saml_url, headers=headers, timeout=30, allow_redirects=True)

        def submit_saml_response(html_text: str, referer_url: str) -> str:
            saml_response = ""
            relay_state = ""
            acs_url = ""
            saml_match = re.search(r'<input[^>]*name="SAMLResponse"[^>]*value="([^"]*)"', html_text, re.IGNORECASE)
            if saml_match:
                saml_response = saml_match.group(1)
            relay_match = re.search(r'<input[^>]*name="RelayState"[^>]*value="([^"]*)"', html_text, re.IGNORECASE)
            if relay_match:
                relay_state = relay_match.group(1)
            acs_match = re.search(r'<form[^>]*action="([^"]*)"[^>]*>', html_text, re.IGNORECASE)
            if acs_match:
                acs_url = acs_match.group(1)
            if not acs_url:
                acs_match2 = re.search(r'https://external\.auth\.openai\.com/sso/saml/acs/[a-zA-Z0-9]+', html_text)
                if acs_match2:
                    acs_url = acs_match2.group(0)
            if not saml_response or not acs_url:
                return ""
            logger.info(f"SAMLResponse 长度: {len(saml_response)}, ACS: {acs_url[:80]}")
            acs_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": referer_url,
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            acs_data = {"SAMLResponse": saml_response}
            if relay_state:
                acs_data["RelayState"] = relay_state
            acs_resp = self.session.post(acs_url, headers=acs_headers, data=acs_data, timeout=30, allow_redirects=False)
            if acs_resp.status_code in (301, 302, 303, 307, 308):
                location = acs_resp.headers.get("Location", "")
                logger.info(f"ACS 重定向到: {location[:100]}")
                return location
            if acs_resp.status_code == 200:
                redirect_match = re.search(r'window\.location\s*=\s*["\']([^"\']*)["\']', acs_resp.text)
                if redirect_match:
                    return redirect_match.group(1)
            logger.warning(f"ACS 响应异常: HTTP {acs_resp.status_code}")
            return ""

        html = resp.text
        saml_result = submit_saml_response(html, resp.url)
        if saml_result:
            return saml_result

        # Step 2: 找到登录表单的 action URL
        # Keycloak 登录表单通常在当前页面或重定向后的页面
        login_action = ""

        # 尝试从 HTML 中提取 form action
        action_match = re.search(r'<form[^>]*action="([^"]*)"[^>]*>', html, re.IGNORECASE)
        if action_match:
            login_action = action_match.group(1)
            if login_action.startswith("/"):
                login_action = urljoin(resp.url, login_action)

        # 如果没找到 form，可能是重定向到登录页
        if not login_action:
            # Keycloak 登录 URL 通常是 /realms/xxx/login-actions/authenticate
            if "/login-actions/" in resp.url or "/login" in resp.url:
                login_action = resp.url
            else:
                # 尝试从页面中找登录 URL
                login_url_match = re.search(r'(https?://[^"\']*login-actions[^"\']*)', html)
                if login_url_match:
                    login_action = login_url_match.group(1)

        if not login_action:
            logger.error(f"未找到 Keycloak 登录表单 action URL")
            return ""

        logger.info(f"Keycloak 登录表单: {login_action[:100]}")

        # Step 3: POST 登录表单（email + password）
        # Keycloak 表单字段通常是 username/password
        login_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": resp.url,
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        login_data = {
            "username": email,
            "password": password,
            "credentialId": "",
        }

        # 提取 hidden fields（如 session_code, tab_id 等）
        hidden_fields = re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]*)"[^>]*value="([^"]*)"', html, re.IGNORECASE)
        for name, value in hidden_fields:
            if name not in login_data:
                login_data[name] = value

        resp = self.session.post(login_action, headers=login_headers, data=login_data, timeout=30, allow_redirects=True)

        # Step 4: 解析 SAMLResponse（HTML auto-submit form）
        html = resp.text
        saml_result = submit_saml_response(html, resp.url)
        if saml_result:
            return saml_result
        if "SAMLResponse" not in html:
            logger.error("未找到 SAMLResponse，登录可能失败")
            logger.debug(f"响应内容: {html[:500]}")
            return ""
        return ""

    def handle_signin_consent(self, consent_url: str) -> str:
        """提交 WorkOS/OpenAI SSO interstitial confirm，返回下一跳 URL。"""
        logger.info("[5.8/9] SSO consent confirm...")
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": "https://external.auth.openai.com/",
            "User-Agent": USER_AGENT,
        }
        resp = self.session.get(consent_url, headers=headers, timeout=30, allow_redirects=False)
        if resp.status_code != 200:
            logger.warning(f"SSO consent 页面异常: HTTP {resp.status_code}")
            return ""
        action, fields = extract_confirm_form(resp.text)
        if not action or not fields:
            logger.warning("SSO consent 未找到 confirm 表单")
            return ""
        post_url = urljoin(consent_url, action)
        post_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Origin": "https://external.auth.openai.com",
            "Referer": consent_url,
            "User-Agent": USER_AGENT,
        }
        resp = self.session.post(post_url, headers=post_headers, data=fields, timeout=30, allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if location:
                location = urljoin(post_url, location)
                logger.info(f"SSO consent 重定向到: {location[:100]}")
                return location
        logger.warning(f"SSO consent 提交异常: HTTP {resp.status_code}")
        return ""

    def handle_codex_consent(self, consent_url: str, html: str = "") -> str:
        """提交 Codex OAuth consent 的 workspace 选择，返回下一跳 URL。"""
        logger.info("[6.5/8] Codex consent workspace select...")
        if not html:
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": "https://auth.openai.com/",
                "User-Agent": USER_AGENT,
            }
            resp = self.session.get(consent_url, headers=headers, timeout=30, allow_redirects=False)
            if resp.status_code != 200:
                logger.warning(f"Codex consent 页面异常: HTTP {resp.status_code}")
                return ""
            html = resp.text or ""
        workspace_id = extract_workspace_id(html)
        if not workspace_id:
            logger.warning("Codex consent 未找到 workspace_id")
            return ""
        headers = common_headers(consent_url, self.device_id)
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json"
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/workspace/select",
            headers=headers,
            json={"workspace_id": workspace_id},
            timeout=30,
            allow_redirects=False,
        )
        if resp.status_code != 200:
            logger.warning(f"Codex workspace/select 异常: HTTP {resp.status_code} {resp.text[:200]}")
            return ""
        next_url = normalize_continue_url(extract_continue_url(resp.json()))
        if next_url:
            logger.info(f"Codex consent 下一跳: {next_url[:100]}")
            return next_url
        logger.warning("Codex workspace/select 未返回 continue_url")
        return ""

    def follow_redirect_chain(
        self,
        start_url: str,
        email: str = "",
        password: str = "",
        redirect_uri: str = "",
    ) -> tuple:
        logger.info("[6/9] 跟踪重定向链...")
        current_url = start_url
        callback_url = ""
        redirect_uri = redirect_uri or self._oauth_redirect_uri or "https://chatgpt.com/api/auth/callback/openai"
        local_callback = redirect_uri_is_localhost(redirect_uri)
        processed_callback = False
        for i in range(20):
            if callback_has_code(current_url, redirect_uri):
                callback_url = current_url
                if local_callback:
                    break
                if processed_callback:
                    break
                processed_callback = True
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": "https://chatgpt.com/",
                "User-Agent": USER_AGENT,
            }
            try:
                resp = self.session.get(current_url, headers=headers, timeout=30, allow_redirects=False)
            except Exception:
                break

            # 检测 SAML SSO 重定向（Keycloak）
            if resp.status_code == 200 and "SAMLRequest" in (resp.url or ""):
                logger.info("检测到 SAML SSO 重定向")
                if email and password:
                    saml_result = self.handle_saml_login(resp.url, email, password)
                    if saml_result:
                        current_url = saml_result
                        continue
                    else:
                        logger.error("SAML SSO 登录失败")
                        break
                else:
                    logger.error("SAML SSO 需要邮箱和密码")
                    break

            if resp.status_code == 200 and "external.auth.openai.com/sso/signin-consent" in current_url:
                consent_result = self.handle_signin_consent(current_url)
                if consent_result:
                    current_url = consent_result
                    continue
                break

            if resp.status_code == 200 and "/sign-in-with-chatgpt/codex/consent" in current_url:
                codex_consent_result = self.handle_codex_consent(current_url, resp.text or "")
                if codex_consent_result:
                    current_url = codex_consent_result
                    continue
                break

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if not location:
                    break
                if location.startswith("/"):
                    location = urljoin(current_url, location)

                # 检测 SAML SSO 重定向（Keycloak）
                if "SAMLRequest" in location or "/protocol/saml" in location:
                    logger.info("检测到 SAML SSO 重定向")
                    if email and password:
                        saml_result = self.handle_saml_login(location, email, password)
                        if saml_result:
                            current_url = saml_result
                            continue
                        else:
                            logger.error("SAML SSO 登录失败")
                            break
                    else:
                        logger.error("SAML SSO 需要邮箱和密码")
                        break

                if "/api/auth/callback/openai" in location and "code=" in location:
                    callback_url = location
                    current_url = location
                    continue
                if callback_has_code(location, redirect_uri):
                    callback_url = location
                    if local_callback:
                        break
                    current_url = location
                    continue
                current_url = location
            else:
                break
        # 补一跳首页
        if not callback_url:
            try:
                self.session.get("https://chatgpt.com/", headers={"Referer": current_url}, timeout=30)
            except Exception:
                pass
        logger.info(f"重定向完成, callback: {'有' if callback_url else '无'}")
        return callback_url, current_url

    def get_auth_session(self) -> tuple:
        logger.info("[7/9] 获取 auth session...")
        headers = common_headers("https://chatgpt.com/")
        resp = self.session.get("https://chatgpt.com/api/auth/session", headers=headers, timeout=30)
        resp.raise_for_status()
        session_token = get_cookie_value(self.session, "__Secure-next-auth.session-token")
        access_token = resp.json().get("accessToken", "")
        logger.info(f"session_token: {'有' if session_token else '无'}, access_token: {'有' if access_token else '无'}")
        return session_token, access_token

    def oauth_token_exchange(self, callback_url: str, continue_url: str) -> tuple:
        logger.info("[8/9] OAuth Token 交换...")
        auth_code = extract_query_first(callback_url, ["code"]) or extract_query_first(continue_url, ["code"])
        if not auth_code:
            logger.warning("缺少 auth_code，跳过 token exchange")
            return "", "", ""
        # 收集 code_verifier 候选
        verifier_candidates = []
        for src, val in [
            ("query", extract_query_first(continue_url, ["login_verifier", "code_verifier", "verifier"])),
            ("query_cb", extract_query_first(callback_url, ["login_verifier", "code_verifier", "verifier"])),
            ("captured", self._captured_login_verifier),
            ("cookie_lv", get_cookie_value(self.session, "login_verifier")),
            ("cookie_cv", get_cookie_value(self.session, "code_verifier")),
        ]:
            v = (val or "").strip()
            if v and v not in [x[1] for x in verifier_candidates]:
                verifier_candidates.append((src, v))

        client_id = self._oauth_client_id or "YOUR_OPENAI_WEB_CLIENT_ID"
        redirect_uri = self._oauth_redirect_uri or "https://chatgpt.com/api/auth/callback/openai"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        }
        base_form = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": auth_code,
            "redirect_uri": redirect_uri,
        }
        # 先试有 verifier 的，再试无 verifier 的
        candidates = []
        for src, verifier in verifier_candidates:
            d = dict(base_form)
            d["code_verifier"] = verifier
            candidates.append((f"verifier_{src}", d))
        candidates.append(("no_verifier", dict(base_form)))

        for mode, form in candidates:
            resp = self.session.post(
                "https://auth.openai.com/oauth/token",
                headers=headers, data=urlencode(form), timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                id_token = data.get("id_token", "")
                access_token = data.get("access_token", "")
                refresh_token = data.get("refresh_token", "")
                logger.info(f"Token 交换成功(mode={mode}): refresh_token={'有' if refresh_token else '无'}")
                return access_token or "", refresh_token or "", id_token or ""
            logger.debug(f"Token 交换失败({mode}): {resp.status_code}")
        return "", "", ""

    def select_unified_session(self, choose_url: str, html: str = "") -> dict:
        logger.info("[9.1/9] Codex 选择已有账号...")
        if not html:
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": "https://auth.openai.com/oauth/authorize",
                "User-Agent": USER_AGENT,
            }
            resp = self.session.get(choose_url, headers=headers, timeout=30, allow_redirects=False)
            if resp.status_code != 200:
                raise RuntimeError(f"choose-an-account 页面失败: HTTP {resp.status_code}")
            html = resp.text or ""
        session_id = extract_unified_session_id(html)
        if not session_id:
            raise RuntimeError("choose-an-account 未找到 unified session id")
        headers = common_headers(choose_url, self.device_id)
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json"
        resp = self.session.post(
            "https://auth.openai.com/api/accounts/session/select",
            headers=headers,
            json={"session_id": session_id},
            timeout=30,
            allow_redirects=False,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"session/select 失败: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json() if resp else {}

    def codex_oauth_exchange(self, session_token: str, access_token: str, email: str = "", password: str = "") -> tuple:
        """用已有 session 做 Codex OAuth，换取 refresh_token + id_token"""
        logger.info("[9/9] Codex OAuth 换 refresh_token...")
        state = b64url_no_pad(secrets.token_bytes(24))
        verifier, challenge = build_pkce_pair()
        auth_params = {
            "client_id": CODEX_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": CODEX_REDIRECT,
            "scope": CODEX_SCOPE,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
        }
        auth_url = f"https://auth.openai.com/oauth/authorize?{urlencode(auth_params)}"
        # 跟踪 authorize 链路
        current = auth_url
        callback_url = ""
        for i in range(12):
            if callback_has_code(current, CODEX_REDIRECT):
                callback_url = current
                break
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": "https://chatgpt.com/",
                "User-Agent": USER_AGENT,
            }
            try:
                resp = self.session.get(current, headers=headers, timeout=30, allow_redirects=False)
            except Exception:
                break
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if not location:
                    break
                if location.startswith("/"):
                    location = urljoin(current, location)
                if callback_has_code(location, CODEX_REDIRECT):
                    callback_url = location
                    break
                current = location
            else:
                if resp.status_code == 200 and "/choose-an-account" in current:
                    selected = self.select_unified_session(current, resp.text or "")
                    selected_type = extract_page_type(selected)
                    next_url = normalize_continue_url(extract_continue_url(selected))
                    if selected_type == "sso":
                        sso_data = self.do_sso_connection_continue(extract_sso_connection(selected))
                        next_url = normalize_continue_url(extract_continue_url(sso_data))
                    if next_url:
                        callback_url, codex_final_url = self.follow_redirect_chain(
                            next_url,
                            email=email,
                            password=password,
                            redirect_uri=CODEX_REDIRECT,
                        )
                        if not callback_url and "/add-phone" in (codex_final_url or ""):
                            logger.warning("Codex OAuth 需要补手机号验证，无法获取 refresh_token")
                    break
                break

        if not callback_url:
            logger.warning("Codex OAuth 未捕获 callback")
            return "", "", ""

        qs = parse_qs(urlparse(callback_url).query)
        code = (qs.get("code", [""])[0] or "").strip()
        if not code:
            logger.warning("Codex callback 无 code")
            return "", "", ""

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        }
        form = {
            "grant_type": "authorization_code",
            "client_id": CODEX_CLIENT_ID,
            "code": code,
            "redirect_uri": CODEX_REDIRECT,
            "code_verifier": verifier,
        }
        resp = self.session.post(
            "https://auth.openai.com/oauth/token",
            headers=headers, data=urlencode(form), timeout=30,
        )
        if resp.status_code != 200:
            logger.warning(f"Codex token 交换失败: {resp.status_code} {resp.text[:200]}")
            return "", "", ""

        data = resp.json()
        id_token = data.get("id_token", "")
        codex_access = data.get("access_token", "")
        refresh_token = data.get("refresh_token", "")
        logger.info(f"Codex OAuth 成功: access={'有' if codex_access else '无'} refresh={'有' if refresh_token else '无'}")
        return codex_access or "", refresh_token or "", id_token or ""

    def direct_codex_token_exchange(self, callback_url: str, verifier: str) -> tuple:
        logger.info("[8/8] Codex OAuth token exchange...")
        code = extract_query_first(callback_url, ["code"])
        if not code:
            raise RuntimeError("Codex localhost callback 缺少 code")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Origin": "https://auth.openai.com",
            "Referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        }
        form = {
            "grant_type": "authorization_code",
            "client_id": CODEX_CLIENT_ID,
            "code": code,
            "redirect_uri": CODEX_REDIRECT,
            "code_verifier": verifier,
        }
        resp = self.session.post(
            "https://auth.openai.com/oauth/token",
            headers=headers,
            data=urlencode(form),
            timeout=30,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Codex token exchange 失败: HTTP {resp.status_code} {resp.text[:300]}")
        data = resp.json()
        access_token = data.get("access_token", "") or ""
        refresh_token = data.get("refresh_token", "") or ""
        id_token = data.get("id_token", "") or ""
        logger.info(f"Codex token exchange 成功: access={'有' if access_token else '无'} refresh={'有' if refresh_token else '无'}")
        return access_token, refresh_token, id_token

    def login_direct_codex(self, email: str, password: str) -> dict:
        """从 Codex OAuth URL 开始登录，SSO 完成后直接换 Codex token。"""
        logger.info("[0/8] 直接 Codex OAuth 登录...")
        state = b64url_no_pad(secrets.token_bytes(24))
        verifier, challenge = build_pkce_pair()
        auth_params = {
            "client_id": CODEX_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": CODEX_REDIRECT,
            "scope": CODEX_SCOPE,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
        }
        auth_url = f"https://auth.openai.com/oauth/authorize?{urlencode(auth_params)}"
        self._oauth_auth_url = auth_url
        self._oauth_client_id = CODEX_CLIENT_ID
        self._oauth_redirect_uri = CODEX_REDIRECT
        self._oauth_state = state

        self.auth_oauth_init(auth_url)

        step_data = self.do_authorize_continue(email)
        page_type = extract_page_type(step_data)
        continue_url = normalize_continue_url(extract_continue_url(step_data))

        if page_type == "login_password" or "/log-in/password" in (continue_url or ""):
            login_data = self.login_password_verify(password)
            continue_url = normalize_continue_url(extract_continue_url(login_data))
        elif page_type == "sso":
            sso_data = self.do_sso_connection_continue(extract_sso_connection(step_data))
            continue_url = normalize_continue_url(extract_continue_url(sso_data))
        elif page_type == "email_otp_verification":
            raise RuntimeError(f"需要 OTP 验证码，协议模式不支持。邮箱: {email}")

        if not continue_url:
            raise RuntimeError("Codex OAuth 登录流程未返回 continue_url")

        callback_url, final_url = self.follow_redirect_chain(
            continue_url,
            email=email,
            password=password,
            redirect_uri=CODEX_REDIRECT,
        )
        if not callback_url:
            if "/add-phone" in (final_url or ""):
                raise RuntimeError("Codex OAuth 需要补手机号验证，未返回 localhost callback")
            raise RuntimeError(f"Codex OAuth 未捕获 localhost callback，final_url={final_url[:200]}")

        access_token, refresh_token, id_token = self.direct_codex_token_exchange(callback_url, verifier)
        if not access_token:
            raise RuntimeError("Codex token exchange 完成但未获取 access_token")

        account_id = extract_account_id(access_token, id_token)
        jwt_p = jwt_decode(access_token)
        profile = jwt_p.get("https://api.openai.com/profile", {})
        email_from_jwt = profile.get("email") or jwt_p.get("email") or email

        auth_data = {
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": None,
            "tokens": {
                "id_token": id_token,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "account_id": account_id,
            },
            "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return auth_data, email_from_jwt

    def login(self, email: str, password: str) -> dict:
        """完整登录流程，返回 auth_data dict"""
        return self.login_direct_codex(email, password)

    def login_chatgpt_then_codex(self, email: str, password: str) -> dict:
        """旧流程：先登录 ChatGPT Web，再用已有 session 发起 Codex OAuth。"""
        csrf = self.get_csrf_token()
        auth_url = self.get_auth_url(csrf)
        self.auth_oauth_init(auth_url)

        # authorize/continue 判断分支
        step_data = self.do_authorize_continue(email)
        page_type = extract_page_type(step_data)
        continue_url = normalize_continue_url(extract_continue_url(step_data))

        if page_type == "login_password" or "/log-in/password" in (continue_url or ""):
            login_data = self.login_password_verify(password)
            continue_url = normalize_continue_url(extract_continue_url(login_data))
        elif page_type == "sso":
            connection = extract_sso_connection(step_data)
            sso_data = self.do_sso_connection_continue(connection)
            continue_url = normalize_continue_url(extract_continue_url(sso_data))
        elif page_type == "email_otp_verification":
            raise RuntimeError(f"需要 OTP 验证码，协议模式不支持。邮箱: {email}")

        if not continue_url:
            raise RuntimeError("登录流程未返回 continue_url")

        callback_url, final_url = self.follow_redirect_chain(continue_url, email, password)
        session_token, access_token = self.get_auth_session()

        # 尝试 OAuth token exchange
        if callback_url or continue_url:
            at, rt, idt = self.oauth_token_exchange(callback_url or "", continue_url or "")
            if at:
                access_token = at
            if rt:
                pass  # web OAuth 的 refresh_token 不是 Codex 的

        # Codex OAuth 换 refresh_token
        codex_access, codex_refresh, codex_id = self.codex_oauth_exchange(session_token, access_token, email, password)

        final_access = codex_access or access_token
        final_id = codex_id
        final_refresh = codex_refresh
        account_id = extract_account_id(final_access, final_id)

        if not final_access:
            raise RuntimeError("登录完成但未获取 access_token")

        email_from_jwt = email
        jwt_p = jwt_decode(final_access)
        profile = jwt_p.get("https://api.openai.com/profile", {})
        email_from_jwt = profile.get("email") or jwt_p.get("email") or email

        auth_data = {
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": None,
            "tokens": {
                "id_token": final_id,
                "access_token": final_access,
                "refresh_token": final_refresh,
                "account_id": account_id,
            },
            "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return auth_data, email_from_jwt


def safe_account_filename(email: str) -> str:
    name = email.strip().replace("@", "__at__")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    if name:
        return name
    return hashlib.sha256(email.encode("utf-8")).hexdigest()[:16]


def atomic_write_json(out_path: Path, data: Any) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_name(f".{out_path.name}.{uuid.uuid4().hex}.tmp")
    try:
        tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(out_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def login_and_save(email: str, password: str, out_path: Path, proxy: str = None) -> bool:
    try:
        client = CodexLogin(proxy=proxy)
        auth_data, logged_email = client.login(email, password)
        atomic_write_json(out_path, auth_data)
        tokens = auth_data["tokens"]
        logger.info(f"✓ 登录成功: {logged_email}")
        logger.info(f"  Account ID: {tokens['account_id']}")
        logger.info(f"  access_token: {tokens['access_token'][:30]}...")
        logger.info(f"  refresh_token: {'有' if tokens['refresh_token'] else '无'}")
        logger.info(f"  已保存到: {out_path}")
        return True
    except Exception as e:
        logger.error(f"✗ 登录失败 {email}: {e}")
        return False


def login_batch_job(
    index: int,
    total: int,
    email: str,
    password: str,
    out_path: Path,
    proxy: str = None,
    retries: int = 0,
    skip_existing: bool = False,
) -> dict:
    if skip_existing and out_path.exists():
        logger.info(f"[{index}/{total}] 跳过已存在: {email} -> {out_path}")
        return {"email": email, "out_path": str(out_path), "status": "skipped", "success": True}

    attempts = retries + 1
    for attempt in range(1, attempts + 1):
        logger.info(f"[{index}/{total}] {email} (尝试 {attempt}/{attempts})")
        if login_and_save(email, password, out_path, proxy):
            return {"email": email, "out_path": str(out_path), "status": "success", "success": True}
        if attempt < attempts:
            time.sleep(min(5, attempt * 2))

    return {"email": email, "out_path": str(out_path), "status": "failed", "success": False}


def main() -> int:
    parser = argparse.ArgumentParser(description="Codex 协议登录（纯 HTTP）")
    parser.add_argument("--email", help="登录邮箱")
    parser.add_argument("--password", help="登录密码")
    parser.add_argument("--csv", help="CSV 文件（email,password）")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", help="单账号输出路径")
    group.add_argument("--out-dir", help="批量输出目录")
    parser.add_argument("--proxy", help="代理 URL")
    parser.add_argument("--concurrency", type=int, default=1, help="CSV 批量登录并发数 [默认: 1]")
    parser.add_argument("--retries", type=int, default=2, help="CSV 批量登录失败重试次数 [默认: 2]")
    parser.add_argument("--skip-existing", action="store_true", help="CSV 批量登录时跳过已存在的输出 JSON")
    args = parser.parse_args()

    if args.concurrency <= 0:
        print(f"[!] --concurrency 必须大于 0，当前: {args.concurrency}")
        return 1
    if args.retries < 0:
        print(f"[!] --retries 不能小于 0，当前: {args.retries}")
        return 1

    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    if args.email and args.password:
        out_path = Path(args.out) if args.out else Path(args.out_dir) / f"{safe_account_filename(args.email)}.json"
        ok = login_and_save(args.email, args.password, out_path, args.proxy)
        return 0 if ok else 1

    if not args.csv:
        print("[!] 需要 --email/--password 或 --csv")
        return 1
    if not args.out_dir:
        print("[!] CSV 批量模式需要 --out-dir")
        return 1

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"[!] CSV 不存在: {csv_path}")
        return 1

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    accounts = []
    with open(csv_path, encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) >= 2 and row[0].strip() and not row[0].startswith("#"):
                accounts.append((row[0].strip(), row[1].strip()))

    if not accounts:
        print("[!] CSV 无有效账号")
        return 1

    jobs = []
    seen_paths = set()
    duplicate_count = 0
    for email, password in accounts:
        safe_name = safe_account_filename(email)
        out_path = out_dir / f"{safe_name}.json"
        resolved_key = str(out_path.resolve())
        if resolved_key in seen_paths:
            duplicate_count += 1
            logger.warning(f"跳过重复输出路径: {email} -> {out_path}")
            continue
        seen_paths.add(resolved_key)
        jobs.append((email, password, out_path))

    if not jobs:
        print("[!] CSV 中没有可执行账号")
        return 1

    logger.info(
        f"批量登录: {len(jobs)} 个账号，并发 {args.concurrency}，"
        f"失败重试 {args.retries} 次"
    )
    if duplicate_count:
        logger.warning(f"已跳过 {duplicate_count} 个重复输出路径")

    results = []
    success = 0
    skipped = 0
    max_workers = min(args.concurrency, len(jobs))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                login_batch_job,
                i,
                len(jobs),
                email,
                password,
                out_path,
                args.proxy,
                args.retries,
                args.skip_existing,
            ): email
            for i, (email, password, out_path) in enumerate(jobs, 1)
        }
        for future in as_completed(futures):
            email = futures[future]
            try:
                result = future.result()
            except Exception as e:
                result = {"email": email, "status": "failed", "success": False, "error": str(e)}
                logger.error(f"✗ 批量任务异常 {email}: {e}")
            results.append(result)
            if result.get("success"):
                success += 1
                if result.get("status") == "skipped":
                    skipped += 1

    print(f"\n{'='*60}")
    print(f"批量登录完成: {success}/{len(jobs)} 成功，跳过 {skipped} 个")
    failed = [r["email"] for r in results if not r.get("success")]
    if failed:
        print("失败账号:")
        for email in failed:
            print(f"  - {email}")
    print(f"{'='*60}")
    return 0 if success > 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 用户取消。")
        sys.exit(130)
