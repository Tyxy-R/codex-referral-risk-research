#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex 全自动登录 & Token 截获脚本
==================================
用 Playwright 自动完成 OpenAI 登录（email+password），截获 Codex OAuth token，保存为 auth.json。

用法：
  # 单个账号登录
  python codex_sso_login.py --email xxx@example.com --password P@ssw0rd --out ./accounts/xxx.json

  # 批量：从 CSV 文件读取（格式：email,password）
  python codex_sso_login.py --csv accounts.csv --out-dir ./accounts

  # 带代理
  python codex_sso_login.py --email xxx --password yyy --out ./accounts/xxx.json --proxy socks5://127.0.0.1:18898

  # OTP 回调：登录需要验证码时调用外部命令获取
  python codex_sso_login.py --email xxx --password yyy --out ./accounts/xxx.json --otp-cmd "python3 get_otp.py {email}"
"""

import os
import sys
import json
import csv
import time
import hashlib
import base64
import secrets
import argparse
import logging
import subprocess
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs

sys.stdout.reconfigure(encoding="utf-8")

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

# ── 常量 ──────────────────────────────────────────────────────────────
CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_REDIRECT = "http://localhost:1455/auth/callback"
CODEX_SCOPE = "openid email profile offline_access"
TOKEN_ENDPOINT = "https://auth.openai.com/oauth/token"
CHATGPT_URL = "https://chatgpt.com"


def b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def build_pkce_pair() -> tuple:
    verifier = b64url_no_pad(secrets.token_bytes(64))
    challenge = b64url_no_pad(hashlib.sha256(verifier.encode()).digest())
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


def get_otp_from_cmd(cmd: str, email: str, timeout: int = 120) -> str:
    """调用外部命令获取 OTP 验证码"""
    full_cmd = cmd.replace("{email}", email)
    logger.info(f"调用 OTP 命令: {full_cmd}")
    try:
        result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        otp = result.stdout.strip()
        if otp:
            logger.info(f"获得 OTP: {otp}")
            return otp
        logger.error(f"OTP 命令无输出: stderr={result.stderr[:200]}")
    except subprocess.TimeoutExpired:
        logger.error(f"OTP 命令超时 ({timeout}s)")
    except Exception as e:
        logger.error(f"OTP 命令异常: {e}")
    return ""


def build_playwright_proxy(proxy_url: str) -> dict:
    if not proxy_url:
        return {}
    parsed = urlparse(proxy_url)
    proxy_dict = {"server": proxy_url}
    if parsed.username:
        proxy_dict["username"] = parsed.username
        proxy_dict["password"] = parsed.password or ""
    return dict(proxy_dict)


def auto_login(
    email: str,
    password: str,
    out_path: Path,
    proxy_url: str = None,
    otp_cmd: str = None,
    headless: bool = False,
    timeout: int = 300,
) -> bool:
    """全自动登录流程：打开浏览器 → 填邮箱密码 → 截获 token → 保存"""
    from playwright.sync_api import sync_playwright

    pw_proxy = build_playwright_proxy(proxy_url)
    verifier, challenge = build_pkce_pair()
    codex_state = b64url_no_pad(secrets.token_bytes(24))

    # Codex OAuth 授权 URL
    auth_params = {
        "client_id": CODEX_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": CODEX_REDIRECT,
        "scope": CODEX_SCOPE,
        "state": codex_state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    codex_auth_url = f"https://auth.openai.com/oauth/authorize?{urlencode(auth_params)}"

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=headless,
            proxy=pw_proxy if pw_proxy else None,
        )
        context = browser.new_context()
        page = context.new_page()

        # 拦截 localhost:1455 回调
        callback_holder = {"url": ""}

        def intercept_callback(route):
            url = route.request.url
            if "localhost:1455" in url and "code=" in url:
                callback_holder["url"] = url
                logger.info(f"拦截到 Codex callback: {url[:150]}")
            try:
                route.fulfill(status=200, content_type="text/html", body="<html>OK</html>")
            except Exception:
                try:
                    route.abort()
                except Exception:
                    pass

        page.route("**/localhost:1455/**", intercept_callback)
        page.route("http://localhost:1455/**", intercept_callback)

        # Step 1: 打开 Codex OAuth 授权页
        logger.info(f"打开 Codex OAuth 授权页: {email}")
        try:
            page.goto(codex_auth_url, wait_until="networkidle", timeout=60000)
        except Exception as e:
            logger.info(f"页面加载: {str(e)[:120]}")

        # Step 2: 自动填邮箱
        logger.info("填写邮箱...")
        try:
            # 等待邮箱输入框出现
            email_input = page.wait_for_selector('input[name="email"], input[name="username"], input[type="email"], #email-input', timeout=15000)
            if email_input:
                email_input.fill(email)
                time.sleep(0.5)
                # 点击 Continue / Next 按钮
                continue_btn = page.query_selector('button[type="submit"], button:has-text("Continue"), button:has-text("Next"), button:has-text("继续")')
                if continue_btn:
                    continue_btn.click()
                    logger.info("已点击 Continue")
                    time.sleep(2)
        except Exception as e:
            logger.info(f"邮箱填写: {str(e)[:120]}")

        # Step 3: 自动填密码
        logger.info("填写密码...")
        try:
            password_input = page.wait_for_selector('input[name="password"], input[type="password"]', timeout=15000)
            if password_input:
                password_input.fill(password)
                time.sleep(0.5)
                # 点击 Continue / Log in 按钮
                login_btn = page.query_selector('button[type="submit"], button:has-text("Continue"), button:has-text("Log in"), button:has-text("登录")')
                if login_btn:
                    login_btn.click()
                    logger.info("已点击登录")
                    time.sleep(3)
        except Exception as e:
            logger.info(f"密码填写: {str(e)[:120]}")

        # Step 4: 处理 OTP 验证码（如果需要）
        try:
            otp_input = page.wait_for_selector(
                'input[name="code"], input[name="otp"], input[autocomplete="one-time-code"], input[data-type="otp"]',
                timeout=8000,
            )
            if otp_input and otp_cmd:
                logger.info("检测到 OTP 验证码输入框，获取验证码...")
                otp_code = get_otp_from_cmd(otp_cmd, email)
                if otp_code:
                    otp_input.fill(otp_code)
                    time.sleep(0.5)
                    otp_btn = page.query_selector('button[type="submit"], button:has-text("Continue"), button:has-text("Verify")')
                    if otp_btn:
                        otp_btn.click()
                        logger.info("已提交 OTP")
                        time.sleep(3)
                else:
                    logger.error("无法获取 OTP，登录失败")
                    browser.close()
                    return False
            elif otp_input and not otp_cmd:
                logger.error("需要 OTP 验证码但未提供 --otp-cmd")
                browser.close()
                return False
        except Exception:
            pass  # 没有 OTP 输入框，继续

        # Step 5: 等待回调拦截
        logger.info("等待 Codex OAuth 回调...")
        start = time.time()
        while time.time() - start < timeout:
            if callback_holder["url"]:
                break
            if "localhost:1455" in page.url and "code=" in page.url:
                callback_holder["url"] = page.url
                break
            time.sleep(0.5)

        # 清理 route
        try:
            page.unroute("**/localhost:1455/**")
            page.unroute("http://localhost:1455/**")
        except Exception:
            pass

        cb_url = callback_holder["url"]

        # 同时获取 /api/auth/session 的 accessToken
        access_token = ""
        try:
            session_info = page.evaluate('''async () => {
                const r = await fetch("/api/auth/session", {credentials: "include"});
                return await r.json();
            }''')
            access_token = session_info.get("accessToken", "") if isinstance(session_info, dict) else ""
        except Exception:
            pass

        browser.close()

    # Step 6: 交换 Codex token
    if not cb_url:
        if access_token:
            logger.warning("未拦截到 Codex callback，但有 access_token，尝试用 refresh_token 方式获取...")
            # 尝试用 access_token 做 token exchange
            account_id = extract_account_id(access_token)
            auth_data = {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": None,
                "tokens": {
                    "id_token": "",
                    "access_token": access_token,
                    "refresh_token": "",
                    "account_id": account_id,
                },
                "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(auth_data, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.info(f"✓ 登录成功（仅 access_token）: {email}")
            logger.info(f"  Account ID: {account_id}")
            logger.info(f"  已保存到: {out_path}")
            return True
        logger.error("未拦截到 Codex callback，登录失败")
        return False

    # 提取 auth code
    qs = parse_qs(urlparse(cb_url).query)
    code = (qs.get("code") or [""])[0]
    if not code:
        logger.error(f"回调 URL 中无 code: {cb_url[:150]}")
        return False

    logger.info("获得 auth code，交换 token...")
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    sess = requests.Session()
    if proxy_url:
        sess.proxies.update({"http": proxy_url, "https": proxy_url})

    try:
        resp = sess.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "authorization_code",
                "client_id": CODEX_CLIENT_ID,
                "code": code,
                "redirect_uri": CODEX_REDIRECT,
                "code_verifier": verifier,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            timeout=30,
            verify=False,
        )
        if resp.status_code != 200:
            logger.error(f"Token 交换失败: HTTP {resp.status_code} {resp.text[:200]}")
            return False
        token_data = resp.json()
    except Exception as e:
        logger.error(f"Token 交换异常: {e}")
        return False

    refresh_token = token_data.get("refresh_token", "")
    id_token = token_data.get("id_token", "")
    codex_access_token = token_data.get("access_token", "")
    final_access_token = codex_access_token or access_token
    account_id = extract_account_id(final_access_token, id_token)

    if not final_access_token:
        logger.error("未能获取 access_token")
        return False

    # 构造 auth.json
    auth_data = {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": id_token,
            "access_token": final_access_token,
            "refresh_token": refresh_token,
            "account_id": account_id,
        },
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    jwt_p = jwt_decode(final_access_token)
    profile = jwt_p.get("https://api.openai.com/profile", {})
    logged_email = profile.get("email") or jwt_p.get("email") or email

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(auth_data, indent=2, ensure_ascii=False), encoding="utf-8")

    logger.info(f"✓ 登录成功: {logged_email}")
    logger.info(f"  Account ID: {account_id}")
    logger.info(f"  access_token: {final_access_token[:30]}...")
    logger.info(f"  refresh_token: {'有' if refresh_token else '无'}")
    logger.info(f"  已保存到: {out_path}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Codex 全自动登录 & Token 截获")

    # 单账号模式
    parser.add_argument("--email", help="登录邮箱")
    parser.add_argument("--password", help="登录密码")

    # 批量模式
    parser.add_argument("--csv", help="CSV 文件路径（格式：email,password）")

    # 输出
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", help="单账号输出 auth.json 路径")
    group.add_argument("--out-dir", help="批量输出目录")

    # 选项
    parser.add_argument("--proxy", help="代理 URL")
    parser.add_argument("--otp-cmd", help="OTP 获取命令（{email} 会被替换为邮箱）")
    parser.add_argument("--headless", action="store_true", help="无头模式（不显示浏览器）")
    parser.add_argument("--timeout", type=int, default=300, help="登录超时秒数 [默认: 300]")
    args = parser.parse_args()

    # 单账号模式
    if args.email and args.password:
        out_path = Path(args.out) if args.out else Path(args.out_dir) / f"{args.email.split('@')[0]}.json"
        ok = auto_login(args.email, args.password, out_path, args.proxy, args.otp_cmd, args.headless, args.timeout)
        return 0 if ok else 1

    # 批量模式
    if not args.csv:
        print("[!] 需要 --email/--password 或 --csv")
        return 1

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"[!] CSV 文件不存在: {csv_path}")
        return 1

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    accounts = []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2 and row[0].strip() and not row[0].startswith("#"):
                accounts.append((row[0].strip(), row[1].strip()))

    if not accounts:
        print("[!] CSV 中无有效账号")
        return 1

    logger.info(f"批量登录: {len(accounts)} 个账号")
    success = 0
    for i, (email, password) in enumerate(accounts):
        safe_name = email.split("@")[0].replace("/", "_").replace("\\", "_")
        out_path = out_dir / f"{safe_name}.json"
        print(f"\n{'='*60}")
        print(f"[{i+1}/{len(accounts)}] 登录: {email}")
        print(f"{'='*60}")
        if auto_login(email, password, out_path, args.proxy, args.otp_cmd, args.headless, args.timeout):
            success += 1
        else:
            logger.warning(f"登录失败: {email}")

    print(f"\n{'='*60}")
    print(f"批量登录完成: {success}/{len(accounts)} 成功")
    print(f"{'='*60}")
    return 0 if success > 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 用户取消。")
        sys.exit(130)
