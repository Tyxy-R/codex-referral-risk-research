#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex Referral Invitation Helper (协议邀请工具脚本)
=================================================
模拟 Codex Desktop App 进行工作区推荐邀请 (Workspace Referrals)。
该脚本实现：
1. 从凭证文件读取/刷新授权 token
2. 预先检查当前母号/工作区的剩余邀请额度 (Eligibility Rules)
3. 发送批量邀请请求，支持随机生成或指定邮箱列表
4. 绕过 Cloudflare 安全验证并支持 HTTP 住宅代理

依赖：
  pip install requests
  pip install cloudscraper (可选，推荐用以绕过 Cloudflare 五秒盾)

使用示例：
  # 从默认 ~/.codex/auth.json 读取母号，向 5 个生成的随机邮箱发送邀请并走代理
  python codex_invitation_helper.py --generate 5 --domain example.com --proxy http://127.0.0.1:7890

  # 指定特定的邮箱进行邀请
  python codex_invitation_helper.py --emails test1@example.com,test2@example.com --auth-file .\codex_login_auth.json
"""

import os
import sys
import json
import secrets
import string
import argparse
import base64
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

sys.stdout.reconfigure(encoding="utf-8")

try:
    import requests
except ImportError:
    print("[!] 缺少 requests 依赖，请运行: pip install requests")
    sys.exit(1)

# ── 协议常量 ──────────────────────────────────────────────────────────
INVITE_URL = "https://chatgpt.com/backend-api/wham/referrals/invite"
ELIGIBILITY_URL = "https://chatgpt.com/backend-api/wham/referrals/eligibility_rules"
REFERRAL_KEY = "codex_referral_workspace_out_of_credits"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
TOKEN_ENDPOINT = "https://auth.openai.com/oauth/token"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
EMAIL_ALPHABET = string.ascii_lowercase + string.digits

def log(msg: str, symbol: str = "*") -> None:
    import time
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{symbol}] {msg}", flush=True)

def random_email(domain: str, prefix_len: int = 20) -> str:
    prefix = "".join(secrets.choice(EMAIL_ALPHABET) for _ in range(prefix_len))
    return f"{prefix}@{domain.lstrip('@')}"

def jwt_decode(token: str) -> Dict[str, Any]:
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
        account_id = auth_info.get("chatgpt_account_id") or auth_info.get("account_id") or jwt.get("account_id")
        if account_id:
            return str(account_id)
    return ""

def refresh_access_token(refresh_tok: str, proxy: Optional[str] = None) -> Optional[Dict[str, Any]]:
    sess = requests.Session()
    sess.trust_env = False
    if proxy:
        sess.proxies.update({"http": proxy, "https": proxy})
    try:
        resp = sess.post(
            TOKEN_ENDPOINT,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refresh_tok,
            },
            timeout=30,
            verify=False,
        )
        if resp.status_code == 200:
            return resp.json()
        log(f"刷新 Token 失败: HTTP {resp.status_code} {resp.text[:200]}", "!")
    except Exception as e:
        log(f"刷新 Token 发生网络错误: {e}", "!")
    return None

def load_auth_tokens(auth_path: Path, proxy: Optional[str] = None, save_back: bool = False) -> Tuple[str, str]:
    if not auth_path.exists():
        print(f"[!] 授权文件不存在: {auth_path}")
        sys.exit(1)
        
    try:
        data = json.loads(auth_path.read_text(encoding="utf-8"))
        tokens = data.get("tokens", {})
        access_token = tokens.get("access_token", "")
        id_token = tokens.get("id_token", "")
        refresh_tok = tokens.get("refresh_token", "")

        if refresh_tok:
            refreshed = refresh_access_token(refresh_tok, proxy)
            if refreshed and refreshed.get("access_token"):
                access_token = refreshed["access_token"]
                tokens["access_token"] = access_token
                if refreshed.get("refresh_token"):
                    tokens["refresh_token"] = refreshed["refresh_token"]
                if refreshed.get("id_token"):
                    tokens["id_token"] = refreshed["id_token"]
                    id_token = refreshed["id_token"]

        account_id = tokens.get("account_id", "") or extract_account_id(access_token, id_token)
        if account_id:
            tokens["account_id"] = account_id
        
        if not access_token or not account_id:
            print(f"[!] 授权文件 {auth_path} 中缺少 tokens.access_token 或 tokens.account_id")
            sys.exit(1)
        if save_back:
            auth_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return access_token, account_id
    except Exception as e:
        print(f"[!] 解析授权文件失败: {e}")
        sys.exit(1)

def build_session(proxy_url: Optional[str] = None) -> Tuple[str, requests.Session]:
    """构建 Session，优先标准 requests，cloudscraper 仅作可选 fallback"""
    session = requests.Session()
    session.trust_env = False
    if proxy_url:
        session.proxies.update({"http": proxy_url, "https": proxy_url})
    log("初始化标准 requests.Session 成功")
    return "requests", session

def get_headers(access_token: str, account_id: str, is_json: bool = False) -> Dict[str, str]:
    headers = {
        "Host": "chatgpt.com",
        "Authorization": f"Bearer {access_token}",
        "chatgpt-account-id": account_id,
        "originator": "Codex Desktop",
        "oai-language": "zh-CN",
        "User-Agent": UA,
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "no-cors",
        "Sec-Fetch-Dest": "empty"
    }
    if is_json:
        headers["Content-Type"] = "application/json"
    return headers

def check_eligibility(session: requests.Session, access_token: str, account_id: str) -> Optional[int]:
    """查询当前账户邀请剩余额度"""
    try:
        resp = session.get(
            ELIGIBILITY_URL,
            headers=get_headers(access_token, account_id),
            params={"referral_key": REFERRAL_KEY},
            timeout=20,
            verify=False
        )
        if resp.status_code == 200:
            data = resp.json()
            rules = data.get("time_frame_rules", [])
            remaining_invites = []
            for r in rules:
                sent = r.get("invites_sent")
                total = r.get("invites_total")
                if sent is not None and total is not None:
                    remaining_invites.append(max(0, int(total) - int(sent)))
            if remaining_invites:
                return min(remaining_invites)
        else:
            log(f"预检额度失败: HTTP {resp.status_code} {resp.text[:150]}", "!")
    except Exception as e:
        log(f"请求 eligibility_rules 失败: {e}", "!")
    return None

def main() -> int:
    parser = argparse.ArgumentParser(description="Codex 邀请协议辅助脚本")
    
    # 授权
    parser.add_argument(
        "--auth-file",
        default=os.path.expanduser("~/.codex/auth.json"),
        help="母号凭证 JSON 文件的路径 [默认: ~/.codex/auth.json]"
    )
    
    # 邮箱设置
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--emails", help="以英文逗号分隔的特定受邀邮箱列表")
    group.add_argument("--generate", type=int, help="自动随机生成指定数量的受邀邮箱")
    
    parser.add_argument("--domain", default="example.com", help="当随机生成邮箱时的域名 [默认: example.com]")
    parser.add_argument("--prefix-len", type=int, default=20, help="随机邮箱前缀长度 [默认: 20]")
    
    # 代理与输出
    parser.add_argument("--proxy", help="HTTP 住宅或本地代理 URL")
    parser.add_argument("--out", help="成功发送后，将已发送的邮箱列表保存至该 JSON 文件路径")
    parser.add_argument("--dry-run", action="store_true", help="只做预检，输出准备邀请的邮箱，不发送实际邀请")
    parser.add_argument("--save-back", action="store_true", help="刷新 token 或补齐 account_id 后写回原文件")
    
    args = parser.parse_args()
    
    # 禁用 SSL 校验警告（配合代理）
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass

    # 1. 解析/生成邮箱
    if args.emails:
        emails = [e.strip() for e in args.emails.split(",") if e.strip()]
    else:
        emails = [random_email(args.domain, args.prefix_len) for _ in range(args.generate)]
        
    if not emails:
        print("[!] 待邀请邮箱列表为空。")
        return 1

    # 2. 读取凭据
    auth_file_path = Path(args.auth_file)
    access_token, account_id = load_auth_tokens(auth_file_path, args.proxy, args.save_back)
    
    print("=" * 60)
    print("母号信息:")
    print(f"  凭证源   : {auth_file_path}")
    print(f"  Account ID: {account_id}")
    print("待处理邮箱:")
    for idx, em in enumerate(emails, 1):
        print(f"  [{idx}] {em}")
    print("=" * 60)

    # 3. 初始化请求会话
    session_type, session = build_session(args.proxy)

    # 4. 查询额度预检
    log("查询当前母号可邀请额度中...")
    remaining = check_eligibility(session, access_token, account_id)
    if remaining is not None:
        log(f"母号当前剩余可用邀请额度: {remaining} 个", "✓")
        if remaining <= 0:
            log("当前无剩余可用邀请额度，邀请流程中止！", "!")
            return 1
        if len(emails) > remaining:
            log(f"请求邀请数量 ({len(emails)}) 大于剩余可用额度 ({remaining})，已自动裁剪为前 {remaining} 个", "!")
            emails = emails[:remaining]
    else:
        log("未能查询到准确的剩余邀请额度，将直接尝试发送...", "!")

    if args.dry_run:
        log("由于设置了 --dry-run 参数，本次将不会发起实际的邀请请求。")
        return 0

    # 5. 发起邀请
    log(f"开始向 OpenAI 发送推荐邀请 (共 {len(emails)} 个邮箱)...")
    try:
        resp = session.post(
            INVITE_URL,
            headers=get_headers(access_token, account_id, is_json=True),
            json={
                "referral_key": REFERRAL_KEY,
                "emails": emails
            },
            timeout=30,
            verify=False
        )
        status = resp.status_code
        if status == 200:
            try:
                res_data = resp.json()
            except Exception as e:
                log(f"邀请接口返回 HTTP 200，但响应不是 JSON: {e}", "!")
                return 1

            invites_info = res_data.get("invites", [])
            if not isinstance(invites_info, list):
                log(f"邀请接口返回 HTTP 200，但响应缺少 invites 列表: {str(res_data)[:300]}", "!")
                return 1
            if not invites_info:
                log(f"邀请接口返回 HTTP 200，但 invites 为空，请求邮箱数: {len(emails)}", "!")
                return 1
            if len(invites_info) != len(emails):
                log(f"邀请部分成功: {len(invites_info)}/{len(emails)} 条邀请", "!")
            else:
                log("全部邮箱邀请发送成功！✓", "✓")
            log(f"服务端返回的邀请记录数: {len(invites_info)}")
                
            # 保存输出
            if args.out:
                out_path = Path(args.out)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps({
                    "emails": emails,
                    "response": res_data,
                    "invites": invites_info
                }, indent=2, ensure_ascii=False), encoding="utf-8")
                log(f"结果已写入文件: {out_path}")
            return 0
        else:
            log(f"邀请发送失败: HTTP {status} {resp.text[:300]}", "!")
            return 1
    except Exception as e:
        log(f"邀请发送发生网络错误异常: {e}", "!")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 用户取消。")
        sys.exit(130)
