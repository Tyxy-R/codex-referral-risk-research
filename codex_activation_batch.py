#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex 批量并行激活调度器
========================
扫描一个目录下所有子号 auth.json，并发执行 protocol 激活。

用法：
  python codex_activation_batch.py --auth-dir ./accounts

  # 配合代理
  python codex_activation_batch.py --auth-dir ./accounts --proxy http://127.0.0.1:7890

  # 激活后写回刷新的 token
  python codex_activation_batch.py --auth-dir ./accounts --save-back
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout.reconfigure(encoding="utf-8")

from codex_activation_helper import run_protocol_activation, jwt_decode


def log(msg: str, symbol: str = "*") -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{symbol}] {msg}", flush=True)


def is_auth_json_file(path: Path) -> bool:
    """只接收包含 access_token 或 refresh_token 的账号凭证文件。"""
    if "metadata" in path.name or "system_bak" in path.name:
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    tokens = data.get("tokens", {})
    return isinstance(tokens, dict) and bool(tokens.get("access_token") or tokens.get("refresh_token"))


def extract_email(auth_data: dict) -> str:
    tokens = auth_data.get("tokens", {})
    jwt_p = jwt_decode(tokens.get("access_token", ""))
    profile = jwt_p.get("https://api.openai.com/profile", {})
    return profile.get("email") or jwt_p.get("email") or "unknown"


def process_account(auth_path: Path, proxy: str = None, save_back: bool = False) -> dict:
    result = {
        "auth_file": str(auth_path),
        "success": False,
        "email": "unknown",
        "saved_back": False,
        "error": None,
    }
    try:
        content = auth_path.read_text(encoding="utf-8")
        auth_data = json.loads(content)
    except Exception as e:
        result["error"] = f"JSON 解析失败: {e}"
        return result

    if "tokens" not in auth_data:
        result["error"] = "缺少 tokens 节点"
        return result

    old_tokens_blob = json.dumps(auth_data.get("tokens", {}), sort_keys=True, ensure_ascii=False)
    result["email"] = extract_email(auth_data)

    ok = run_protocol_activation(auth_data, proxy)
    result["success"] = ok
    result["email"] = extract_email(auth_data)

    if save_back:
        new_tokens_blob = json.dumps(auth_data.get("tokens", {}), sort_keys=True, ensure_ascii=False)
        if old_tokens_blob != new_tokens_blob:
            try:
                auth_path.write_text(json.dumps(auth_data, indent=2, ensure_ascii=False), encoding="utf-8")
                result["saved_back"] = True
            except Exception as e:
                result["error"] = f"写回失败: {e}"
                result["success"] = False

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Codex 批量并行激活调度器")
    parser.add_argument("--auth-dir", required=True, help="子号凭证目录")
    parser.add_argument("--proxy", help="HTTP 代理 URL")
    parser.add_argument("--save-back", action="store_true", help="刷新 token 后写回原文件")
    args = parser.parse_args()

    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass

    auth_dir = Path(args.auth_dir)
    if not auth_dir.is_dir():
        print(f"[!] 目录不存在: {auth_dir}")
        return 1

    all_json_files = sorted(auth_dir.glob("*.json"))
    auth_files = [fp for fp in all_json_files if is_auth_json_file(fp)]
    if not auth_files:
        print(f"[!] 目录下无有效账号 JSON 文件: {auth_dir}")
        return 1

    skipped = len(all_json_files) - len(auth_files)
    if skipped:
        log(f"已跳过 {skipped} 个非账号 JSON 文件")
    max_workers = len(auth_files)
    log(f"扫描到 {len(auth_files)} 个子号，并发数 {max_workers}")

    results = []
    success_count = 0

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(process_account, fp, args.proxy, args.save_back): fp
            for fp in auth_files
        }
        for future in as_completed(futures):
            fp = futures[future]
            try:
                r = future.result()
            except Exception as e:
                r = {"auth_file": str(fp), "success": False, "email": fp.stem, "error": str(e)}

            results.append(r)
            if r["success"]:
                success_count += 1
                suffix = " (已写回)" if r.get("saved_back") else ""
                log(f"✓ {r['email']}{suffix}", "✓")
            else:
                log(f"✗ {r['email']}: {r.get('error', '部分接口失败')}", "!")

    print("\n" + "=" * 60)
    print(f"激活汇总: {success_count}/{len(auth_files)} 成功")
    print("=" * 60)
    return 0 if success_count > 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 用户取消。")
        sys.exit(130)
