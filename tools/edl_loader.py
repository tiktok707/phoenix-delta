#!/usr/bin/env python3
"""
PHOENIX_DELTA — EDL (Emergency Download) Loader
Triggers Qualcomm devices into EDL (9008) mode for direct flash access.
"""

import sys
import struct
import os
import subprocess
from typing import Optional


def trigger_edl_via_usb() -> bool:
    """
    Trigger EDL mode via USB usingQualcomm Sahara/Firehose protocol.
    Works with devices connected via USB.
    """
    try:
        import usb.core
        import usb.util

        # Qualcomm vendor ID
        QUALCOMM_VID = 0x05C6
        EDL_PID = 0x9008

        dev = usb.core.find(idVendor=QUALCOMM_VID, idProduct=EDL_PID)
        if dev is not None:
            print("[+] Device already in EDL mode")
            return True

        # Try to find any Qualcomm device
        dev = usb.core.find(idVendor=QUALCOMM_VID)
        if dev is None:
            print("[-] No Qualcomm device found")
            return False

        # Send switch-to-EDL request
        try:
            dev.ctrl_transfer(0x40, 0xB0, 0, 0, b"\x00" * 8)
            print("[+] Sent EDL switch command via USB control transfer")
            return True
        except usb.core.USBError:
            pass

    except ImportError:
        pass

    return False


def trigger_edl_via_adb(device_ip: str = None) -> bool:
    """
    Trigger EDL mode via ADB reboot command.
    """
    adb_cmd = "adb"
    if device_ip:
        adb_cmd = f"adb -s {device_ip}:5555"

    try:
        result = subprocess.run(
            f"{adb_cmd} reboot edl".split(),
            capture_output=True, timeout=10
        )
        if result.returncode == 0:
            print("[+] Sent 'reboot edl' command via ADB")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return False


def trigger_edl_via_fastboot(serial: str = None) -> bool:
    """
    Trigger EDL mode via fastboot oem edl command.
    """
    cmd = "fastboot"
    if serial:
        cmd += f" --serial {serial}"

    try:
        result = subprocess.run(
            f"{cmd} oem edl".split(),
            capture_output=True, timeout=10
        )
        if result.returncode == 0:
            print("[+] Sent 'oem edl' command via fastboot")
            return True

        # Try alternative command
        result = subprocess.run(
            f"{cmd} reboot emergency".split(),
            capture_output=True, timeout=10
        )
        if result.returncode == 0:
            print("[+] Sent 'reboot emergency' command via fastboot")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return False


def write_firehose_config(partition: str, payload_path: str) -> bool:
    """
    Write a payload to a partition using Firehose protocol.
    Used when device is already in EDL mode.
    """
    config_xml = f"""<?xml version="1.0" ?>
<data>
    <program SECTOR_SIZE_IN_BYTES="512"
             file_sector_offset="0"
             filename="{payload_path}"
             label="{partition}"
             num_partition_sectors="65536"
             physical_partition_number="0"
             start_sector="0" />
</data>"""

    config_path = f"/tmp/firehose_{partition}.xml"
    with open(config_path, "w") as f:
        f.write(config_xml)

    try:
        result = subprocess.run(
            ["qfuse", "--firehose", config_path],
            capture_output=True, timeout=60
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <device_mac_or_ip_or_serial>")
        print(f"       {sys.argv[0]} --write <partition> <payload>")
        sys.exit(1)

    if sys.argv[1] == "--write" and len(sys.argv) >= 4:
        partition = sys.argv[2]
        payload = sys.argv[3]
        success = write_firehose_config(partition, payload)
        sys.exit(0 if success else 1)

    target = sys.argv[1]
    print(f"[*] Triggering EDL mode on: {target}")

    # Try USB first
    if trigger_edl_via_usb():
        print("[+] EDL mode triggered via USB")
        sys.exit(0)

    # Try ADB
    if trigger_edl_via_adb(target):
        print("[+] EDL mode triggered via ADB")
        sys.exit(0)

    # Try fastboot
    if trigger_edl_via_fastboot(target):
        print("[+] EDL mode triggered via fastboot")
        sys.exit(0)

    print("[-] Could not trigger EDL mode")
    sys.exit(1)


if __name__ == "__main__":
    main()
