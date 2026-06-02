import logging
import time
from datetime import datetime, timedelta
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class Blocklist:
    def __init__(self, db=None):
        self._db = db
        self._blocked: Set[str] = set()
        self._ttl: Dict[str, datetime] = {}
        self._reasons: Dict[str, str] = {}
        self._lock = Lock()

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            if ip in self._blocked:
                if ip in self._ttl and datetime.now() > self._ttl[ip]:
                    self._blocked.remove(ip)
                    del self._ttl[ip]
                    self._reasons.pop(ip, None)
                    return False
                return True
            return False

    def block(self, ip: str, reason: str = "", ttl_seconds: int = 3600):
        with self._lock:
            self._blocked.add(ip)
            self._ttl[ip] = datetime.now() + timedelta(seconds=ttl_seconds)
            self._reasons[ip] = reason
            logger.info(f"[Blocklist] Blocked {ip}: {reason} ({ttl_seconds}s)")
            if self._db:
                try:
                    self._db.add_block(ip, reason, ttl_seconds)
                except Exception as e:
                    logger.error(f"Failed to persist block: {e}")

    def unblock(self, ip: str):
        with self._lock:
            self._blocked.discard(ip)
            self._ttl.pop(ip, None)
            self._reasons.pop(ip, None)
            logger.info(f"[Blocklist] Unblocked {ip}")

    def get_all(self) -> List[Dict]:
        with self._lock:
            now = datetime.now()
            result = []
            for ip in list(self._blocked):
                ttl = self._ttl.get(ip)
                if ttl and now > ttl:
                    self._blocked.remove(ip)
                    del self._ttl[ip]
                    self._reasons.pop(ip, None)
                    continue
                result.append({
                    "ip": ip,
                    "reason": self._reasons.get(ip, ""),
                    "expires_at": ttl.isoformat() if ttl else None,
                    "remaining_seconds": int((ttl - now).total_seconds()) if ttl else 0,
                })
            return result

    def sync_from_db(self):
        if not self._db:
            return
        with self._lock:
            try:
                conn = self._db._get_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT ip_address, reason, block_until FROM blocks WHERE block_until > ? AND applied = 1",
                    (datetime.now().isoformat(),)
                )
                for row in cursor.fetchall():
                    ip = row["ip_address"]
                    self._blocked.add(ip)
                    self._reasons[ip] = row["reason"]
                    block_until = datetime.fromisoformat(row["block_until"])
                    self._ttl[ip] = block_until
                logger.info(f"[Blocklist] Synced {len(self._blocked)} blocks from DB")
            except Exception as e:
                logger.error(f"Failed to sync from DB: {e}")

    def cleanup_expired(self):
        with self._lock:
            now = datetime.now()
            expired = [ip for ip in self._blocked if ip in self._ttl and now > self._ttl[ip]]
            for ip in expired:
                self._blocked.remove(ip)
                del self._ttl[ip]
                self._reasons.pop(ip, None)
                logger.info(f"[Blocklist] Expired: {ip}")
