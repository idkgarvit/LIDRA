import ipaddress
import logging
import time
import threading
import struct
import socket
import subprocess
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Callable
from detection.log_parser import LogParser

logger = logging.getLogger(__name__)

try:
    import dpkt
    HAS_DPKT = True
except ImportError:
    HAS_DPKT = False
    logger.warning("dpkt not available, using minimal packet parser")

# nfnetlink_queue constants (from <linux/netfilter/nfnetlink_queue.h>)
NFNL_SUBSYS_QUEUE = 3
NETLINK_NETFILTER = 12
NFQNL_MSG_PACKET = 0
NFQNL_MSG_VERDICT = 1
NFQNL_MSG_CONFIG = 2
NFQNL_CFG_CMD_NONE = 0
NFQNL_CFG_CMD_BIND = 1
NFQNL_CFG_CMD_UNBIND = 2
NFQNL_CFG_CMD_PF_BIND = 3
NFQNL_CFG_CMD_PF_UNBIND = 4
NFQNL_COPY_NONE = 0
NFQNL_COPY_META = 1
NFQNL_COPY_PACKET = 2
NFQA_CFG_CMD = 1
NFQA_CFG_PARAMS = 2
NFQA_CFG_QUEUE_MAXLEN = 4
NFQA_PACKET_HDR = 1
NFQA_PAYLOAD = 10
NFQA_VERDICT_HDR = 2
NF_ACCEPT = 1
NF_DROP = 0

NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 1
NLM_F_ACK = 4

from utils.interface import local_ips
from response.verdict import Verdict, decide_verdict
from response.blocklist import Blocklist
from response.rate_limiter import RateLimiter
from detection.packet_analyzer import PacketAnalyzer
from bridge.connection_tracker import ConnectionTracker
from bridge.forensics import ForensicRecorder
from bridge.stream_reassembler import StreamReassembler
from detection.dpi_engine import DPIEngine
from bridge.safe_link import SafeLink, always_bypass


class InlineEngine:
    def __init__(self, config: dict, db=None, detector=None,
                 response_handler=None, metrics_collector=None):
        self._config = config
        self._db = db
        self._detector = detector
        self._response_handler = response_handler
        self._metrics_collector = metrics_collector

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._queue_num = config.get("local", {}).get("nfqueue_num") or config.get("bridge", {}).get("nfqueue_num") or 0
        local_cfg = config.get("local", {}) or {}
        self._local_inline = bool(local_cfg.get("inline", False))
        # ponytail: monitor_only defaults True — installing a queue rule must
        # never silently start dropping; enforce needs explicit opt-in.
        self._monitor_only = bool(local_cfg.get("monitor_only", True))
        self._queue_maxlen = int((config.get("bridge", {}) or {}).get("nfqueue_maxlen")
                                 or local_cfg.get("nfqueue_maxlen") or 1024)
        self._nfqueue_family = "inet"  # recorded by _setup_nfqueue_nft; teardown removes the same family
        self._nfqueue_table = None
        self._nfqueue_iface = None
        # Armed after the netlink consumer BINDs; watches that the queue rule
        # both survives and still has a consumer. See bridge/safe_link.py.
        self._safe_link: Optional[SafeLink] = None
        self._ct_time = 0.0
        self._ct_solicited = set()  # conntrack-backed solicited keys, 1s refresh
        self._own_time = 0.0  # own-IP refresh (v6 privacy extensions rotate)

        inline_cfg = config.get("inline", {})
        rate_cfg = inline_cfg.get("rate_limiting", {})

        self._blocklist = Blocklist(db)
        self._rate_limiter = RateLimiter(rate_cfg)
        self._packet_analyzer = PacketAnalyzer(inline_cfg, self._rate_limiter, self._blocklist)
        self._connection_tracker = ConnectionTracker(config)
        self._stream_reassembler = StreamReassembler(
            inline_cfg.get("dpi", {}).get("max_reassembly_buffers", 10000)
        )
        self._dpi_engine = DPIEngine(
            rules_loader=None,
            log_parser=LogParser
        )

        from detection.analyzer.dos_detector import DoSDetector
        from detection.analyzer.fragment_analyzer import FragmentAnalyzer
        from detection.analyzer.port_analyzer import PortAnalyzer
        from detection.analyzer.tunnel_detector import TunnelDetector
        from detection.analyzer.covert_detector import CovertDetector
        from detection.analyzer.ipv6_analyzer import IPv6Analyzer
        from detection.analyzer.l2_analyzer import L2Analyzer
        from detection.analyzer.timing_analyzer import TimingAnalyzer
        from detection.analyzer.proxy_detector import ProxyDetector
        self._dos_detector = DoSDetector(inline_cfg.get("dos", {}))
        self._fragment_analyzer = FragmentAnalyzer()
        self._port_analyzer = PortAnalyzer()
        self._tunnel_detector = TunnelDetector()
        self._covert_detector = CovertDetector(self._config)
        self._ipv6_analyzer = IPv6Analyzer()
        self._l2_analyzer = L2Analyzer()
        self._timing_analyzer = TimingAnalyzer()
        self._proxy_detector = ProxyDetector()

        # ponytail: our own egress is not an attack — without this the
        # sensor flags its own DNS/HTTPS (e.g. 8.8.8.8: 1000+ bogus rows).
        self._own_ips = local_ips()
        # ponytail: flows WE solicited (DNS query out, HTTPS out) — replies
        # on them skip content inspection (DPI/session), else every CDN page
        # scores its server as an attacker. Rate/shape detectors still run.
        self._solicited: Dict[str, float] = {}
        self._packet_count = 0
        self._pass_count = 0
        self._drop_count = 0
        self._rate_limit_count = 0
        self._total_latency = 0.0
        # ponytail: per-hit log cooldown — the MONITOR/DETECTED pair at
        # 400+/sec (disk) stalled the verdict loop and held queued packets
        # hostage. Cooldown gates the repeat log line only; counters, DB,
        # and verdicts still record every hit.
        self._hit_log_at: Dict[str, float] = {}
        self._hit_log_cooldown = 5.0
        self._start_time = 0.0
        self._lock = threading.RLock()

        from detection.analyzer.tcp_fingerprinter import TCPFingerprinter
        from detection.analyzer.behavioral_analyzer import BehavioralAnalyzer
        from detection.analyzer.session_correlator import SessionCorrelator
        from detection.baseline.per_ip_baseline import PerIPBaseline
        from utils.bloom import BloomFilter, FlowCache
        self._tcp_fingerprinter = TCPFingerprinter()
        self._behavioral_analyzer = BehavioralAnalyzer()
        self._session_correlator = SessionCorrelator()
        self._per_ip_baseline = PerIPBaseline(inline_cfg.get("baseline", {}))
        bf_cfg = config.get("inline", {}).get("bloom", {})
        self._bloom_filter = BloomFilter(capacity=bf_cfg.get("capacity", 50000), error_rate=bf_cfg.get("error_rate", 0.001))
        fc_cfg = config.get("inline", {}).get("flow_cache", {})
        self._flow_cache = FlowCache(
            capacity=fc_cfg.get("capacity", 5000),
            clean_threshold=fc_cfg.get("clean_threshold", 15)
        )

        self._recorder = ForensicRecorder(config)
        self._on_detection_callback: Optional[Callable] = None
        self._pipeline_order = ["blocklist", "header_analysis", "stream_reassembly", "dpi", "verdict"]
        self._criteria_packets = 0
        self._high_priority = 0
        self._low_priority = 0

    @property
    def blocklist(self) -> Blocklist:
        return self._blocklist

    @property
    def rate_limiter(self) -> RateLimiter:
        return self._rate_limiter

    @property
    def connection_tracker(self) -> ConnectionTracker:
        return self._connection_tracker

    def register_detection_callback(self, callback: Callable):
        self._on_detection_callback = callback

    def start(self):
        if self._running:
            logger.warning("[InlineEngine] Already running")
            return
        self._running = True
        self._start_time = time.time()
        self._blocklist.sync_from_db()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="inline-engine")
        self._thread.start()
        logger.info(f"[InlineEngine] Started (NFQUEUE {self._queue_num})")

    def stop(self):
        self._running = False
        logger.info("[InlineEngine] Stopped")

    def _run_loop(self):
        mode = self._config.get("mode", "local")
        # Local inline (laptop): NFQUEUE on the INPUT hook drops inbound attacks
        # before the app — opt-in via local.inline (installer asks). Queue rule
        # uses bypass, so a dead engine fails open; AF_PACKET stays fallback.
        if mode != "local" or self._local_inline:
            # Attempt 1: NFQUEUE — true inline verdicts (DROP before delivery).
            # ponytail: retry BIND 3x — restart races (old consumer draining)
            # fail it once; don't degrade to sniff-only on a transient.
            for attempt in range(3):
                try:
                    self._run_nfqueue_capture()
                    return
                except Exception as e:
                    if attempt == 2:
                        logger.warning(f"[InlineEngine] NFQUEUE unavailable ({e}); trying AF_PACKET")
                    else:
                        logger.info(f"[InlineEngine] NFQUEUE bind try {attempt + 1}/3 failed ({e}); retrying")
                        time.sleep(2)

        # Attempt 2: AF_PACKET raw socket — works on ALL Linux distros.
        # No kernel modules, no WiFi breakage. Detection works, blocking
        # uses iptables DROP rules (can't drop the first malicious packet,
        # but blocks subsequent ones from that IP).
        try:
            self._run_raw_capture()
            return
        except Exception as e:
            logger.warning(f"[InlineEngine] AF_PACKET capture failed ({e}); trying tcpdump")

        try:
            self._run_tcpdump_capture()
            return
        except Exception as e:
            logger.warning(f"[InlineEngine] tcpdump capture failed ({e}); running cleanup loop")
            self._run_cleanup_loop()

    def _run_cleanup_loop(self):
        logger.info("[InlineEngine] Cleanup-only fallback loop")
        cleanup_interval = 60
        last_cleanup = time.time()
        while self._running:
            time.sleep(0.5)
            now = time.time()
            if now - last_cleanup > cleanup_interval:
                self._connection_tracker.cleanup_stale()
                self._stream_reassembler.cleanup_stale()
                self._rate_limiter.cleanup_stale()
                self._blocklist.cleanup_expired()
                last_cleanup = now

    def _detect_interface(self) -> str:
        """Detect active interface config-first, then auto-detect."""
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from utils.interface import detect_interface
        preferred = self._config.get("local", {}).get("interface") or self._config.get("collectors", {}).get("network", {}).get("interface") or self._config.get("bridge", {}).get("interfaces", {}).get("wan")
        try:
            return detect_interface(preferred)
        except RuntimeError as e:
            logger.error(f"[InlineEngine] {e}")
            raise

    def _get_interface(self):
        cfg_iface = (
            self._config.get("local", {}).get("interface") or
            self._config.get("bridge", {}).get("interfaces", {}).get("wan") or
            self._detect_interface()
        )
        bridge_iface = self._config.get("bridge", {}).get("interfaces", {}).get("bridge")
        if not bridge_iface:
            brport = Path(f"/sys/class/net/{cfg_iface}/brport/bridge")
            if brport.exists():
                try:
                    bridge_iface = brport.resolve().name
                except Exception as e:
                    logger.warning(f"[InlineEngine] Could not resolve bridge for {cfg_iface}: {e}")
            if not bridge_iface:
                try:
                    import subprocess
                    r = subprocess.run(["bridge", "link", "show", "dev", cfg_iface],
                                       capture_output=True, text=True, timeout=5)
                    if r.returncode == 0 and "master" in r.stdout:
                        parts = r.stdout.split()
                        if "master" in parts:
                            idx = parts.index("master")
                            bridge_iface = parts[idx + 1]
                            logger.debug(f"[InlineEngine] Detected bridge via `bridge link show`: {bridge_iface}")
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    logger.debug("[InlineEngine] `bridge link show` not available")
            if not bridge_iface:
                try:
                    import subprocess
                    r = subprocess.run(["brctl", "show"],
                                       capture_output=True, text=True, timeout=5)
                    if r.returncode == 0:
                        for line in r.stdout.splitlines()[1:]:
                            if cfg_iface in line:
                                bridge_iface = line.split()[0]
                                logger.debug(f"[InlineEngine] Detected bridge via `brctl show`: {bridge_iface}")
                                break
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    logger.debug("[InlineEngine] `brctl show` not available")
        if bridge_iface:
            if Path(f"/sys/class/net/{bridge_iface}").exists():
                logger.info(f"[InlineEngine] Using bridge interface {bridge_iface}")
                return bridge_iface
            logger.debug(f"[InlineEngine] Bridge {bridge_iface} not found, using {cfg_iface}")
        return cfg_iface

    def _run_tcpdump_capture(self):
        interface = self._get_interface()
        logger.info(f"[InlineEngine] Starting tcpdump capture on {interface}")

        try:
            result = subprocess.run(
                ["which", "tcpdump"], capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError("tcpdump not found")
        except Exception as e:
            raise RuntimeError(f"tcpdump not available: {e}") from e

        proc = subprocess.Popen(
            ["tcpdump", "-i", interface, "-nn", "--packet-buffered", "-w", "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )
        logger.info(f"[InlineEngine] tcpdump PID {proc.pid} capturing on {interface}")

        cleanup_interval = 60
        last_cleanup = time.time()
        last_stats = time.time()
        pkt_batch_count = 0

        try:
            if HAS_DPKT:
                for ts, buf in dpkt.pcap.Reader(proc.stdout):
                    if not self._running:
                        break
                    packet = self._parse_packet(buf)
                    if not packet:
                        continue

                    with self._lock:
                        self._packet_count += 1
                        pkt_batch_count += 1

                    detections = self._run_detection_pipeline(packet)
                    verdict = self._decide(packet, detections)
                    self._apply_verdict(0, verdict, packet, detections, time.time())

                    now = time.time()
                    if now - last_cleanup > cleanup_interval:
                        self._connection_tracker.cleanup_stale()
                        self._stream_reassembler.cleanup_stale()
                        self._rate_limiter.cleanup_stale()
                        self._blocklist.cleanup_expired()
                        last_cleanup = now
                    if now - last_stats > 5 and self._on_detection_callback:
                        self._on_detection_callback({
                            "type": "stats",
                            "data": self.get_stats()
                        })
                        pkt_batch_count = 0
                        last_stats = now
            else:
                logger.warning("[InlineEngine] dpkt not available — cannot parse pcap from tcpdump")
                raise RuntimeError("dpkt required for tcpdump capture")
        except Exception as e:
            logger.warning(f"[InlineEngine] tcpdump capture error: {e}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception as e:
                logger.warning(f"[InlineEngine] proc.wait timeout, killing: {e}")
                proc.kill()

    def _run_raw_capture(self):
        interface = self._get_interface()
        logger.info(f"[InlineEngine] Raw capture mode on {interface}")
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            s.bind((interface, 0))
            s.settimeout(1.0)
            logger.info(f"[InlineEngine] Bound raw socket to {interface}")
        except Exception as e:
            logger.warning(f"[InlineEngine] Cannot open raw socket on {interface}: {e}")
            fallback = self._detect_interface()
            if fallback != interface:
                try:
                    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                    s.bind((fallback, 0))
                    s.settimeout(1.0)
                    interface = fallback
                    logger.info(f"[InlineEngine] Bound raw socket to {fallback} (auto-detected)")
                except Exception as e2:
                    logger.warning(f"[InlineEngine] Raw socket failed on {fallback} too: {e2}")
                    self._run_cleanup_loop()
                    return
            else:
                self._run_cleanup_loop()
                return

        cleanup_interval = 60
        last_cleanup = time.time()
        last_stats = time.time()
        pkt_batch_count = 0
        while self._running:
            try:
                data = s.recv(65535)
            except socket.timeout:
                now = time.time()
                if now - last_cleanup > cleanup_interval:
                    self._connection_tracker.cleanup_stale()
                    self._stream_reassembler.cleanup_stale()
                    self._rate_limiter.cleanup_stale()
                    self._blocklist.cleanup_expired()
                    last_cleanup = now
                if now - last_stats > 5:
                    if pkt_batch_count > 0 and self._on_detection_callback:
                        self._on_detection_callback({
                            "type": "stats",
                            "data": self.get_stats()
                        })
                        pkt_batch_count = 0
                        last_stats = now
                continue

            try:
                packet = self._parse_packet(data)
                if not packet:
                    continue

                with self._lock:
                    self._packet_count += 1
                    pkt_batch_count += 1

                detections = self._run_detection_pipeline(packet)
                if not detections or not isinstance(detections, list):
                    detections = []
                verdict = self._decide(packet, detections)
                self._apply_verdict(0, verdict, packet, detections, time.time())
            except Exception as e:
                logger.warning(f"[InlineEngine] Packet processing error: {e}")
                continue

            now = time.time()
            if now - last_cleanup > cleanup_interval:
                self._connection_tracker.cleanup_stale()
                self._stream_reassembler.cleanup_stale()
                self._rate_limiter.cleanup_stale()
                self._blocklist.cleanup_expired()
                last_cleanup = now

            if now - last_stats > 5:
                if self._on_detection_callback:
                    self._on_detection_callback({
                        "type": "stats",
                        "data": self.get_stats()
                    })
                pkt_batch_count = 0
                last_stats = now

    def _packet_handler(self, payload) -> int:
        # ponytail: never let one bad packet kill capture — fail open (ACCEPT)
        try:
            start = time.time()
            packet = self._parse_packet(payload.get_data())
            if not packet:
                return 1

            with self._lock:
                self._packet_count += 1

            detection = self._run_detection_pipeline(packet)
            verdict = self._decide(packet, detection)

            self._apply_verdict(0, verdict, packet, detection, start)
            return 0
        except Exception as e:
            logger.warning(f"[InlineEngine] Packet handler error (ACCEPT): {e}")
            return 1

    @staticmethod
    def _canon_key(packet: Dict) -> str:
        """Directionless flow key — our egress and their reply share it."""
        a = (packet.get("src_ip", ""), packet.get("src_port", 0))
        b = (packet.get("dst_ip", ""), packet.get("dst_port", 0))
        lo, hi = (a, b) if a <= b else (b, a)
        return f"{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}-{packet.get('protocol', '')}"

    def _touch_solicited(self, key: str) -> None:
        now = time.time()
        self._solicited[key] = now
        if len(self._solicited) > 4096:  # ponytail: lazy prune, no timer thread
            cutoff = now - 300
            stale = [k for k, t in self._solicited.items() if t < cutoff]
            for k in stale:
                del self._solicited[k]
            if len(self._solicited) > 4096:
                for k in list(self._solicited)[:1024]:
                    del self._solicited[k]

    def _is_solicited(self, key: str) -> bool:
        ts = self._solicited.get(key, 0)
        if ts and time.time() - ts < 300:
            self._solicited[key] = time.time()  # active flows never expire
            return True
        return False

    def _conntrack_solicited(self, packet: Dict) -> bool:
        """True when the kernel holds a locally-initiated, bidirectional
        conntrack entry for this flow — i.e. we asked for this traffic.
        Detections still fire (alerts kept); only content-DPI verdicts skip."""
        try:
            now = time.time()
            if now - self._own_time > 60:
                # ponytail: v6 privacy extensions rotate temp addresses; a
                # startup-only snapshot goes stale and everything looks foreign.
                try:
                    self._own_ips = local_ips()
                except Exception:
                    pass
                self._own_time = now
            if now - self._ct_time > 1.0:
                self._ct_solicited = self._read_conntrack_solicited()
                self._ct_time = now
            proto = str(packet.get("protocol", "")).lower()
            a = (self._norm_ip(packet.get("src_ip", "")), packet.get("src_port", 0) or 0)
            b = (self._norm_ip(packet.get("dst_ip", "")), packet.get("dst_port", 0) or 0)
            if a[1] == 0 and b[1] == 0:
                key = (proto, min(a[0], b[0]), max(a[0], b[0]))
            else:
                lo, hi = (a, b) if a <= b else (b, a)
                key = (proto, lo, hi)
            return key in self._ct_solicited
        except Exception:
            return False

    def _read_conntrack_solicited(self) -> set:
        out = set()
        try:
            with open("/proc/net/nf_conntrack") as f:
                lines = f.read().splitlines()
        except OSError:
            return out  # no conntrack (container?) — suppression off, monitor shows it
        for line in lines:
            parts = line.split()
            if len(parts) < 6:
                continue
            # ponytail: parts[2] is the proto NAME, parts[3] the number —
            # indexing [2] against numbers silently matched nothing, so no
            # local flow was ever recognized as solicited.
            proto = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmp"}.get(parts[3])
            if not proto:
                proto = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmp"}.get(parts[2])
            if not proto:
                continue
            if proto == "tcp" and "[ASSURED]" not in line and "ESTABLISHED" not in line:
                continue  # half-open outbound — nobody answered yet
            # ponytail: UDP/ICMP accept in-flight entries too — the reply
            # packet that SETS assured is judged before the flag exists,
            # so requiring it missed every first reply (DNS, ping).
            fields: Dict[str, str] = {}
            for p in parts[5:]:
                if "=" in p:
                    k, _, v = p.partition("=")
                    fields.setdefault(k, v)  # first occurrence = original direction
            # ponytail: normalize v6 (conntrack zero-pads, parser doesn't —
            # "01e3" != "1e3" as strings for the same address).
            o_src, o_dst = self._norm_ip(fields.get("src", "")), self._norm_ip(fields.get("dst", ""))
            if not o_src or not o_dst or o_src not in self._own_ips:
                continue  # not initiated by us (inbound attack keeps full DPI)
            o_sport = int(fields.get("sport", 0) or 0)
            o_dport = int(fields.get("dport", 0) or 0)
            if o_sport == 0 and o_dport == 0:
                out.add((proto, min(o_src, o_dst), max(o_src, o_dst)))
            else:
                a, b = (o_src, o_sport), (o_dst, o_dport)
                lo, hi = (a, b) if a <= b else (b, a)
                out.add((proto, lo, hi))
                # ponytail: coarser host-pair key too — v6 packets with
                # extension headers parse portless, and only the tuple key
                # would miss them. Rates still run; only content skips.
                out.add((proto, min(o_src, o_dst), max(o_src, o_dst)))
        return out

    @staticmethod
    def _norm_ip(ip: str) -> str:
        try:
            return ipaddress.ip_address(ip).compressed if ":" in str(ip) else str(ip)
        except ValueError:
            return str(ip)

    def _decide(self, packet: Dict, detections: List[Dict]) -> Verdict:
        """Verdict with flood rate-limiting consulted (was wired but inert)."""
        try:
            payload = packet.get("payload") or b""
            throttled, _info = self._rate_limiter.check(
                packet.get("src_ip", ""), byte_count=len(payload))
        except Exception as e:
            logger.debug(f"[InlineEngine] Rate limiter error: {e}")
            return decide_verdict(detections)
        return decide_verdict(detections, rate_info={"is_throttled": throttled})

    def _hit_log_allowed(self, packet: Dict, detections: List[Dict]) -> bool:
        """Per-(src_ip, attack_type) log gate for the verdict hot path."""
        if not detections:
            return False
        key = f"{packet.get('src_ip', '')}|{detections[0].get('attack_type', '')}"
        now = time.time()
        if now - self._hit_log_at.get(key, 0.0) < self._hit_log_cooldown:
            return False
        self._hit_log_at[key] = now
        if len(self._hit_log_at) > 5000:  # ponytail: cardinality cap, never delete
            self._hit_log_at.clear()
        return True

    def _run_detection_pipeline(self, packet: Dict) -> List[Dict]:
        # ponytail: pipeline-wide guard — an unhandled raise here used to kill
        # the NFQUEUE/tcpdump thread while _running stayed true (silent outage)
        detections: List[Dict] = []
        try:
            return self._run_detection_pipeline_inner(packet, detections)
        except Exception as e:
            logger.warning(f"[InlineEngine] Pipeline error (partial={len(detections)}): {e}")
            return detections

    def _run_detection_pipeline_inner(self, packet: Dict, detections: List[Dict]) -> List[Dict]:
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        src_port = packet.get("src_port", 0)
        dst_port = packet.get("dst_port", 0)
        protocol = packet.get("protocol", "")
        flags = packet.get("flags", "")
        has_payload = bool(packet.get("payload"))

        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"

        whitelist = self._config.get("whitelist", [])
        if src_ip in whitelist:
            self._flow_cache.track_packet(flow_key, has_payload)
            return detections

        # ponytail: 127/8 NOT skipped — localhost attacks (malicious local
        # process, pentester curling localhost, container-to-container) are
        # real signal; replay fixtures are 127.0.0.1-sourced.
        if src_ip in self._own_ips:
            self._touch_solicited(self._canon_key(packet))
            return detections

        solicited = self._is_solicited(self._canon_key(packet))
        if not solicited and self._local_inline and not self._is_bridge_mode():
            # ponytail: INPUT-only queue never sees our egress, so the
            # in-memory set stays empty — ask the kernel's conntrack instead.
            solicited = self._conntrack_solicited(packet)

        if self._bloom_filter.contains(src_ip):
            detections.append({
                "attack_type": "blocked_ip_traffic",
                "severity": "high",
                "source_ip": src_ip,
                "details": "IP on bloom blocklist",
            })

        if self._blocklist.is_blocked(src_ip):
            detections.append({
                "attack_type": "blocked_ip_traffic",
                "severity": "high",
                "source_ip": src_ip,
                "details": "IP on blocklist",
            })

        if "S" in flags and "A" not in flags:
            self._criteria_packets += 1

        if has_payload and self._flow_cache.is_benign(flow_key):
            self._low_priority += 1
            return detections

        header_result = self._packet_analyzer.analyze_header(packet)
        if header_result:
            detections.append(header_result)

        run_dpi = False
        if protocol == "tcp":
            conn = self._connection_tracker.track(packet)
            if has_payload:
                direction = "client" if src_port > 1024 else "server"
                messages = self._stream_reassembler.add_segment(packet, direction)
                if messages and conn and not solicited:
                    app_proto = conn.app_protocol if conn else ""
                    run_dpi = True
                    for msg in messages:
                        dpi_result = self._dpi_engine.inspect_stream(msg, app_proto)
                        if dpi_result:
                            detections.append({
                                "attack_type": dpi_result.attack_type,
                                "severity": dpi_result.severity,
                                "source_ip": src_ip,
                                "details": dpi_result.details,
                                "confidence": dpi_result.confidence,
                                "mitre": dpi_result.mitre,
                            })
                elif conn and conn.app_protocol == "tls" and not solicited:
                    payload = packet.get("payload", b"")
                    if payload:
                        dpi_result = self._dpi_engine.inspect_stream(payload, "tls")
                        if dpi_result:
                            detections.append({
                                "attack_type": dpi_result.attack_type,
                                "severity": dpi_result.severity,
                                "source_ip": src_ip,
                                "details": dpi_result.details,
                                "confidence": dpi_result.confidence,
                                "mitre": dpi_result.mitre,
                            })
        else:
            payload = packet.get("payload", b"")
            if payload and not solicited:
                run_dpi = True
                dpi_result = self._dpi_engine.inspect_packet(payload, protocol)
                if dpi_result:
                    detections.append({
                        "attack_type": dpi_result.attack_type,
                        "severity": dpi_result.severity,
                        "source_ip": src_ip,
                        "details": dpi_result.details,
                        "confidence": dpi_result.confidence,
                        "mitre": dpi_result.mitre,
                    })

        analyzers = (self._dos_detector, self._fragment_analyzer,
                       self._port_analyzer, self._tunnel_detector,
                       self._covert_detector, self._ipv6_analyzer,
                       self._l2_analyzer, self._timing_analyzer,
                       self._proxy_detector,
                       self._tcp_fingerprinter,
                       self._behavioral_analyzer,
                       self._session_correlator,
                       self._per_ip_baseline)
        # ponytail: replies we asked for — rates yes, content no. Session
        # correlator + IPv6-tunnel heuristics both judge content and both
        # FP'd on solicited DNS/TLS replies (8.8.8.8, Telegram).
        if solicited:
            analyzers = tuple(a for a in analyzers
                              if a not in (self._session_correlator,
                                           self._ipv6_analyzer))
        for analyzer in analyzers:
            try:
                result = analyzer.analyze(packet)
                if result:
                    detections.extend(result)
            except Exception as e:
                logger.warning(f"[{type(analyzer).__name__}] analyzer error: {e}")

        if detections:
            self._flow_cache.mark_suspicious(flow_key)
        elif run_dpi and has_payload:
            self._flow_cache.track_packet(flow_key, has_payload)
            self._high_priority += 1

        return detections

    def _apply_verdict(self, packet_id: int, verdict: Verdict, packet: Dict,
                       detections: List[Dict], start_time: float):
        latency = (time.time() - start_time) * 1000
        with self._lock:
            self._total_latency += latency
            if verdict == Verdict.PASS:
                self._pass_count += 1
            elif verdict == Verdict.DROP:
                self._drop_count += 1
            elif verdict == Verdict.RATE_LIMIT:
                self._rate_limit_count += 1

        if detections and self._on_detection_callback:
            for d in detections:
                try:
                    pcap = self._recorder.maybe_dump(d)
                    if pcap:
                        d["forensics_pcap"] = pcap
                    self._on_detection_callback({
                        "type": "attack",
                        "data": {
                            "detection": d,
                            "verdict": verdict.value,
                            "packet": {
                                "src_ip": packet.get("src_ip", ""),
                                "dst_ip": packet.get("dst_ip", ""),
                                "src_port": packet.get("src_port", 0),
                                "dst_port": packet.get("dst_port", 0),
                                "protocol": packet.get("protocol", ""),
                            },
                            "latency_ms": round(latency, 2),
                        }
                    })
                except Exception as e:
                    logger.warning(f"[InlineEngine] Detection callback error: {e}")

    def _parse_packet(self, raw_data: bytes) -> Optional[Dict]:
        if not raw_data or len(raw_data) < 14:
            return None

        # ponytail: forensics window fills here — the one choke point every
        # capture source flows through. Framing mirrors the eth check below.
        is_eth = raw_data[12:14] in (b"\x08\x00", b"\x86\xdd") and self._inner_ip_ok(raw_data)
        self._recorder.note_packet(time.time(), raw_data, is_eth)

        if HAS_DPKT:
            try:
                # ponytail: ethertype-first. The old first-nibble sniff misparsed
                # any Ethernet frame whose dst MAC starts 0x4_/0x6_ as raw IP —
                # in bridge mode that blinded us to every frame forwarded to such
                # a host (parsed as IPv6 garbage, payload invisible, no detects).
                eth_type = struct.unpack("!H", raw_data[12:14])[0]
                if eth_type in (0x0800, 0x86DD) and self._inner_ip_ok(raw_data):
                    first_nibble = None
                else:
                    first_nibble = raw_data[0] >> 4
                if first_nibble == 4:
                    return self._parse_dpkt_ip(raw_data, dpkt.ip.IP)
                elif first_nibble == 6:
                    return self._parse_dpkt_ip6(raw_data, dpkt.ip6.IP6)
                eth = dpkt.ethernet.Ethernet(raw_data)

                if isinstance(eth.data, dpkt.ip.IP):
                    return self._parse_dpkt_ip_from_eth(eth)
                elif isinstance(eth.data, dpkt.ip6.IP6):
                    # ponytail: same v6 parse as the raw-L3 path — a separate
                    # inline version here once left all framed v6 portless.
                    return self._parse_dpkt_ip6(bytes(eth.data), dpkt.ip6.IP6)

            except Exception as e:
                logger.warning(f"[InlineEngine] dpkt parse error: {e}")
                return None
        else:
            return self._minimal_parse(raw_data)

        return None

    @staticmethod
    def _inner_ip_ok(raw_data: bytes) -> bool:
        """Sanity-check bytes[14:] look like an IP header before treating
        raw_data as an Ethernet frame — a raw L3 packet from 8.0.x.x would
        otherwise collide on ethertype 0x0800. Total-len check allows
        Ethernet min-frame padding (buffer bigger than header claims)."""
        if len(raw_data) < 20:
            return False
        ver = raw_data[14] >> 4
        if ver == 6:
            return len(raw_data) >= 14 + 40
        if ver != 4:
            return False
        ihl = (raw_data[14] & 0x0F) * 4
        if ihl < 20 or len(raw_data) < 14 + ihl:
            return False
        total = struct.unpack("!H", raw_data[16:18])[0]
        return total <= len(raw_data) - 14

    def _parse_dpkt_ip(self, raw_data, ip_class):
        ip = ip_class(raw_data)
        packet = {"raw_len": len(raw_data)}
        packet["src_ip"] = socket.inet_ntoa(ip.src)
        packet["dst_ip"] = socket.inet_ntoa(ip.dst)
        packet["protocol"] = {6: "tcp", 17: "udp", 1: "icmp"}.get(ip.p, f"proto_{ip.p}")
        packet["frag_offset"] = ip.offset
        packet["ttl"] = ip.ttl
        packet["payload_len"] = len(ip.data)
        return self._parse_transport(ip, packet)

    def _parse_dpkt_ip6(self, raw_data, ip6_class):
        ip6 = ip6_class(raw_data)
        packet = {"raw_len": len(raw_data)}
        packet["src_ip"] = socket.inet_ntop(socket.AF_INET6, ip6.src)
        packet["dst_ip"] = socket.inet_ntop(socket.AF_INET6, ip6.dst)
        # ponytail: v6 used to stop here (protocol "ipv6", no ports/payload) —
        # most laptop web traffic is v6, so the shield was half-blind. dpkt
        # already decodes the upper layer; reuse the v4 transport parse.
        packet["protocol"] = {6: "tcp", 17: "udp", 58: "icmp"}.get(getattr(ip6, "nxt", -1), "ipv6")
        packet["payload_len"] = len(ip6.data)
        if packet["protocol"] in ("tcp", "udp"):
            try:
                self._parse_transport(ip6, packet)
            except Exception:
                pass
        if "src_port" not in packet:
            # dpkt leaves data raw when extension headers sit between v6
            # and L4 (common on CDN traffic) — walk them manually.
            try:
                self._manual_v6_l4(raw_data, packet)
            except Exception:
                pass
        return packet

    def _manual_v6_l4(self, v6_raw: bytes, packet: Dict) -> None:
        """Extract TCP/UDP ports walking v6 extension headers. Mirrors the
        v4 manual parse; ESP(50) is opaque and terminal."""
        if len(v6_raw) < 40:
            return
        nxt = v6_raw[6]
        off = 40
        while nxt in (0, 43, 44, 60, 135, 140, 51):
            if off + 8 > len(v6_raw):
                return
            nxt_new = v6_raw[off]
            if nxt == 44:
                ln = 8
            elif nxt == 51:
                ln = (v6_raw[off + 1] + 2) * 4
            else:
                ln = (v6_raw[off + 1] + 1) * 8
            off += ln
            nxt = nxt_new
            if off > len(v6_raw):
                return
        if nxt == 6 and len(v6_raw) >= off + 20:
            hdr = v6_raw[off:]
            packet["src_port"] = struct.unpack("!H", hdr[0:2])[0]
            packet["dst_port"] = struct.unpack("!H", hdr[2:4])[0]
            packet["tcp_seq"] = struct.unpack("!I", hdr[4:8])[0]
            fb = hdr[13]
            packet["flags"] = ""
            if fb & 0x02:
                packet["flags"] += "S"
            if fb & 0x10:
                packet["flags"] += "A"
            if fb & 0x01:
                packet["flags"] += "F"
            if fb & 0x04:
                packet["flags"] += "R"
            if fb & 0x08:
                packet["flags"] += "P"
            tlen = ((hdr[12] >> 4) & 0x0F) * 4
            packet["payload"] = hdr[tlen:]
            packet["payload_len"] = len(packet["payload"])
            packet["protocol"] = "tcp"
        elif nxt == 17 and len(v6_raw) >= off + 8:
            hdr = v6_raw[off:]
            packet["src_port"] = struct.unpack("!H", hdr[0:2])[0]
            packet["dst_port"] = struct.unpack("!H", hdr[2:4])[0]
            ulen = struct.unpack("!H", hdr[4:6])[0]
            packet["payload"] = hdr[8:ulen]
            packet["payload_len"] = len(packet["payload"])
            packet["protocol"] = "udp"

    def _parse_dpkt_ip_from_eth(self, eth):
        ip = eth.data
        packet = {"raw_len": len(eth.data) + 14}
        packet["src_ip"] = socket.inet_ntoa(ip.src)
        packet["dst_ip"] = socket.inet_ntoa(ip.dst)
        packet["protocol"] = {6: "tcp", 17: "udp", 1: "icmp"}.get(ip.p, f"proto_{ip.p}")
        packet["frag_offset"] = ip.offset
        packet["ttl"] = ip.ttl
        packet["payload_len"] = len(ip.data)
        return self._parse_transport(ip, packet)

    def _parse_transport(self, ip, packet):
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            packet["src_port"] = tcp.sport
            packet["dst_port"] = tcp.dport
            packet["tcp_seq"] = tcp.seq
            packet["tcp_ack"] = tcp.ack
            packet["flags"] = ""
            if tcp.flags & dpkt.tcp.TH_SYN:
                packet["flags"] += "S"
            if tcp.flags & dpkt.tcp.TH_ACK:
                packet["flags"] += "A"
            if tcp.flags & dpkt.tcp.TH_FIN:
                packet["flags"] += "F"
            if tcp.flags & dpkt.tcp.TH_RST:
                packet["flags"] += "R"
            if tcp.flags & dpkt.tcp.TH_PUSH:
                packet["flags"] += "P"
            if tcp.flags & dpkt.tcp.TH_URG:
                packet["flags"] += "U"
            packet["payload"] = tcp.data
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            packet["src_port"] = udp.sport
            packet["dst_port"] = udp.dport
            packet["payload"] = udp.data
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data
            packet["icmp_type"] = icmp.type
            packet["icmp_code"] = icmp.code
        return packet

    def _minimal_parse(self, raw_data: bytes) -> Optional[Dict]:
        try:
            packet = {"raw_len": len(raw_data)}
            if len(raw_data) < 14:
                return None
            eth_type = struct.unpack("!H", raw_data[12:14])[0]
            if eth_type == 0x0800:
                ip_header = raw_data[14:]
                if len(ip_header) < 20:
                    return None
                ip_ihl = (ip_header[0] & 0x0F) * 4
                packet["src_ip"] = socket.inet_ntoa(ip_header[12:16])
                packet["dst_ip"] = socket.inet_ntoa(ip_header[16:20])
                proto_map = {6: "tcp", 17: "udp", 1: "icmp"}
                packet["protocol"] = proto_map.get(ip_header[9], f"proto_{ip_header[9]}")
                packet["frag_offset"] = (struct.unpack("!H", ip_header[6:8])[0] & 0x1FFF)
                if ip_header[9] == 6 and len(ip_header) >= ip_ihl + 20:
                    tcp_hdr = ip_header[ip_ihl:]
                    packet["src_port"] = struct.unpack("!H", tcp_hdr[0:2])[0]
                    packet["dst_port"] = struct.unpack("!H", tcp_hdr[2:4])[0]
                    packet["tcp_seq"] = struct.unpack("!I", tcp_hdr[4:8])[0]
                    flags_byte = tcp_hdr[13]
                    packet["flags"] = ""
                    if flags_byte & 0x02:
                        packet["flags"] += "S"
                    if flags_byte & 0x10:
                        packet["flags"] += "A"
                    if flags_byte & 0x01:
                        packet["flags"] += "F"
                    if flags_byte & 0x04:
                        packet["flags"] += "R"
                    if flags_byte & 0x08:
                        packet["flags"] += "P"
                    if flags_byte & 0x20:
                        packet["flags"] += "U"
                    tcp_offset = ((tcp_hdr[12] >> 4) & 0x0F) * 4
                    packet["payload"] = tcp_hdr[tcp_offset:]
                    packet["payload_len"] = len(packet["payload"])
                elif ip_header[9] == 17 and len(ip_header) >= ip_ihl + 8:
                    udp_hdr = ip_header[ip_ihl:]
                    packet["src_port"] = struct.unpack("!H", udp_hdr[0:2])[0]
                    packet["dst_port"] = struct.unpack("!H", udp_hdr[2:4])[0]
                    udp_len = struct.unpack("!H", udp_hdr[4:6])[0]
                    packet["payload"] = udp_hdr[8:udp_len]
                    packet["payload_len"] = len(packet["payload"])
                return packet
        except Exception as e:
            logger.warning(f"[InlineEngine] minimal parse error: {e}")
        return None

    def _run_nfqueue_capture(self):
        queue_num = self._queue_num
        if not self._setup_nfqueue_nft(self._nfqueue_chain()):
            raise RuntimeError("Failed to set up nftables queue rule")
        sock = None
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
            # ponytail: bursts ENOBUFS'd the default 212KB rcvbuf faster than
            # the pipeline drains → shield silently fell back to sniff-only.
            # 8MB holds ~5k full-size packets of verdict backlog.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            sock.settimeout(1.0)
            for port_attempt in range(5):
                try:
                    sock.bind((os.getpid() + port_attempt, 0))
                    break
                except OSError as e:
                    if port_attempt == 4:
                        raise
                    logger.debug(f"[InlineEngine] Bind attempt {port_attempt} failed: {e}")
                    continue
            # ponytail: queue BIND takes pf=AF_UNSPEC — a family-specific pf
            # (AF_INET/...) is rejected with ENODEV. PF_BIND was removed from
            # modern kernels, so don't send it at all. One bind serves every
            # family (inet + bridge hooks can share the queue number).
            # ponytail: UNBIND must consume its own reply — a no-ack unbind
            # leaves a stale ERROR in the socket buffer that the BIND ack-read
            # then misattributes to BIND (phantom ENODEV, NFQUEUE never starts).
            try:
                self._nfq_send_config(sock, NFQNL_CFG_CMD_UNBIND, 0, queue_num,
                                      "UNBIND")
            except Exception:
                pass  # queue wasn't bound; BIND proceeds
            self._nfq_send_config(sock, NFQNL_CFG_CMD_BIND, 0, queue_num, "BIND")
            self._nfq_set_copy_mode(sock, queue_num, NFQNL_COPY_PACKET, 0xFFFF)
            self._nfq_set_queue_maxlen(sock, queue_num, self._queue_maxlen)
            logger.info(f"[InlineEngine] NFQUEUE consumer bound to queue {queue_num} (monitor_only={self._monitor_only})")
            # Only now can a queue rule be considered safe: a consumer exists.
            # The guard fails the link OPEN (loudly) if that stops being true.
            self._safe_link = SafeLink(
                config=self._config,
                interface=self._nfqueue_iface or self._get_interface(),
                table=self._nfqueue_table or self._config.get("nftables", {}).get("queue_table", "lidra_nfqueue"),
                family=self._nfqueue_family,
                alert_callback=self._on_detection_callback,
                dry_run=self._monitor_only,
            )
            self._safe_link.arm()
        except Exception as e:
            if sock:
                sock.close()
            self._teardown_nfqueue_nft()
            raise RuntimeError(f"NFQUEUE bind failed: {e}") from e
        try:
            self._nfq_recv_loop(sock, queue_num)
        finally:
            sock.close()
            self._teardown_nfqueue_nft()

    def _nfq_send_config(self, sock, cmd, pf, queue_num, label="", request_ack=True):
        nlm_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG
        # ponytail: uapi struct is (command, pf, queue_num) — the old code sent
        # (cmd, 0, pf), so BIND always targeted the wrong queue. queue_num also
        # rides in the nfgen header; the two must agree or the kernel ENODEVs.
        cmd_data = struct.pack(">BBH", cmd, pf, queue_num)
        attr = self._nfq_nlattr(NFQA_CFG_CMD, cmd_data)
        nfgen = struct.pack(">BBH", 0, 0, queue_num)
        payload = nfgen + attr
        flags = NLM_F_REQUEST | (NLM_F_ACK if request_ack else 0)
        msg = self._nfq_nlmsg(nlm_type, flags, 1, os.getpid(), payload)
        sock.send(msg)
        if request_ack:
            self._nfq_recv_ack(sock, label)

    def _nfq_set_copy_mode(self, sock, queue_num, copy_mode, copy_range):
        nlm_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG
        params = struct.pack(">IB", copy_range, copy_mode) + b"\x00\x00\x00"
        attr = self._nfq_nlattr(NFQA_CFG_PARAMS, params)
        nfgen = struct.pack(">BBH", 0, 0, queue_num)
        payload = nfgen + attr
        msg = self._nfq_nlmsg(nlm_type, NLM_F_REQUEST | NLM_F_ACK, 2, os.getpid(), payload)
        sock.send(msg)
        self._nfq_recv_ack(sock, "COPY_MODE")

    def _nfq_set_queue_maxlen(self, sock, queue_num, maxlen):
        nlm_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG
        attr = self._nfq_nlattr(NFQA_CFG_QUEUE_MAXLEN, struct.pack(">I", maxlen))
        nfgen = struct.pack(">BBH", 0, 0, queue_num)
        payload = nfgen + attr
        msg = self._nfq_nlmsg(nlm_type, NLM_F_REQUEST | NLM_F_ACK, 3, os.getpid(), payload)
        sock.send(msg)
        self._nfq_recv_ack(sock, "QUEUE_MAXLEN")

    def _nfq_recv_ack(self, sock, label=""):
        data = sock.recv(4096)
        if len(data) < 16:
            raise RuntimeError(f"Short ACK response ({label})")
        _len, _type, _flg, _seq, _pid = struct.unpack("=IHHII", data[:16])
        if _type == NLMSG_ERROR and len(data) >= 20:
            err = struct.unpack("=i", data[16:20])[0]
            if err != 0:
                raise RuntimeError(f"Netlink error ({label}): {os.strerror(abs(err))} (errno={err})")

    @staticmethod
    def _nfq_nlmsg(msg_type, flags, seq, pid, payload):
        length = 16 + len(payload)
        return struct.pack("=IHHII", length, msg_type, flags, seq, pid) + payload

    @staticmethod
    def _nfq_nlattr(attr_type, data):
        pad = (4 - (len(data) % 4)) % 4
        length = 4 + len(data) + pad
        return struct.pack("=HH", length, attr_type) + data + b"\x00" * pad

    def _nfq_recv_loop(self, sock, queue_num):
        logger.info(f"[InlineEngine] NFQUEUE recv loop started on queue {queue_num}")
        cleanup_interval = 60
        last_cleanup = time.time()
        last_stats = time.time()
        pkt_batch_count = 0
        while self._running:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                now = time.time()
                if now - last_cleanup > cleanup_interval:
                    self._connection_tracker.cleanup_stale()
                    self._stream_reassembler.cleanup_stale()
                    self._rate_limiter.cleanup_stale()
                    self._blocklist.cleanup_expired()
                    last_cleanup = now
                if now - last_stats > 5 and pkt_batch_count > 0 and self._on_detection_callback:
                    self._on_detection_callback({"type": "stats", "data": self.get_stats()})
                    pkt_batch_count = 0
                    last_stats = now
                continue
            packets = self._nfq_parse_messages(data, queue_num)
            for packet_id, packet in packets:
                if not packet:
                    self._nfq_send_verdict(sock, NF_ACCEPT, packet_id, queue_num)
                    continue
                with self._lock:
                    self._packet_count += 1
                    pkt_batch_count += 1
                detections = self._run_detection_pipeline(packet)
                verdict = self._decide(packet, detections)
                nf_verdict = self._apply_nf_verdict(verdict)
                log_hit = self._hit_log_allowed(packet, detections)
                if nf_verdict == NF_DROP and self._monitor_only:
                    # ponytail: monitor soak — log what WOULD drop, accept all.
                    if log_hit:
                        logger.warning(f"[InlineEngine] MONITOR would-drop {detections[0]['attack_type'] if detections else 'unknown'} from {packet.get('src_ip','')} (accepted)")
                    nf_verdict = NF_ACCEPT
                self._nfq_send_verdict(sock, nf_verdict, packet_id, queue_num)
                self._apply_verdict(packet_id, verdict, packet, detections, time.time())
                if detections and log_hit:
                    logger.info(f"[InlineEngine] DETECTED {detections[0]['attack_type']} from {packet.get('src_ip','')} -> verdict={verdict.value}")
                elif pkt_batch_count % 100 == 0:
                    logger.debug(f"[InlineEngine] Processed {pkt_batch_count} packets...")
            now = time.time()
            if now - last_cleanup > cleanup_interval:
                self._connection_tracker.cleanup_stale()
                self._stream_reassembler.cleanup_stale()
                self._rate_limiter.cleanup_stale()
                self._blocklist.cleanup_expired()
                last_cleanup = now
            if now - last_stats > 5 and self._on_detection_callback:
                self._on_detection_callback({"type": "stats", "data": self.get_stats()})
                pkt_batch_count = 0
                last_stats = now

    def _nfq_parse_messages(self, data, queue_num):
        results = []
        offset = 0
        while offset < len(data):
            if offset + 16 > len(data):
                break
            nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack("=IHHII", data[offset:offset + 16])
            if nlmsg_len < 16 or offset + nlmsg_len > len(data):
                break
            payload = data[offset + 16:offset + nlmsg_len]
            subsys = nlmsg_type >> 8
            msg_type = nlmsg_type & 0xFF
            if subsys == NFNL_SUBSYS_QUEUE and msg_type == NFQNL_MSG_PACKET and len(payload) >= 4:
                nfgen_family, nfgen_version, nfgen_res_id = struct.unpack(">BBH", payload[:4])
                attr_offset = 4
                packet_id = None
                packet_data = None
                while attr_offset < len(payload):
                    if attr_offset + 4 > len(payload):
                        break
                    nla_len, nla_type = struct.unpack("=HH", payload[attr_offset:attr_offset + 4])
                    if nla_len < 4 or attr_offset + nla_len > len(payload):
                        break
                    nla_data = payload[attr_offset + 4:attr_offset + nla_len]
                    if nla_type == NFQA_PACKET_HDR and len(nla_data) >= 4:
                        packet_id = struct.unpack(">I", nla_data[:4])[0]
                    elif nla_type == NFQA_PAYLOAD:
                        packet_data = nla_data
                    attr_offset += (nla_len + 3) & ~3
                if packet_id is not None:
                    parsed = self._parse_packet(packet_data) if packet_data else None
                    results.append((packet_id, parsed))
            elif nlmsg_type == NLMSG_ERROR and len(payload) >= 4:
                err = struct.unpack("=i", payload[:4])[0]
                if err != 0:
                    logger.warning(f"[InlineEngine] Async netlink error: {os.strerror(abs(err))}")
            offset += nlmsg_len
        return results

    def _nfq_send_verdict(self, sock, verdict, packet_id, queue_num):
        nlm_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT
        vhdr = struct.pack(">II", verdict, packet_id)
        vhdr_attr = self._nfq_nlattr(NFQA_VERDICT_HDR, vhdr)
        nfgen = struct.pack(">BBH", 2, 0, queue_num)
        payload = nfgen + vhdr_attr
        msg = self._nfq_nlmsg(nlm_type, NLM_F_REQUEST, 0, 0, payload)
        try:
            sock.send(msg)
        except Exception as e:
            logger.warning(f"[InlineEngine] Failed to send verdict: {e}")

    def _setup_nfqueue_nft(self, chain: str = "input"):
        interface = self._get_interface()
        queue_num = self._queue_num
        nft_tool, nft_family, hook_priority, hook = self._nfqueue_nft_params(chain)
        table = self._config.get("nftables", {}).get("queue_table", "lidra_nfqueue")
        # ponytail: a table left behind by a killed agent is an orphan queue
        # rule — drop it before installing ours so we never stack two.
        subprocess.run(["nft", "delete", "table", nft_family, table],
                       capture_output=True, timeout=5)
        try:
            subprocess.run([nft_tool, "add", "table", nft_family, table],
                           capture_output=True, timeout=5)
            subprocess.run([nft_tool, "add", "chain", nft_family, table, chain,
                           "{", "type", "filter", "hook", hook, "priority", f"{hook_priority};",
                           "policy", "accept;", "}"],
                           capture_output=True, timeout=5)
            subprocess.run([nft_tool, "flush", "chain", nft_family, table, chain],
                           capture_output=True, timeout=5)
            cmd = [nft_tool, "add", "rule", nft_family, table, chain,
                   "meta", "iifname", interface,
                   "queue", "num", str(queue_num)]
            result = subprocess.run(always_bypass(cmd), capture_output=True, timeout=5)
            if result.returncode != 0:
                cmd = [nft_tool, "add", "rule", nft_family, table, chain,
                       "queue", "num", str(queue_num)]
                result = subprocess.run(always_bypass(cmd), capture_output=True, timeout=5)
                if result.returncode != 0:
                    logger.warning(f"[InlineEngine] nft queue rule failed: {result.stderr.decode()}")
                    self._teardown_nfqueue_nft()
                    return False
            logger.info(f"[InlineEngine] nftables queue {queue_num} on {interface} (chain={chain})")
            self._nfqueue_family = nft_family
            self._nfqueue_table = table
            self._nfqueue_iface = interface
            return True
        except Exception as e:
            logger.warning(f"[InlineEngine] nftables setup error: {e}")
            self._teardown_nfqueue_nft()
            return False

    def _teardown_nfqueue_nft(self):
        if self._safe_link:
            self._safe_link.disarm()
        try:
            subprocess.run(["nft", "delete", "table", self._nfqueue_family,
                            self._config.get("nftables", {}).get("queue_table", "lidra_nfqueue")],
                           capture_output=True, timeout=5)
        except Exception as e:
            logger.warning(f"[InlineEngine] NFQUEUE teardown skipped: {e}")

    def _is_bridge_mode(self) -> bool:
        # ponytail: stock config ships placeholder bridge_name/interfaces, so
        # only explicit opt-ins count — presence alone false-positived every
        # local install onto the FORWARD chain.
        if self._config.get("mode") == "inline":
            return True
        bridge_cfg = self._config.get("bridge", {}) or {}
        if bridge_cfg.get("enabled") is True:
            return True
        if bridge_cfg.get("auto_create") is True:
            return True
        return False

    def _nfqueue_chain(self) -> str:
        bridge_cfg = self._config.get("bridge", {})
        return str(bridge_cfg.get("nfqueue_chain", "FORWARD" if self._is_bridge_mode() else "INPUT")).lower()

    @staticmethod
    def _nfqueue_nft_params(chain: str):
        chain_l = (chain or "input").lower()
        if chain_l == "forward":
            return ("nft", "bridge", 0, "forward")
        if chain_l == "output":
            return ("nft", "inet", 0, "output")
        return ("nft", "inet", 0, "input")

    def setup_nfqueue_chain(self, chain: str = "FORWARD") -> bool:
        return self._setup_nfqueue_nft(chain.lower())

    def _apply_nf_verdict(self, verdict: Verdict) -> int:
        if verdict in (Verdict.PASS, Verdict.RATE_LIMIT):
            return NF_ACCEPT
        if verdict == Verdict.DROP:
            return NF_DROP
        return NF_ACCEPT

    def get_stats(self) -> Dict:
        with self._lock:
            elapsed = time.time() - self._start_time if self._start_time else 1
            return {
                "packets_in": self._packet_count,
                "packets_passed": self._pass_count,
                "packets_dropped": self._drop_count,
                "packets_rate_limited": self._rate_limit_count,
                "avg_latency_ms": round(self._total_latency / max(self._packet_count, 1), 2),
                "uptime_seconds": round(elapsed),
                "packet_rate": round(self._packet_count / elapsed, 1),
            }

    def get_packet_rate(self) -> float:
        with self._lock:
            elapsed = time.time() - self._start_time if self._start_time else 1
            return self._packet_count / max(elapsed, 1)
