import logging
import time
import threading
import struct
import socket
import subprocess
import fcntl
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Callable

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
NFQA_PACKET_HDR = 1
NFQA_PAYLOAD = 10
NFQA_VERDICT_HDR = 2
NF_ACCEPT = 1
NF_DROP = 0

NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 1
NLM_F_ACK = 4

from response.verdict import Verdict, decide_verdict
from response.blocklist import Blocklist
from response.rate_limiter import RateLimiter
from detection.packet_analyzer import PacketAnalyzer
from bridge.connection_tracker import ConnectionTracker
from bridge.stream_reassembler import StreamReassembler
from detection.dpi_engine import DPIEngine


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
            log_parser=None
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

        self._packet_count = 0
        self._pass_count = 0
        self._drop_count = 0
        self._rate_limit_count = 0
        self._total_latency = 0.0
        self._start_time = 0.0
        self._lock = threading.Lock()

        from detection.analyzer.tcp_fingerprinter import TCPFingerprinter
        from detection.analyzer.behavioral_analyzer import BehavioralAnalyzer
        from detection.analyzer.session_correlator import SessionCorrelator
        from utils.bloom import BloomFilter, FlowCache
        self._tcp_fingerprinter = TCPFingerprinter()
        self._behavioral_analyzer = BehavioralAnalyzer()
        self._session_correlator = SessionCorrelator()
        self._bloom_filter = BloomFilter(capacity=50000, error_rate=0.001)
        self._flow_cache = FlowCache(capacity=5000, clean_threshold=15)

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
        # NFQUEUE requires nftables INPUT rules that break WiFi on Kali.
        # Only use NFQUEUE in bridge/gateway mode (separate-box deployment).
        # In local mode, skip straight to AF_PACKET.
        if mode != "local":
            # Attempt 1: NFQUEUE — true inline verdicts (DROP before delivery).
            try:
                self._run_nfqueue_capture()
                return
            except Exception as e:
                logger.warning(f"[InlineEngine] NFQUEUE unavailable ({e}); trying AF_PACKET")

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
                except Exception:
                    pass
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
                    verdict = decide_verdict(detections)
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
            except Exception:
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

            packet = self._parse_packet(data)
            if not packet:
                continue

            with self._lock:
                self._packet_count += 1
                pkt_batch_count += 1

            detections = self._run_detection_pipeline(packet)
            verdict = decide_verdict(detections)
            self._apply_verdict(0, verdict, packet, detections, time.time())

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
        start = time.time()
        packet = self._parse_packet(payload.get_data())
        if not packet:
            return 1

        with self._lock:
            self._packet_count += 1

        detection = self._run_detection_pipeline(packet)

        ip_reputation = None
        rate_info = None
        verdict = decide_verdict(detection, ip_reputation, rate_info)

        self._apply_verdict(0, verdict, packet, detection, start)
        return 0

    def _run_detection_pipeline(self, packet: Dict) -> List[Dict]:
        detections = []
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        src_port = packet.get("src_port", 0)
        dst_port = packet.get("dst_port", 0)
        protocol = packet.get("protocol", "")
        flags = packet.get("flags", "")
        has_payload = bool(packet.get("payload"))

        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"

        whitelist = self._config.get("whitelist", [])
        if src_ip in whitelist or dst_ip in whitelist:
            self._flow_cache.track_packet(flow_key, has_payload)
            return detections

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
                if messages and conn:
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
        else:
            payload = packet.get("payload", b"")
            if payload:
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

        for analyzer in (self._dos_detector, self._fragment_analyzer,
                         self._port_analyzer, self._tunnel_detector,
                         self._covert_detector, self._ipv6_analyzer,
                         self._l2_analyzer, self._timing_analyzer,
                         self._proxy_detector,
                         self._tcp_fingerprinter,
                         self._behavioral_analyzer,
                         self._session_correlator):
            try:
                result = analyzer.analyze(packet)
                if result:
                    detections.extend(result)
            except Exception as e:
                logger.debug(f"[{type(analyzer).__name__}] error: {e}")

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

    def _parse_packet(self, raw_data: bytes) -> Optional[Dict]:
        if not raw_data or len(raw_data) < 14:
            return None

        if HAS_DPKT:
            try:
                first_nibble = raw_data[0] >> 4
                if first_nibble == 4:
                    return self._parse_dpkt_ip(raw_data, dpkt.ip.IP)
                elif first_nibble == 6:
                    return self._parse_dpkt_ip6(raw_data, dpkt.ip6.IP6)
                eth = dpkt.ethernet.Ethernet(raw_data)
                packet = {"raw_len": len(raw_data)}

                if isinstance(eth.data, dpkt.ip.IP):
                    return self._parse_dpkt_ip_from_eth(eth)
                elif isinstance(eth.data, dpkt.ip6.IP6):
                    ip6 = eth.data
                    packet["src_ip"] = socket.inet_ntop(socket.AF_INET6, ip6.src)
                    packet["dst_ip"] = socket.inet_ntop(socket.AF_INET6, ip6.dst)
                    packet["protocol"] = "ipv6"
                    packet["payload_len"] = len(ip6.data)
                    return packet

            except Exception as e:
                logger.debug(f"dpkt parse error: {e}")
                return None
        else:
            return self._minimal_parse(raw_data)

        return None

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
        packet["protocol"] = "ipv6"
        packet["payload_len"] = len(ip6.data)
        return packet

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
            logger.debug(f"minimal parse error: {e}")
        return None

    def _run_nfqueue_capture(self):
        queue_num = self._queue_num
        if not self._setup_nfqueue_nft():
            raise RuntimeError("Failed to set up nftables queue rule")
        sock = None
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
            sock.settimeout(1.0)
            for port_attempt in range(5):
                try:
                    sock.bind((os.getpid() + port_attempt, 0))
                    break
                except OSError:
                    if port_attempt == 4:
                        raise
                    continue
            # Clean up stale bindings: best-effort (no ACK), may fail on fresh boot
            try:
                self._nfq_send_config(sock, NFQNL_CFG_CMD_PF_UNBIND, socket.AF_INET, 0,
                                      "PF_UNBIND AF_INET", request_ack=False)
                self._nfq_send_config(sock, NFQNL_CFG_CMD_UNBIND, socket.AF_INET, queue_num,
                                      "UNBIND", request_ack=False)
            except Exception:
                pass
            self._nfq_send_config(sock, NFQNL_CFG_CMD_PF_BIND, socket.AF_INET, 0, "PF_BIND AF_INET")
            self._nfq_send_config(sock, NFQNL_CFG_CMD_PF_BIND, socket.AF_INET6, 0, "PF_BIND AF_INET6")
            self._nfq_send_config(sock, NFQNL_CFG_CMD_BIND, socket.AF_INET, queue_num, "BIND")
            self._nfq_set_copy_mode(sock, queue_num, NFQNL_COPY_PACKET, 0xFFFF)
            logger.info(f"[InlineEngine] NFQUEUE consumer bound to queue {queue_num}")
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
        cmd_data = struct.pack(">BBH", cmd, 0, pf)
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
                verdict = decide_verdict(detections)
                nf_verdict = NF_ACCEPT if verdict in (Verdict.PASS, Verdict.RATE_LIMIT) else NF_DROP
                self._nfq_send_verdict(sock, nf_verdict, packet_id, queue_num)
                self._apply_verdict(packet_id, verdict, packet, detections, time.time())
                if detections:
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

    def _setup_nfqueue_nft(self):
        interface = self._get_interface()
        queue_num = self._queue_num
        try:
            subprocess.run(["nft", "add", "table", "inet", self._config.get("nftables", {}).get("queue_table", "lidra_nfqueue")],
                           capture_output=True, timeout=5)
            subprocess.run(["nft", "add", "chain", "inet", self._config.get("nftables", {}).get("queue_table", "lidra_nfqueue"), "input",
                           "{", "type", "filter", "hook", "input", "priority", "0;",
                           "policy", "accept;", "}"],
                           capture_output=True, timeout=5)
            subprocess.run(["nft", "flush", "chain", "inet", self._config.get("nftables", {}).get("queue_table", "lidra_nfqueue"), "input"],
                           capture_output=True, timeout=5)
            cmd = ["nft", "add", "rule", "inet", self._config.get("nftables", {}).get("queue_table", "lidra_nfqueue"), "input",
                   "meta", "iifname", interface,
                   "queue", "num", str(queue_num)]
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode != 0:
                cmd = ["nft", "add", "rule", "inet", self._config.get("nftables", {}).get("queue_table", "lidra_nfqueue"), "input",
                       "queue", "num", str(queue_num)]
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                if result.returncode != 0:
                    logger.warning(f"[InlineEngine] nft queue rule failed: {result.stderr.decode()}")
                    self._teardown_nfqueue_nft()
                    return False
            logger.info(f"[InlineEngine] nftables queue {queue_num} on {interface}")
            return True
        except Exception as e:
            logger.warning(f"[InlineEngine] nftables setup error: {e}")
            self._teardown_nfqueue_nft()
            return False

    def _teardown_nfqueue_nft(self):
        try:
            subprocess.run(["nft", "delete", "table", "inet", self._config.get("nftables", {}).get("queue_table", "lidra_nfqueue")],
                           capture_output=True, timeout=5)
        except Exception:
            pass

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
        elapsed = time.time() - self._start_time if self._start_time else 1
        return self._packet_count / max(elapsed, 1)
