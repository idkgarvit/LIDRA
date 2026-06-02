import logging
import time
import threading
import struct
import socket
import subprocess
from typing import Dict, List, Optional, Callable

logger = logging.getLogger(__name__)

try:
    import dpkt
    HAS_DPKT = True
except ImportError:
    HAS_DPKT = False
    logger.warning("dpkt not available, using minimal packet parser")



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
        self._queue_num = (
            config.get("local", {}).get("nfqueue_num") or
            config.get("bridge", {}).get("nfqueue_num") or
            0
        )

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

        self._packet_count = 0
        self._pass_count = 0
        self._drop_count = 0
        self._rate_limit_count = 0
        self._total_latency = 0.0
        self._start_time = 0.0
        self._lock = threading.Lock()

        self._on_detection_callback: Optional[Callable] = None
        self._pipeline_order = ["blocklist", "header_analysis", "stream_reassembly", "dpi", "verdict"]

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
        # Primary capture: AF_PACKET raw socket — works on ALL Linux distros.
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

    def _get_interface(self):
        return (
            self._config.get("local", {}).get("interface") or
            self._config.get("bridge", {}).get("interfaces", {}).get("wan") or
            "eth0"
        )

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
        logger.info(f"[InlineEngine] Raw capture mode on {interface} (FALLBACK — sniff only)")
        try:
            import fcntl
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            ifidx = socket.if_nametoindex(interface)
            s.bind((interface, 0))
            s.settimeout(1.0)
            logger.info(f"[InlineEngine] Bound raw socket to {interface}")
        except Exception as e:
            logger.warning(f"[InlineEngine] Cannot open raw socket on {interface}: {e}; trying eth0")
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                s.bind(("eth0", 0))
                s.settimeout(1.0)
                interface = "eth0"
                logger.info("[InlineEngine] Bound raw socket to eth0 (fallback)")
            except Exception as e2:
                logger.warning(f"[InlineEngine] Raw socket failed on eth0 too: {e2}")
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

        if self._blocklist.is_blocked(src_ip):
            detections.append({
                "attack_type": "blocked_ip_traffic",
                "severity": "high",
                "source_ip": src_ip,
                "details": "IP on blocklist",
            })

        header_result = self._packet_analyzer.analyze_header(packet)
        if header_result:
            detections.append(header_result)

        protocol = packet.get("protocol", "tcp")
        if protocol == "tcp":
            conn = self._connection_tracker.track(packet)
            if packet.get("payload"):
                direction = "client" if packet.get("src_port", 0) < 1024 else "server"
                messages = self._stream_reassembler.add_segment(packet, direction)
                if messages and conn:
                    app_proto = conn.app_protocol if conn else ""
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
        if not raw_data:
            return None

        if HAS_DPKT:
            try:
                eth = dpkt.ethernet.Ethernet(raw_data)
                packet = {"raw_len": len(raw_data)}

                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    packet["src_ip"] = socket.inet_ntoa(ip.src)
                    packet["dst_ip"] = socket.inet_ntoa(ip.dst)
                    packet["protocol"] = {6: "tcp", 17: "udp", 1: "icmp"}.get(ip.p, f"proto_{ip.p}")
                    packet["frag_offset"] = ip.offset
                    packet["ttl"] = ip.ttl
                    packet["payload_len"] = len(ip.data)

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
