import threading
import logging

try:
    from prometheus_client import start_http_server, Counter, Gauge, Histogram
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False
    Counter = Gauge = Histogram = None
    def start_http_server(*a, **kw):
        raise RuntimeError("prometheus_client not installed")

logger = logging.getLogger("LIDRA-metrics")

if HAS_PROMETHEUS:
    packets_total = Counter("lidra_packets_total", "Total packets processed", ["verdict"])
    attacks_total = Counter("lidra_attacks_total", "Total attacks detected", ["type", "severity"])
    blocks_total = Counter("lidra_blocks_total", "Total IPs blocked", ["method"])
    active_connections = Gauge("lidra_active_connections", "Currently tracked connections")
    cpu_usage = Gauge("lidra_cpu_percent", "Agent CPU usage percent")
    memory_usage = Gauge("lidra_memory_percent", "Agent memory usage percent")
    packet_rate = Gauge("lidra_packet_rate", "Packets per second")
    throughput_mbps = Gauge("lidra_throughput_mbps", "Throughput in Mbps")
    detection_latency = Histogram("lidra_detection_latency_seconds", "Detection processing latency")
else:
    packets_total = attacks_total = blocks_total = None
    active_connections = cpu_usage = memory_usage = None
    packet_rate = throughput_mbps = None
    detection_latency = None

class MetricsServer:
    def __init__(self, port: int = 8080, cert_path: str = None, key_path: str = None):
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self._thread = None
        self._httpd = None

    def start(self):
        if not HAS_PROMETHEUS:
            logger.info("Metrics disabled — install prometheus-client")
            return
        def _serve():
            try:
                if self.cert_path and self.key_path:
                    from wsgiref.simple_server import make_server
                    import ssl
                    from prometheus_client.exposition import make_wsgi_app
                    app = make_wsgi_app()
                    httpd = make_server("0.0.0.0", self.port, app)
                    httpd.socket = ssl.wrap_socket(
                        httpd.socket,
                        certfile=self.cert_path,
                        keyfile=self.key_path,
                        server_side=True,
                    )
                    logger.info(f"Metrics server (TLS) on 0.0.0.0:{self.port}/metrics")
                    httpd.serve_forever()
                else:
                    start_http_server(self.port)
                    logger.info(f"Metrics server on 0.0.0.0:{self.port}/metrics")
            except Exception as e:
                logger.warning(f"Metrics server failed to start: {e}")
        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()

    def stop(self):
        pass
