# src/dashboard/main.py
"""LIDRA v3 Web Dashboard."""

import psutil
import time
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
import uvicorn

from database.db import LIDRADatabase


app = FastAPI(title="LIDRA Dashboard", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db_path = Path(__file__).parent.parent.parent / "data" / "lidra.db"
db = LIDRADatabase(str(db_path))

# Load config for dashboard port
_cfg_path = Path(__file__).parent.parent / "config" / "config.yaml"
DASHBOARD_PORT = 9090
try:
    import yaml
    with open(_cfg_path) as _f:
        _cfg = yaml.safe_load(_f)
    DASHBOARD_PORT = _cfg.get("dashboard", {}).get("port", 9090)
except Exception:
    logger.debug("[Dashboard] Config load failed, using default port")

# Collector state (set by agent)
collector_state = {
    "network": {"packets_captured": 0, "attacks_detected": 0},
    "syslog": {"messages_received": 0, "attacks_detected": 0}
}


class BlockRequest(BaseModel):
    ip: str
    reason: str
    ttl_seconds: int = 3600


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/api/stats")
async def get_stats():
    stats = db.get_attacker_stats()
    cpu = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    network = psutil.net_io_counters()
    return {
        **stats,
        "system": {
            "cpu_percent": cpu,
            "memory_percent": memory.percent,
            "memory_used_mb": memory.used / (1024*1024),
            "disk_percent": disk.percent,
            "network_rx_mb": network.bytes_recv / (1024*1024),
            "network_tx_mb": network.bytes_sent / (1024*1024),
        },
        "uptime_seconds": int(time.time() - psutil.boot_time())
    }


@app.get("/api/attackers")
async def get_attackers(limit: int = 100, offset: int = 0):
    return {"attackers": db.get_attackers(limit, offset)}


@app.get("/api/recent-attacks")
async def get_recent_attacks(limit: int = 50):
    return {"attacks": db.get_recent_attacks(limit)}


@app.get("/api/alerts")
async def get_alerts(limit: int = 20):
    return {"alerts": db.get_recent_alerts(limit)}


@app.get("/api/attack-types")
async def get_attack_types():
    conn = db._get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT attack_type, COUNT(*) as count FROM attacks GROUP BY attack_type ORDER BY count DESC")
    return {"types": [{"type": row[0], "count": row[1]} for row in cursor.fetchall()]}


@app.get("/api/mitre-coverage")
async def get_mitre_coverage():
    from detection.mitre import MITREMapper
    mitre = MITREMapper()
    return mitre.get_coverage_report()


@app.get("/api/honeypot-stats")
async def get_honeypot_stats():
    conn = db._get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT a.attack_type, COUNT(*) as count, at.ip_address FROM attacks a JOIN attackers at ON a.attacker_id = at.id WHERE a.attack_type IN ('honeypot_connection', 'honeyfile_access') GROUP BY a.attack_type, at.ip_address ORDER BY count DESC")
    attack_rows = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) as total FROM honeypot_sessions")
    sessions_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) as total FROM honeyfile_hits")
    honeyfile_count = cursor.fetchone()[0]
    honeypot_hits = sum(1 for r in attack_rows if r[0] == 'honeypot_connection')
    honeyfile_hits = sum(1 for r in attack_rows if r[0] == 'honeyfile_access')
    top_ips = [{"ip": ip, "type": at, "count": cnt} for at, cnt, ip in attack_rows[:10]]
    return {"honeypot_connections": honeypot_hits, "honeyfile_accesses": honeyfile_hits, "total_sessions": sessions_count, "total_honeyfile_hits": honeyfile_count, "top_attackers": top_ips}


@app.get("/api/blocks")
async def get_blocks():
    conn = db._get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocks WHERE block_until > datetime('now') ORDER BY created_at DESC")
    return {"blocks": [dict(row) for row in cursor.fetchall()]}


@app.post("/api/block")
async def block_ip(request: BlockRequest):
    from response.firewall import FirewallManager
    fw = FirewallManager(dry_run=False)
    block_id = db.add_block(request.ip, request.reason, request.ttl_seconds)
    fw.block_ip(request.ip, request.ttl_seconds)
    db.mark_block_applied(block_id)
    return {"status": "ok", "message": f"Blocked {request.ip}"}


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "lidra-v3-dashboard", "version": "3.0.0"}


DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>LIDRA v3 - Security Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0f172a; color: white; font-family: system-ui, sans-serif; height: 100vh; overflow: hidden; }
        .dashboard { display: flex; flex-direction: column; height: 100vh; padding: 8px; gap: 8px; }
        .header { background: #1e293b; padding: 8px 16px; display: flex; justify-content: space-between; align-items: center; border-radius: 6px; flex-shrink: 0; }
        .metrics { display: flex; gap: 8px; flex-shrink: 0; }
        .metric-box { background: #1e293b; padding: 8px 12px; border-radius: 6px; text-align: center; min-width: 80px; flex: 1; }
        .metric-label { font-size: 10px; color: #94a3b8; }
        .metric-value { font-size: 18px; font-weight: bold; }
        .main-area { display: flex; gap: 8px; flex: 1; min-height: 0; }
        .charts-area { display: flex; flex-direction: column; gap: 8px; flex: 1; min-width: 0; }
        .chart-box, .table-box { background: #1e293b; padding: 8px; border-radius: 6px; flex: 1; min-height: 0; display: flex; flex-direction: column; }
        .chart-title, .table-title { font-size: 12px; font-weight: 600; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; }
        .tables-area { display: flex; flex-direction: column; gap: 8px; flex: 1; min-width: 0; }
        .table-content { flex: 1; overflow-y: auto; font-size: 11px; }
        .table-row { display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #334155; }
        .table-row:hover { background: #334155; }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <div style="display:flex;align-items:center;gap:10px;">
                <span style="font-size:18px;font-weight:bold;color:#22c55e;">🛡️</span>
                <span style="font-size:16px;font-weight:bold;">LIDRA v3</span>
                <span style="font-size:11px;color:#64748b;">Security Dashboard</span>
            </div>
            <div style="display:flex;align-items:center;gap:12px;">
                <span style="font-size:11px;color:#64748b;">Mode: <span style="color:#22c55e;">Production</span></span>
                <span style="background:#22c55e;color:white;padding:2px 8px;border-radius:4px;font-size:11px;">Active</span>
            </div>
        </div>
        <div class="metrics">
            <div class="metric-box"><div class="metric-label">Attackers</div><div class="metric-value" id="total-attackers">0</div></div>
            <div class="metric-box"><div class="metric-label">24h</div><div class="metric-value" id="attacks-24h" style="color:#f97316">0</div></div>
            <div class="metric-box"><div class="metric-label">CPU</div><div class="metric-value" id="cpu">0%</div></div>
            <div class="metric-box"><div class="metric-label">Memory</div><div class="metric-value" id="memory">0%</div></div>
            <div class="metric-box"><div class="metric-label">Network</div><div class="metric-value" id="network" style="color:#3b82f6">0MB</div></div>
            <div class="metric-box"><div class="metric-label">Alerts</div><div class="metric-value" id="alert-count" style="color:#eab308">0</div></div>
            <div class="metric-box"><div class="metric-label">MITRE</div><div class="metric-value" id="mitre-coverage" style="color:#8b5cf6">0%</div></div>
            <div class="metric-box"><div class="metric-label">Uptime</div><div class="metric-value" id="uptime" style="color:#22c55e">0h</div></div>
            <div class="metric-box"><div class="metric-label">Packets</div><div class="metric-value" id="packets" style="color:#06b6d4">0</div></div>
            <div class="metric-box"><div class="metric-label">Syslog</div><div class="metric-value" id="syslog" style="color:#ec4899">0</div></div>
        </div>
        <div class="main-area">
            <div class="charts-area">
                <div class="chart-box"><div class="chart-title">📊 Attack Types</div><div style="flex:1;min-height:0;"><canvas id="attackChart"></canvas></div></div>
                <div class="chart-box"><div class="chart-title">🎯 MITRE ATT&CK</div><div style="flex:1;min-height:0;"><canvas id="mitreChart"></canvas></div></div>
            </div>
            <div class="tables-area">
                <div class="table-box"><div class="table-title">💀 Recent Attacks</div><div class="table-content" id="recent-attacks"><div class="table-row"><span style="color:#64748b">No attacks</span></div></div></div>
                <div class="table-box"><div class="table-title">👤 Active Attackers</div><div class="table-content" id="active-attackers"><div class="table-row"><span style="color:#64748b">No attackers</span></div></div></div>
            </div>
        </div>
    </div>
    <script>
        let attackChart, mitreChart;
        async function loadData() {
            try {
                const [stats, attackTypes, recentAttacks, attackers, alerts, mitre, collectors] = await Promise.all([
                    fetch('/api/stats').then(r => r.json()),
                    fetch('/api/attack-types').then(r => r.json()),
                    fetch('/api/recent-attacks?limit=20').then(r => r.json()),
                    fetch('/api/attackers?limit=20').then(r => r.json()),
                    fetch('/api/alerts?limit=20').then(r => r.json()),
                    fetch('/api/mitre-coverage').then(r => r.json()),
                    fetch('/api/collector-stats').then(r => r.json()).catch(() => ({network:{packets_captured:0},syslog:{messages_received:0}}))
                ]);
                document.getElementById('total-attackers').textContent = stats.total_attackers || 0;
                document.getElementById('attacks-24h').textContent = stats.attacks_24h || 0;
                document.getElementById('cpu').textContent = (stats.system?.cpu_percent || 0).toFixed(0) + '%';
                document.getElementById('memory').textContent = (stats.system?.memory_percent || 0).toFixed(0) + '%';
                document.getElementById('network').textContent = ((stats.system?.network_rx_mb || 0) + (stats.system?.network_tx_mb || 0)).toFixed(0) + 'MB';
                document.getElementById('alert-count').textContent = alerts.alerts?.length || 0;
                document.getElementById('mitre-coverage').textContent = (mitre.coverage_percentage || 0) + '%';
                document.getElementById('uptime').textContent = Math.floor((stats.uptime_seconds || 0) / 3600) + 'h';
                document.getElementById('packets').textContent = (collectors.network?.packets_captured || 0).toLocaleString();
                document.getElementById('syslog').textContent = (collectors.syslog?.messages_received || 0).toLocaleString();
                if (attackChart) attackChart.destroy();
                attackChart = new Chart(document.getElementById('attackChart'), { type: 'doughnut', data: { labels: attackTypes.types?.map(t => t.type) || [], datasets: [{ data: attackTypes.types?.map(t => t.count) || [], backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e','#3b82f6','#8b5cf6','#ec4899','#06b6d4'] }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#94a3b8', font: {size: 10} } } } } });
                if (mitreChart) mitreChart.destroy();
                mitreChart = new Chart(document.getElementById('mitreChart'), { type: 'bar', data: { labels: mitre.tactics?.slice(0,8) || [], datasets: [{ label: 'Tactics', data: mitre.tactics?.slice(0,8).map(() => 1) || [], backgroundColor: '#f97316' }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { display: false }, x: { ticks: { color: '#94a3b8', font: {size: 9} }, grid: { display: false } } } } });
                document.getElementById('recent-attacks').innerHTML = recentAttacks.attacks?.map(a => '<div class="table-row"><span style="color:#f87171">' + (a.ip_address || '-') + '</span><span style="color:#fb923c">' + (a.attack_type || '-') + '</span><span style="color:#64748b">' + new Date(a.timestamp).toLocaleTimeString() + '</span></div>').join('') || '<div class="table-row"><span style="color:#64748b">No attacks</span></div>';
                document.getElementById('active-attackers').innerHTML = attackers.attackers?.map(a => '<div class="table-row"><span style="color:#fb923c">' + (a.ip_address || '-') + '</span><span style="color:#60a5fa">' + (a.country || '-') + '</span><span style="color:#64748b">' + (a.total_attacks || 0) + '</span></div>').join('') || '<div class="table-row"><span style="color:#64748b">No attackers</span></div>';
            } catch(e) { console.error(e); }
        }
        loadData();
        setInterval(loadData, 5000);
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=DASHBOARD_PORT)