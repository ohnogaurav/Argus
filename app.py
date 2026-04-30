"""
CyberCrime Investigation System — Real Data Edition
Windows + Admin required for full features.
"""

from flask import Flask, render_template_string, request, jsonify
import json

app = Flask(__name__)

# ── HTML BASE ──────────────────────────────────────────────────────────
BASE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYBER OPS — {{ title }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@500;700;900&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#03070d;--panel:#070f1a;--panel2:#0a1525;
  --border:#0e2d4a;--border2:#1a4a6e;
  --accent:#00e5ff;--accent2:#ff1744;--accent3:#ffab00;--accent4:#00e676;
  --text:#b0d4ee;--dim:#2e5f80;--dimmer:#1a3a55;
}
html{scroll-behavior:smooth}
body{
  background:var(--bg);color:var(--text);
  font-family:'Share Tech Mono',monospace;
  min-height:100vh;
  background-image:
    radial-gradient(ellipse 80% 50% at 10% 40%,rgba(0,229,255,.05) 0%,transparent 70%),
    radial-gradient(ellipse 60% 40% at 90% 20%,rgba(255,23,68,.04) 0%,transparent 70%),
    repeating-linear-gradient(0deg,transparent,transparent 47px,rgba(0,229,255,.025) 47px,rgba(0,229,255,.025) 48px),
    repeating-linear-gradient(90deg,transparent,transparent 47px,rgba(0,229,255,.015) 47px,rgba(0,229,255,.015) 48px);
}

/* ── HEADER ── */
header{
  position:sticky;top:0;z-index:100;
  background:rgba(3,7,13,.96);
  border-bottom:1px solid var(--border);
  backdrop-filter:blur(8px);
  display:flex;align-items:center;gap:14px;
  padding:14px 28px;
}
.logo{
  font-family:'Orbitron',sans-serif;font-size:1rem;font-weight:900;
  color:var(--accent);letter-spacing:3px;
  text-shadow:0 0 16px rgba(0,229,255,.6);
  white-space:nowrap;
}
.logo span{color:var(--accent2);text-shadow:0 0 12px rgba(255,23,68,.6)}
.live-badge{
  font-size:.58rem;background:var(--accent2);color:#fff;
  padding:2px 8px;border-radius:2px;letter-spacing:1px;font-weight:700;
  animation:pulse 1.2s infinite;
}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 6px var(--accent2)}50%{opacity:.5;box-shadow:none}}
nav{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap}
nav a{
  color:var(--dim);text-decoration:none;font-size:.72rem;
  padding:5px 12px;border:1px solid var(--border);border-radius:2px;
  letter-spacing:1px;transition:all .2s;
}
nav a:hover,nav a.on{
  color:var(--accent);border-color:var(--accent);
  text-shadow:0 0 8px var(--accent);
  box-shadow:0 0 12px rgba(0,229,255,.15);
}

/* ── MAIN ── */
main{max-width:1100px;margin:36px auto;padding:0 20px 80px}
h1{
  font-family:'Orbitron',sans-serif;font-size:1.2rem;font-weight:700;
  color:var(--accent);letter-spacing:3px;
  text-shadow:0 0 18px rgba(0,229,255,.5);
  margin-bottom:24px;padding-bottom:12px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:12px;
}

/* ── CARDS ── */
.card{
  background:var(--panel);border:1px solid var(--border);
  border-radius:3px;padding:22px;margin-bottom:18px;
  position:relative;overflow:hidden;
}
.card::after{
  content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent 0%,var(--accent) 50%,transparent 100%);
  opacity:.5;
}
.card-title{
  font-family:'Orbitron',sans-serif;font-size:.65rem;
  color:var(--dim);letter-spacing:2px;margin-bottom:16px;
  display:flex;align-items:center;gap:10px;
}

/* ── TABLES ── */
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{text-align:left;color:var(--dim);padding:7px 12px;
   border-bottom:1px solid var(--border);font-size:.65rem;letter-spacing:1px}
td{padding:8px 12px;border-bottom:1px solid rgba(14,45,74,.6);vertical-align:top;word-break:break-all}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(0,229,255,.03)}

/* ── STATUS COLORS ── */
.red{color:var(--accent2)}
.green{color:var(--accent4)}
.yellow{color:var(--accent3)}
.blue{color:var(--accent)}
.dim{color:var(--dim)}

/* ── BADGES ── */
.badge{display:inline-block;padding:2px 8px;border-radius:2px;font-size:.7rem;font-weight:700}
.badge-red{background:rgba(255,23,68,.15);color:var(--accent2);border:1px solid rgba(255,23,68,.4)}
.badge-green{background:rgba(0,230,118,.1);color:var(--accent4);border:1px solid rgba(0,230,118,.3)}
.badge-yellow{background:rgba(255,171,0,.1);color:var(--accent3);border:1px solid rgba(255,171,0,.3)}
.badge-blue{background:rgba(0,229,255,.08);color:var(--accent);border:1px solid rgba(0,229,255,.3)}

/* ── STATS ROW ── */
.stats{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
.stat-box{
  background:var(--panel2);border:1px solid var(--border);
  border-radius:3px;padding:14px 20px;flex:1;min-width:120px;
}
.stat-val{font-family:'Orbitron',sans-serif;font-size:1.6rem;font-weight:700;color:var(--accent)}
.stat-val.red{color:var(--accent2)}
.stat-val.green{color:var(--accent4)}
.stat-val.yellow{color:var(--accent3)}
.stat-lbl{font-size:.62rem;color:var(--dim);letter-spacing:1px;margin-top:4px}

/* ── FORMS ── */
.input-row{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;align-items:center}
input[type=text],input[type=number],select{
  background:var(--panel2);border:1px solid var(--border2);
  color:var(--text);font-family:'Share Tech Mono',monospace;
  font-size:.8rem;padding:8px 14px;border-radius:2px;outline:none;
}
input[type=text]:focus,select:focus{border-color:var(--accent);box-shadow:0 0 8px rgba(0,229,255,.2)}
button,a.btn{
  background:transparent;border:1px solid var(--accent);
  color:var(--accent);font-family:'Share Tech Mono',monospace;
  font-size:.78rem;padding:8px 20px;border-radius:2px;
  cursor:pointer;letter-spacing:1px;transition:all .2s;text-decoration:none;display:inline-block;
}
button:hover,a.btn:hover{background:rgba(0,229,255,.1);box-shadow:0 0 14px rgba(0,229,255,.2)}
button.danger{border-color:var(--accent2);color:var(--accent2)}
button.danger:hover{background:rgba(255,23,68,.1)}

/* ── HOME GRID ── */
.hero{text-align:center;padding:50px 0 30px}
.hero-title{
  font-family:'Orbitron',sans-serif;font-size:2.2rem;font-weight:900;
  color:var(--accent);letter-spacing:6px;
  text-shadow:0 0 30px rgba(0,229,255,.6),0 0 60px rgba(0,229,255,.2);
  margin-bottom:8px;
}
.hero-sub{color:var(--dim);font-size:.78rem;letter-spacing:3px;margin-bottom:50px}
.menu-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;max-width:800px;margin:0 auto}
.menu-card{
  display:block;text-decoration:none;
  background:var(--panel);border:1px solid var(--border);
  border-radius:3px;padding:28px 20px;text-align:center;
  transition:all .25s;position:relative;overflow:hidden;
}
.menu-card::before{
  content:'';position:absolute;bottom:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--accent),transparent);
  transform:scaleX(0);transition:transform .3s;
}
.menu-card:hover{border-color:var(--accent);transform:translateY(-3px);
  box-shadow:0 8px 30px rgba(0,229,255,.1)}
.menu-card:hover::before{transform:scaleX(1)}
.menu-icon{font-size:2rem;margin-bottom:12px;display:block}
.menu-label{font-family:'Orbitron',sans-serif;font-size:.7rem;color:var(--accent);letter-spacing:2px}
.menu-desc{font-size:.7rem;color:var(--dim);margin-top:8px;line-height:1.5}
.menu-real{font-size:.6rem;color:var(--accent4);letter-spacing:1px;margin-top:6px}

/* ── PACKET FEED ── */
.pkt-row{font-size:.72rem;padding:6px 10px;border-bottom:1px solid var(--border);
  display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap}
.pkt-row:hover{background:rgba(0,229,255,.03)}
.pkt-time{color:var(--dim);white-space:nowrap;min-width:70px}
.pkt-ip{color:var(--accent);white-space:nowrap}
.pkt-payload{color:var(--dimmer);flex:1;word-break:break-all;font-size:.68rem}
.pkt-flagged{border-left:2px solid var(--accent2);background:rgba(255,23,68,.04)}

/* ── SCORE BAR ── */
.score-bar{background:var(--panel2);border-radius:2px;height:6px;margin-top:4px;overflow:hidden}
.score-fill{height:100%;border-radius:2px;transition:width .5s}

/* ── SCROLLBAR ── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}

/* ── ALERT ── */
.alert{padding:12px 16px;border-radius:2px;margin-bottom:16px;font-size:.8rem;border-left:3px solid}
.alert-warn{background:rgba(255,171,0,.08);border-color:var(--accent3);color:var(--accent3)}
.alert-info{background:rgba(0,229,255,.06);border-color:var(--accent);color:var(--accent)}
.alert-err{background:rgba(255,23,68,.08);border-color:var(--accent2);color:var(--accent2)}

.spinner{display:inline-block;width:12px;height:12px;border:2px solid var(--border);
  border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<header>
  <div class="logo">CYBER<span>OPS</span></div>
  <span class="live-badge">LIVE</span>
  <nav>
    <a href="/" {% if active=='home' %}class="on"{% endif %}>HOME</a>
    <a href="/log" {% if active=='log' %}class="on"{% endif %}>AUTH LOG</a>
    <a href="/scan" {% if active=='scan' %}class="on"{% endif %}>PORT SCAN</a>
    <a href="/packet" {% if active=='packet' %}class="on"{% endif %}>PACKETS</a>
    <a href="/threat" {% if active=='threat' %}class="on"{% endif %}>THREAT INTEL</a>
  </nav>
</header>
<main>
{% block body %}{% endblock %}
</main>
</body>
</html>"""

# ── HOME ──────────────────────────────────────────────────────────────
HOME_TMPL = BASE.replace("{% block body %}{% endblock %}", """
<div class="hero">
  <div class="hero-title">&#x26A1; CYBEROPS</div>
  <div class="hero-sub">REAL-TIME FORENSIC INVESTIGATION TERMINAL</div>
  <div class="menu-grid">
    <a class="menu-card" href="/log">
      <span class="menu-icon">&#x1F4CB;</span>
      <div class="menu-label">AUTH LOG</div>
      <div class="menu-desc">Windows Security Event Log. Real failed &amp; successful logins.</div>
      <div class="menu-real">&#x2714; REAL DATA</div>
    </a>
    <a class="menu-card" href="/scan">
      <span class="menu-icon">&#x1F4E1;</span>
      <div class="menu-label">PORT SCANNER</div>
      <div class="menu-desc">Scan any host. Concurrent socket scanner with service ID.</div>
      <div class="menu-real">&#x2714; REAL NETWORK</div>
    </a>
    <a class="menu-card" href="/packet">
      <span class="menu-icon">&#x26A1;</span>
      <div class="menu-label">LIVE PACKETS</div>
      <div class="menu-desc">Scapy packet capture. SQL injection &amp; payload detection.</div>
      <div class="menu-real">&#x2714; REAL TRAFFIC</div>
    </a>
    <a class="menu-card" href="/threat">
      <span class="menu-icon">&#x1F3AF;</span>
      <div class="menu-label">THREAT INTEL</div>
      <div class="menu-desc">AbuseIPDB live lookup + local blacklist matching.</div>
      <div class="menu-real">&#x2714; REAL API</div>
    </a>
  </div>
</div>
""")

# ── LOG PAGE ──────────────────────────────────────────────────────────
LOG_TMPL = BASE.replace("{% block body %}{% endblock %}", """
<h1>&#x1F4CB; WINDOWS AUTH LOG</h1>
{% if error %}
<div class="alert alert-err">&#x26A0; {{ error }}</div>
{% endif %}
<div class="stats">
  <div class="stat-box"><div class="stat-val red">{{ bf_count }}</div><div class="stat-lbl">BRUTE FORCE IPs</div></div>
  <div class="stat-box"><div class="stat-val yellow">{{ si_count }}</div><div class="stat-lbl">SUSPICIOUS IPs</div></div>
  <div class="stat-box"><div class="stat-val">{{ ev_count }}</div><div class="stat-lbl">EVENTS SCANNED</div></div>
</div>

<div class="card">
  <div class="card-title">&#x1F525; BRUTE FORCE DETECTED</div>
  <table>
    <thead><tr><th>IP ADDRESS</th><th>FAILED LOGINS</th><th>VERDICT</th></tr></thead>
    <tbody>
    {% for x in brute_force %}
    <tr><td class="blue">{{ x.ip }}</td><td class="red">{{ x.fails }}</td><td><span class="badge badge-red">BRUTE FORCE</span></td></tr>
    {% else %}
    <tr><td colspan="3" class="green">No brute force detected in last 24h</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<div class="card">
  <div class="card-title">&#x26A0; RECENT AUTH EVENTS (last 100)</div>
  <table>
    <thead><tr><th>TIME</th><th>TYPE</th><th>USER</th><th>IP</th></tr></thead>
    <tbody>
    {% for e in events %}
    <tr>
      <td class="dim">{{ e.time }}</td>
      <td>{% if e.type=='FAILED' %}<span class="badge badge-red">FAILED</span>{% else %}<span class="badge badge-green">SUCCESS</span>{% endif %}</td>
      <td class="yellow">{{ e.user }}</td>
      <td class="blue">{{ e.ip }}</td>
    </tr>
    {% else %}
    <tr><td colspan="4" class="dim">No events found</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
""")

# ── SCAN PAGE ─────────────────────────────────────────────────────────
SCAN_TMPL = BASE.replace("{% block body %}{% endblock %}", """
<h1>&#x1F4E1; PORT SCANNER</h1>
<div class="card">
  <div class="card-title">SCAN TARGET</div>
  <form method="GET" action="/scan">
    <div class="input-row">
      <input type="text" name="host" placeholder="Host / IP (e.g. 192.168.1.1)" value="{{ host }}" style="width:260px">
      <select name="mode">
        <option value="common" {% if mode=='common' %}selected{% endif %}>Common ports (fast)</option>
        <option value="range" {% if mode=='range' %}selected{% endif %}>Range 1–1024</option>
        <option value="full" {% if mode=='full' %}selected{% endif %}>Range 1–65535 (slow)</option>
      </select>
      <button type="submit">&#x25B6; SCAN</button>
    </div>
  </form>
</div>

{% if result %}
{% if result.error %}
<div class="alert alert-err">{{ result.error }}</div>
{% else %}
<div class="stats">
  <div class="stat-box"><div class="stat-val red">{{ result.open|length }}</div><div class="stat-lbl">OPEN PORTS</div></div>
  <div class="stat-box"><div class="stat-val">{{ result.total_scanned }}</div><div class="stat-lbl">PORTS SCANNED</div></div>
  <div class="stat-box"><div class="stat-val green">{{ result.elapsed }}s</div><div class="stat-lbl">ELAPSED</div></div>
</div>
<div class="alert alert-info">HOST: {{ result.host }} &rarr; {{ result.ip }}</div>
<div class="card">
  <div class="card-title">OPEN PORTS</div>
  <table>
    <thead><tr><th>PORT</th><th>SERVICE</th><th>RISK</th></tr></thead>
    <tbody>
    {% for p in result.open %}
    <tr>
      <td class="blue">{{ p.port }}</td>
      <td class="yellow">{{ p.service }}</td>
      <td>{% if p.service in ['RDP','TELNET','VNC','FTP'] %}<span class="badge badge-red">HIGH RISK</span>{% elif p.service in ['SSH','SMB','MSSQL','MYSQL','MONGODB','REDIS'] %}<span class="badge badge-yellow">MEDIUM</span>{% else %}<span class="badge badge-green">NORMAL</span>{% endif %}</td>
    </tr>
    {% else %}
    <tr><td colspan="3" class="green">No open ports found</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}
{% else %}
<div class="alert alert-info">Enter a host and click SCAN. Works on any IP or hostname.</div>
{% endif %}
""")

# ── PACKET PAGE ───────────────────────────────────────────────────────
PACKET_TMPL = BASE.replace("{% block body %}{% endblock %}", """
<h1>&#x26A1; LIVE PACKET CAPTURE</h1>
{% if not scapy_ok %}
<div class="alert alert-err">
  &#x26A0; Scapy not installed or Npcap missing.<br>
  1. Install Npcap: <strong>https://npcap.com/#download</strong><br>
  2. Run: <strong>pip install scapy</strong><br>
  3. Run Flask as Administrator
</div>
{% else %}
<div class="card">
  <div class="card-title">CAPTURE CONTROL</div>
  <div class="input-row">
    <select id="iface">
      {% for i in interfaces %}<option>{{ i }}</option>{% endfor %}
    </select>
    <input type="number" id="dur" value="30" min="5" max="300" style="width:90px"> <span class="dim" style="font-size:.72rem">seconds</span>
    <button onclick="startCap()">&#x25B6; START CAPTURE</button>
    <button class="danger" onclick="stopCap()">&#x25A0; STOP</button>
    <button onclick="toggleFilter()">&#x1F6A8; THREATS ONLY</button>
  </div>
</div>

<div class="stats">
  <div class="stat-box"><div class="stat-val" id="s-total">{{ total }}</div><div class="stat-lbl">TOTAL CAPTURED</div></div>
  <div class="stat-box"><div class="stat-val red" id="s-flagged">{{ flagged }}</div><div class="stat-lbl">THREATS DETECTED</div></div>
  <div class="stat-box"><div class="stat-val" id="s-running">{{ 'ACTIVE' if running else 'IDLE' }}</div><div class="stat-lbl">STATUS</div></div>
</div>

<div class="card" style="padding:0">
  <div class="card-title" style="padding:16px 22px 0">PACKET FEED</div>
  <div id="feed" style="max-height:480px;overflow-y:auto">
    {% for p in packets %}
    <div class="pkt-row {% if p.flagged %}pkt-flagged{% endif %}">
      <span class="pkt-time">{{ p.time }}</span>
      <span class="pkt-ip">{{ p.src }}</span>
      <span class="dim">&#x2192;</span>
      <span class="pkt-ip">{{ p.dst }}</span>
      <span class="badge {% if p.proto=='TCP' %}badge-blue{% else %}badge-yellow{% endif %}">{{ p.proto }}</span>
      <span class="dim">:{{ p.dport }}</span>
      {% if p.threats %}<span class="badge badge-red">{{ p.threats|join(', ') }}</span>{% endif %}
      {% if p.payload %}<span class="pkt-payload">{{ p.payload }}</span>{% endif %}
    </div>
    {% else %}
    <div class="pkt-row dim">No packets captured yet. Start capture above.</div>
    {% endfor %}
  </div>
</div>

<script>
let filterThreats=false;
let autoRefresh=null;
function startCap(){
  let iface=document.getElementById('iface').value;
  let dur=document.getElementById('dur').value;
  fetch('/packet/start',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({iface,duration:parseInt(dur)})})
  .then(r=>r.json()).then(d=>{
    alert(d.message);
    autoRefresh=setInterval(refreshFeed,2000);
  });
}
function stopCap(){
  fetch('/packet/stop',{method:'POST'});
  clearInterval(autoRefresh);
}
function toggleFilter(){filterThreats=!filterThreats;refreshFeed()}
function refreshFeed(){
  let url='/packet/data?flagged_only='+(filterThreats?'1':'0');
  fetch(url).then(r=>r.json()).then(d=>{
    document.getElementById('s-total').textContent=d.total;
    document.getElementById('s-flagged').textContent=d.flagged;
    document.getElementById('s-running').textContent=d.running?'ACTIVE':'IDLE';
    let feed=document.getElementById('feed');
    feed.innerHTML=d.packets.map(p=>`
      <div class="pkt-row ${p.flagged?'pkt-flagged':''}">
        <span class="pkt-time">${p.time}</span>
        <span class="pkt-ip">${p.src}</span>
        <span class="dim">→</span>
        <span class="pkt-ip">${p.dst}</span>
        <span class="badge ${p.proto==='TCP'?'badge-blue':'badge-yellow'}">${p.proto}</span>
        <span class="dim">:${p.dport}</span>
        ${p.threats.length?`<span class="badge badge-red">${p.threats.join(', ')}</span>`:''}
        ${p.payload?`<span class="pkt-payload">${p.payload}</span>`:''}
      </div>`).join('') || '<div class="pkt-row dim">No packets yet.</div>';
  });
}
</script>
{% endif %}
""")

# ── THREAT PAGE ───────────────────────────────────────────────────────
THREAT_TMPL = BASE.replace("{% block body %}{% endblock %}", """
<h1>&#x1F3AF; THREAT INTELLIGENCE</h1>
<div class="alert alert-info">Uses AbuseIPDB API + local blacklist. Set ABUSEIPDB_KEY env var for live lookup.</div>

<div class="card">
  <div class="card-title">CHECK IP</div>
  <form method="GET" action="/threat">
    <div class="input-row">
      <input type="text" name="ip" placeholder="Enter IP address" value="{{ query_ip }}" style="width:240px">
      <button type="submit">&#x1F50D; CHECK</button>
    </div>
  </form>
</div>

{% if result %}
<div class="card">
  <div class="card-title">RESULT: {{ result.ip }}</div>
  <div class="stats">
    <div class="stat-box">
      <div class="stat-val {% if result.is_malicious %}red{% else %}green{% endif %}">
        {% if result.is_malicious %}THREAT{% else %}CLEAN{% endif %}
      </div>
      <div class="stat-lbl">VERDICT</div>
    </div>
    {% if result.api.api %}
    <div class="stat-box">
      <div class="stat-val {% if result.api.abuse_score > 50 %}red{% elif result.api.abuse_score > 25 %}yellow{% else %}green{% endif %}">
        {{ result.api.abuse_score }}%
      </div>
      <div class="stat-lbl">ABUSE SCORE</div>
    </div>
    <div class="stat-box"><div class="stat-val yellow">{{ result.api.total_reports }}</div><div class="stat-lbl">REPORTS</div></div>
    <div class="stat-box"><div class="stat-val">{{ result.api.country }}</div><div class="stat-lbl">COUNTRY</div></div>
    {% endif %}
  </div>
  {% if result.api.api %}
  <table>
    <tr><td class="dim">ISP</td><td>{{ result.api.isp }}</td></tr>
    <tr><td class="dim">DOMAIN</td><td>{{ result.api.domain }}</td></tr>
    <tr><td class="dim">TOR NODE</td><td class="{% if result.api.is_tor %}red{% else %}green{% endif %}">{{ result.api.is_tor }}</td></tr>
    <tr><td class="dim">LAST REPORTED</td><td>{{ result.api.last_reported }}</td></tr>
  </table>
  {% elif result.local.local_hit %}
  <div class="alert alert-warn">&#x26A0; LOCAL BLACKLIST HIT: {{ result.local.reason }}</div>
  {% else %}
  <div class="alert alert-warn">Set ABUSEIPDB_KEY environment variable for live API data.</div>
  {% endif %}
</div>
{% endif %}

<div class="card">
  <div class="card-title">LOCAL BLACKLIST</div>
  <table>
    <thead><tr><th>IP ADDRESS</th><th>REASON</th></tr></thead>
    <tbody>
    {% for ip, reason in blacklist.items() %}
    <tr><td class="blue">{{ ip }}</td><td class="red">{{ reason }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
""")

# ── ROUTES ────────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template_string(HOME_TMPL, active="home", title="HOME")


@app.route("/log")
def log():
    from log_scanner import read_windows_auth_log
    d = read_windows_auth_log(hours_back=24)
    return render_template_string(LOG_TMPL,
        active="log", title="AUTH LOG",
        error=d.get("error"),
        brute_force=d.get("brute_force", []),
        events=d.get("events", []),
        bf_count=len(d.get("brute_force", [])),
        si_count=len(d.get("suspicious_ips", [])),
        ev_count=d.get("total_scanned", 0)
    )


@app.route("/scan")
def scan():
    from log_scanner import scan_ports_real, quick_scan_common
    host = request.args.get("host", "")
    mode = request.args.get("mode", "common")
    result = None
    if host:
        if mode == "common":
            result = quick_scan_common(host)
        elif mode == "range":
            result = scan_ports_real(host, port_range=(1, 1024))
        else:
            result = scan_ports_real(host, port_range=(1, 65535), max_workers=200)
    return render_template_string(SCAN_TMPL,
        active="scan", title="PORT SCAN",
        host=host, mode=mode, result=result
    )


@app.route("/packet")
def packet():
    from packet_capture import get_packets, get_interfaces, get_status
    status = get_status()
    pkts = get_packets(limit=80)
    return render_template_string(PACKET_TMPL,
        active="packet", title="PACKETS",
        scapy_ok=status["scapy_ok"],
        interfaces=get_interfaces(),
        packets=pkts,
        total=status["total"],
        flagged=status["flagged"],
        running=status["running"]
    )


@app.route("/packet/start", methods=["POST"])
def packet_start():
    from packet_capture import start_capture
    data = request.get_json()
    ok, msg = start_capture(iface=data.get("iface"), duration=data.get("duration", 30))
    return jsonify({"ok": ok, "message": msg})


@app.route("/packet/stop", methods=["POST"])
def packet_stop():
    from packet_capture import stop_capture
    stop_capture()
    return jsonify({"ok": True})


@app.route("/packet/data")
def packet_data():
    from packet_capture import get_packets, get_status
    flagged_only = request.args.get("flagged_only") == "1"
    status = get_status()
    pkts = get_packets(limit=80, flagged_only=flagged_only)
    return jsonify({
        "packets": pkts,
        "total": status["total"],
        "flagged": status["flagged"],
        "running": status["running"]
    })


@app.route("/threat")
def threat():
    from threat_intel import check_ip_full, get_local_blacklist
    query_ip = request.args.get("ip", "")
    result = None
    if query_ip:
        result = check_ip_full(query_ip.strip())
    return render_template_string(THREAT_TMPL,
        active="threat", title="THREAT INTEL",
        query_ip=query_ip,
        result=result,
        blacklist=get_local_blacklist()
    )


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  CYBEROPS — Real Cyber Investigation System")
    print("  http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(debug=False, host="0.0.0.0", port=5000)
