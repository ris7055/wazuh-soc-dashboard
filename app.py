#!/usr/bin/env python3
"""
Ai-SOC.MSP Dashboard V2 — FortiSIEM-style Interface
====================================================
Standalone web UI on port 8444 (HTTPS).
All data fetched from Wazuh Manager (API + Indexer).
Login: admin / adminW@zuh
"""

import base64
import csv
import functools
import io
import json
import logging
import os
import re
import ssl
import subprocess
import threading
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask, Response, jsonify, redirect, render_template,
    request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
CERT_DIR = SCRIPT_DIR / "certs"

# Docker: persist user data to /app/data volume if it exists
_DATA_DIR = Path("/app/data")
if _DATA_DIR.is_dir():
    USERS_FILE = _DATA_DIR / ".users.json"
else:
    USERS_FILE = SCRIPT_DIR / ".users.json"

LOG_FILE = os.environ.get("SOC_LOG_FILE", "/var/ossec/logs/soc_dashboard.log")

WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://127.0.0.1:9200")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "kibanaro")
WAZUH_INDEXER_PASS = os.environ.get("WAZUH_INDEXER_PASSWORD",
                                     "Br?nO.UmT25r+ue8FhRacY99zHk8Ym*0")
# Admin credentials for AD plugin APIs (kibanaro lacks permissions)
WAZUH_INDEXER_ADMIN_USER = os.environ.get("WAZUH_INDEXER_ADMIN_USER", "admin")
WAZUH_INDEXER_ADMIN_PASS = os.environ.get("WAZUH_INDEXER_ADMIN_PASSWORD",
                                           "?uzRHjvR6+x3mAw?Aq9FiN??3I3CRVp*")

WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", "WmIB*DpruSCjX7ygiGhoqXp.I6EDJ4TH")

# Also check for password file used by V1
_API_PASS_FILE = Path("/var/ossec/wodles/snmp-icmp-monitor/.api_pass")
if _API_PASS_FILE.exists():
    try:
        _file_pass = _API_PASS_FILE.read_text().strip()
        if _file_pass:
            WAZUH_API_PASS = _file_pass
    except OSError:
        pass

# V1 config.yaml for SNMP/ICMP device data
V1_CONFIG_PATH = Path("/var/ossec/wodles/snmp-icmp-monitor/config.yaml")
V1_MONITOR_STATE = Path("/var/ossec/wodles/snmp-icmp-monitor/.monitor_state.json")

# SSL context (no cert verification for internal services)
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

# Caches
_wazuh_token_cache = {"token": None, "expires": 0}
_agents_cache = {"data": [], "expires": 0}
AGENTS_CACHE_TTL = 120
_dashboard_cache = {"data": {}, "expires": 0}
DASHBOARD_CACHE_TTL = 60

# Discovery scan state
DISCOVERY_SCRIPT = Path("/var/ossec/wodles/snmp-icmp-monitor/snmp_discovery.py")
DISCOVERY_VENV_PYTHON = Path("/var/ossec/wodles/snmp-icmp-monitor/venv/bin/python3")
WODLE_DIR = Path("/var/ossec/wodles/snmp-icmp-monitor")
_discovery_results = {}
_discovery_lock = threading.Lock()

# Agent metrics caches (for Device Inventory enrichment)
_agent_metrics_cache = {"data": {}, "expires": 0}
AGENT_METRICS_TTL = 120
_system_metrics_cache = {"data": {}, "expires": 0}
SYSTEM_METRICS_TTL = 120

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    handlers = [logging.StreamHandler(sys.stderr)]
    try:
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        handlers.append(logging.FileHandler(LOG_FILE))
    except (PermissionError, OSError):
        pass
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
    )
    return logging.getLogger("soc_dashboard")


logger = setup_logging()

# ---------------------------------------------------------------------------
# Wazuh API helpers
# ---------------------------------------------------------------------------
def _get_wazuh_api_token():
    now = time.time()
    if _wazuh_token_cache["token"] and now < _wazuh_token_cache["expires"]:
        return _wazuh_token_cache["token"]
    credentials = base64.b64encode(
        ("%s:%s" % (WAZUH_API_USER, WAZUH_API_PASS)).encode()
    ).decode()
    auth_req = urllib.request.Request(
        "%s/security/user/authenticate" % WAZUH_API_URL,
        method="POST",
        headers={"Authorization": "Basic %s" % credentials},
    )
    with urllib.request.urlopen(auth_req, context=_ssl_ctx, timeout=15) as resp:
        token_data = json.loads(resp.read().decode("utf-8"))
    token = token_data.get("data", {}).get("token")
    if token:
        _wazuh_token_cache["token"] = token
        _wazuh_token_cache["expires"] = now + 850
    return token


def _wazuh_api_get(path):
    token = _get_wazuh_api_token()
    if not token:
        return None
    req = urllib.request.Request(
        "%s%s" % (WAZUH_API_URL, path),
        headers={"Authorization": "Bearer %s" % token},
    )
    with urllib.request.urlopen(req, context=_ssl_ctx, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Wazuh Indexer helpers
# ---------------------------------------------------------------------------
def _indexer_query(index, query_body, timeout=15):
    """Execute a query against the Wazuh Indexer."""
    body = json.dumps(query_body).encode("utf-8")
    credentials = base64.b64encode(
        ("%s:%s" % (WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS)).encode()
    ).decode()
    req = urllib.request.Request(
        "%s/%s/_search" % (WAZUH_INDEXER_URL, index),
        data=body,
        headers={
            "Authorization": "Basic %s" % credentials,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, context=_ssl_ctx, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _indexer_query_admin(index, query_body, timeout=15):
    """Execute a query against the Wazuh Indexer using admin credentials.
    Needed for AD plugin result indices that kibanaro cannot access.
    """
    body = json.dumps(query_body).encode("utf-8")
    credentials = base64.b64encode(
        ("%s:%s" % (WAZUH_INDEXER_ADMIN_USER, WAZUH_INDEXER_ADMIN_PASS)).encode()
    ).decode()
    req = urllib.request.Request(
        "%s/%s/_search" % (WAZUH_INDEXER_URL, index),
        data=body,
        headers={
            "Authorization": "Basic %s" % credentials,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, context=_ssl_ctx, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _indexer_request(path, method="GET", body=None, timeout=15, use_admin=True):
    """Generic HTTP request to the Wazuh Indexer (for non-search APIs).
    Uses admin credentials by default for AD plugin access.
    """
    user = WAZUH_INDEXER_ADMIN_USER if use_admin else WAZUH_INDEXER_USER
    passwd = WAZUH_INDEXER_ADMIN_PASS if use_admin else WAZUH_INDEXER_PASS
    credentials = base64.b64encode(
        ("%s:%s" % (user, passwd)).encode()
    ).decode()
    headers = {
        "Authorization": "Basic %s" % credentials,
        "Content-Type": "application/json",
    }
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(
        "%s%s" % (WAZUH_INDEXER_URL, path),
        data=data,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(req, context=_ssl_ctx, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Category / Severity mapping (FortiSIEM-style)
# ---------------------------------------------------------------------------
def _categorize_alert(rule_groups):
    """Map Wazuh rule groups to FortiSIEM categories."""
    if not rule_groups:
        return "Security"
    groups_lower = [g.lower() for g in rule_groups]
    groups_str = " ".join(groups_lower)

    # Availability
    if any(k in groups_str for k in [
        "network_monitor", "availability", "system_metrics_report",
        "host_down", "host_up", "ping",
    ]):
        return "Availability"

    # Performance
    if any(k in groups_str for k in [
        "performance", "disk_warning", "disk_critical", "disk_full",
        "cpu_load", "system_metrics_disk", "system_metrics_cpu",
        "snmp_performance",
    ]):
        return "Performance"

    # Change
    if any(k in groups_str for k in [
        "syscheck", "fim", "config_changed", "audit",
        "rootcheck", "policy_changed",
    ]):
        return "Change"

    return "Security"


def _level_to_severity(level):
    """Map Wazuh rule level to FortiSIEM severity."""
    if level >= 12:
        return "Critical"
    elif level >= 10:
        return "High"
    elif level >= 7:
        return "Medium"
    elif level >= 4:
        return "Low"
    return "Info"


# ---------------------------------------------------------------------------
# Flask App
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()
app.config["PERMANENT_SESSION_LIFETIME"] = 86400


# ===================================================================
# USER / AUTH
# ===================================================================
def load_users():
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    default_users = {
        "admin": {
            "password_hash": generate_password_hash("adminW@zuh"),
            "role": "admin",
            "created": datetime.now(timezone.utc).isoformat(),
        }
    }
    save_users(default_users)
    logger.info("Created default admin user")
    return default_users


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    try:
        os.chmod(str(USERS_FILE), 0o600)
    except OSError:
        pass


def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if "user" in session:
            return redirect(url_for("index"))
        return render_template("login.html")

    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    users = load_users()
    user = users.get(username)

    if user and check_password_hash(user["password_hash"], password):
        session.permanent = True
        session["user"] = username
        session["role"] = user.get("role", "viewer")
        if request.is_json:
            return jsonify({"message": "Login successful", "user": username})
        return redirect(url_for("index"))

    if request.is_json:
        return jsonify({"error": "Invalid username or password"}), 401
    return render_template("login.html", error="Invalid username or password")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@login_required
def index():
    return render_template("index.html", user=session.get("user", ""))


# ===================================================================
# DASHBOARD API
# ===================================================================
@app.route("/api/dashboard/summary")
@login_required
def api_dashboard_summary():
    """SOC Dashboard overview — aggregated stats."""
    timerange = request.args.get("timerange", "24h")
    time_map = {"1h": "now-1h", "6h": "now-6h", "12h": "now-12h",
                "24h": "now-24h", "7d": "now-7d", "30d": "now-30d"}
    time_gte = time_map.get(timerange, "now-24h")

    # Determine trend interval based on timerange
    if timerange in ("1h", "6h"):
        trend_interval = "10m"
    elif timerange in ("12h", "24h"):
        trend_interval = "1h"
    else:
        trend_interval = "6h"

    # Cache key includes timerange
    now = time.time()
    cache_key = "dash_%s" % timerange
    if (_dashboard_cache.get("key") == cache_key
            and _dashboard_cache["data"] and now < _dashboard_cache["expires"]):
        return jsonify(_dashboard_cache["data"])

    result = {
        "agents": {"total": 0, "active": 0, "disconnected": 0},
        "alerts": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_category": {
            "Security": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "Performance": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "Availability": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "Change": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        },
        "top_agents": [],
        "top_rules": [],
        "top_src_ips": [],
        "trend": [],
        "recent_critical": [],
        "timerange": timerange,
    }

    # --- Agents from Wazuh API ---
    try:
        agents_data = _wazuh_api_get("/agents?limit=500&select=id,name,status")
        if agents_data:
            items = agents_data.get("data", {}).get("affected_items", [])
            result["agents"]["total"] = len(items)
            result["agents"]["active"] = sum(
                1 for a in items if a.get("status") == "active"
            )
            result["agents"]["disconnected"] = sum(
                1 for a in items if a.get("status") == "disconnected"
            )
    except Exception as e:
        logger.warning("Dashboard: agent fetch error: %s", e)

    # --- Alerts from Indexer ---
    _SEVERITY_RANGES = [
        {"key": "low", "from": 3, "to": 7},
        {"key": "medium", "from": 7, "to": 10},
        {"key": "high", "from": 10, "to": 12},
        {"key": "critical", "from": 12},
    ]
    try:
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_gte}}},
                        {"range": {"rule.level": {"gte": 3}}},
                    ]
                }
            },
            "aggs": {
                "by_level": {
                    "range": {"field": "rule.level", "ranges": _SEVERITY_RANGES}
                },
                "by_agent": {
                    "terms": {"field": "agent.name", "size": 10},
                    "aggs": {
                        "top_descs": {
                            "terms": {"field": "rule.description", "size": 4}
                        },
                        "severity": {
                            "range": {"field": "rule.level", "ranges": _SEVERITY_RANGES}
                        },
                    },
                },
                "by_rule": {
                    "terms": {"field": "rule.id", "size": 10},
                    "aggs": {
                        "desc": {
                            "terms": {"field": "rule.description", "size": 1}
                        },
                        "top_agent": {
                            "terms": {"field": "agent.name", "size": 3}
                        },
                    },
                },
                "by_src_ip": {
                    "terms": {"field": "data.srcip", "size": 10},
                    "aggs": {
                        "severity": {
                            "range": {"field": "rule.level", "ranges": _SEVERITY_RANGES}
                        },
                    },
                },
                "hourly_trend": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": trend_interval,
                    },
                    "aggs": {
                        "severity": {
                            "range": {"field": "rule.level", "ranges": _SEVERITY_RANGES}
                        }
                    },
                },
                "by_groups": {
                    "terms": {"field": "rule.groups", "size": 50},
                    "aggs": {
                        "severity": {
                            "range": {"field": "rule.level", "ranges": _SEVERITY_RANGES}
                        }
                    },
                },
            },
        }
        data = _indexer_query("wazuh-alerts-*", query, timeout=20)
        total = data.get("hits", {}).get("total", {})
        if isinstance(total, dict):
            result["alerts"]["total"] = total.get("value", 0)
        else:
            result["alerts"]["total"] = total

        # Severity counts
        for bucket in data.get("aggregations", {}).get("by_level", {}).get("buckets", []):
            key = bucket.get("key", "")
            cnt = bucket.get("doc_count", 0)
            if key in result["alerts"]:
                result["alerts"][key] = cnt

        # Top agents — enriched with top incident descriptions + severity
        for b in data.get("aggregations", {}).get("by_agent", {}).get("buckets", []):
            agent_entry = {"name": b["key"], "count": b["doc_count"], "top_incidents": [], "severity": {}}
            for d in b.get("top_descs", {}).get("buckets", []):
                agent_entry["top_incidents"].append({"desc": d["key"], "count": d["doc_count"]})
            for sb in b.get("severity", {}).get("buckets", []):
                agent_entry["severity"][sb["key"]] = sb["doc_count"]
            result["top_agents"].append(agent_entry)

        # Top rules — enriched with description + top agents
        for b in data.get("aggregations", {}).get("by_rule", {}).get("buckets", []):
            rule_entry = {"rule_id": b["key"], "count": b["doc_count"], "description": "", "agents": []}
            desc_buckets = b.get("desc", {}).get("buckets", [])
            if desc_buckets:
                rule_entry["description"] = desc_buckets[0]["key"]
            for ab in b.get("top_agent", {}).get("buckets", []):
                rule_entry["agents"].append(ab["key"])
            result["top_rules"].append(rule_entry)

        # Top source IPs — enriched with severity
        for b in data.get("aggregations", {}).get("by_src_ip", {}).get("buckets", []):
            ip_entry = {"ip": b["key"], "count": b["doc_count"], "severity": {}}
            for sb in b.get("severity", {}).get("buckets", []):
                ip_entry["severity"][sb["key"]] = sb["doc_count"]
            result["top_src_ips"].append(ip_entry)

        # Trend
        for bucket in data.get("aggregations", {}).get("hourly_trend", {}).get("buckets", []):
            entry = {"time": bucket.get("key_as_string", ""), "total": bucket.get("doc_count", 0)}
            for sb in bucket.get("severity", {}).get("buckets", []):
                entry[sb["key"]] = sb["doc_count"]
            result["trend"].append(entry)

        # Category breakdown — with severity per category
        group_buckets = data.get("aggregations", {}).get("by_groups", {}).get("buckets", [])
        _categorize_from_groups(group_buckets, result["by_category"])

        # Compute Security as remainder
        total_classified = sum(
            result["by_category"][c]["total"]
            for c in ("Performance", "Availability", "Change")
        )
        result["by_category"]["Security"]["total"] = max(
            0, result["alerts"]["total"] - total_classified
        )
        # Estimate Security severity from overall minus others
        for sev in ("critical", "high", "medium", "low"):
            other_sev = sum(
                result["by_category"][c].get(sev, 0)
                for c in ("Performance", "Availability", "Change")
            )
            result["by_category"]["Security"][sev] = max(
                0, result["alerts"].get(sev, 0) - other_sev
            )

    except Exception as e:
        logger.warning("Dashboard: indexer error: %s", e)

    # --- Recent critical alerts (level >= 10) ---
    try:
        query = {
            "size": 15,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_gte}}},
                        {"range": {"rule.level": {"gte": 10}}},
                    ]
                }
            },
            "_source": [
                "timestamp", "rule.id", "rule.level", "rule.description",
                "rule.groups", "rule.mitre", "agent.name", "agent.id",
                "data.srcip", "data.dstip",
            ],
        }
        data = _indexer_query("wazuh-alerts-*", query, timeout=10)
        for hit in data.get("hits", {}).get("hits", []):
            src = hit["_source"]
            rule = src.get("rule", {})
            mitre = rule.get("mitre", {})
            result["recent_critical"].append({
                "timestamp": src.get("timestamp", ""),
                "rule_id": rule.get("id", ""),
                "level": rule.get("level", 0),
                "description": rule.get("description", ""),
                "severity": _level_to_severity(rule.get("level", 0)),
                "category": _categorize_alert(rule.get("groups", [])),
                "agent_name": src.get("agent", {}).get("name", ""),
                "src_ip": src.get("data", {}).get("srcip", ""),
                "mitre_tactic": ", ".join(mitre.get("tactic", [])) if mitre else "",
                "mitre_id": ", ".join(mitre.get("id", [])) if mitre else "",
            })
    except Exception as e:
        logger.warning("Dashboard: recent critical error: %s", e)

    _dashboard_cache["data"] = result
    _dashboard_cache["key"] = cache_key
    _dashboard_cache["expires"] = now + DASHBOARD_CACHE_TTL
    return jsonify(result)


def _categorize_from_groups(group_buckets, by_category):
    """Categorize alerts from rule.groups aggregation, with severity breakdown."""
    avail_groups = {"network_monitor", "system_metrics_report", "host_down", "host_up"}
    perf_groups = {"system_metrics_disk", "system_metrics_cpu", "disk_warning",
                   "disk_critical", "cpu_load_warning", "cpu_load_critical",
                   "snmp_performance"}
    change_groups = {"syscheck", "rootcheck", "audit", "fim"}

    for bucket in group_buckets:
        g = bucket["key"].lower()
        cnt = bucket["doc_count"]
        # Determine category
        if g in avail_groups:
            cat = "Availability"
        elif g in perf_groups:
            cat = "Performance"
        elif g in change_groups:
            cat = "Change"
        else:
            continue  # Security computed as remainder

        by_category[cat]["total"] += cnt
        # Add severity breakdown from sub-aggregation
        for sb in bucket.get("severity", {}).get("buckets", []):
            sev_key = sb["key"]  # critical, high, medium, low
            by_category[cat][sev_key] = by_category[cat].get(sev_key, 0) + sb["doc_count"]


# ===================================================================
# INCIDENTS API (all Wazuh alerts, FortiSIEM-style)
# ===================================================================
@app.route("/api/incidents")
@login_required
def api_incidents():
    """Query all Wazuh alerts as incidents with FortiSIEM-style categorization.

    Query params:
        severity  - Critical, High, Medium, Low (comma-sep)
        category  - Security, Performance, Availability, Change (comma-sep)
        timerange - 1h, 6h, 12h, 24h, 7d, 30d (default 24h)
        limit     - max results (default 200, max 1000)
        search    - free text on description/agent
        min_level - minimum rule level (default 3)
    """
    severity_filter = request.args.get("severity", "")
    category_filter = request.args.get("category", "")
    timerange = request.args.get("timerange", "24h")
    limit = min(request.args.get("limit", 200, type=int), 1000)
    search_q = request.args.get("search", "").strip()
    min_level = request.args.get("min_level", 3, type=int)

    time_map = {
        "1h": "now-1h", "2h": "now-2h", "6h": "now-6h", "12h": "now-12h",
        "24h": "now-24h", "7d": "now-7d", "30d": "now-30d",
        "90d": "now-90d", "180d": "now-180d",
    }
    time_from = time_map.get(timerange, "now-24h")

    must = [
        {"range": {"timestamp": {"gte": time_from, "lte": "now"}}},
        {"range": {"rule.level": {"gte": min_level}}},
    ]

    # Severity filter via rule.level
    sev_list = [s.strip() for s in severity_filter.split(",") if s.strip()] \
        if severity_filter else []
    if sev_list:
        level_ranges = []
        for s in sev_list:
            if s == "Critical":
                level_ranges.append({"range": {"rule.level": {"gte": 12}}})
            elif s == "High":
                level_ranges.append({"range": {"rule.level": {"gte": 10, "lt": 12}}})
            elif s == "Medium":
                level_ranges.append({"range": {"rule.level": {"gte": 7, "lt": 10}}})
            elif s == "Low":
                level_ranges.append({"range": {"rule.level": {"gte": 3, "lt": 7}}})
        if level_ranges:
            must.append({"bool": {"should": level_ranges, "minimum_should_match": 1}})

    # Category filter via rule.groups
    if category_filter:
        cat_list = [c.strip() for c in category_filter.split(",") if c.strip()]
        cat_groups = []
        for cat in cat_list:
            if cat == "Availability":
                cat_groups.extend(["network_monitor", "system_metrics_report",
                                   "host_down", "host_up"])
            elif cat == "Performance":
                cat_groups.extend(["system_metrics_disk", "system_metrics_cpu",
                                   "disk_warning", "disk_critical",
                                   "cpu_load_warning", "snmp_performance"])
            elif cat == "Change":
                cat_groups.extend(["syscheck", "rootcheck", "audit", "fim"])
            elif cat == "Security":
                cat_groups.extend(["authentication_failed", "authentication_success",
                                   "attack", "exploit", "ids", "firewall",
                                   "web", "vulnerability"])
        if cat_groups:
            must.append({"terms": {"rule.groups": cat_groups}})

    if search_q:
        must.append({"multi_match": {
            "query": search_q,
            "fields": ["rule.description", "agent.name", "data.srcip",
                        "data.dstip", "full_log"],
            "type": "phrase_prefix",
        }})

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": [
            "timestamp", "rule.id", "rule.level", "rule.description",
            "rule.groups", "rule.mitre", "agent.name", "agent.id", "agent.ip",
            "data.srcip", "data.dstip", "data.srcport", "data.dstport",
            "data.srcuser", "data.dstuser", "data.protocol",
            "data.monitor.host.address", "data.monitor.host.name",
            "data.monitor.check_type", "data.monitor.status",
        ],
    }

    try:
        data = _indexer_query("wazuh-alerts-*", query, timeout=30)
        hits = data.get("hits", {}).get("hits", [])
        total_hits = data.get("hits", {}).get("total", {})
        total_count = total_hits.get("value", len(hits)) if isinstance(total_hits, dict) else total_hits

        incidents = []
        sev_counter = {}
        cat_counter = {}
        agent_counter = {}
        rule_counter = {}
        ip_counter = {}
        user_counter = {}
        trend_map = {}

        for hit in hits:
            src = hit["_source"]
            rule = src.get("rule", {})
            level = rule.get("level", 0)
            groups = rule.get("groups", [])
            severity = _level_to_severity(level)
            category = _categorize_alert(groups)
            agent_name = src.get("agent", {}).get("name", "")
            src_ip = src.get("data", {}).get("srcip", "")
            dst_ip = src.get("data", {}).get("dstip", "")
            src_user = src.get("data", {}).get("srcuser", "")
            dst_user = src.get("data", {}).get("dstuser", "")
            mitre = rule.get("mitre", {})

            incident = {
                "timestamp": src.get("timestamp", ""),
                "rule_id": rule.get("id", ""),
                "level": level,
                "severity": severity,
                "category": category,
                "incident": rule.get("description", ""),
                "subcategory": ", ".join(groups[:3]) if groups else "",
                "source": src_ip,
                "target": agent_name,
                "target_ip": src.get("agent", {}).get("ip", ""),
                "detail": rule.get("description", ""),
                "src_user": src_user,
                "dst_user": dst_user,
                "mitre_ids": mitre.get("id", []) if mitre else [],
                "mitre_tactics": mitre.get("tactic", []) if mitre else [],
                "mitre_techniques": mitre.get("technique", []) if mitre else [],
                "user": src_user or dst_user or "",
                "status": "Active",
                "resolution": "Open",
            }
            incidents.append(incident)

            sev_counter[severity] = sev_counter.get(severity, 0) + 1
            cat_counter[category] = cat_counter.get(category, 0) + 1
            if agent_name:
                agent_counter[agent_name] = agent_counter.get(agent_name, 0) + 1
            rid = rule.get("id", "")
            desc = rule.get("description", "")
            rule_counter[rid] = rule_counter.get(rid, {"desc": desc, "count": 0})
            rule_counter[rid]["count"] += 1
            if src_ip:
                ip_counter[src_ip] = ip_counter.get(src_ip, 0) + 1
            user = src_user or dst_user
            if user:
                user_counter[user] = user_counter.get(user, 0) + 1

            ts = src.get("timestamp", "")
            if ts:
                date_key = ts[:13]  # YYYY-MM-DDTHH (hourly)
                if date_key not in trend_map:
                    trend_map[date_key] = {}
                trend_map[date_key][severity] = trend_map[date_key].get(severity, 0) + 1

        # Build sorted breakdowns
        trend = [{"time": k, **v} for k, v in sorted(trend_map.items())]

        rule_breakdown = sorted(
            [{"rule_id": k, "incident": v["desc"], "count": v["count"]}
             for k, v in rule_counter.items()],
            key=lambda x: x["count"], reverse=True,
        )[:20]

        agent_breakdown = sorted(
            [{"name": k, "count": v} for k, v in agent_counter.items()],
            key=lambda x: x["count"], reverse=True,
        )[:20]

        ip_breakdown = sorted(
            [{"ip": k, "count": v} for k, v in ip_counter.items()],
            key=lambda x: x["count"], reverse=True,
        )[:20]

        user_breakdown = sorted(
            [{"user": k, "count": v} for k, v in user_counter.items()],
            key=lambda x: x["count"], reverse=True,
        )[:20]

        return jsonify({
            "incidents": incidents,
            "total": total_count,
            "returned": len(incidents),
            "severity_summary": sev_counter,
            "category_summary": cat_counter,
            "trend": trend,
            "rule_breakdown": rule_breakdown,
            "agent_breakdown": agent_breakdown,
            "ip_breakdown": ip_breakdown,
            "user_breakdown": user_breakdown,
        })
    except Exception as e:
        import traceback
        logger.warning("Incidents error: %s\n%s", e, traceback.format_exc())
        return jsonify({
            "incidents": [], "total": 0, "returned": 0,
            "severity_summary": {}, "category_summary": {},
            "trend": [], "rule_breakdown": [], "agent_breakdown": [],
            "ip_breakdown": [], "user_breakdown": [],
            "error": str(e),
        })


# ===================================================================
# CMDB / AGENTS API
# ===================================================================
@app.route("/api/cmdb/agents")
@login_required
def api_cmdb_agents():
    """List all Wazuh agents with enriched syscollector + system_metrics data."""
    now = time.time()
    if _agents_cache["data"] and now < _agents_cache["expires"]:
        return jsonify({"agents": _agents_cache["data"]})

    agents = []
    try:
        data = _wazuh_api_get(
            "/agents?limit=500&select=id,name,ip,status,os.name,os.version,"
            "os.platform,lastKeepAlive,dateAdd,version,manager,group"
        )
        if not data:
            return jsonify({"agents": [], "error": "Cannot reach Wazuh API"})

        items = data.get("data", {}).get("affected_items", [])
        for agent in items:
            aid = agent.get("id", "")
            entry = {
                "id": aid,
                "name": agent.get("name", ""),
                "ip": agent.get("ip", ""),
                "status": agent.get("status", "unknown"),
                "os_name": agent.get("os", {}).get("name", ""),
                "os_version": agent.get("os", {}).get("version", ""),
                "os_platform": agent.get("os", {}).get("platform", ""),
                "last_keep_alive": agent.get("lastKeepAlive", ""),
                "date_add": agent.get("dateAdd", ""),
                "version": agent.get("version", ""),
                "manager": agent.get("manager", ""),
                "group": agent.get("group", []),
                "cpu_cores": "",
                "cpu_name": "",
                "ram_pct": "",
                "ram_total": "",
                "uptime": "",
                "disk": "",
                "cpu_load": "",
            }

            # Enrich with syscollector if active
            if agent.get("status") == "active" and aid != "000":
                try:
                    hw = _wazuh_api_get("/syscollector/%s/hardware" % aid)
                    if hw:
                        hw_items = hw.get("data", {}).get("affected_items", [])
                        if hw_items:
                            ram = hw_items[0].get("ram", {})
                            cpu = hw_items[0].get("cpu", {})
                            entry["ram_pct"] = ram.get("usage", "")
                            entry["ram_total"] = ram.get("total", "")
                            entry["cpu_cores"] = cpu.get("cores", "")
                            entry["cpu_name"] = cpu.get("name", "")
                except Exception:
                    pass

            agents.append(entry)

        # Enrich with system_metrics from Indexer (wodle command data)
        try:
            sm_query = {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"rule.id": ["100860", "100861", "100862",
                                                    "100863", "100865", "100866"]}},
                            {"range": {"timestamp": {"gte": "now-30m"}}},
                        ]
                    }
                },
                "aggs": {
                    "by_agent": {
                        "terms": {"field": "agent.id", "size": 500},
                        "aggs": {
                            "latest": {
                                "top_hits": {
                                    "size": 1,
                                    "sort": [{"timestamp": {"order": "desc"}}],
                                    "_source": ["agent.id", "data.system_metrics"],
                                }
                            }
                        },
                    }
                },
            }
            sm_data = _indexer_query("wazuh-alerts-*", sm_query, timeout=10)
            sm_map = {}
            for bucket in sm_data.get("aggregations", {}).get("by_agent", {}).get("buckets", []):
                hits = bucket.get("latest", {}).get("hits", {}).get("hits", [])
                if hits:
                    src = hits[0]["_source"]
                    sm = src.get("data", {}).get("system_metrics", {})
                    agent_id = src.get("agent", {}).get("id", "")
                    if agent_id and sm:
                        sm_map[agent_id] = sm

            for entry in agents:
                sm = sm_map.get(entry["id"])
                if sm:
                    entry["uptime"] = sm.get("uptime", {}).get("formatted", "")
                    entry["disk"] = sm.get("disk_max_usage_pct", "")
                    entry["cpu_load"] = sm.get("cpu", {}).get("load_1min", "")
                    entry["cpu_load_5"] = sm.get("cpu", {}).get("load_5min", "")
                    entry["cpu_load_15"] = sm.get("cpu", {}).get("load_15min", "")
                    entry["disks"] = sm.get("disk", [])
        except Exception as e:
            logger.debug("System metrics enrichment error: %s", e)

    except Exception as e:
        logger.warning("CMDB agents error: %s", e)
        return jsonify({"agents": [], "error": str(e)})

    _agents_cache["data"] = agents
    _agents_cache["expires"] = now + AGENTS_CACHE_TTL
    return jsonify({"agents": agents})


@app.route("/api/cmdb/agents/<agent_id>")
@login_required
def api_cmdb_agent_detail(agent_id):
    """Detailed info for a single agent — syscollector + recent alerts."""
    result = {"agent": {}, "alerts": [], "ports": [], "interfaces": []}

    try:
        data = _wazuh_api_get(
            "/agents?agents_list=%s&select=id,name,ip,status,os.name,os.version,"
            "os.platform,os.arch,lastKeepAlive,dateAdd,version,manager,group,"
            "node_name,registerIP" % agent_id
        )
        if data:
            items = data.get("data", {}).get("affected_items", [])
            if items:
                agent = items[0]
                result["agent"] = {
                    "id": agent.get("id", ""),
                    "name": agent.get("name", ""),
                    "ip": agent.get("ip", ""),
                    "status": agent.get("status", ""),
                    "os_name": agent.get("os", {}).get("name", ""),
                    "os_version": agent.get("os", {}).get("version", ""),
                    "os_platform": agent.get("os", {}).get("platform", ""),
                    "os_arch": agent.get("os", {}).get("arch", ""),
                    "last_keep_alive": agent.get("lastKeepAlive", ""),
                    "date_add": agent.get("dateAdd", ""),
                    "version": agent.get("version", ""),
                    "manager": agent.get("manager", ""),
                    "group": agent.get("group", []),
                    "node_name": agent.get("node_name", ""),
                    "register_ip": agent.get("registerIP", ""),
                }
    except Exception as e:
        logger.warning("Agent detail error: %s", e)

    # Syscollector: hardware, OS, ports, interfaces
    if agent_id != "000":
        try:
            hw = _wazuh_api_get("/syscollector/%s/hardware" % agent_id)
            if hw:
                hw_items = hw.get("data", {}).get("affected_items", [])
                if hw_items:
                    hwd = hw_items[0]
                    result["agent"]["cpu_name"] = hwd.get("cpu", {}).get("name", "")
                    result["agent"]["cpu_cores"] = hwd.get("cpu", {}).get("cores", "")
                    result["agent"]["cpu_mhz"] = hwd.get("cpu", {}).get("mhz", "")
                    result["agent"]["ram_total"] = hwd.get("ram", {}).get("total", "")
                    result["agent"]["ram_free"] = hwd.get("ram", {}).get("free", "")
                    result["agent"]["ram_usage"] = hwd.get("ram", {}).get("usage", "")
        except Exception:
            pass

        try:
            ports = _wazuh_api_get("/syscollector/%s/ports?limit=50" % agent_id)
            if ports:
                result["ports"] = ports.get("data", {}).get("affected_items", [])
        except Exception:
            pass

        try:
            ifaces = _wazuh_api_get("/syscollector/%s/netiface?limit=50" % agent_id)
            if ifaces:
                result["interfaces"] = ifaces.get("data", {}).get("affected_items", [])
        except Exception:
            pass

    # Recent alerts for this agent
    try:
        alerts_query = {
            "size": 20,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"match": {"agent.id": agent_id}},
                        {"range": {"timestamp": {"gte": "now-7d"}}},
                        {"range": {"rule.level": {"gte": 3}}},
                    ]
                }
            },
            "_source": [
                "timestamp", "rule.id", "rule.level", "rule.description",
                "rule.groups", "data.srcip",
            ],
        }
        alerts_data = _indexer_query("wazuh-alerts-*", alerts_query, timeout=10)
        for hit in alerts_data.get("hits", {}).get("hits", []):
            src = hit["_source"]
            rule = src.get("rule", {})
            result["alerts"].append({
                "timestamp": src.get("timestamp", ""),
                "rule_id": rule.get("id", ""),
                "level": rule.get("level", 0),
                "description": rule.get("description", ""),
                "severity": _level_to_severity(rule.get("level", 0)),
                "category": _categorize_alert(rule.get("groups", [])),
            })
    except Exception as e:
        logger.debug("Agent alerts error: %s", e)

    return jsonify(result)


# ===================================================================
# ICMP DATA API
# ===================================================================
@app.route("/api/icmp")
@login_required
def api_icmp_data():
    """Fetch ICMP monitoring alerts from Wazuh Indexer."""
    timerange = request.args.get("timerange", "24h")
    limit = min(request.args.get("limit", 200, type=int), 1000)

    time_map = {
        "1h": "now-1h", "6h": "now-6h", "12h": "now-12h",
        "24h": "now-24h", "7d": "now-7d", "30d": "now-30d",
        "90d": "now-90d", "180d": "now-180d",
    }
    time_from = time_map.get(timerange, "now-24h")

    # ICMP rule IDs: 100801-100808, 100840, 100841
    icmp_rules = ["100801", "100802", "100803", "100804",
                  "100805", "100806", "100807", "100808",
                  "100840", "100841"]

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"terms": {"rule.id": icmp_rules}},
                    {"range": {"timestamp": {"gte": time_from}}},
                ]
            }
        },
        "_source": [
            "timestamp", "rule.id", "rule.level", "rule.description",
            "agent.name", "data.monitor.host.address",
            "data.monitor.host.name", "data.monitor.check_type",
            "data.monitor.status", "data.monitor.state_change",
            "data.monitor.icmp.avg_rtt_ms", "data.monitor.icmp.packet_loss",
        ],
    }

    try:
        data = _indexer_query("wazuh-alerts-*", query, timeout=15)
        hits = data.get("hits", {}).get("hits", [])
        results = []
        for hit in hits:
            src = hit["_source"]
            rule = src.get("rule", {})
            monitor = src.get("data", {}).get("monitor", {})
            host_info = monitor.get("host", {})
            icmp = monitor.get("icmp", {})
            results.append({
                "timestamp": src.get("timestamp", ""),
                "rule_id": rule.get("id", ""),
                "level": rule.get("level", 0),
                "severity": _level_to_severity(rule.get("level", 0)),
                "description": rule.get("description", ""),
                "host_address": host_info.get("address", ""),
                "host_name": host_info.get("name", ""),
                "check_type": monitor.get("check_type", ""),
                "status": monitor.get("status", ""),
                "state_change": monitor.get("state_change", ""),
                "rtt_ms": icmp.get("avg_rtt_ms"),
                "packet_loss": icmp.get("packet_loss"),
            })
        return jsonify({"data": results, "total": len(results)})
    except Exception as e:
        logger.warning("ICMP data error: %s", e)
        return jsonify({"data": [], "total": 0, "error": str(e)})


# ===================================================================
# SNMP PERFORMANCE API
# ===================================================================
@app.route("/api/snmp")
@login_required
def api_snmp_data():
    """Fetch SNMP performance alerts from Wazuh Indexer."""
    timerange = request.args.get("timerange", "24h")
    limit = min(request.args.get("limit", 200, type=int), 1000)

    time_map = {
        "1h": "now-1h", "6h": "now-6h", "12h": "now-12h",
        "24h": "now-24h", "7d": "now-7d", "30d": "now-30d",
        "90d": "now-90d", "180d": "now-180d",
    }
    time_from = time_map.get(timerange, "now-24h")

    # SNMP rule IDs: 100810-100811, 100820-100822, 100830, 100842, 100850-100856
    snmp_rules = ["100810", "100811", "100820", "100821", "100822",
                  "100830", "100842", "100850", "100851", "100852",
                  "100853", "100854", "100855", "100856"]

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"terms": {"rule.id": snmp_rules}},
                    {"range": {"timestamp": {"gte": time_from}}},
                ]
            }
        },
        "_source": [
            "timestamp", "rule.id", "rule.level", "rule.description",
            "agent.name", "data.monitor.host.address",
            "data.monitor.host.name", "data.monitor.check_type",
            "data.monitor.snmp_data", "data.monitor.snmp_perf",
            "data.monitor.snmp_performance",
            "data.monitor.status",
        ],
    }

    try:
        data = _indexer_query("wazuh-alerts-*", query, timeout=15)
        hits = data.get("hits", {}).get("hits", [])
        results = []
        for hit in hits:
            src = hit["_source"]
            rule = src.get("rule", {})
            monitor = src.get("data", {}).get("monitor", {})
            host_info = monitor.get("host", {})
            snmp_data = monitor.get("snmp_data", {})
            snmp_perf = monitor.get("snmp_perf", {})
            snmp_performance = monitor.get("snmp_performance", {})
            perf_cpu = snmp_performance.get("cpu", {})
            perf_mem = snmp_performance.get("memory", {})
            perf_disks = snmp_performance.get("disk", [])
            perf_disk_max = ""
            if perf_disks:
                try:
                    perf_disk_max = max(d.get("usage_pct", 0) for d in perf_disks)
                except (ValueError, TypeError):
                    perf_disk_max = perf_disks[0].get("usage_pct", "") if perf_disks else ""
            results.append({
                "timestamp": src.get("timestamp", ""),
                "rule_id": rule.get("id", ""),
                "level": rule.get("level", 0),
                "severity": _level_to_severity(rule.get("level", 0)),
                "description": rule.get("description", ""),
                "host_address": host_info.get("address", ""),
                "host_name": host_info.get("name", ""),
                "check_type": monitor.get("check_type", ""),
                "status": monitor.get("status", ""),
                "sys_name": snmp_data.get("sysName", ""),
                "sys_uptime": snmp_data.get("sysUpTime", ""),
                "sys_descr": snmp_data.get("sysDescr", ""),
                "cpu_load": perf_cpu.get("load_1min", "") or snmp_perf.get("cpu_load", ""),
                "ram_percent": perf_mem.get("usage_pct", "") or snmp_perf.get("ram_percent", ""),
                "disk_percent": perf_disk_max or snmp_perf.get("disk_percent", ""),
                "overall_status": snmp_performance.get("overall_status", ""),
                "overall_severity": snmp_performance.get("overall_severity", ""),
            })
        return jsonify({"data": results, "total": len(results)})
    except Exception as e:
        logger.warning("SNMP data error: %s", e)
        return jsonify({"data": [], "total": 0, "error": str(e)})


# ===================================================================
# ALERTS STREAM API (real-time feed)
# ===================================================================
@app.route("/api/alerts/recent")
@login_required
def api_recent_alerts():
    """Get recent alerts (all types) for real-time event stream."""
    limit = min(request.args.get("limit", 50, type=int), 200)
    min_level = request.args.get("min_level", 3, type=int)

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": "now-1h"}}},
                    {"range": {"rule.level": {"gte": min_level}}},
                ]
            }
        },
        "_source": [
            "timestamp", "rule.id", "rule.level", "rule.description",
            "rule.groups", "agent.name", "agent.id",
            "data.srcip", "data.dstip",
        ],
    }

    try:
        data = _indexer_query("wazuh-alerts-*", query, timeout=10)
        alerts = []
        for hit in data.get("hits", {}).get("hits", []):
            src = hit["_source"]
            rule = src.get("rule", {})
            alerts.append({
                "timestamp": src.get("timestamp", ""),
                "rule_id": rule.get("id", ""),
                "level": rule.get("level", 0),
                "severity": _level_to_severity(rule.get("level", 0)),
                "category": _categorize_alert(rule.get("groups", [])),
                "description": rule.get("description", ""),
                "agent_name": src.get("agent", {}).get("name", ""),
                "src_ip": src.get("data", {}).get("srcip", ""),
            })
        return jsonify({"alerts": alerts, "total": len(alerts)})
    except Exception as e:
        return jsonify({"alerts": [], "total": 0, "error": str(e)})


# ===================================================================
# V1 DEVICE DATA (config.yaml + monitor state) — full enrichment
# ===================================================================

def _v1_load_config():
    import yaml
    if not V1_CONFIG_PATH.exists():
        return {"defaults": {}, "hosts": []}
    with open(V1_CONFIG_PATH, "r") as f:
        return yaml.safe_load(f) or {"defaults": {}, "hosts": []}


def _v1_save_config(config):
    import yaml
    import shutil
    backup = V1_CONFIG_PATH.with_suffix(".yaml.bak")
    if V1_CONFIG_PATH.exists():
        shutil.copy2(V1_CONFIG_PATH, backup)
    with open(V1_CONFIG_PATH, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False,
                  allow_unicode=True, width=120)


def _v1_load_monitor_state():
    if V1_MONITOR_STATE.exists():
        try:
            with open(V1_MONITOR_STATE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _extract_agent_id(tags):
    for tag in (tags or []):
        m = re.match(r"^agent-(\d+)$", tag)
        if m:
            return m.group(1).zfill(3)
    return None


def _fetch_agent_metrics():
    now = time.time()
    if _agent_metrics_cache["data"] and now < _agent_metrics_cache["expires"]:
        return _agent_metrics_cache["data"]
    metrics = {}
    try:
        agents_data = _wazuh_api_get(
            "/agents?limit=500&select=id,name,status,lastKeepAlive"
        )
        if not agents_data:
            return metrics
        items = agents_data.get("data", {}).get("affected_items", [])
        for agent in items:
            aid = agent.get("id", "")
            status = agent.get("status", "")
            entry = {
                "agent_status": status,
                "last_keep_alive": agent.get("lastKeepAlive", ""),
            }
            if status == "active" and aid != "000":
                try:
                    hw = _wazuh_api_get("/syscollector/%s/hardware" % aid)
                    if hw:
                        hw_items = hw.get("data", {}).get("affected_items", [])
                        if hw_items:
                            ram = hw_items[0].get("ram", {})
                            cpu = hw_items[0].get("cpu", {})
                            entry["ram_pct"] = ram.get("usage", "")
                            entry["cpu_cores"] = cpu.get("cores", "")
                            entry["cpu_name"] = cpu.get("name", "")
                except Exception:
                    pass
                try:
                    os_data = _wazuh_api_get("/syscollector/%s/os" % aid)
                    if os_data:
                        os_items = os_data.get("data", {}).get("affected_items", [])
                        if os_items:
                            entry["os_name"] = os_items[0].get("os_name", "")
                            entry["os_version"] = os_items[0].get("os_version", "")
                except Exception:
                    pass
            metrics[aid] = entry
    except Exception as e:
        logger.debug("Agent metrics error: %s", e)
    _agent_metrics_cache["data"] = metrics
    _agent_metrics_cache["expires"] = now + AGENT_METRICS_TTL
    return metrics


def _fetch_system_metrics():
    now = time.time()
    if _system_metrics_cache["data"] and now < _system_metrics_cache["expires"]:
        return _system_metrics_cache["data"]
    metrics = {}
    try:
        query = {
            "size": 0,
            "query": {"bool": {"must": [
                {"terms": {"rule.id": ["100860", "100861", "100862",
                                        "100863", "100865", "100866"]}},
                {"range": {"timestamp": {"gte": "now-30m"}}},
            ]}},
            "aggs": {"by_agent": {
                "terms": {"field": "agent.id", "size": 500},
                "aggs": {"latest": {"top_hits": {
                    "size": 1,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "_source": ["agent.id", "data.system_metrics"],
                }}},
            }},
        }
        data = _indexer_query("wazuh-alerts-*", query, timeout=10)
        buckets = (data.get("aggregations", {})
                       .get("by_agent", {}).get("buckets", []))
        for bucket in buckets:
            hits = bucket.get("latest", {}).get("hits", {}).get("hits", [])
            if not hits:
                continue
            src = hits[0].get("_source", {})
            sm = src.get("data", {}).get("system_metrics", {})
            agent_id = src.get("agent", {}).get("id", "")
            if not agent_id or not sm:
                continue
            metrics[agent_id] = {
                "uptime_formatted": sm.get("uptime", {}).get("formatted", ""),
                "cpu_load_1": sm.get("cpu", {}).get("load_1min", ""),
                "disk_max_pct": sm.get("disk_max_usage_pct", ""),
            }
    except Exception as e:
        logger.debug("System metrics error: %s", e)
    _system_metrics_cache["data"] = metrics
    _system_metrics_cache["expires"] = now + SYSTEM_METRICS_TTL
    return metrics


def _build_device_list():
    config = _v1_load_config()
    hosts = config.get("hosts", [])
    monitor_state = _v1_load_monitor_state()
    try:
        agent_metrics = _fetch_agent_metrics()
    except Exception:
        agent_metrics = {}
    try:
        sys_metrics = _fetch_system_metrics()
    except Exception:
        sys_metrics = {}

    devices = []
    for host in hosts:
        addr = host.get("address", "")
        device = {
            "address": addr,
            "name": host.get("name", addr),
            "group": host.get("group", "default"),
            "tags": host.get("tags", []),
            "snmp_enabled": host.get("snmp_enabled", False),
            "icmp": host.get("icmp", {}),
            "snmp": host.get("snmp", {}),
            "cpu": "", "ram": "", "disk": "", "uptime": "",
            "cpu_load": "",
        }
        hs = monitor_state.get(addr, {})
        if hs:
            device["last_seen"] = hs.get("last_check", hs.get("last_seen", ""))
            icmp_r = hs.get("icmp_reachable")
            if icmp_r is True:
                device["status"] = "up"
            elif icmp_r is False:
                device["status"] = "down"
            else:
                device["status"] = hs.get("status", "unknown")
            device["last_rtt"] = hs.get("avg_rtt", 0)
            device["last_loss"] = hs.get("packet_loss", 0)
            sd = hs.get("snmp_data", {})
            sp = hs.get("snmp_perf", {})
            device["uptime"] = sd.get("sysUpTime", "")
            device["cpu"] = sp.get("cpu_load", "")
            device["ram"] = sp.get("ram_percent", "")
            device["disk"] = sp.get("disk_percent", "")
        else:
            device["status"] = "unknown"
            device["last_rtt"] = 0
            device["last_loss"] = 0

        agent_id = _extract_agent_id(host.get("tags", []))
        if agent_id and agent_id in agent_metrics:
            am = agent_metrics[agent_id]
            if not device.get("ram") and am.get("ram_pct") not in (None, ""):
                device["ram"] = am["ram_pct"]
            if not device.get("cpu") and am.get("cpu_cores"):
                device["cpu"] = "%s cores" % am["cpu_cores"]
            device["agent_id"] = agent_id
            device["agent_status"] = am.get("agent_status", "")
            device["last_keep_alive"] = am.get("last_keep_alive", "")
            if am.get("os_name"):
                device["os_info"] = "%s %s" % (
                    am.get("os_name", ""), am.get("os_version", ""))
            agent_st = am.get("agent_status", "")
            if agent_st == "active":
                device["status"] = "up"
                device["status_source"] = "agent"
            elif agent_st == "disconnected":
                device["status"] = "down"
                device["status_source"] = "agent"
            if agent_id in sys_metrics:
                sm = sys_metrics[agent_id]
                if not device.get("disk") and sm.get("disk_max_pct") not in (None, ""):
                    device["disk"] = sm["disk_max_pct"]
                if not device.get("uptime") and sm.get("uptime_formatted"):
                    device["uptime"] = sm["uptime_formatted"]
                if sm.get("cpu_load_1") not in (None, ""):
                    device["cpu_load"] = sm["cpu_load_1"]
        if "status_source" not in device:
            device["status_source"] = "icmp"
        devices.append(device)
    return devices


@app.route("/api/v1/devices")
@login_required
def api_v1_devices():
    """List all V1 devices with full agent enrichment."""
    try:
        devices = _build_device_list()
    except Exception as e:
        logger.warning("V1 devices error: %s", e)
        devices = []
    return jsonify({"devices": devices, "total": len(devices)})


@app.route("/api/v1/devices/<path:address>")
@login_required
def api_v1_device_detail(address):
    """Get single device detail."""
    try:
        devices = _build_device_list()
        for d in devices:
            if d["address"] == address:
                return jsonify(d)
        return jsonify({"error": "Device not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/devices/<path:address>/alerts")
@login_required
def api_v1_device_alerts(address):
    """Get recent Wazuh alerts for a specific device."""
    try:
        config = _v1_load_config()
        host_name = address
        for h in config.get("hosts", []):
            if h.get("address") == address:
                host_name = h.get("name", address)
                break
        query = {
            "size": 10,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"should": [
                {"match_phrase": {"data.host_address": address}},
                {"match_phrase": {"agent.name": host_name}},
            ], "minimum_should_match": 1,
               "filter": [{"range": {"timestamp": {"gte": "now-24h"}}}]}},
            "_source": ["timestamp", "rule.id", "rule.level",
                        "rule.description", "agent.name"],
        }
        data = _indexer_query("wazuh-alerts-*", query, timeout=10)
        alerts = []
        for hit in data.get("hits", {}).get("hits", []):
            src = hit["_source"]
            rule = src.get("rule", {})
            alerts.append({
                "timestamp": src.get("timestamp", ""),
                "rule_id": rule.get("id", ""),
                "level": rule.get("level", 0),
                "description": rule.get("description", ""),
            })
        return jsonify({"alerts": alerts, "total": len(alerts)})
    except Exception as e:
        return jsonify({"alerts": [], "total": 0, "error": str(e)})


@app.route("/api/v1/devices", methods=["POST"])
@login_required
def api_v1_device_add():
    """Add a new device to config.yaml."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    address = data.get("address", "").strip()
    if not address:
        return jsonify({"error": "IP Address is required"}), 400

    config = _v1_load_config()
    for h in config.get("hosts", []):
        if h.get("address") == address:
            return jsonify({"error": "Device %s already exists" % address}), 409

    host = {"address": address}
    if data.get("name"):
        host["name"] = data["name"]
    host["group"] = data.get("group", "default")
    if data.get("tags"):
        host["tags"] = [t.strip() for t in data["tags"].split(",") if t.strip()]

    icmp = {}
    if data.get("ping_count"):
        icmp["count"] = int(data["ping_count"])
    if data.get("latency_warn"):
        icmp["latency_warn"] = float(data["latency_warn"])
    if data.get("latency_crit"):
        icmp["latency_crit"] = float(data["latency_crit"])
    if icmp:
        host["icmp"] = icmp

    if data.get("snmp_enabled"):
        host["snmp_enabled"] = True
        host["snmp"] = {
            "version": data.get("snmp_version", "2c"),
            "community": data.get("snmp_community", "public"),
            "port": int(data.get("snmp_port", 161)),
            "oids": ["sysName", "sysUpTime", "sysDescr"],
            "walk_interfaces": bool(data.get("walk_interfaces")),
            "performance": {
                "enabled": bool(data.get("perf_enabled", True)),
                "cpu_load_warn": float(data.get("cpu_warn", 2.0)),
                "cpu_load_crit": float(data.get("cpu_crit", 5.0)),
                "ram_warn": int(data.get("ram_warn", 80)),
                "ram_crit": int(data.get("ram_crit", 90)),
                "disk_warn": int(data.get("disk_warn", 80)),
                "disk_crit": int(data.get("disk_crit", 90)),
                "disk_mounts": ["/"],
            },
        }

    config.setdefault("hosts", []).append(host)
    _v1_save_config(config)
    logger.info("Added device: %s (%s)", address, host.get("name", ""))
    return jsonify({"message": "Device %s added" % address, "device": host}), 201


@app.route("/api/v1/devices/<path:address>", methods=["PUT"])
@login_required
def api_v1_device_update(address):
    """Update an existing device in config.yaml."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    config = _v1_load_config()
    idx = None
    for i, h in enumerate(config.get("hosts", [])):
        if h.get("address") == address:
            idx = i
            break
    if idx is None:
        return jsonify({"error": "Device not found"}), 404

    host = config["hosts"][idx]
    if "name" in data:
        host["name"] = data["name"]
    if "group" in data:
        host["group"] = data["group"]
    if "tags" in data:
        host["tags"] = [t.strip() for t in data["tags"].split(",") if t.strip()]

    icmp = host.get("icmp", {})
    if data.get("ping_count"):
        icmp["count"] = int(data["ping_count"])
    if data.get("latency_warn"):
        icmp["latency_warn"] = float(data["latency_warn"])
    if data.get("latency_crit"):
        icmp["latency_crit"] = float(data["latency_crit"])
    if icmp:
        host["icmp"] = icmp

    if "snmp_enabled" in data:
        host["snmp_enabled"] = bool(data["snmp_enabled"])
        if host["snmp_enabled"]:
            host["snmp"] = {
                "version": data.get("snmp_version", "2c"),
                "community": data.get("snmp_community", "public"),
                "port": int(data.get("snmp_port", 161)),
                "oids": ["sysName", "sysUpTime", "sysDescr"],
                "walk_interfaces": bool(data.get("walk_interfaces")),
                "performance": {
                    "enabled": bool(data.get("perf_enabled", True)),
                    "cpu_load_warn": float(data.get("cpu_warn", 2.0)),
                    "cpu_load_crit": float(data.get("cpu_crit", 5.0)),
                    "ram_warn": int(data.get("ram_warn", 80)),
                    "ram_crit": int(data.get("ram_crit", 90)),
                    "disk_warn": int(data.get("disk_warn", 80)),
                    "disk_crit": int(data.get("disk_crit", 90)),
                    "disk_mounts": ["/"],
                },
            }

    config["hosts"][idx] = host
    _v1_save_config(config)
    logger.info("Updated device: %s", address)
    return jsonify({"message": "Device %s updated" % address, "device": host})


@app.route("/api/v1/devices/<path:address>", methods=["DELETE"])
@login_required
def api_v1_device_delete(address):
    """Delete a device from config.yaml."""
    config = _v1_load_config()
    idx = None
    for i, h in enumerate(config.get("hosts", [])):
        if h.get("address") == address:
            idx = i
            break
    if idx is None:
        return jsonify({"error": "Device not found"}), 404
    removed = config["hosts"].pop(idx)
    _v1_save_config(config)
    logger.info("Deleted device: %s", address)
    return jsonify({"message": "Device %s deleted" % address})


@app.route("/api/v1/devices/export")
@login_required
def api_v1_devices_export():
    """Export devices as CSV."""
    config = _v1_load_config()
    hosts = config.get("hosts", [])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["address", "name", "group", "tags", "snmp_enabled"])
    for h in hosts:
        writer.writerow([
            h.get("address", ""),
            h.get("name", ""),
            h.get("group", ""),
            ",".join(h.get("tags", [])),
            h.get("snmp_enabled", False),
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=devices.csv"},
    )


@app.route("/api/v1/devices/import", methods=["POST"])
@login_required
def api_v1_devices_import():
    """Import devices from CSV."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    config = _v1_load_config()
    existing = {h.get("address") for h in config.get("hosts", [])}
    added = 0
    skipped = 0

    try:
        content = file.read().decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            addr = (row.get("address") or "").strip()
            if not addr or addr in existing:
                skipped += 1
                continue
            host = {
                "address": addr,
                "name": row.get("name", addr).strip(),
                "group": row.get("group", "default").strip(),
            }
            tags_str = row.get("tags", "")
            if tags_str:
                host["tags"] = [t.strip() for t in tags_str.split(",") if t.strip()]
            if row.get("snmp_enabled", "").lower() in ("true", "1", "yes"):
                host["snmp_enabled"] = True
                host["snmp"] = {
                    "version": "2c", "community": "public", "port": 161,
                    "oids": ["sysName", "sysUpTime", "sysDescr"],
                }
            config.setdefault("hosts", []).append(host)
            existing.add(addr)
            added += 1
        _v1_save_config(config)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"message": "%d added, %d skipped" % (added, skipped),
                    "added": added, "skipped": skipped})


# ===================================================================
# DISCOVERY SCAN (migrated from V1 Web UI)
# ===================================================================
@app.route("/api/discovery/scan", methods=["POST"])
@login_required
def api_discovery_scan():
    """Start an SNMP discovery scan on a subnet."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    subnet = data.get("subnet", "").strip()
    if not subnet:
        return jsonify({"error": "Subnet is required"}), 400
    community = data.get("community", "public")
    ping_first = data.get("ping_first", True)

    with _discovery_lock:
        if _discovery_results.get("_running"):
            return jsonify({"error": "A discovery scan is already running"}), 409
        scan_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        _discovery_results.update({
            "_running": True, "_scan_id": scan_id, "_subnet": subnet,
            "_started": datetime.now(timezone.utc).isoformat(),
            "_status": "running", "_results": [],
        })

    logger.info("Discovery scan started on %s (community=%s)", subnet, community)

    def run_discovery():
        try:
            python = str(DISCOVERY_VENV_PYTHON) if DISCOVERY_VENV_PYTHON.exists() else sys.executable
            cmd = [python, str(DISCOVERY_SCRIPT), "--subnet", subnet,
                   "--community", community, "--output-json"]
            if ping_first:
                cmd.append("--ping-first")
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=600, cwd=str(WODLE_DIR))
            results = []
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    output = json.loads(proc.stdout.strip())
                    if isinstance(output, list):
                        results = output
                    elif isinstance(output, dict):
                        results = output.get("devices",
                                             output.get("discovered", []))
                except json.JSONDecodeError:
                    logger.warning("Discovery output was not valid JSON")
            with _discovery_lock:
                _discovery_results.update({
                    "_running": False, "_status": "completed",
                    "_finished": datetime.now(timezone.utc).isoformat(),
                    "_results": results,
                    "_stdout": (proc.stdout or "")[-2000:],
                    "_stderr": (proc.stderr or "")[-2000:],
                })
            logger.info("Discovery complete: %d devices found", len(results))
        except subprocess.TimeoutExpired:
            with _discovery_lock:
                _discovery_results.update({
                    "_running": False, "_status": "timeout"})
            logger.error("Discovery scan timed out")
        except Exception as e:
            with _discovery_lock:
                _discovery_results.update({
                    "_running": False, "_status": "error: %s" % e,
                })
            logger.error("Discovery error: %s", e)

    threading.Thread(target=run_discovery, daemon=True).start()
    return jsonify({
        "message": "Discovery scan started on %s" % subnet,
        "scan_id": scan_id,
    }), 202


@app.route("/api/discovery/status")
@login_required
def api_discovery_status():
    """Get current discovery scan status and results."""
    with _discovery_lock:
        return jsonify({
            "running": _discovery_results.get("_running", False),
            "status": _discovery_results.get("_status", "idle"),
            "subnet": _discovery_results.get("_subnet", ""),
            "started": _discovery_results.get("_started", ""),
            "finished": _discovery_results.get("_finished", ""),
            "results": _discovery_results.get("_results", []),
            "result_count": len(_discovery_results.get("_results", [])),
        })


@app.route("/api/discovery/add", methods=["POST"])
@login_required
def api_discovery_add():
    """Add a discovered device to the V1 config.yaml."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    address = data.get("address", "").strip()
    if not address:
        return jsonify({"error": "Address is required"}), 400

    try:
        import yaml
        if not V1_CONFIG_PATH.exists():
            return jsonify({"error": "V1 config.yaml not found"}), 404
        with open(V1_CONFIG_PATH, "r") as f:
            config = yaml.safe_load(f) or {}
        hosts = config.get("hosts", [])

        for h in hosts:
            if h.get("address") == address:
                return jsonify({"error": "Device %s already exists" % address}), 409

        host = {"address": address}
        host["name"] = data.get("name", data.get("sysName", address))
        host["group"] = data.get("group",
                                 data.get("suggested_group", "discovered_devices"))
        tags = []
        if data.get("vendor"):
            tags.append(data["vendor"].lower())
        if data.get("os"):
            tags.append(data["os"].lower())
        if data.get("template"):
            tags.append("template:%s" % data["template"])
        host["tags"] = tags

        if data.get("snmp_reachable"):
            host["snmp_enabled"] = True
            host["snmp"] = {
                "version": "2c",
                "community": data.get("snmp_community", "public"),
                "port": data.get("snmp_port", 161),
                "oids": ["sysName", "sysUpTime", "sysDescr"],
                "walk_interfaces": True,
                "performance": {
                    "enabled": True,
                    "cpu_load_warn": 2.0, "cpu_load_crit": 5.0,
                    "ram_warn": 80, "ram_crit": 90,
                    "disk_warn": 80, "disk_crit": 90,
                    "disk_mounts": ["/"],
                },
            }

        config.setdefault("hosts", []).append(host)
        with open(V1_CONFIG_PATH, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        logger.info("Added discovered device: %s (%s)", address, host.get("name"))
        return jsonify({
            "message": "Device %s added to monitoring" % address,
            "device": host,
        }), 201

    except Exception as e:
        logger.error("Discovery add error: %s", e)
        return jsonify({"error": str(e)}), 500


# ===================================================================
# CHANGE PASSWORD
# ===================================================================
@app.route("/api/change-password", methods=["POST"])
@login_required
def api_change_password():
    data = request.get_json()
    current = data.get("current_password", "")
    new_pass = data.get("new_password", "")
    if not new_pass or len(new_pass) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    users = load_users()
    username = session.get("user", "")
    user = users.get(username)
    if not user or not check_password_hash(user["password_hash"], current):
        return jsonify({"error": "Current password is incorrect"}), 401

    users[username]["password_hash"] = generate_password_hash(new_pass)
    save_users(users)
    return jsonify({"message": "Password changed successfully"})


# ===================================================================
# SSL / Main
# ===================================================================
# ===================================================================
# UEBA — User & Entity Behavior Analytics
# ===================================================================
# Inspired by OpenUBA (https://github.com/GACWR/OpenUBA)
# Uses Wazuh alert data from the Indexer to build entity profiles,
# detect anomalies, and calculate risk scores.
# ===================================================================

_ueba_cache = {"data": {}, "expires": 0}
UEBA_CACHE_TTL = 120  # 2 minutes

# RCF Anomaly Detection — dynamic detector discovery with cache
_rcf_detector_cache = {"detectors": [], "expires": 0}
_RCF_DETECTOR_CACHE_TTL = 300  # 5 minutes

# Icon/category mapping based on detector name keywords
_DETECTOR_CATEGORY_MAP = {
    "login": ("Authentication", "shield-lock"),
    "auth": ("Authentication", "shield-lock"),
    "ssh": ("Authentication", "shield-lock"),
    "mitre": ("Threat Detection", "exclamation-triangle"),
    "escalat": ("Threat Detection", "exclamation-triangle"),
    "network": ("Network", "diagram-3"),
    "firewall": ("Network", "diagram-3"),
    "connection": ("Network", "diagram-3"),
    "fim": ("Integrity", "file-earmark-diff"),
    "syscheck": ("Integrity", "file-earmark-diff"),
    "file": ("Integrity", "file-earmark-diff"),
    "health": ("Performance", "heart-pulse"),
    "cpu": ("Performance", "cpu"),
    "memory": ("Performance", "memory"),
}


def _classify_detector(name):
    """Infer category and icon from detector name."""
    name_lower = name.lower()
    for keyword, (category, icon) in _DETECTOR_CATEGORY_MAP.items():
        if keyword in name_lower:
            return category, icon
    return "Security", "cpu"


def _discover_rcf_detectors():
    """Dynamically discover all RCF anomaly detectors from OpenSearch.
    Results are cached for 5 minutes to avoid excessive API calls.
    Any detector you create in OpenSearch will auto-appear here.
    """
    now = time.time()
    if (_rcf_detector_cache["detectors"]
            and now < _rcf_detector_cache["expires"]):
        return _rcf_detector_cache["detectors"]

    detectors = []
    try:
        data = _indexer_request(
            "/_plugins/_anomaly_detection/detectors/_search",
            method="POST",
            body={"query": {"match_all": {}}, "size": 100},
            timeout=15,
        )
        for hit in data.get("hits", {}).get("hits", []):
            det_id = hit["_id"]
            src = hit.get("_source", {})
            name = src.get("name", det_id)
            indices = src.get("indices", [])

            # Skip detectors not targeting wazuh-alerts-* (e.g. sample data)
            if indices and not any("wazuh" in idx for idx in indices):
                continue

            result_index = src.get("result_index", "")
            description = src.get("description", "")
            det_type = src.get("detector_type", "SINGLE_ENTITY")
            category_fields = src.get("category_field", [])
            interval = src.get("detection_interval", {}).get("period", {})
            interval_str = "%s %s" % (
                interval.get("interval", "?"),
                interval.get("unit", ""),
            )

            features = []
            for fa in src.get("feature_attributes", []):
                features.append({
                    "name": fa.get("feature_name", ""),
                    "enabled": fa.get("feature_enabled", False),
                })

            category, icon = _classify_detector(name)

            # Build a readable label from the name
            label = name.replace("-", " ").replace("_", " ").title()

            detectors.append({
                "id": det_id,
                "name": name,
                "label": label,
                "result_index": result_index,
                "category": category,
                "icon": icon,
                "description": description,
                "detector_type": det_type,
                "category_fields": category_fields,
                "interval": interval_str,
                "features": features,
            })

        logger.info("RCF: Discovered %d detectors targeting wazuh-alerts-*",
                     len(detectors))
    except Exception as e:
        logger.warning("RCF: Failed to discover detectors: %s", e)
        # Fall back to cached data if available
        if _rcf_detector_cache["detectors"]:
            return _rcf_detector_cache["detectors"]

    _rcf_detector_cache["detectors"] = detectors
    _rcf_detector_cache["expires"] = now + _RCF_DETECTOR_CACHE_TTL
    return detectors


def _fetch_rcf_detector_status():
    """Get status of all RCF anomaly detectors (auto-discovered)."""
    detectors = _discover_rcf_detectors()
    result = []
    for det in detectors:
        try:
            profile = _indexer_request(
                "/_plugins/_anomaly_detection/detectors/%s/profile" % det["id"],
                timeout=10,
            )
            state = profile.get("state", "UNKNOWN")
            total_entities = profile.get("total_entities", 0)
            init_progress = profile.get("init_progress", {})
            result.append({
                "id": det["id"],
                "name": det["name"],
                "label": det["label"],
                "category": det["category"],
                "icon": det["icon"],
                "description": det.get("description", ""),
                "detector_type": det.get("detector_type", ""),
                "interval": det.get("interval", ""),
                "features": det.get("features", []),
                "state": state,
                "total_entities": total_entities,
                "init_progress": init_progress,
            })
        except Exception as e:
            logger.debug("RCF detector %s status error: %s", det["name"], e)
            result.append({
                "id": det["id"],
                "name": det["name"],
                "label": det["label"],
                "category": det["category"],
                "icon": det["icon"],
                "state": "ERROR",
                "total_entities": 0,
                "init_progress": {},
            })
    return result


def _fetch_rcf_anomalies(timerange="7d"):
    """
    Fetch ML-detected anomalies from all RCF detector result indices.
    Returns anomalies with grade > 0, enriched with correlated alert details.
    Uses admin credentials and epoch_millis for data_start_time range.
    """
    import time as _time
    now_ms = int(_time.time() * 1000)
    delta_map = {
        "1h": 3600_000, "6h": 21600_000, "12h": 43200_000,
        "24h": 86400_000, "7d": 604800_000, "30d": 2592000_000,
    }
    delta = delta_map.get(timerange, 604800_000)
    gte_ms = now_ms - delta

    discovered = _discover_rcf_detectors()
    ml_anomalies = []
    ml_summary = {
        "total_ml_anomalies": 0,
        "detectors_active": 0,
        "detectors_total": len(discovered),
        "by_detector": {},
    }

    for det in discovered:
        try:
            query = {
                "size": 50,
                "sort": [{"data_start_time": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"anomaly_grade": {"gt": 0}}},
                            {"range": {"data_start_time": {"gte": gte_ms}}},
                        ]
                    }
                },
            }
            data = _indexer_query_admin(det["result_index"], query, timeout=15)
            hits = data.get("hits", {}).get("hits", [])
            det_count = data.get("hits", {}).get("total", {}).get("value", 0)
            ml_summary["by_detector"][det["name"]] = det_count
            if det_count > 0:
                ml_summary["detectors_active"] += 1

            for hit in hits:
                src = hit.get("_source", {})
                grade = src.get("anomaly_grade", 0)
                confidence = src.get("confidence", 0)
                entity_name = src.get("entity", [{}])
                if isinstance(entity_name, list) and entity_name:
                    entity_name = entity_name[0].get("value", "unknown")
                elif isinstance(entity_name, dict):
                    entity_name = entity_name.get("value", "unknown")
                else:
                    entity_name = str(entity_name) if entity_name else "unknown"

                start_time = src.get("data_start_time", 0)
                end_time = src.get("data_end_time", 0)

                feature_data = src.get("feature_data", [])
                feature_values = {}
                for fd in feature_data:
                    fname = fd.get("feature_name", "")
                    fval = fd.get("data", 0)
                    feature_values[fname] = fval

                expected = src.get("expected_values", [])
                expected_values = {}
                for ev in expected:
                    likelihood = ev.get("likelihood", 0)
                    val_list = ev.get("value_list", [])
                    if val_list:
                        expected_values["expected"] = val_list[0].get("data", 0)
                    expected_values["likelihood"] = likelihood

                severity = "Critical" if grade >= 0.8 else "High" if grade >= 0.5 else "Medium"

                ml_anomalies.append({
                    "detector_name": det["name"],
                    "detector_label": det["label"],
                    "detector_category": det["category"],
                    "detector_icon": det["icon"],
                    "entity": entity_name,
                    "anomaly_grade": round(grade, 3),
                    "confidence": round(confidence, 3),
                    "severity": severity,
                    "start_time": start_time,
                    "end_time": end_time,
                    "feature_values": feature_values,
                    "expected_values": expected_values,
                    "source": "ml",
                })

        except Exception as e:
            logger.warning("RCF fetch for %s: %s", det["name"], e)

    ml_anomalies.sort(key=lambda x: x["anomaly_grade"], reverse=True)
    ml_summary["total_ml_anomalies"] = len(ml_anomalies)

    # Enrich top ML anomalies with correlated alerts from wazuh-alerts-*
    for anom in ml_anomalies[:30]:
        try:
            start_ms = anom["start_time"]
            end_ms = anom["end_time"]
            entity = anom["entity"]
            if not start_ms or not end_ms or entity == "unknown":
                continue
            corr_query = {
                "size": 5,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"timestamp": {"gte": start_ms, "lte": end_ms, "format": "epoch_millis"}}},
                            {"match_phrase": {"agent.name": entity}},
                            {"range": {"rule.level": {"gte": 3}}},
                        ]
                    }
                },
                "_source": [
                    "timestamp", "rule.id", "rule.level", "rule.description",
                    "rule.groups", "rule.mitre", "data.srcip", "data.srcuser",
                ],
            }
            corr_data = _indexer_query("wazuh-alerts-*", corr_query, timeout=10)
            corr_alerts = []
            for chit in corr_data.get("hits", {}).get("hits", []):
                csrc = chit.get("_source", {})
                crule = csrc.get("rule", {})
                corr_alerts.append({
                    "timestamp": csrc.get("timestamp", ""),
                    "rule_id": crule.get("id", ""),
                    "level": crule.get("level", 0),
                    "description": crule.get("description", ""),
                    "groups": crule.get("groups", []),
                    "mitre": crule.get("mitre", {}),
                    "src_ip": csrc.get("data", {}).get("srcip", ""),
                    "src_user": csrc.get("data", {}).get("srcuser", ""),
                })
            anom["correlated_alerts"] = corr_alerts
        except Exception:
            anom["correlated_alerts"] = []

    return ml_anomalies, ml_summary


def _ueba_build_entity_profiles(timerange="7d"):
    """
    Build entity (user + host) profiles from Wazuh alerts.
    Returns entity risk scores, anomaly counts, behavioral data.
    Includes user-level entity tracking and cross-entity correlation.
    """
    time_map = {"1h": "now-1h", "6h": "now-6h", "12h": "now-12h",
                "24h": "now-24h", "7d": "now-7d", "30d": "now-30d"}
    time_gte = time_map.get(timerange, "now-7d")

    result = {
        "entities": [],
        "user_entities": [],
        "correlations": [],
        "summary": {
            "total_entities": 0,
            "total_users": 0,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0,
            "total_anomalies": 0,
            "total_ml_anomalies": 0,
        },
        "anomaly_types": {},
        "risk_trend": [],
        "top_anomalies": [],
        "ml_anomalies": [],
        "ml_summary": {"total_ml_anomalies": 0, "detectors_active": 0,
                        "detectors_total": 0, "by_detector": {}},
        "timerange": timerange,
    }

    # ----- Query 1: Per-agent alert profile -----
    try:
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_gte}}},
                        {"range": {"rule.level": {"gte": 3}}},
                    ]
                }
            },
            "aggs": {
                "by_agent": {
                    "terms": {"field": "agent.name", "size": 100},
                    "aggs": {
                        "severity": {
                            "range": {
                                "field": "rule.level",
                                "ranges": [
                                    {"key": "low", "from": 3, "to": 7},
                                    {"key": "medium", "from": 7, "to": 10},
                                    {"key": "high", "from": 10, "to": 12},
                                    {"key": "critical", "from": 12},
                                ],
                            }
                        },
                        "rule_types": {
                            "terms": {"field": "rule.description", "size": 10}
                        },
                        "groups": {
                            "terms": {"field": "rule.groups", "size": 20}
                        },
                        "src_ips": {
                            "terms": {"field": "data.srcip", "size": 10}
                        },
                        "hourly": {
                            "date_histogram": {
                                "field": "timestamp",
                                "fixed_interval": "6h" if timerange in ("7d", "30d") else "1h",
                            }
                        },
                        "mitre": {
                            "terms": {"field": "rule.mitre.id", "size": 10}
                        },
                    },
                },
                "anomaly_trend": {
                    "date_histogram": {
                        "field": "timestamp",
                        "fixed_interval": "1d" if timerange in ("7d", "30d") else "6h",
                    },
                    "aggs": {
                        "high_sev": {
                            "filter": {"range": {"rule.level": {"gte": 10}}}
                        }
                    },
                },
            },
        }

        data = _indexer_query("wazuh-alerts-*", query, timeout=30)
        aggs = data.get("aggregations", {})

        # ----- Build entity profiles -----
        entities = []
        for bucket in aggs.get("by_agent", {}).get("buckets", []):
            name = bucket["key"]
            total_alerts = bucket["doc_count"]

            # Severity breakdown
            sev = {}
            for sb in bucket.get("severity", {}).get("buckets", []):
                sev[sb["key"]] = sb["doc_count"]

            critical = sev.get("critical", 0)
            high = sev.get("high", 0)
            medium = sev.get("medium", 0)
            low = sev.get("low", 0)

            # ---- Risk Score Calculation (0-100) ----
            # Weighted formula inspired by OpenUBA's IsolationForest approach
            # but adapted for rule-based Wazuh data
            risk_score = min(100, int(
                critical * 25 +
                high * 10 +
                medium * 2 +
                low * 0.2
            ))

            # Determine risk level
            if risk_score >= 75:
                risk_level = "Critical"
            elif risk_score >= 50:
                risk_level = "High"
            elif risk_score >= 25:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            # Top rule descriptions (behavioral indicators)
            top_rules = []
            for rb in bucket.get("rule_types", {}).get("buckets", []):
                top_rules.append({"description": rb["key"], "count": rb["doc_count"]})

            # Groups for categorization
            groups = [g["key"] for g in bucket.get("groups", {}).get("buckets", [])]

            # Source IPs associated
            src_ips = [ip["key"] for ip in bucket.get("src_ips", {}).get("buckets", [])]

            # Activity timeline (for sparkline)
            activity = []
            for hb in bucket.get("hourly", {}).get("buckets", []):
                activity.append({
                    "time": hb["key_as_string"],
                    "count": hb["doc_count"],
                })

            # MITRE ATT&CK techniques
            mitre = [m["key"] for m in bucket.get("mitre", {}).get("buckets", [])]

            # Anomaly indicators — detect behavioral anomalies
            anomalies = []

            # Anomaly: Authentication failures
            auth_groups = [g for g in groups if any(
                k in g.lower() for k in ["authentication_fail", "invalid_login",
                                          "brute_force", "authentication_failed"]
            )]
            if auth_groups:
                anomalies.append({
                    "type": "Authentication Anomaly",
                    "description": "Multiple authentication failures detected",
                    "severity": "High" if critical + high > 3 else "Medium",
                    "indicators": auth_groups[:3],
                })

            # Anomaly: Privilege escalation
            priv_groups = [g for g in groups if any(
                k in g.lower() for k in ["sudo", "su", "privilege", "escalation",
                                          "admin_login", "root"]
            )]
            if priv_groups:
                anomalies.append({
                    "type": "Privilege Escalation",
                    "description": "Elevated privilege usage detected",
                    "severity": "High",
                    "indicators": priv_groups[:3],
                })

            # Anomaly: Policy violations
            policy_groups = [g for g in groups if any(
                k in g.lower() for k in ["policy", "syscheck", "rootcheck",
                                          "config_changed", "fim"]
            )]
            if policy_groups:
                anomalies.append({
                    "type": "Policy Violation",
                    "description": "System policy or file integrity changes",
                    "severity": "Medium",
                    "indicators": policy_groups[:3],
                })

            # Anomaly: Multiple source IPs (geo-anomaly proxy)
            if len(src_ips) > 3:
                anomalies.append({
                    "type": "Multi-Source Activity",
                    "description": "Activity from %d different source IPs" % len(src_ips),
                    "severity": "Medium",
                    "indicators": src_ips[:5],
                })

            # Anomaly: High volume of critical alerts
            if critical >= 5:
                anomalies.append({
                    "type": "Critical Alert Surge",
                    "description": "%d critical alerts in selected period" % critical,
                    "severity": "Critical",
                    "indicators": [r["description"] for r in top_rules[:3]],
                })

            # Entity type detection
            entity_type = "Host"
            type_icon = "server"
            if any(k in name.lower() for k in ["laptop", "desktop", "pc", "lenovo", "dell", "hp"]):
                entity_type = "Endpoint"
                type_icon = "laptop"
            elif any(k in name.lower() for k in ["fw", "firewall", "fortigate", "palo"]):
                entity_type = "Firewall"
                type_icon = "shield-lock"
            elif any(k in name.lower() for k in ["switch", "router", "ap"]):
                entity_type = "Network"
                type_icon = "router"

            entities.append({
                "name": name,
                "entity_type": entity_type,
                "type_icon": type_icon,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "total_alerts": total_alerts,
                "severity": sev,
                "top_rules": top_rules[:5],
                "groups": groups[:10],
                "src_ips": src_ips,
                "activity": activity,
                "mitre": mitre,
                "anomalies": anomalies,
                "anomaly_count": len(anomalies),
            })

        # Sort by risk score descending
        entities.sort(key=lambda e: e["risk_score"], reverse=True)

        # Summary
        result["entities"] = entities
        result["summary"]["total_entities"] = len(entities)
        result["summary"]["high_risk"] = sum(1 for e in entities if e["risk_score"] >= 50)
        result["summary"]["medium_risk"] = sum(1 for e in entities if 25 <= e["risk_score"] < 50)
        result["summary"]["low_risk"] = sum(1 for e in entities if e["risk_score"] < 25)
        result["summary"]["total_anomalies"] = sum(e["anomaly_count"] for e in entities)

        # Anomaly type breakdown
        anom_types = {}
        for e in entities:
            for a in e["anomalies"]:
                t = a["type"]
                anom_types[t] = anom_types.get(t, 0) + 1
        result["anomaly_types"] = anom_types

        # All anomalies across all entities (no limit)
        all_anomalies = []
        for e in entities:
            for a in e["anomalies"]:
                all_anomalies.append({
                    "entity": e["name"],
                    "entity_type": e["entity_type"],
                    "risk_score": e["risk_score"],
                    **a,
                })
        all_anomalies.sort(key=lambda x: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(x["severity"], 0), reverse=True)
        result["top_anomalies"] = all_anomalies

        # Risk trend over time
        for tb in aggs.get("anomaly_trend", {}).get("buckets", []):
            result["risk_trend"].append({
                "time": tb["key_as_string"],
                "total": tb["doc_count"],
                "high_severity": tb.get("high_sev", {}).get("doc_count", 0),
            })

    except Exception as e:
        logger.warning("UEBA: Error building profiles: %s", e)

    # ----- Query 2: User-level entity profiles -----
    try:
        user_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_gte}}},
                        {"range": {"rule.level": {"gte": 3}}},
                        {"exists": {"field": "data.srcuser"}},
                    ]
                }
            },
            "aggs": {
                "by_user": {
                    "terms": {"field": "data.srcuser", "size": 50},
                    "aggs": {
                        "severity": {
                            "range": {
                                "field": "rule.level",
                                "ranges": [
                                    {"key": "low", "from": 3, "to": 7},
                                    {"key": "medium", "from": 7, "to": 10},
                                    {"key": "high", "from": 10, "to": 12},
                                    {"key": "critical", "from": 12},
                                ],
                            }
                        },
                        "hosts": {
                            "terms": {"field": "agent.name", "size": 20}
                        },
                        "rule_types": {
                            "terms": {"field": "rule.description", "size": 10}
                        },
                        "groups": {
                            "terms": {"field": "rule.groups", "size": 20}
                        },
                        "src_ips": {
                            "terms": {"field": "data.srcip", "size": 10}
                        },
                        "mitre": {
                            "terms": {"field": "rule.mitre.id", "size": 10}
                        },
                        "hourly": {
                            "date_histogram": {
                                "field": "timestamp",
                                "fixed_interval": "6h" if timerange in ("7d", "30d") else "1h",
                            }
                        },
                    },
                },
            },
        }

        user_data = _indexer_query("wazuh-alerts-*", user_query, timeout=30)
        user_aggs = user_data.get("aggregations", {})
        user_entities = []

        for bucket in user_aggs.get("by_user", {}).get("buckets", []):
            uname = bucket["key"]
            if not uname or uname in ("-", "(none)", "unknown", ""):
                continue
            total_alerts = bucket["doc_count"]

            sev = {}
            for sb in bucket.get("severity", {}).get("buckets", []):
                sev[sb["key"]] = sb["doc_count"]

            critical = sev.get("critical", 0)
            high = sev.get("high", 0)
            medium = sev.get("medium", 0)
            low = sev.get("low", 0)

            risk_score = min(100, int(
                critical * 25 + high * 10 + medium * 2 + low * 0.2
            ))
            if risk_score >= 75:
                risk_level = "Critical"
            elif risk_score >= 50:
                risk_level = "High"
            elif risk_score >= 25:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            hosts = [h["key"] for h in bucket.get("hosts", {}).get("buckets", [])]
            groups = [g["key"] for g in bucket.get("groups", {}).get("buckets", [])]
            src_ips = [ip["key"] for ip in bucket.get("src_ips", {}).get("buckets", [])]
            mitre = [m["key"] for m in bucket.get("mitre", {}).get("buckets", [])]
            top_rules = [{"description": rb["key"], "count": rb["doc_count"]}
                         for rb in bucket.get("rule_types", {}).get("buckets", [])]
            activity = [{"time": hb["key_as_string"], "count": hb["doc_count"]}
                        for hb in bucket.get("hourly", {}).get("buckets", [])]

            # Anomaly detection for users
            anomalies = []
            auth_groups = [g for g in groups if any(
                k in g.lower() for k in ["authentication_fail", "invalid_login",
                                          "brute_force", "authentication_failed"]
            )]
            if auth_groups:
                anomalies.append({
                    "type": "Authentication Anomaly",
                    "description": "Multiple authentication failures for user %s" % uname,
                    "severity": "High" if critical + high > 3 else "Medium",
                    "indicators": auth_groups[:3],
                })

            priv_groups = [g for g in groups if any(
                k in g.lower() for k in ["sudo", "su", "privilege", "escalation",
                                          "admin_login", "root"]
            )]
            if priv_groups:
                anomalies.append({
                    "type": "Privilege Escalation",
                    "description": "Elevated privilege usage by user %s" % uname,
                    "severity": "High",
                    "indicators": priv_groups[:3],
                })

            if len(hosts) > 2:
                anomalies.append({
                    "type": "Multi-Host Activity",
                    "description": "User %s active on %d different hosts" % (uname, len(hosts)),
                    "severity": "High" if len(hosts) > 4 else "Medium",
                    "indicators": hosts[:5],
                })

            if len(src_ips) > 2:
                anomalies.append({
                    "type": "Multi-Source Activity",
                    "description": "User %s connecting from %d different IPs" % (uname, len(src_ips)),
                    "severity": "Medium",
                    "indicators": src_ips[:5],
                })

            user_entities.append({
                "name": uname,
                "entity_type": "User",
                "type_icon": "person-fill",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "total_alerts": total_alerts,
                "severity": sev,
                "top_rules": top_rules[:5],
                "groups": groups[:10],
                "src_ips": src_ips,
                "hosts": hosts,
                "activity": activity,
                "mitre": mitre,
                "anomalies": anomalies,
                "anomaly_count": len(anomalies),
            })

        user_entities.sort(key=lambda e: e["risk_score"], reverse=True)
        result["user_entities"] = user_entities
        result["summary"]["total_users"] = len(user_entities)

        # Include user entities in risk level counts
        result["summary"]["high_risk"] += sum(1 for ue in user_entities if ue["risk_score"] >= 50)
        result["summary"]["medium_risk"] += sum(1 for ue in user_entities if 25 <= ue["risk_score"] < 50)
        result["summary"]["low_risk"] += sum(1 for ue in user_entities if ue["risk_score"] < 25)

        # Add user anomalies to top_anomalies, total count, and anomaly_types
        user_anomalies = []
        for ue in user_entities:
            for a in ue.get("anomalies", []):
                user_anomalies.append({
                    "entity": ue["name"],
                    "entity_type": "User",
                    "risk_score": ue["risk_score"],
                    **a,
                })
                atype = a.get("type", "")
                if atype:
                    result["anomaly_types"][atype] = result["anomaly_types"].get(atype, 0) + 1
        if user_anomalies:
            result["top_anomalies"] = result.get("top_anomalies", []) + user_anomalies
            result["top_anomalies"].sort(
                key=lambda x: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(x.get("severity", ""), 0),
                reverse=True,
            )
            result["summary"]["total_anomalies"] = (
                result["summary"].get("total_anomalies", 0) + sum(ue.get("anomaly_count", 0) for ue in user_entities)
            )

    except Exception as e:
        logger.warning("UEBA: Error building user profiles: %s", e)

    # ----- Query 3: Cross-entity correlation (IPs targeting multiple hosts) -----
    try:
        corr_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_gte}}},
                        {"range": {"rule.level": {"gte": 7}}},
                        {"exists": {"field": "data.srcip"}},
                    ]
                }
            },
            "aggs": {
                "by_srcip": {
                    "terms": {"field": "data.srcip", "size": 50},
                    "aggs": {
                        "targets": {
                            "terms": {"field": "agent.name", "size": 20}
                        },
                        "users": {
                            "terms": {"field": "data.srcuser", "size": 10}
                        },
                        "rule_types": {
                            "terms": {"field": "rule.description", "size": 5}
                        },
                        "mitre": {
                            "terms": {"field": "rule.mitre.id", "size": 5}
                        },
                        "severity": {
                            "range": {
                                "field": "rule.level",
                                "ranges": [
                                    {"key": "medium", "from": 7, "to": 10},
                                    {"key": "high", "from": 10, "to": 12},
                                    {"key": "critical", "from": 12},
                                ],
                            }
                        },
                    },
                },
            },
        }
        corr_data = _indexer_query("wazuh-alerts-*", corr_query, timeout=20)
        corr_aggs = corr_data.get("aggregations", {})
        correlations = []

        for bucket in corr_aggs.get("by_srcip", {}).get("buckets", []):
            src_ip = bucket["key"]
            targets = [t["key"] for t in bucket.get("targets", {}).get("buckets", [])]
            if len(targets) < 2:
                continue

            users = [u["key"] for u in bucket.get("users", {}).get("buckets", [])]
            top_rules = [r["key"] for r in bucket.get("rule_types", {}).get("buckets", [])]
            mitre = [m["key"] for m in bucket.get("mitre", {}).get("buckets", [])]

            sev = {}
            for sb in bucket.get("severity", {}).get("buckets", []):
                sev[sb["key"]] = sb["doc_count"]
            critical = sev.get("critical", 0)
            high = sev.get("high", 0)

            severity = "Critical" if critical > 0 else "High" if high > 0 else "Medium"

            correlations.append({
                "source_ip": src_ip,
                "target_count": len(targets),
                "targets": targets,
                "users": users,
                "total_alerts": bucket["doc_count"],
                "top_rules": top_rules,
                "mitre": mitre,
                "severity": severity,
            })

        correlations.sort(key=lambda c: c["target_count"], reverse=True)
        result["correlations"] = correlations[:15]

    except Exception as e:
        logger.warning("UEBA: Error building correlations: %s", e)

    # ----- Query 4: RCF ML anomaly detection results -----
    try:
        ml_anomalies, ml_summary = _fetch_rcf_anomalies(timerange)
        result["ml_anomalies"] = ml_anomalies
        result["ml_summary"] = ml_summary

        # Enrich entity profiles with ML anomaly counts
        entity_ml_map = {}
        for ma in ml_anomalies:
            ename = ma.get("entity", "")
            if ename not in entity_ml_map:
                entity_ml_map[ename] = []
            entity_ml_map[ename].append(ma)

        for e in result.get("entities", []):
            ml_hits = entity_ml_map.get(e["name"], [])
            e["ml_anomaly_count"] = len(ml_hits)
            e["ml_max_grade"] = max((h["anomaly_grade"] for h in ml_hits), default=0)
            e["ml_max_confidence"] = max((h["confidence"] for h in ml_hits), default=0)
            if ml_hits:
                best = max(ml_hits, key=lambda x: x["anomaly_grade"])
                e["ml_top_detector"] = best.get("detector_label", "")

        # Add ML anomalies to top_anomalies with source='ml' marker
        for ma in ml_anomalies:
            result["top_anomalies"].append({
                "entity": ma["entity"],
                "entity_type": "Host",
                "risk_score": 0,
                "type": "ML: %s" % ma["detector_label"],
                "description": "RCF anomaly grade %.2f (confidence %.0f%%)" % (
                    ma["anomaly_grade"], ma["confidence"] * 100),
                "severity": ma["severity"],
                "indicators": [a.get("description", "") for a in ma.get("correlated_alerts", [])[:3]],
                "source": "ml",
                "anomaly_grade": ma["anomaly_grade"],
                "confidence": ma["confidence"],
                "detector_name": ma["detector_name"],
                "detector_label": ma["detector_label"],
                "detector_icon": ma["detector_icon"],
                "start_time": ma["start_time"],
                "end_time": ma["end_time"],
                "correlated_alerts": ma.get("correlated_alerts", []),
                "feature_values": ma.get("feature_values", {}),
                "expected_values": ma.get("expected_values", {}),
            })

        # Re-sort: ML anomalies by grade, rule-based by severity
        def _anomaly_sort_key(x):
            if x.get("source") == "ml":
                return (5, x.get("anomaly_grade", 0))
            sev_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            return (sev_map.get(x.get("severity", ""), 0), 0)
        result["top_anomalies"].sort(key=_anomaly_sort_key, reverse=True)

        result["summary"]["total_ml_anomalies"] = ml_summary["total_ml_anomalies"]
    except Exception as e:
        logger.warning("UEBA: Error fetching RCF anomalies: %s", e)
        result["ml_anomalies"] = []
        result["ml_summary"] = {"total_ml_anomalies": 0, "detectors_active": 0,
                                "detectors_total": 0, "by_detector": {}}

    return result


@app.route("/api/ueba/summary")
@login_required
def api_ueba_summary():
    """UEBA entity risk summary."""
    timerange = request.args.get("timerange", "7d")

    now = time.time()
    cache_key = "ueba_%s" % timerange
    if (_ueba_cache.get("key") == cache_key
            and _ueba_cache["data"] and now < _ueba_cache["expires"]):
        return jsonify(_ueba_cache["data"])

    data = _ueba_build_entity_profiles(timerange)

    _ueba_cache["key"] = cache_key
    _ueba_cache["data"] = data
    _ueba_cache["expires"] = now + UEBA_CACHE_TTL

    return jsonify(data)


@app.route("/api/ueba/entity/<entity_name>")
@login_required
def api_ueba_entity_detail(entity_name):
    """Detailed UEBA profile for a single entity."""
    timerange = request.args.get("timerange", "7d")
    time_map = {"1h": "now-1h", "6h": "now-6h", "12h": "now-12h",
                "24h": "now-24h", "7d": "now-7d", "30d": "now-30d"}
    time_gte = time_map.get(timerange, "now-7d")

    result = {
        "entity": entity_name,
        "alerts": [],
        "timeline": [],
    }

    try:
        # Get recent alerts for this entity
        query = {
            "size": 50,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_gte}}},
                        {"match_phrase": {"agent.name": entity_name}},
                        {"range": {"rule.level": {"gte": 3}}},
                    ]
                }
            },
            "_source": [
                "timestamp", "rule.id", "rule.level", "rule.description",
                "rule.groups", "rule.mitre", "data.srcip", "data.dstip",
                "data.srcuser", "data.dstuser", "agent.name",
            ],
        }
        data = _indexer_query("wazuh-alerts-*", query, timeout=15)
        for hit in data.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            rule = src.get("rule", {})
            alert_data = src.get("data", {})
            result["alerts"].append({
                "timestamp": src.get("timestamp", ""),
                "rule_id": rule.get("id", ""),
                "level": rule.get("level", 0),
                "severity": _level_to_severity(rule.get("level", 0)),
                "description": rule.get("description", ""),
                "groups": rule.get("groups", []),
                "mitre": rule.get("mitre", {}),
                "src_ip": alert_data.get("srcip", ""),
                "src_user": alert_data.get("srcuser", ""),
            })

    except Exception as e:
        logger.warning("UEBA entity detail error: %s", e)

    return jsonify(result)


@app.route("/api/ueba/user/<username>")
@login_required
def api_ueba_user_detail(username):
    """Detailed UEBA profile for a user entity (by data.srcuser)."""
    timerange = request.args.get("timerange", "7d")
    time_map = {"1h": "now-1h", "6h": "now-6h", "12h": "now-12h",
                "24h": "now-24h", "7d": "now-7d", "30d": "now-30d"}
    time_gte = time_map.get(timerange, "now-7d")

    result = {"entity": username, "alerts": [], "timeline": []}

    try:
        query = {
            "size": 50,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_gte}}},
                        {"match_phrase": {"data.srcuser": username}},
                        {"range": {"rule.level": {"gte": 3}}},
                    ]
                }
            },
            "_source": [
                "timestamp", "rule.id", "rule.level", "rule.description",
                "rule.groups", "rule.mitre", "data.srcip", "data.dstip",
                "data.srcuser", "data.dstuser", "agent.name",
            ],
        }
        data = _indexer_query("wazuh-alerts-*", query, timeout=15)
        for hit in data.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            rule = src.get("rule", {})
            alert_data = src.get("data", {})
            result["alerts"].append({
                "timestamp": src.get("timestamp", ""),
                "rule_id": rule.get("id", ""),
                "level": rule.get("level", 0),
                "severity": _level_to_severity(rule.get("level", 0)),
                "description": rule.get("description", ""),
                "groups": rule.get("groups", []),
                "mitre": rule.get("mitre", {}),
                "src_ip": alert_data.get("srcip", ""),
                "src_user": alert_data.get("srcuser", ""),
                "agent": src.get("agent", {}).get("name", ""),
            })
    except Exception as e:
        logger.warning("UEBA user detail error: %s", e)

    return jsonify(result)


@app.route("/api/ueba/correlation/<src_ip>")
@login_required
def api_ueba_correlation_detail(src_ip):
    """Detailed alerts for a cross-entity correlation source IP."""
    timerange = request.args.get("timerange", "7d")
    time_map = {"1h": "now-1h", "6h": "now-6h", "12h": "now-12h",
                "24h": "now-24h", "7d": "now-7d", "30d": "now-30d"}
    time_gte = time_map.get(timerange, "now-7d")

    result = {"source_ip": src_ip, "alerts": []}

    try:
        query = {
            "size": 50,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": time_gte}}},
                        {"match_phrase": {"data.srcip": src_ip}},
                        {"range": {"rule.level": {"gte": 7}}},
                    ]
                }
            },
            "_source": [
                "timestamp", "rule.id", "rule.level", "rule.description",
                "rule.groups", "rule.mitre", "data.srcip",
                "data.srcuser", "agent.name",
            ],
        }
        data = _indexer_query("wazuh-alerts-*", query, timeout=15)
        for hit in data.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            rule = src.get("rule", {})
            alert_data = src.get("data", {})
            result["alerts"].append({
                "timestamp": src.get("timestamp", ""),
                "rule_id": rule.get("id", ""),
                "level": rule.get("level", 0),
                "severity": _level_to_severity(rule.get("level", 0)),
                "description": rule.get("description", ""),
                "mitre": rule.get("mitre", {}),
                "src_ip": alert_data.get("srcip", ""),
                "src_user": alert_data.get("srcuser", ""),
                "target_host": src.get("agent", {}).get("name", ""),
            })
    except Exception as e:
        logger.warning("UEBA correlation detail error: %s", e)

    return jsonify(result)


@app.route("/api/ueba/rcf/detectors")
@login_required
def api_ueba_rcf_detectors():
    """Get status of all RCF anomaly detectors."""
    detectors = _fetch_rcf_detector_status()
    return jsonify({"detectors": detectors})


@app.route("/api/ueba/rcf/detectors/refresh", methods=["POST"])
@login_required
def api_ueba_rcf_refresh_cache():
    """Force-refresh the detector discovery cache."""
    _rcf_detector_cache["expires"] = 0
    detectors = _discover_rcf_detectors()
    return jsonify({"status": "ok", "detectors_found": len(detectors)})


@app.route("/api/ueba/rcf/detectors/<detector_id>/start", methods=["POST"])
@login_required
def api_ueba_rcf_start(detector_id):
    """Start an RCF anomaly detector."""
    try:
        result = _indexer_request(
            "/_plugins/_anomaly_detection/detectors/%s/_start" % detector_id,
            method="POST",
            timeout=15,
        )
        return jsonify({"status": "ok", "result": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/ueba/rcf/detectors/<detector_id>/stop", methods=["POST"])
@login_required
def api_ueba_rcf_stop(detector_id):
    """Stop an RCF anomaly detector."""
    try:
        result = _indexer_request(
            "/_plugins/_anomaly_detection/detectors/%s/_stop" % detector_id,
            method="POST",
            timeout=15,
        )
        return jsonify({"status": "ok", "result": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ===================================================================
# CASES — Incident Investigation & Case Management (FortiSIEM-style)
# ===================================================================
# Groups related Wazuh alerts into cases by rule + agent + time proximity.
# Provides timeline, topology graph, and event drill-down per case.
# ===================================================================

_cases_cache = {"data": None, "expires": 0}
_CASES_CACHE_TTL = 180  # 3 minutes


def _build_cases(timerange="7d"):
    """
    Build cases by grouping alerts with same rule.id that occur on same/multiple
    agents within a time window. Each case contains multiple incidents (individual
    alert occurrences) with source IPs, GeoIP, and MITRE mapping.
    """
    now = time.time()
    if _cases_cache["data"] and now < _cases_cache["expires"]:
        cached = _cases_cache["data"]
        if cached.get("_timerange") == timerange:
            return cached

    delta_map = {
        "1h": "now-1h", "6h": "now-6h", "12h": "now-12h",
        "24h": "now-24h", "7d": "now-7d", "30d": "now-30d",
    }
    gte = delta_map.get(timerange, "now-7d")

    # Query: aggregate by rule.id, then by source IP, with top hits for details
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": gte}}},
                    {"range": {"rule.level": {"gte": 5}}},
                ]
            }
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.id", "size": 50, "order": {"_count": "desc"}},
                "aggs": {
                    "rule_desc": {"top_hits": {"size": 1, "_source": ["rule.description"]}},
                    "rule_level": {"max": {"field": "rule.level"}},
                    "rule_groups": {"terms": {"field": "rule.groups", "size": 10}},
                    "mitre_tactic": {"terms": {"field": "rule.mitre.tactic", "size": 5}},
                    "mitre_technique": {"terms": {"field": "rule.mitre.technique", "size": 5}},
                    "mitre_id": {"terms": {"field": "rule.mitre.id", "size": 5}},
                    "by_srcip": {
                        "terms": {"field": "data.srcip", "size": 20},
                        "aggs": {
                            "geo": {
                                "top_hits": {
                                    "size": 1,
                                    "_source": [
                                        "GeoLocation.city_name",
                                        "GeoLocation.country_name",
                                        "GeoLocation.region_name",
                                        "GeoLocation.location",
                                    ],
                                }
                            },
                            "first_seen": {"min": {"field": "timestamp"}},
                            "last_seen": {"max": {"field": "timestamp"}},
                        },
                    },
                    "by_agent": {
                        "terms": {"field": "agent.name", "size": 20},
                        "aggs": {
                            "count": {"value_count": {"field": "timestamp"}},
                        },
                    },
                    "first_occurred": {"min": {"field": "timestamp"}},
                    "last_occurred": {"max": {"field": "timestamp"}},
                    "timeline": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "1d",
                        }
                    },
                },
            }
        },
    }

    try:
        data = _indexer_query("wazuh-alerts-*", query, timeout=30)
    except Exception as e:
        logger.warning("Cases: query error: %s", e)
        return {"cases": [], "summary": {}}

    rule_buckets = data.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    cases = []
    case_id_counter = 7302730000  # FortiSIEM-style case ID prefix

    for rb in rule_buckets:
        rule_id = rb["key"]
        total_count = rb["doc_count"]
        rule_desc_hits = rb.get("rule_desc", {}).get("hits", {}).get("hits", [])
        rule_desc = "Unknown Rule"
        if rule_desc_hits:
            rule_desc = rule_desc_hits[0].get("_source", {}).get("rule", {}).get("description", "Unknown Rule")
        rule_level = int(rb.get("rule_level", {}).get("value", 0) or 0)
        rule_groups = [g["key"] for g in rb.get("rule_groups", {}).get("buckets", [])]

        mitre_tactics = [t["key"] for t in rb.get("mitre_tactic", {}).get("buckets", [])]
        mitre_techniques = [t["key"] for t in rb.get("mitre_technique", {}).get("buckets", [])]
        mitre_ids = [t["key"] for t in rb.get("mitre_id", {}).get("buckets", [])]

        first_occurred = rb.get("first_occurred", {}).get("value_as_string", "")
        last_occurred = rb.get("last_occurred", {}).get("value_as_string", "")

        # Severity mapping (Wazuh level -> FortiSIEM severity)
        if rule_level >= 12:
            severity = "Critical"
        elif rule_level >= 9:
            severity = "High"
        elif rule_level >= 5:
            severity = "Medium"
        else:
            severity = "Low"

        # Build incidents from source IPs
        incidents = []
        srcip_buckets = rb.get("by_srcip", {}).get("buckets", [])
        for sip in srcip_buckets:
            ip = sip["key"]
            ip_count = sip["doc_count"]
            geo_hits = sip.get("geo", {}).get("hits", {}).get("hits", [])
            geo_data = {}
            if geo_hits:
                geo_src = geo_hits[0].get("_source", {}).get("GeoLocation", {})
                geo_data = {
                    "city": geo_src.get("city_name", ""),
                    "country": geo_src.get("country_name", ""),
                    "region": geo_src.get("region_name", ""),
                    "lat": geo_src.get("location", {}).get("lat"),
                    "lon": geo_src.get("location", {}).get("lon"),
                }
            first_seen = sip.get("first_seen", {}).get("value_as_string", "")
            last_seen = sip.get("last_seen", {}).get("value_as_string", "")

            case_id_counter += 1
            incidents.append({
                "incident_id": case_id_counter,
                "src_ip": ip,
                "entity_type": "ip",
                "count": ip_count,
                "geo": geo_data,
                "first_seen": first_seen,
                "last_seen": last_seen,
            })

        # Agents involved
        agents = []
        for ab in rb.get("by_agent", {}).get("buckets", []):
            agents.append({"name": ab["key"], "count": ab["doc_count"]})

        # If no source IPs, create incidents from agents instead
        if not incidents and agents:
            for ag in agents:
                case_id_counter += 1
                incidents.append({
                    "incident_id": case_id_counter,
                    "src_ip": "",
                    "agent_name": ag["name"],
                    "entity_type": "agent",
                    "count": ag["count"],
                    "geo": {},
                    "first_seen": first_occurred,
                    "last_seen": last_occurred,
                })

        # Timeline histogram
        timeline = []
        for tb in rb.get("timeline", {}).get("buckets", []):
            timeline.append({
                "date": tb.get("key_as_string", ""),
                "count": tb["doc_count"],
            })

        case_id_counter += 1
        cases.append({
            "case_id": case_id_counter,
            "rule_id": rule_id,
            "title": rule_desc,
            "severity": severity,
            "rule_level": rule_level,
            "rule_groups": rule_groups,
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "mitre_ids": mitre_ids,
            "total_events": total_count,
            "incident_count": len(incidents),
            "incidents": incidents,
            "agents": agents,
            "first_occurred": first_occurred,
            "last_occurred": last_occurred,
            "timeline": timeline,
            "status": "Active",
        })

    # Sort by severity then event count
    sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    cases.sort(key=lambda c: (sev_order.get(c["severity"], 0), c["total_events"]),
               reverse=True)

    summary = {
        "total_cases": len(cases),
        "critical": sum(1 for c in cases if c["severity"] == "Critical"),
        "high": sum(1 for c in cases if c["severity"] == "High"),
        "medium": sum(1 for c in cases if c["severity"] == "Medium"),
        "low": sum(1 for c in cases if c["severity"] == "Low"),
        "total_incidents": sum(c["incident_count"] for c in cases),
        "total_events": sum(c["total_events"] for c in cases),
    }

    result = {"cases": cases, "summary": summary, "_timerange": timerange}
    _cases_cache["data"] = result
    _cases_cache["expires"] = now + _CASES_CACHE_TTL
    return result


def _get_case_events(rule_id, src_ip=None, agent_name=None,
                     timerange="7d", page=1, size=100):
    """Fetch raw trigger events for a specific case/incident."""
    delta_map = {
        "1h": "now-1h", "6h": "now-6h", "12h": "now-12h",
        "24h": "now-24h", "7d": "now-7d", "30d": "now-30d",
    }
    gte = delta_map.get(timerange, "now-7d")

    must = [
        {"range": {"timestamp": {"gte": gte}}},
        {"term": {"rule.id": rule_id}},
    ]
    if src_ip:
        must.append({"term": {"data.srcip": src_ip}})
    if agent_name:
        must.append({"term": {"agent.name": agent_name}})

    query = {
        "size": size,
        "from": (page - 1) * size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": must}},
        "_source": [
            "timestamp", "agent.name", "agent.id", "rule.id", "rule.level",
            "rule.description", "rule.groups", "rule.mitre",
            "data.srcip", "data.srcuser", "data.dstuser", "data.srcport",
            "data.dstport", "data.protocol", "GeoLocation",
            "full_log", "decoder.name",
        ],
    }

    try:
        data = _indexer_query("wazuh-alerts-*", query, timeout=20)
        hits = data.get("hits", {}).get("hits", [])
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        events = []
        for hit in hits:
            src = hit.get("_source", {})
            events.append({
                "timestamp": src.get("timestamp", ""),
                "agent": src.get("agent", {}).get("name", ""),
                "rule_id": src.get("rule", {}).get("id", ""),
                "rule_level": src.get("rule", {}).get("level", 0),
                "rule_description": src.get("rule", {}).get("description", ""),
                "src_ip": src.get("data", {}).get("srcip", ""),
                "src_user": src.get("data", {}).get("srcuser", ""),
                "dst_user": src.get("data", {}).get("dstuser", ""),
                "src_port": src.get("data", {}).get("srcport", ""),
                "dst_port": src.get("data", {}).get("dstport", ""),
                "geo": {
                    "city": src.get("GeoLocation", {}).get("city_name", ""),
                    "country": src.get("GeoLocation", {}).get("country_name", ""),
                },
                "full_log": (src.get("full_log", "") or "")[:500],
                "decoder": src.get("decoder", {}).get("name", ""),
            })
        return {"events": events, "total": total, "page": page, "size": size}
    except Exception as e:
        logger.warning("Cases: event query error: %s", e)
        return {"events": [], "total": 0, "page": page, "size": size}


# --- Cases API endpoints ---

@app.route("/api/cases")
@login_required
def api_cases():
    """Get all cases (grouped incidents)."""
    timerange = request.args.get("timerange", "7d")
    result = _build_cases(timerange)
    return jsonify(result)


@app.route("/api/cases/<int:case_id>")
@login_required
def api_case_detail(case_id):
    """Get detail for a specific case."""
    timerange = request.args.get("timerange", "7d")
    result = _build_cases(timerange)
    for c in result.get("cases", []):
        if c["case_id"] == case_id:
            return jsonify(c)
    return jsonify({"error": "Case not found"}), 404


@app.route("/api/cases/<int:case_id>/events")
@login_required
def api_case_events(case_id):
    """Get raw trigger events for a case."""
    timerange = request.args.get("timerange", "7d")
    page = int(request.args.get("page", 1))
    src_ip = request.args.get("src_ip")
    agent_name = request.args.get("agent_name")

    result = _build_cases(timerange)
    case = None
    for c in result.get("cases", []):
        if c["case_id"] == case_id:
            case = c
            break
    if not case:
        return jsonify({"error": "Case not found"}), 404

    events = _get_case_events(case["rule_id"], src_ip=src_ip,
                              agent_name=agent_name,
                              timerange=timerange, page=page)
    return jsonify(events)


def generate_self_signed_cert(cert_dir):
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_file = cert_dir / "server.pem"
    key_file = cert_dir / "server.key"
    if cert_file.exists() and key_file.exists():
        return str(cert_file), str(key_file)
    logger.info("Generating self-signed certificate...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key_file), "-out", str(cert_file),
        "-days", "365", "-nodes",
        "-subj", "/CN=wazuh-soc-dashboard/O=Wazuh/C=US",
    ], check=True, capture_output=True)
    return str(cert_file), str(key_file)


def find_letsencrypt_cert():
    """Check for Let's Encrypt cert on the Wazuh server."""
    le_dir = Path("/etc/letsencrypt/live")
    if le_dir.exists():
        for domain_dir in le_dir.iterdir():
            cert = domain_dir / "fullchain.pem"
            key = domain_dir / "privkey.pem"
            if cert.exists() and key.exists():
                return str(cert), str(key)
    return None, None


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Ai-SOC.MSP Dashboard V2")
    parser.add_argument("--port", type=int, default=8444)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        global logger
        logger = setup_logging(debug=True)

    # Try Let's Encrypt first, fall back to self-signed
    cert_file, key_file = find_letsencrypt_cert()
    if not cert_file:
        cert_file, key_file = generate_self_signed_cert(CERT_DIR)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(cert_file, key_file)

    logger.info("Starting Ai-SOC.MSP Dashboard V2 on https://%s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port, ssl_context=ssl_context, debug=args.debug)


if __name__ == "__main__":
    main()
