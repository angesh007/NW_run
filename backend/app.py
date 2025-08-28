#!/usr/bin/env python3
# app.py — Backend API for Security MVP (investor-ready)

import os
import json
import datetime as dt
from datetime import timezone
from decimal import Decimal
from collections import Counter

from flask import Flask, jsonify, request
from flask_cors import CORS
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# OpenAI v1 SDK (optional)
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

load_dotenv()

# ------------------ Config ------------------ #
DATABASE_URL = os.getenv("DATABASE_URL")  # e.g. postgresql+psycopg2://user:pass@host:5432/db
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN")  # e.g. https://your-frontend.example.com
COMPLIANCE_TABLE = os.getenv("COMPLIANCE_TABLE", "regulatory_compliance")  # change if spelled differently

app = Flask(__name__)
if FRONTEND_ORIGIN:
    CORS(app, resources={r"/api/*": {"origins": FRONTEND_ORIGIN}})
else:
    # Dev: allow all
    CORS(app)

# Engine with sane timeouts/pooling
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=10,
    connect_args={"options": "-c statement_timeout=8000"}  # 8s per statement
)

# ------------------ Helpers ------------------ #
# ------------------ Helpers ------------------ #
def _to_float(v, default=0.0):
    try:
        if v is None:
            return default
        if isinstance(v, (float, int)):
            return float(v)
        if isinstance(v, Decimal):
            return float(v)
        return float(str(v))
    except Exception:
        return default

def _today_range_utc():
    now_utc = dt.datetime.now(tz=timezone.utc)
    start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    end   = start.replace(hour=23, minute=59, second=59, microsecond=999999)
    return start, end

def _yesterday_range_utc():
    now_utc = dt.datetime.now(tz=timezone.utc)
    y = (now_utc - dt.timedelta(days=1)).date()
    start = dt.datetime(y.year, y.month, y.day, tzinfo=timezone.utc)
    end   = start.replace(hour=23, minute=59, second=59, microsecond=999999)
    return start, end

def _json_bool_true_sql(expr: str) -> str:
    """
    Safe boolean check for JSON text booleans:
    expr should be something like "data->>'active_threat'".
    """
    return f"( {expr} IS NOT NULL AND lower({expr}) IN ('true','t','1') )"
# =========================================================
#                       API ROUTES
# =========================================================
# --- helpers (UTC day ranges) ---
# simple in-memory toggle (OK for MVP demo)
AUTO_REM_ENABLED = True

@app.route("/api/summary")
def summary():
    """
    Returns KPI + human-readable story fields for investor view.
    """
    start, end   = _today_range_utc()
    ystart, yend = _yesterday_range_utc()

    with engine.connect() as conn:
        # -------- Active threats today / yesterday --------
        q_active = text("""
            WITH ul AS (
              SELECT COUNT(*) AS c
              FROM devl.unified_logs
              WHERE "timestamp" BETWEEN :start AND :end
                AND lower(coalesce(data->>'active_threat','')) IN ('true','t','1')
            ),
            ml AS (
              SELECT COUNT(*) AS c
              FROM devl.model_logs
              WHERE "timestamp" BETWEEN :start AND :end
                AND predicted_active_threat = true
            )
            SELECT (SELECT c FROM ul) + (SELECT c FROM ml) AS total;
        """)
        active_today = _to_float(conn.execute(q_active, {"start": start, "end": end}).scalar(), 0.0)

        q_active_y = text("""
            WITH ul AS (
              SELECT COUNT(*) AS c
              FROM devl.unified_logs
              WHERE "timestamp" BETWEEN :start AND :end
                AND lower(coalesce(data->>'active_threat','')) IN ('true','t','1')
            ),
            ml AS (
              SELECT COUNT(*) AS c
              FROM devl.model_logs
              WHERE "timestamp" BETWEEN :start AND :end
                AND predicted_active_threat = true
            )
            SELECT (SELECT c FROM ul) + (SELECT c FROM ml) AS total;
        """)
        active_yesterday = _to_float(conn.execute(q_active_y, {"start": ystart, "end": yend}).scalar(), 0.0)

        change_pct = 0.0
        if active_yesterday > 0:
            change_pct = (active_today - active_yesterday) * 100.0 / active_yesterday

        # -------- Model accuracy snapshot (or 7d fallback) --------
        q_acc = text("""
            SELECT accuracy_overall
            FROM devl.model_logs
            WHERE accuracy_overall IS NOT NULL
            ORDER BY accuracy_updated_at DESC NULLS LAST, created_at DESC
            LIMIT 1;
        """)
        row = conn.execute(q_acc).first()
        if row and row.accuracy_overall is not None:
            model_accuracy = _to_float(row.accuracy_overall, 0.0) * 1.0
        else:
            q_acc_7d = text("""
                SELECT
                  SUM(CASE WHEN feedback_label IS NOT NULL
                            AND (
                              (feedback_label = 1 AND predicted_anomaly = true) OR
                              (feedback_label = 0 AND predicted_anomaly = false)
                            )
                      THEN 1 ELSE 0 END)::float /
                  NULLIF(SUM(CASE WHEN feedback_label IS NOT NULL THEN 1 ELSE 0 END),0) AS acc
                FROM devl.model_logs
                WHERE "timestamp" >= NOW() - INTERVAL '7 days';
            """)
            acc = conn.execute(q_acc_7d).scalar()
            model_accuracy = (_to_float(acc, 0.0) * 100.0) if acc is not None else 0.0

        # Trend vs prior week (pp)
        q_acc_trend = text("""
            WITH this AS (
              SELECT
                SUM(CASE WHEN feedback_label IS NOT NULL
                          AND (
                            (feedback_label = 1 AND predicted_anomaly = true) OR
                            (feedback_label = 0 AND predicted_anomaly = false)
                          )
                    THEN 1 ELSE 0 END)::float /
                NULLIF(SUM(CASE WHEN feedback_label IS NOT NULL THEN 1 ELSE 0 END),0) AS acc
              FROM devl.model_logs
              WHERE "timestamp" >= NOW() - INTERVAL '7 days'
            ),
            prev AS (
              SELECT
                SUM(CASE WHEN feedback_label IS NOT NULL
                          AND (
                            (feedback_label = 1 AND predicted_anomaly = true) OR
                            (feedback_label = 0 AND predicted_anomaly = false)
                          )
                    THEN 1 ELSE 0 END)::float /
                NULLIF(SUM(CASE WHEN feedback_label IS NOT NULL THEN 1 ELSE 0 END),0) AS acc
              FROM devl.model_logs
              WHERE "timestamp" >= NOW() - INTERVAL '14 days'
                AND "timestamp" < NOW() - INTERVAL '7 days'
            )
            SELECT (COALESCE((SELECT acc FROM this),0) - COALESCE((SELECT acc FROM prev),0)) * 100.0;
        """)
        trend_pct = _to_float(conn.execute(q_acc_trend).scalar(), 0.0)

        # -------- Data coverage (today vs 30d baseline) --------
        q_cov = text("""
            WITH baseline AS (
              SELECT COUNT(DISTINCT source_file) AS n
              FROM devl.unified_logs
              WHERE "timestamp" >= NOW() - INTERVAL '30 days'
            ),
            today AS (
              SELECT COUNT(DISTINCT source_file) AS n
              FROM devl.unified_logs
              WHERE "timestamp" BETWEEN :start AND :end
            )
            SELECT CASE WHEN (SELECT n FROM baseline) = 0 THEN 0
                        ELSE (SELECT n FROM today)::float * 100.0 / (SELECT n FROM baseline) END AS pct;
        """)
        cov_pct = _to_float(conn.execute(q_cov, {"start": start, "end": end}).scalar(), 0.0)

        # -------- Data volume (TB) today --------
        q_vol = text("""
            SELECT COALESCE(SUM(octet_length(to_jsonb(data)::text)),0) / POWER(1024.0, 4)
            FROM devl.unified_logs
            WHERE "timestamp" BETWEEN :start AND :end;
        """)
        tb_today = _to_float(conn.execute(q_vol, {"start": start, "end": end}).scalar(), 0.0)

        # -------- Avg response time (last 24h) --------
        q_resp = text("""
            SELECT AVG( (data->>'response_time_sec')::float )
            FROM devl.unified_logs
            WHERE "timestamp" >= NOW() - INTERVAL '24 hours'
              AND (data ? 'response_time_sec');
        """)
        avg_resp = _to_float(conn.execute(q_resp).scalar(), 0.0)

    # --- Human-readable investor stories ---
    if avg_resp <= 0:
        response_story = "No incidents detected in last 24h — system idle (no response needed)"
    else:
        response_story = f"Avg Response Speed: {avg_resp:.2f}s (near real-time blocking)"

    auto_story = (
        "✅ Auto-remediation enabled — system automatically blocks threats without human delay"
        if AUTO_REM_ENABLED else
        "⚠️ Manual remediation required — analyst approval needed"
    )

    return jsonify({
        "active_threats": int(active_today),
        "active_threats_change_pct": round(change_pct, 2),
        "model_accuracy": round(model_accuracy, 2),
        "model_accuracy_trend_pct": round(trend_pct, 2),
        "data_coverage_pct": round(cov_pct, 2),
        "data_volume_tb_today": round(tb_today, 3),
        "avg_response_time_sec": round(avg_resp, 3),
        "auto_remediation_enabled": bool(AUTO_REM_ENABLED),
        # story fields used by investor-facing UI
        "response_story": response_story,
        "auto_remediation_story": auto_story
    })

@app.route("/api/auto-remediation", methods=["GET", "POST"])
def toggle_auto_remediation():
    global AUTO_REM_ENABLED
    if request.method == "POST":
        enabled = (request.json or {}).get("enabled")
        AUTO_REM_ENABLED = bool(enabled)
    return jsonify({"enabled": AUTO_REM_ENABLED})


@app.route("/api/heatmap")
def heatmap():
    """MITRE ATT&CK tactic counts for last 7 days (simple heuristic mapping)."""
    tactic_map = {
        "Access Control Policy Engine": "Initial Access",
        "traffic_analysis": "Reconnaissance",
        "user_behavior": "Discovery",
        "credential_scanning": "Credential Access",
        "config_change": "Defense Evasion",
        "Execution": "Execution",
        "Credential Access": "Credential Access",
        "Command and Control": "Command and Control",
        "Discovery": "Discovery",
        "Persistence": "Persistence",
        "Defense Evasion": "Defense Evasion",
        "Collection": "Collection",
        "Reconnaissance": "Reconnaissance"
    }
    with engine.connect() as conn:
        q = text("""
            SELECT
              COALESCE(data->>'rule_engine_classified', '') AS rule_cls,
              COALESCE(data->>'discovery_method', '') AS disc
            FROM devl.unified_logs
            WHERE "timestamp" >= NOW() - INTERVAL '7 days';
        """)
        rows = conn.execute(q).fetchall()

    counts = {}
    for r in rows:
        rule = (r.rule_cls or "").strip()
        disc = (r.disc or "").strip()
        tactic = tactic_map.get(rule) or tactic_map.get(disc)
        if tactic:
            counts[tactic] = counts.get(tactic, 0) + 1

    core = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact", "Reconnaissance", "Resource Development"]
    for t in core:
        counts.setdefault(t, 0)

    return jsonify({"tactics": counts})

@app.route("/api/assets")
def assets():
    """
    Latest affected assets where active_threat true (or predicted).
    Filters:
      - since_days (default 7)
      - limit (default 20, max 200)
      - require_context=1 (default) -> only show rows with hostname or ip present
    """
    since_days = int(request.args.get("since_days", 7))
    limit = min(int(request.args.get("limit", 20)), 200)
    require_ctx = request.args.get("require_context", "1").lower() in ("1","true","t","yes","on")

    with engine.connect() as conn:
        q = text(f"""
            WITH ul AS (
              SELECT
                data->>'asset_id'  AS asset_id,
                NULLIF(data->>'hostname','')  AS hostname,
                NULLIF(data->>'ip_address','') AS ip,
                "timestamp" AS ts
              FROM devl.unified_logs
              WHERE "timestamp" >= NOW() - make_interval(days => :since)
                AND ( data->>'active_threat' IS NOT NULL AND lower(data->>'active_threat') IN ('true','t','1') )
            ),
            ml AS (
              SELECT
                record_id::text AS asset_id,
                NULL::text AS hostname,
                NULL::text AS ip,
                "timestamp" AS ts
              FROM devl.model_logs
              WHERE "timestamp" >= NOW() - make_interval(days => :since)
                AND predicted_active_threat = true
            ),
            merged AS (
              SELECT * FROM ul
              UNION ALL
              SELECT * FROM ml
            )
            SELECT asset_id, hostname, ip, ts
            FROM merged
            WHERE asset_id IS NOT NULL
            { 'AND (hostname IS NOT NULL OR ip IS NOT NULL)' if require_ctx else '' }
            ORDER BY ts DESC
            LIMIT :lim;
        """)
        rows = conn.execute(q, {"since": since_days, "lim": limit}).fetchall()

    data = [
        {"asset_id": r.asset_id, "hostname": r.hostname, "ip_address": r.ip, "timestamp": r.ts.isoformat()}
        for r in rows
    ]
    return jsonify({"assets": data})

@app.route("/api/sessions")
def sessions():
    """Session-like rows with trust/risk/decision/anomaly_detected."""
    with engine.connect() as conn:
        q = text("""
            SELECT
              id,
              source_file,
              "timestamp",
              data->>'owner' AS owner,
              data->>'hostname' AS hostname,
              data->>'ip_address' AS ip,
              data->>'trust_score' AS trust_score,
              data->>'risk_score' AS risk_score,
              data->>'access_decision' AS access_decision,
              data->>'anomaly_detected' AS anomaly_detected
            FROM devl.unified_logs
            WHERE (data ? 'trust_score') OR (data ? 'access_decision') OR (data ? 'anomaly_detected')
            ORDER BY "timestamp" DESC
            LIMIT 100;
        """)
        rows = conn.execute(q).fetchall()

    sessions = []
    for r in rows:
        sessions.append({
            "id": r.id,
            "source_file": r.source_file,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "owner": r.owner,
            "hostname": r.hostname,
            "ip_address": r.ip,
            "trust_score": r.trust_score,
            "risk_score": r.risk_score,
            "access_decision": r.access_decision,
            "anomaly_detected": r.anomaly_detected
        })
    return jsonify({"sessions": sessions})


@app.route("/api/correlation")
def correlation():
    """
    Pull lightweight explainability + correlation and add a short story summary.
    """
    with engine.connect() as conn:
        q = text("""
            SELECT
              id,
              "timestamp",
              record_id,
              correlation_id,
              explanation_top_feature,
              explanation_score,
              learning_note
            FROM devl.model_logs
            WHERE correlation_id IS NOT NULL
               OR explanation_top_feature IS NOT NULL
               OR learning_note IS NOT NULL
            ORDER BY "timestamp" DESC NULLS LAST, created_at DESC
            LIMIT 50;
        """)
        rows = conn.execute(q).fetchall()

    data = []
    for r in rows:
        data.append({
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "record_id": r.record_id,
            "correlation_id": r.correlation_id,
            "explanation_top_feature": r.explanation_top_feature,
            "explanation_score": _to_float(r.explanation_score, None),
            "learning_note": r.learning_note
        })

    # Simple, investor-friendly story: group by feature, rank by avg score
    if not data:
        story = "No recent correlation patterns detected."
    else:
        from collections import defaultdict
        agg = defaultdict(lambda: {"n": 0, "sum": 0.0})
        for d in data:
            f = d.get("explanation_top_feature") or "other"
            s = _to_float(d.get("explanation_score"), 0.0)
            agg[f]["n"] += 1
            agg[f]["sum"] += s
        items = []
        for f, a in agg.items():
            avg = (a["sum"] / a["n"]) if a["n"] else 0.0
            items.append((f, a["n"], avg))
        items.sort(key=lambda t: t[2], reverse=True)
        topf, topn, topavg = items[0]
        story = f"Most prominent pattern: {topf} across {topn} records (avg score {topavg:.0f}). Review outliers and apply targeted mitigations."

    return jsonify({"correlations": data, "story": story})

@app.route("/api/model-performance")
def model_performance():
    """Precision/recall/accuracy over last 7 days (requires feedback_label)."""
    with engine.connect() as conn:
        q = text("""
            WITH labeled AS (
              SELECT feedback_label, predicted_anomaly
              FROM devl.model_logs
              WHERE "timestamp" >= NOW() - INTERVAL '7 days'
                AND feedback_label IS NOT NULL
            ),
            agg AS (
              SELECT
                SUM(CASE WHEN feedback_label = 1 AND predicted_anomaly = true THEN 1 ELSE 0 END) AS tp,
                SUM(CASE WHEN feedback_label = 0 AND predicted_anomaly = true THEN 1 ELSE 0 END) AS fp,
                SUM(CASE WHEN feedback_label = 1 AND predicted_anomaly = false THEN 1 ELSE 0 END) AS fn
              FROM labeled
            )
            SELECT
              tp::float / NULLIF(tp+fp,0) AS precision,
              tp::float / NULLIF(tp+fn,0) AS recall,
              (tp)::float / NULLIF((SELECT COUNT(*) FROM labeled),0) AS accuracy
            FROM agg;
        """)
        row = conn.execute(q).first()

    if row:
        precision = _to_float(row.precision) * 100.0 if row.precision is not None else 0.0
        recall = _to_float(row.recall) * 100.0 if row.recall is not None else 0.0
        accuracy = _to_float(row.accuracy) * 100.0 if row.accuracy is not None else 0.0
    else:
        precision = recall = accuracy = 0.0

    return jsonify({
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "accuracy": round(accuracy, 2)
    })


# ----------- NEW: Asset classification summary (Threat/Warning/Safe) ----------- #
@app.route("/api/asset-summary")
def asset_summary():
    """
    Classify assets into Threat / Warning / Safe and return counts + samples.
    - Threat: active_threat true (UL) or predicted_active_threat true (ML) in last 24h
    - Warning: risk_score >= threshold OR anomaly_detected true in last 24h (but not Threat)
    - Safe: seen in last 7d (not Threat/Warning)
    """
    risk_threshold = float(request.args.get("risk_threshold", 70))

    with engine.connect() as conn:
        # Threat assets (UL: by asset_id from JSON; ML: record_id)
        q_threat = text("""
            WITH u AS (
              SELECT DISTINCT data->>'asset_id' AS asset_id
              FROM devl.unified_logs
              WHERE "timestamp" >= NOW() - INTERVAL '24 hours'
                AND ( data->>'active_threat' IS NOT NULL AND lower(data->>'active_threat') IN ('true','t','1') )
                AND data->>'asset_id' IS NOT NULL
            ),
            m AS (
              SELECT DISTINCT record_id::text AS asset_id
              FROM devl.model_logs
              WHERE "timestamp" >= NOW() - INTERVAL '24 hours'
                AND predicted_active_threat = true
            )
            SELECT DISTINCT asset_id FROM (
              SELECT * FROM u UNION ALL SELECT * FROM m
            ) x
            WHERE asset_id IS NOT NULL;
        """)
        threat_assets = {r.asset_id for r in conn.execute(q_threat).fetchall()}

        # Warning assets (UL: risk/anomaly; ML: high explanation_score heuristic)
        q_warning = text("""
            SELECT DISTINCT data->>'asset_id' AS asset_id
            FROM devl.unified_logs
            WHERE "timestamp" >= NOW() - INTERVAL '24 hours'
              AND data->>'asset_id' IS NOT NULL
              AND (
                (data ? 'risk_score'
                 AND NULLIF(trim(data->>'risk_score'), '') IS NOT NULL
                 AND (data->>'risk_score')::float >= :thr)
                OR
                (data ? 'anomaly_detected'
                 AND lower(COALESCE(data->>'anomaly_detected','')) IN ('true','t','1'))
              )
            UNION
            SELECT DISTINCT record_id::text AS asset_id
            FROM devl.model_logs
            WHERE "timestamp" >= NOW() - INTERVAL '24 hours'
              AND (explanation_score IS NOT NULL AND explanation_score >= 0.7)
        """)
        warn_assets = {r.asset_id for r in conn.execute(q_warning, {"thr": risk_threshold}).fetchall()}
        warn_assets -= threat_assets  # keep disjoint

        # Seen assets in 7d (UL by asset_id only; ML by record_id)
        q_seen7d = text("""
            SELECT DISTINCT data->>'asset_id' AS asset_id
            FROM devl.unified_logs
            WHERE "timestamp" >= NOW() - INTERVAL '7 days'
              AND data->>'asset_id' IS NOT NULL
            UNION
            SELECT DISTINCT record_id::text AS asset_id
            FROM devl.model_logs
            WHERE "timestamp" >= NOW() - INTERVAL '7 days'
        """)
        seen7d = {r.asset_id for r in conn.execute(q_seen7d).fetchall() if r.asset_id}
        safe_assets = seen7d - threat_assets - warn_assets

        # Sample details (prefer UL latest row; fallback to ML if UL missing)
        def _sample(asset_ids, limit=10):
            if not asset_ids:
                return []
            ids = list(asset_ids)[:500]
            q = text("""
                WITH ul_latest AS (
                  SELECT DISTINCT ON (data->>'asset_id')
                    data->>'asset_id' AS asset_id,
                    data->>'hostname' AS hostname,
                    data->>'ip_address' AS ip,
                    "timestamp" AS ts
                  FROM devl.unified_logs
                  WHERE data->>'asset_id' = ANY(:ids)
                  ORDER BY data->>'asset_id', "timestamp" DESC
                ),
                ml_latest AS (
                  SELECT DISTINCT ON (record_id::text)
                    record_id::text AS asset_id,
                    NULL::text AS hostname,
                    NULL::text AS ip,
                    "timestamp" AS ts
                  FROM devl.model_logs
                  WHERE record_id::text = ANY(:ids)
                  ORDER BY record_id::text, "timestamp" DESC
                ),
                merged AS (
                  SELECT * FROM ul_latest
                  UNION ALL
                  SELECT * FROM ml_latest
                  WHERE NOT EXISTS (
                    SELECT 1 FROM ul_latest u WHERE u.asset_id = ml_latest.asset_id
                  )
                )
                SELECT asset_id, hostname, ip, ts
                FROM merged
                ORDER BY ts DESC
                LIMIT :lim
            """)
            rows = conn.execute(q, {"ids": ids, "lim": limit}).fetchall()
            return [
                {
                    "asset_id": r.asset_id,
                    "hostname": r.hostname,
                    "ip_address": r.ip,
                    "timestamp": r.ts.isoformat() if r.ts else None
                } for r in rows
            ]

        return jsonify({
            "counts": {
                "threat": len(threat_assets),
                "warning": len(warn_assets),
                "safe": len(safe_assets)
            },
            "samples": {
                "threat": _sample(threat_assets),
                "warning": _sample(warn_assets),
                "safe": _sample(safe_assets)
            }
        })

# ----------- NEW: Live topology graph ----------- #
@app.route("/api/topology")
def topology():
    """
    Live network topology inferred from recent logs.
    Params:
      - since_days (int, default 7)
      - limit (int, default 200) max nodes/edges returned
    Nodes:
      id, label, type in {'user','host','ip'}, status in {'threat','warning','safe'}
    Edges:
      {from, to, type in {'session','asset'}}
    """
    since_days = int(request.args.get("since_days", 7))
    limit = min(int(request.args.get("limit", 200)), 200)

    nodes = {}  # id -> {id,label,type,status}
    edges = []  # {from,to,type}

    def add_node(nid, label, ntype, status):
        if not nid:
            return
        cur = nodes.get(nid)
        # upgrade status if more severe comes in later
        order = {"safe": 0, "warning": 1, "threat": 2}
        if cur:
            if order.get(status, 0) > order.get(cur["status"], 0):
                cur["status"] = status
            return
        nodes[nid] = {"id": nid, "label": label or nid, "type": ntype, "status": status}

    def add_edge(fr, to, etype):
        if fr and to and fr != to:
            edges.append({"from": fr, "to": to, "type": etype})

    with engine.connect() as conn:
        # Sessions → user -> host
        q_sessions = text("""
            SELECT
              "timestamp" AS ts,
              NULLIF(data->>'owner','')     AS owner,
              NULLIF(data->>'hostname','')  AS host,
              NULLIF(data->>'ip_address','')AS ip,
              NULLIF(data->>'risk_score','') AS risk,
              lower(COALESCE(data->>'anomaly_detected','')) IN ('true','t','1') AS is_anom,
              lower(COALESCE(data->>'access_decision',''))   AS decision,
              lower(COALESCE(data->>'active_threat','')) IN ('true','t','1') AS is_threat
            FROM devl.unified_logs
            WHERE "timestamp" >= NOW() - make_interval(days => :since)
              AND (
                (data ? 'trust_score') OR (data ? 'access_decision') OR (data ? 'anomaly_detected')
                OR (data ? 'owner') OR (data ? 'hostname') OR (data ? 'ip_address')
              )
            ORDER BY "timestamp" DESC
            LIMIT 5000
        """)
        sess = conn.execute(q_sessions, {"since": since_days}).fetchall()

        # Assets (active threats) → host/ip under a host
        q_assets = text("""
            SELECT
              "timestamp" AS ts,
              NULLIF(data->>'asset_id','')  AS asset_id,
              NULLIF(data->>'hostname','')  AS host,
              NULLIF(data->>'ip_address','')AS ip,
              lower(COALESCE(data->>'active_threat','')) IN ('true','t','1') AS is_threat
            FROM devl.unified_logs
            WHERE "timestamp" >= NOW() - make_interval(days => :since)
              AND (data ? 'asset_id' OR data ? 'hostname' OR data ? 'ip_address')
            ORDER BY "timestamp" DESC
            LIMIT 5000
        """)
        aset = conn.execute(q_assets, {"since": since_days}).fetchall()

        # Model predictions for threat highlighting (24h)
        q_ml = text("""
            SELECT record_id::text AS asset_id
            FROM devl.model_logs
            WHERE "timestamp" >= NOW() - INTERVAL '24 hours'
              AND predicted_active_threat = true
        """)
        ml_threats = {r.asset_id for r in conn.execute(q_ml).fetchall() if r.asset_id}

    # Build from sessions
    for r in sess:
        owner = r.owner
        host  = r.host
        ip    = r.ip

        # classify status
        status = "safe"
        try:
            risk = float(r.risk) if r.risk not in (None, "") else None
        except:
            risk = None
        if r.is_threat or (r.decision in ("block","blocked","deny","quarantine")):
            status = "threat"
        elif r.is_anom or (risk is not None and risk >= 70):
            status = "warning"

        if owner:
            add_node(f"user:{owner}", owner, "user", status)
        if host:
            add_node(f"host:{host}", host, "host", status)
        if ip:
            add_node(f"ip:{ip}", ip, "ip", status)

        if owner and host:
            add_edge(f"user:{owner}", f"host:{host}", "session")
        if host and ip:
            add_edge(f"host:{host}", f"ip:{ip}", "asset")

    # Build from assets
    for r in aset:
        host = r.host
        ip   = r.ip
        aid  = r.asset_id

        status = "threat" if r.is_threat or (aid and aid in ml_threats) else "safe"

        if host:
            add_node(f"host:{host}", host, "host", status)
        if ip:
            add_node(f"ip:{ip}", ip, "ip", status)

        if host and ip:
            add_edge(f"host:{host}", f"ip:{ip}", "asset")

    # Apply limits: prefer keeping all nodes referenced by edges
    # First, trim edges if too many
    if len(edges) > limit:
        edges = edges[:limit]
    # Nodes that appear in edges
    used_ids = set()
    for e in edges:
        used_ids.add(e["from"]); used_ids.add(e["to"])
    # Add extra nodes (up to limit) if some nodes aren’t in edges but exist
    extra = [nid for nid in nodes.keys() if nid not in used_ids]
    keep_nodes = set(list(used_ids) + extra[:max(0, limit - len(used_ids))])
    nodes_out = [nodes[nid] for nid in keep_nodes if nid in nodes]

    return jsonify({
        "nodes": nodes_out,
        "edges": [e for e in edges if e["from"] in keep_nodes and e["to"] in keep_nodes]
    })

# ----------- NEW: MITRE detected vs blocked ----------- #
@app.route("/api/mitre-breakdown")
def mitre_breakdown():
    """
    Returns detected vs blocked counts by MITRE tactic for last 7 days.
    Also includes an 'Other' bucket for rows with no tactic mapping.
    """
    tactic_map = {
        "Access Control Policy Engine": "Initial Access",
        "traffic_analysis": "Reconnaissance",
        "user_behavior": "Discovery",
        "credential_scanning": "Credential Access",
        "config_change": "Defense Evasion",
        "Execution": "Execution",
        "Credential Access": "Credential Access",
        "Command and Control": "Command and Control",
        "Discovery": "Discovery",
        "Persistence": "Persistence",
        "Defense Evasion": "Defense Evasion",
        "Collection": "Collection",
        "Reconnaissance": "Reconnaissance"
    }
    with engine.connect() as conn:
        q = text("""
            SELECT
              "timestamp",
              COALESCE(data->>'rule_engine_classified','') AS rule_cls,
              COALESCE(data->>'discovery_method','')      AS disc,
              lower(COALESCE(data->>'access_decision','')) AS decision
            FROM devl.unified_logs
            WHERE "timestamp" >= NOW() - INTERVAL '7 days'
        """)
        rows = conn.execute(q).fetchall()

    def map_tactic(rule, disc):
        return tactic_map.get((rule or "").strip()) or tactic_map.get((disc or "").strip()) or "Other"

    out = {}
    for r in rows:
        t = map_tactic(r.rule_cls, r.disc)
        bucket = out.setdefault(t, {"detected": 0, "blocked": 0})
        if r.decision in ("block", "blocked", "deny", "quarantine"):
            bucket["blocked"] += 1
        else:
            bucket["detected"] += 1

    return jsonify({"mitre": out})


# ----------- NEW: Threat intelligence rollup ----------- #
@app.route("/api/threat-intel")
def threat_intel():
    """
    Smarter rollup of recent indicators with type, confidence, time-ago, and actions.
    Falls back to url/domain/ip/hostname + risk/decision if indicator fields are missing.
    Query params:
      - since_days (int, default 7)
      - limit (int, default 20, max 100)
    """
    since_days = int(request.args.get("since_days", 7))
    limit = min(int(request.args.get("limit", 20)), 100)

    def timeago(ts):
        if not ts:
            return None
        try:
            now = dt.datetime.utcnow()
            if ts.tzinfo is not None:
                now = dt.datetime.now(ts.tzinfo)
            delta = now - ts
            s = int(delta.total_seconds())
            if s < 60:   return f"{s}s ago"
            m = s // 60
            if m < 60:   return f"{m}m ago"
            h = m // 60
            if h < 48:   return f"{h}h ago"
            d = h // 24
            return f"{d}d ago"
        except:
            return None

    with engine.connect() as conn:
        # Pull recent rows; prefer real indicator fields, else fall back
        # DISTINCT ON ensures latest per normalized indicator
        q = text("""
            WITH recent AS (
              SELECT
                "timestamp" AS ts,
                COALESCE(NULLIF(data->>'indicator',''),
                         NULLIF(data->>'url',''),
                         NULLIF(data->>'domain',''),
                         NULLIF(data->>'ip_address',''),
                         NULLIF(data->>'hostname','')) AS raw_indicator,
                COALESCE(NULLIF(data->>'threat_type',''),
                         NULLIF(data->>'ioc_type','')) AS raw_type,
                NULLIF(data->>'threat_confidence','') AS raw_conf,
                lower(COALESCE(data->>'access_decision','')) AS decision,
                NULLIF(data->>'risk_score','') AS risk_score,
                CASE WHEN (data->>'active_threat') IS NOT NULL
                           AND lower(data->>'active_threat') IN ('true','t','1')
                     THEN true ELSE false END AS is_active
              FROM devl.unified_logs
              WHERE "timestamp" >= NOW() - make_interval(days => :since)
            ),
            norm AS (
              SELECT
                ts,
                raw_indicator,
                -- Normalize indicator for distinct grouping (lowercase/trim)
                lower(trim(raw_indicator)) AS norm_indicator,
                raw_type,
                raw_conf,
                decision,
                risk_score,
                is_active
              FROM recent
              WHERE raw_indicator IS NOT NULL
            ),
            latest AS (
              SELECT DISTINCT ON (norm_indicator)
                ts, raw_indicator, norm_indicator, raw_type, raw_conf, decision, risk_score, is_active
              FROM norm
              ORDER BY norm_indicator, ts DESC
            )
            SELECT * FROM latest
            ORDER BY ts DESC
            LIMIT :lim
        """)
        rows = conn.execute(q, {"since": since_days, "lim": limit}).fetchall()

    items = []
    for r in rows:
        indicator = r.raw_indicator

        # Infer type if missing
        t = (r.raw_type or "").strip()
        if not t:
            low = (indicator or "").lower()
            if low.startswith("http://") or low.startswith("https://"):
                t = "URL"
            elif any(c.isalpha() for c in low) and "." in low and " " not in low and "/" not in low:
                t = "Domain"
            elif low.count(".") == 3 and all(part.isdigit() and 0 <= int(part) <= 255 for part in low.split(".")):
                t = "IP"
            else:
                t = "Hostname"

        # Normalize confidence
        raw_conf = (r.raw_conf or "").strip().lower()
        if raw_conf in ("critical","high","medium","low"):
            conf = raw_conf.capitalize()
        else:
            # derive from decision/active/risk
            conf = "Unknown"
            try:
                risk = float(r.risk_score) if r.risk_score not in (None, "") else None
            except:
                risk = None
            if r.decision in ("block","blocked","deny","quarantine"):
                conf = "High"
            elif r.is_active:
                conf = "High"
            elif risk is not None:
                conf = "High" if risk >= 80 else "Medium" if risk >= 60 else "Low"

        items.append({
            "indicator": indicator,
            "type": t,
            "confidence": conf,
            "seen": timeago(r.ts),
            "actions": {
                "block": f"/actions/block?indicator={indicator}",
                "info":  f"/actions/info?indicator={indicator}"
            }
        })

    return jsonify({"intel": items})


# ----------- NEW: Compliance score ----------- #
@app.route("/api/compliance-score")
def compliance_score():
    """
    Returns live compliance with an auto-generated one-line story.
    """
    def status_label(pct: float) -> str:
        if pct >= 71: return "Healthy"
        if pct >= 31: return "Needs Attention"
        return "Critical Gap"

    with engine.connect() as conn:
        q = text("""
            WITH base AS (
              SELECT
                compliance_standard,
                CASE
                  WHEN is_compliant IN ('true','t','1','TRUE','True') THEN 1
                  ELSE 0
                END AS ok,
                processed_at
              FROM devl.regulatory_compliance
              WHERE processed_at >= NOW() - INTERVAL '60 days'
            ),
            this_month AS (
              SELECT compliance_standard,
                     SUM(ok) AS ok,
                     COUNT(*) AS total
              FROM base
              WHERE processed_at >= NOW() - INTERVAL '30 days'
              GROUP BY 1
            ),
            prev_month AS (
              SELECT compliance_standard,
                     SUM(ok) AS ok,
                     COUNT(*) AS total
              FROM base
              WHERE processed_at < NOW() - INTERVAL '30 days'
                AND processed_at >= NOW() - INTERVAL '60 days'
              GROUP BY 1
            )
            SELECT
              json_agg(
                json_build_object(
                  'standard', tm.compliance_standard,
                  'ok', tm.ok,
                  'total', tm.total,
                  'pct', CASE WHEN tm.total=0 THEN 0 ELSE ROUND(tm.ok*100.0/tm.total,2) END,
                  'prev_pct', COALESCE(
                      (CASE WHEN pm.total=0 THEN 0 ELSE ROUND(pm.ok*100.0/pm.total,2) END), 0
                  )
                ) ORDER BY tm.compliance_standard
              ) AS by_standard
            FROM this_month tm
            LEFT JOIN prev_month pm USING (compliance_standard);
        """)
        row = conn.execute(q).first()

    by_standard = row.by_standard or []
    if not by_standard:
        return jsonify({
            "overall_pct": 0.0,
            "trend_pct": 0.0,
            "by_standard": [],
            "story": "No compliance records in the last 30 days; populate devl.regulatory_compliance to compute live scores."
        })

    overall_now = sum(s["pct"] for s in by_standard) / len(by_standard)
    overall_prev = sum(s["prev_pct"] for s in by_standard) / len(by_standard)
    trend = overall_now - overall_prev

    top_std = max(by_standard, key=lambda s: s["pct"])
    bot_std = min(by_standard, key=lambda s: s["pct"])

    healthy = sum(1 for s in by_standard if s["pct"] >= 71)
    attention = sum(1 for s in by_standard if 31 <= s["pct"] < 71)
    critical = sum(1 for s in by_standard if s["pct"] < 31)

    dir_word = "up" if trend >= 0 else "down"
    def label(p): 
        if p >= 71: return "Healthy"
        if p >= 31: return "Needs Attention"
        return "Critical Gap"

    story = (
        f"Overall compliance is {overall_now:.0f}% ({dir_word} {abs(trend):.0f}pp MoM). "
        f"{top_std['standard']} leads at {top_std['pct']:.0f}%, while {bot_std['standard']} is at "
        f"{bot_std['pct']:.0f}% ({label(bot_std['pct'])}). "
        f"Coverage: {healthy} Healthy, {attention} Needs Attention, {critical} Critical."
    )

    return jsonify({
        "overall_pct": round(overall_now, 2),
        "trend_pct": round(trend, 2),
        "by_standard": by_standard,
        "story": story
    })
# ----------- Existing: 7-day trend (MITRE + active threats) ----------- #
@app.route("/api/mitre-trend")
def mitre_trend():
    """
    7-day (including today) daily buckets:
      points: [{date, total, ia, c2, active_threats}, ...]
    """
    tactic_map = {
        "Access Control Policy Engine": "Initial Access",
        "traffic_analysis": "Reconnaissance",
        "user_behavior": "Discovery",
        "credential_scanning": "Credential Access",
        "config_change": "Defense Evasion",
        "Execution": "Execution",
        "Credential Access": "Credential Access",
        "Command and Control": "Command and Control",
        "Discovery": "Discovery",
        "Persistence": "Persistence",
        "Defense Evasion": "Defense Evasion",
        "Collection": "Collection",
        "Reconnaissance": "Reconnaissance"
    }

    today = dt.date.today()
    days = [today - dt.timedelta(days=i) for i in range(6, -1, -1)]  # oldest → newest
    buckets = {d.isoformat(): {"total": 0, "ia": 0, "c2": 0, "active_threats": 0} for d in days}
    start_dt = dt.datetime.combine(days[0], dt.time.min)

    with engine.connect() as conn:
        q_tactics = text("""
            SELECT "timestamp",
                   COALESCE(data->>'rule_engine_classified','') AS rule_cls,
                   COALESCE(data->>'discovery_method','')      AS disc
            FROM devl.unified_logs
            WHERE "timestamp" >= :start
        """)
        rows = conn.execute(q_tactics, {"start": start_dt}).fetchall()

        q_ul = text(f"""
            SELECT DATE("timestamp") AS d, COUNT(*) AS c
            FROM devl.unified_logs
            WHERE "timestamp" >= :start
              AND {_json_bool_true_sql("data->>'active_threat'")}
            GROUP BY 1
        """)
        ul_counts = {r.d.isoformat(): int(r.c) for r in conn.execute(q_ul, {"start": start_dt}).fetchall()}

        q_ml = text("""
            SELECT DATE("timestamp") AS d, COUNT(*) AS c
            FROM devl.model_logs
            WHERE "timestamp" >= :start
              AND predicted_active_threat = true
            GROUP BY 1
        """)
        ml_counts = {r.d.isoformat(): int(r.c) for r in conn.execute(q_ml, {"start": start_dt}).fetchall()}

    for r in rows:
        d = r.timestamp.date().isoformat() if r.timestamp else None
        if d not in buckets:
            continue
        rule = (r.rule_cls or "").strip()
        disc = (r.disc or "").strip()
        tactic = tactic_map.get(rule) or tactic_map.get(disc)
        if tactic:
            buckets[d]["total"] += 1
            if tactic == "Initial Access":
                buckets[d]["ia"] += 1
            elif tactic == "Command and Control":
                buckets[d]["c2"] += 1

    for d in buckets.keys():
        buckets[d]["active_threats"] = ul_counts.get(d, 0) + ml_counts.get(d, 0)

    points = [{"date": d, **buckets[d]} for d in sorted(buckets.keys())]
    return jsonify({"points": points})



@app.route("/api/attack-details")
def attack_details():
    """
    Drilldown for a tactic (or 'Other').
    Params:
      - tactic (str) optional; if omitted returns top tactics by count
      - since_days (int) default 7
      - limit_assets (int) default 20
    """
    tactic = (request.args.get("tactic") or "").strip() or None
    since_days = int(request.args.get("since_days", 7))
    limit_assets = min(int(request.args.get("limit_assets", 20)), 100)

    tactic_map = {
        "Access Control Policy Engine": "Initial Access",
        "traffic_analysis": "Reconnaissance",
        "user_behavior": "Discovery",
        "credential_scanning": "Credential Access",
        "config_change": "Defense Evasion",
        "Execution": "Execution",
        "Credential Access": "Credential Access",
        "Command and Control": "Command and Control",
        "Discovery": "Discovery",
        "Persistence": "Persistence",
        "Defense Evasion": "Defense Evasion",
        "Collection": "Collection",
        "Reconnaissance": "Reconnaissance"
    }

    mitigations = {
        "Initial Access":     ["Geo/IP allowlists", "Email link detonation", "MFA hardening", "WAF rules for auth endpoints"],
        "Execution":          ["Application control (AppLocker)", "Script restrictions (Constrained Language Mode)", "EDR prevention rules"],
        "Persistence":        ["Disable autoruns", "Baseline and alert on new services", "Credential hygiene scans"],
        "Privilege Escalation":["LSA protection", "Patch management (kernel/userland)", "CVE-based blocklists"],
        "Defense Evasion":    ["Sysmon hardening", "Tamper protection", "Hide sensitive logs from standard users"],
        "Credential Access":  ["Rotate exposed creds", "Honeytokens", "Block cleartext auth"],
        "Discovery":          ["Rate-limit enumeration", "Deception resources", "Limit directory read scope"],
        "Lateral Movement":   ["SMB signing", "Disable legacy protocols", "Segment east–west"],
        "Collection":         ["DLP rules", "USB control", "Clipboard monitoring"],
        "Command and Control":["Egress filtering", "DNS sinkhole", "TLS inspection allowlist"],
        "Exfiltration":       ["Egress size thresholds", "S3 public block", "Zip exfil detection"],
        "Impact":             ["Backups immutable", "Rapid isolation runbook"],
        "Reconnaissance":     ["Bot trap pages", "Throttle anonymous probes"],
        "Other":              ["Generic anomaly blocking", "Review rules & baselines"]
    }

    def map_t(rule, disc):
        return tactic_map.get((rule or "").strip()) or tactic_map.get((disc or "").strip()) or "Other"

    with engine.connect() as conn:
        q = text("""
            SELECT
              "timestamp" AS ts,
              COALESCE(data->>'asset_id','')   AS asset_id,
              NULLIF(data->>'hostname','')     AS hostname,
              NULLIF(data->>'ip_address','')   AS ip,
              COALESCE(data->>'rule_engine_classified','') AS rule_cls,
              COALESCE(data->>'discovery_method','')      AS disc,
              lower(COALESCE(data->>'access_decision','')) AS decision,
              lower(COALESCE(data->>'active_threat','')) IN ('true','t','1') AS is_threat
            FROM devl.unified_logs
            WHERE "timestamp" >= NOW() - make_interval(days => :since)
        """)
        rows = conn.execute(q, {"since": since_days}).fetchall()

    # Aggregate
    buckets = {}
    assets = []
    detected = blocked = 0

    for r in rows:
        t = map_t(r.rule_cls, r.disc)
        if tactic and t != tactic:
            # if user asked specifically for 'Other', keep only non-mapped
            continue
        # counts
        if r.decision in ("block", "blocked", "deny", "quarantine"):
            blocked += 1
        else:
            detected += 1
        buckets[t] = buckets.get(t, 0) + 1

        # asset samples
        if len(assets) < limit_assets:
            if (r.asset_id or r.hostname or r.ip):
                assets.append({
                    "asset_id": r.asset_id or None,
                    "hostname": r.hostname or None,
                    "ip": r.ip or None,
                    "last_seen": r.ts.isoformat() if r.ts else None,
                    "decision": r.decision or "",
                    "is_active": bool(r.is_threat)
                })

    # If no specific tactic requested, return leaderboard
    if not tactic:
        top = sorted(buckets.items(), key=lambda kv: kv[1], reverse=True)[:10]
        return jsonify({
            "summary": {"detected": detected, "blocked": blocked},
            "top_tactics": [{"tactic": k, "count": v} for k, v in top]
        })

    # Specific tactic details
    total = detected + blocked
    blocked_rate = (blocked * 100.0 / total) if total else 0.0
    # Criticality: red if any active threat & block rate < 40, yellow if < 70, else green
    has_active = any(a["is_active"] for a in assets)
    if has_active and blocked_rate < 40:
        criticality = "critical"
    elif blocked_rate < 70:
        criticality = "medium"
    else:
        criticality = "safe"

    return jsonify({
        "tactic": tactic,
        "counts": {"detected": detected, "blocked": blocked, "total": total, "blocked_rate": round(blocked_rate, 1)},
        "criticality": criticality,  # 'critical' | 'medium' | 'safe'
        "assets": assets,
        "suggested_rules": [f"Rule: tighten {tactic} detection threshold", "Alert: repeated offenders escalation"],
        "mitigations": mitigations.get(tactic, mitigations["Other"])
    })



# ------------------ Chat (HTML response) ------------------ #
@app.route("/api/chat", methods=["POST"])
def chat():
    """
    AI chat assistant that answers questions based on current endpoints.
    Returns HTML; frontend renders directly.
    """
    if OpenAI is None or not OPENAI_API_KEY:
        return jsonify({"error": "OpenAI not configured"}), 400

    user_msg = (request.json or {}).get("message", "").strip()
    if not user_msg:
        return jsonify({"error": "Empty message"}), 400

    # Build context by calling our own endpoints
    summary_json     = summary().get_json()
    heatmap_json     = heatmap().get_json()
    assets_json      = assets().get_json()
    sessions_json    = sessions().get_json()
    correlation_json = correlation().get_json()
    model_perf_json  = model_performance().get_json()
    mitre_break_json = mitre_breakdown().get_json()
    intel_json       = threat_intel().get_json()
    asset_sum_json   = asset_summary().get_json()
    compliance_json  = compliance_score().get_json()

    # Pre-sorted/derived HTML blocks (minimal but useful)
    tactics_map = heatmap_json.get("tactics", {}) or {}
    sorted_tactics = sorted(
        ((k, int(v) if v is not None else 0) for k, v in tactics_map.items()),
        key=lambda kv: kv[1], reverse=True
    )
    tactics_rows_html = "\n".join(
        f"<tr><td>{name}</td><td style='text-align:right'>{count}</td></tr>"
        for name, count in sorted_tactics if count > 0
    ) or "<tr><td colspan='2'>No tactic counts in the last 7 days.</td></tr>"

    sessions_list = sessions_json.get("sessions", []) or []
    def _to_float_safe(v):
        try: return float(v)
        except Exception: return float("nan")
    for s in sessions_list:
        s["_risk_num"] = _to_float_safe(s.get("risk_score"))
    sessions_sorted = sorted(
        sessions_list,
        key=lambda s: (
            0 if s["_risk_num"] == s["_risk_num"] else 1,  # valid first
            -(s["_risk_num"] if s["_risk_num"] == s["_risk_num"] else 0.0),
            s.get("timestamp") or ""
        )
    )[:10]

    # HTML snippets
    tactics_table_html = f"""
    <table>
      <thead><tr><th>Tactic</th><th>Count (7d)</th></tr></thead>
      <tbody>{tactics_rows_html}</tbody>
    </table>
    """
    sessions_rows_html = "\n".join(
        f"<tr>"
        f"<td>{s.get('timestamp') or ''}</td>"
        f"<td>{s.get('owner') or ''}</td>"
        f"<td>{s.get('hostname') or ''}</td>"
        f"<td>{s.get('ip_address') or ''}</td>"
        f"<td style='text-align:right'>{s.get('trust_score') or ''}</td>"
        f"<td style='text-align:right'>{s.get('risk_score') or ''}</td>"
        f"<td>{s.get('access_decision') or ''}</td>"
        f"<td>{s.get('anomaly_detected') or ''}</td>"
        f"</tr>"
        for s in sessions_sorted
    ) or "<tr><td colspan='8'>No session rows.</td></tr>"
    sessions_table_html = f"""
    <table>
      <thead>
        <tr>
          <th>Time</th><th>Owner</th><th>Host</th><th>IP</th>
          <th>Trust</th><th>Risk</th><th>Decision</th><th>Anom</th>
        </tr>
      </thead>
      <tbody>{sessions_rows_html}</tbody>
    </table>
    """

    assets_list = assets_json.get("assets", []) or []
    assets_sorted = sorted(assets_list, key=lambda a: a.get("timestamp") or "", reverse=True)[:10]
    assets_rows_html = "\n".join(
        f"<tr><td>{a.get('timestamp') or ''}</td><td>{a.get('asset_id') or ''}</td>"
        f"<td>{a.get('hostname') or ''}</td><td>{a.get('ip_address') or ''}</td></tr>"
        for a in assets_sorted
    ) or "<tr><td colspan='4'>No recent assets.</td></tr>"
    assets_table_html = f"""
    <table>
      <thead><tr><th>Time</th><th>Asset ID</th><th>Hostname</th><th>IP</th></tr></thead>
      <tbody>{assets_rows_html}</tbody>
    </table>
    """

    corr_list = correlation_json.get("correlations", []) or []
    feat_counts = Counter([c.get("explanation_top_feature") for c in corr_list if c.get("explanation_top_feature")])
    corr_sorted = feat_counts.most_common(10)
    corr_rows_html = "\n".join(
        f"<tr><td>{name}</td><td style='text-align:right'>{cnt}</td></tr>"
        for name, cnt in corr_sorted
    ) or "<tr><td colspan='2'>No correlation features.</td></tr>"
    corr_table_html = f"""
    <table>
      <thead><tr><th>Top Feature</th><th>Occurrences</th></tr></thead>
      <tbody>{corr_rows_html}</tbody>
    </table>
    """

    # KPI block (renamed for investor language)
    kpi_html = f"""
    <ul>
      <li><b>Open Security Incidents (24h):</b> {summary_json['active_threats']} ({summary_json['active_threats_change_pct']}% vs yesterday)</li>
      <li><b>AI Detection Accuracy:</b> {summary_json['model_accuracy']}% (Δ {summary_json['model_accuracy_trend_pct']} pp vs prior week)</li>
      <li><b>Security Data Coverage:</b> {summary_json['data_coverage_pct']}%</li>
      <li><b>Data Volume Today:</b> {summary_json['data_volume_tb_today']} TB</li>
      <li><b>Average Response Speed:</b> {summary_json['avg_response_time_sec']} s</li>
      <li><b>Compliance Score (30d):</b> {compliance_json.get('overall_pct', 0):.2f}%</li>
      <li><b>Auto-remediation:</b> {"ON" if summary_json['auto_remediation_enabled'] else "OFF"}</li>
    </ul>
    """

    # Raw JSON snapshot
    raw_json_html = json.dumps(
        {
            "summary": summary_json,
            "model_performance": model_perf_json,
            "asset_summary": asset_sum_json,
            "mitre_breakdown": mitre_break_json,
            "threat_intel": intel_json,
            "compliance": compliance_json
        },
        ensure_ascii=False,
        indent=2
    )

    context_block = f"""
<h3>Dashboard KPIs</h3>
{kpi_html}

<h3>MITRE Tactics (7d, sorted desc)</h3>
{tactics_table_html}

<h3>Top Risk Sessions (latest, desc risk)</h3>
{sessions_table_html}

<h3>Recent Assets (latest 10)</h3>
{assets_table_html}

<h3>Top Correlation Features</h3>
{corr_table_html}

<pre style="white-space:pre-wrap">{raw_json_html}</pre>
"""

    system_prompt = (
        "You are a helpful security analyst assistant for a dashboard.\n"
        "RESPOND IN HTML ONLY (use <h3>, <p>, <ul>, <ol>, <table>…).\n"
        "Use the 'Context' HTML below as your primary data source. "
        "When asked to count, rank, or list, prefer the pre-sorted tables provided. "
        "If a value is missing, say so. Be concise and actionable. "
        "Offer one short follow-up suggestion at the end."
    )

    client = OpenAI(api_key=OPENAI_API_KEY)
    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"{user_msg}\n\n---\nContext (HTML):\n{context_block}"}
            ],
            temperature=0.2,
            timeout=60  # seconds
        )
        reply_html = completion.choices[0].message.content or "<p>No response.</p>"
    except Exception as e:
        reply_html = f"<p>LLM call failed: {str(e)}</p>"

    return jsonify({"reply": reply_html})


@app.route("/health")
def health():
    return jsonify({"ok": True})


# ------------------ Main ------------------ #
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
