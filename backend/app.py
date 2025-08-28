import os
import datetime as dt
from decimal import Decimal

from flask import Flask, jsonify, request
from flask_cors import CORS
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# OpenAI v1 SDK (pip install openai>=1.0.0)
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")  # e.g. postgres://user:pass@host:5432/dbname
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

app = Flask(__name__)
CORS(app)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# --------- Helper utilities --------- #
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

def _today_range_tz_agnostic():
    # Treat timestamps as UTC; adjust if your DB has timezone awareness
    today = dt.date.today()
    start = dt.datetime.combine(today, dt.time.min)
    end = dt.datetime.combine(today, dt.time.max)
    return start, end

def _yesterday_range_tz_agnostic():
    yesterday = dt.date.today() - dt.timedelta(days=1)
    start = dt.datetime.combine(yesterday, dt.time.min)
    end = dt.datetime.combine(yesterday, dt.time.max)
    return start, end

# --------- Metrics Endpoints --------- #

@app.route("/api/summary")
def summary():
    """
    Returns:
      {
        active_threats: int,
        active_threats_change_pct: float,
        model_accuracy: float,
        model_accuracy_trend_pct: float,
        data_coverage_pct: float,
        data_volume_tb_today: float,
        avg_response_time_sec: float,
        auto_remediation_enabled: bool
      }
    """
    with engine.connect() as conn:
        # Active threats today (from unified_logs.data->active_threat = true OR model_logs predicted)
        start, end = _today_range_tz_agnostic()
        ystart, yend = _yesterday_range_tz_agnostic()

        q_active_today = text("""
            WITH ul AS (
              SELECT COUNT(*) AS c
              FROM devl.unified_logs
              WHERE "timestamp" BETWEEN :start AND :end
                AND ( (data->>'active_threat')::boolean = true )
            ),
            ml AS (
              SELECT COUNT(*) AS c
              FROM devl.model_logs
              WHERE "timestamp" BETWEEN :start AND :end
                AND predicted_active_threat = true
            )
            SELECT (SELECT c FROM ul) + (SELECT c FROM ml) AS total;
        """)
        active_today = conn.execute(q_active_today, {"start": start, "end": end}).scalar() or 0

        q_active_yesterday = text("""
            WITH ul AS (
              SELECT COUNT(*) AS c
              FROM devl.unified_logs
              WHERE "timestamp" BETWEEN :start AND :end
                AND ( (data->>'active_threat')::boolean = true )
            ),
            ml AS (
              SELECT COUNT(*) AS c
              FROM devl.model_logs
              WHERE "timestamp" BETWEEN :start AND :end
                AND predicted_active_threat = true
            )
            SELECT (SELECT c FROM ul) + (SELECT c FROM ml) AS total;
        """)
        active_yesterday = conn.execute(q_active_yesterday, {"start": ystart, "end": yend}).scalar() or 0

        change_pct = 0.0
        if active_yesterday > 0:
            change_pct = (active_today - active_yesterday) * 100.0 / active_yesterday

        # Model accuracy snapshot: prefer snapshot row where accuracy fields not null
        q_acc = text("""
            SELECT accuracy_overall, accuracy_updated_at
            FROM devl.model_logs
            WHERE accuracy_overall IS NOT NULL
            ORDER BY accuracy_updated_at DESC NULLS LAST, created_at DESC
            LIMIT 1;
        """)
        row = conn.execute(q_acc).first()
        if row:
            model_accuracy = _to_float(row.accuracy_overall)
        else:
            # Fallback: compute last 7d accuracy from labeled rows
            q_acc_7d = text("""
                SELECT
                  SUM(CASE WHEN (feedback_label IS NOT NULL)
                            AND ((feedback_label = 1 AND predicted_anomaly = true)
                              OR (feedback_label = 0 AND predicted_anomaly = false))
                      THEN 1 ELSE 0 END)::float /
                  NULLIF(SUM(CASE WHEN feedback_label IS NOT NULL THEN 1 ELSE 0 END),0) AS acc
                FROM devl.model_logs
                WHERE "timestamp" >= NOW() - INTERVAL '7 days';
            """)
            acc = conn.execute(q_acc_7d).scalar()
            model_accuracy = _to_float(acc, default=0.0) * 100.0 if acc is not None else 0.0

        # Accuracy trend vs prior week (simple diff)
        q_acc_trend = text("""
            WITH this AS (
              SELECT
                SUM(CASE WHEN (feedback_label IS NOT NULL)
                          AND ((feedback_label = 1 AND predicted_anomaly = true)
                            OR (feedback_label = 0 AND predicted_anomaly = false))
                    THEN 1 ELSE 0 END)::float /
                NULLIF(SUM(CASE WHEN feedback_label IS NOT NULL THEN 1 ELSE 0 END),0) AS acc
              FROM devl.model_logs
              WHERE "timestamp" >= NOW() - INTERVAL '7 days'
            ),
            prev AS (
              SELECT
                SUM(CASE WHEN (feedback_label IS NOT NULL)
                          AND ((feedback_label = 1 AND predicted_anomaly = true)
                            OR (feedback_label = 0 AND predicted_anomaly = false))
                    THEN 1 ELSE 0 END)::float /
                NULLIF(SUM(CASE WHEN feedback_label IS NOT NULL THEN 1 ELSE 0 END),0) AS acc
              FROM devl.model_logs
              WHERE "timestamp" >= NOW() - INTERVAL '14 days'
                AND "timestamp" < NOW() - INTERVAL '7 days'
            )
            SELECT (COALESCE((SELECT acc FROM this),0) - COALESCE((SELECT acc FROM prev),0)) * 100.0;
        """)
        trend_pct = _to_float(conn.execute(q_acc_trend).scalar(), default=0.0)

        # Data coverage: % of active sources today vs baseline (distinct sources last 30d)
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
        cov_pct = _to_float(conn.execute(q_cov, {"start": start, "end": end}).scalar(), default=0.0)

        # Data volume (TB) approximated by JSON size today
        q_vol = text("""
            SELECT COALESCE(SUM(octet_length(to_jsonb(data)::text)),0) / POWER(1024.0, 4)  -- TB
            FROM devl.unified_logs
            WHERE "timestamp" BETWEEN :start AND :end;
        """)
        tb_today = _to_float(conn.execute(q_vol, {"start": start, "end": end}).scalar(), default=0.0)

        # Avg response time (sec) over last 24h from JSON field data.response_time_sec
        q_resp = text("""
            SELECT AVG( (data->>'response_time_sec')::float )
            FROM devl.unified_logs
            WHERE "timestamp" >= NOW() - INTERVAL '24 hours'
              AND (data ? 'response_time_sec');
        """)
        avg_resp = _to_float(conn.execute(q_resp).scalar(), default=0.0)

        # You can wire this to a flag/table later
        auto_remediation_enabled = True

    return jsonify({
        "active_threats": int(active_today),
        "active_threats_change_pct": round(change_pct, 2),
        "model_accuracy": round(model_accuracy, 2),
        "model_accuracy_trend_pct": round(trend_pct, 2),
        "data_coverage_pct": round(cov_pct, 2),
        "data_volume_tb_today": round(tb_today, 3),
        "avg_response_time_sec": round(avg_resp, 3),
        "auto_remediation_enabled": auto_remediation_enabled
    })

@app.route("/api/heatmap")
def heatmap():
    """
    MITRE ATT&CK tactic counts for last 7 days.
    We map known fields to tactics using simple heuristics.
    """
    # Lightweight on-the-fly mapping (you can expand in mappings.py)
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

    # Ensure core tactics present (even if zero) for consistent UI
    core = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control",
            "Exfiltration", "Impact", "Reconnaissance", "Resource Development"]
    for t in core:
        counts.setdefault(t, 0)

    return jsonify({"tactics": counts})

@app.route("/api/assets")
def assets():
    """
    Latest affected assets where active_threat true (or predicted)
    """
    with engine.connect() as conn:
        q = text("""
            WITH ul AS (
              SELECT
                data->>'asset_id' AS asset_id,
                data->>'hostname' AS hostname,
                data->>'ip_address' AS ip,
                "timestamp" AS ts
              FROM devl.unified_logs
              WHERE (data->>'active_threat')::boolean = true
              ORDER BY "timestamp" DESC
              LIMIT 100
            ),
            ml AS (
              SELECT
                record_id AS asset_id,
                NULL::text AS hostname,
                NULL::text AS ip,
                "timestamp" AS ts
              FROM devl.model_logs
              WHERE predicted_active_threat = true
              ORDER BY "timestamp" DESC
              LIMIT 100
            )
            SELECT asset_id, hostname, ip, ts
            FROM (
              SELECT * FROM ul
              UNION ALL
              SELECT * FROM ml
            ) x
            WHERE asset_id IS NOT NULL
            ORDER BY ts DESC
            LIMIT 100;
        """)
        rows = conn.execute(q).fetchall()

    data = [
        {"asset_id": r.asset_id, "hostname": r.hostname, "ip_address": r.ip, "timestamp": r.ts.isoformat()}
        for r in rows
    ]
    return jsonify({"assets": data})

@app.route("/api/sessions")
def sessions():
    """
    Show session-like records if keys exist in JSONB: trust_score, risk_score, access_decision, anomaly_detected
    """
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
    Pull lightweight explainability + correlation from model_logs (latest 50 rows with content).
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
    return jsonify({"correlations": data})

@app.route("/api/model-performance")
def model_performance():
    """
    Returns precision/recall if feedback_label exists on recent data (last 7d).
    """
    with engine.connect() as conn:
        q = text("""
            WITH labeled AS (
              SELECT
                feedback_label,
                predicted_anomaly
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
# add this with your imports
import json

@app.route("/api/chat", methods=["POST"])
def chat():
    """
    AI chat assistant that can answer questions based on the dashboard data.
    Responds in HTML so the frontend can render tables/lists directly.
    """
    if OpenAI is None or not OPENAI_API_KEY:
        return jsonify({"error": "OpenAI not configured"}), 400

    user_msg = (request.json or {}).get("message", "").strip()
    if not user_msg:
        return jsonify({"error": "Empty message"}), 400

    # IMPORTANT: use *_json names so we don't shadow route functions
    summary_json     = summary().get_json()
    heatmap_json     = heatmap().get_json()
    assets_json      = assets().get_json()
    sessions_json    = sessions().get_json()
    correlation_json = correlation().get_json()
    model_perf_json  = model_performance().get_json()

    # ---------- Derived / sorted views (HTML tables) ----------
    # 1) Tactics sorted desc
    tactics_map = heatmap_json.get("tactics", {}) or {}
    sorted_tactics = sorted(
        ((k, int(v) if v is not None else 0) for k, v in tactics_map.items()),
        key=lambda kv: kv[1],
        reverse=True
    )
    tactics_rows_html = "\n".join(
        f"<tr><td>{name}</td><td style='text-align:right'>{count}</td></tr>"
        for name, count in sorted_tactics if count > 0
    ) or "<tr><td colspan='2'>No tactic counts in the last 7 days.</td></tr>"

    tactics_table_html = f"""
    <table>
      <thead><tr><th>Tactic</th><th>Count (7d)</th></tr></thead>
      <tbody>{tactics_rows_html}</tbody>
    </table>
    """

    # 2) Sessions by highest risk_score (top 10)
    def _to_float_safe(v):
        try:
            return float(v)
        except Exception:
            return float("nan")

    sessions_list = sessions_json.get("sessions", []) or []
    for s in sessions_list:
        s["_risk_num"] = _to_float_safe(s.get("risk_score"))

    # Sort: valid numbers first (NaN sorts last), then by timestamp desc
    sessions_sorted = sorted(
        sessions_list,
        key=lambda s: (
            0 if s["_risk_num"] == s["_risk_num"] else 1,           # 0 for valid, 1 for NaN
            -(s["_risk_num"] if s["_risk_num"] == s["_risk_num"] else 0.0),
            s.get("timestamp") or ""
        )
    )[:10]

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

    # 3) Recent assets (latest 10 by timestamp)
    assets_list = assets_json.get("assets", []) or []
    assets_sorted = sorted(assets_list, key=lambda a: a.get("timestamp") or "", reverse=True)[:10]
    assets_rows_html = "\n".join(
        f"<tr>"
        f"<td>{a.get('timestamp') or ''}</td>"
        f"<td>{a.get('asset_id') or ''}</td>"
        f"<td>{a.get('hostname') or ''}</td>"
        f"<td>{a.get('ip_address') or ''}</td>"
        f"</tr>"
        for a in assets_sorted
    ) or "<tr><td colspan='4'>No recent assets.</td></tr>"

    assets_table_html = f"""
    <table>
      <thead><tr><th>Time</th><th>Asset ID</th><th>Hostname</th><th>IP</th></tr></thead>
      <tbody>{assets_rows_html}</tbody>
    </table>
    """

    # 4) Top correlation features (count by explanation_top_feature), top 10
    from collections import Counter
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

    # KPI summary quick HTML block
    kpi_html = f"""
    <ul>
      <li><b>Active Threats Today:</b> {summary_json['active_threats']} ({summary_json['active_threats_change_pct']}% vs yesterday)</li>
      <li><b>ML Accuracy:</b> {summary_json['model_accuracy']}% (Δ {summary_json['model_accuracy_trend_pct']} pp vs prior week)</li>
      <li><b>Data Coverage:</b> {summary_json['data_coverage_pct']}%</li>
      <li><b>Data Volume Today:</b> {summary_json['data_volume_tb_today']} TB</li>
      <li><b>Avg Response Time:</b> {summary_json['avg_response_time_sec']} s</li>
      <li><b>Auto-remediation:</b> {"ON" if summary_json['auto_remediation_enabled'] else "OFF"}</li>
    </ul>
    """

    # ---- Build the context without %-formatting (prevents ValueError) ----
    raw_json_html = json.dumps(
        {
            "summary": summary_json,
            "model_performance": model_perf_json
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

<!-- Raw JSON snapshots for exact numbers -->
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
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"{user_msg}\n\n---\nContext (HTML):\n{context_block}"}
        ],
        temperature=0.2
    )
    reply_html = completion.choices[0].message.content
    return jsonify({"reply": reply_html})


@app.route("/health")
def health():
    return jsonify({"ok": True})


# --- NEW: 7-day MITRE + Active Threats daily trend ---
@app.route("/api/mitre-trend")
def mitre_trend():
    """
    Returns daily buckets for the last 7 days (including today):
    {
      "points": [
        {"date":"2025-08-22", "total":8, "ia":1, "c2":2, "active_threats":5},
        ...
      ]
    }
    """
    # same mapping as /api/heatmap
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

    # Build day list: today and previous 6 days
    today = dt.date.today()
    days = [today - dt.timedelta(days=i) for i in range(6, -1, -1)]  # oldest -> newest
    # Initialize counters
    buckets = {
        d.isoformat(): {"total": 0, "ia": 0, "c2": 0, "active_threats": 0}
        for d in days
    }

    start_dt = dt.datetime.combine(days[0], dt.time.min)

    with engine.connect() as conn:
        # Pull rows for last 7 days (for tactics)
        q_tactics = text("""
            SELECT "timestamp",
                   COALESCE(data->>'rule_engine_classified','') AS rule_cls,
                   COALESCE(data->>'discovery_method','')      AS disc
            FROM devl.unified_logs
            WHERE "timestamp" >= :start
        """)
        rows = conn.execute(q_tactics, {"start": start_dt}).fetchall()

        # Active threats per day from unified_logs
        q_ul = text("""
            SELECT DATE("timestamp") AS d, COUNT(*) AS c
            FROM devl.unified_logs
            WHERE "timestamp" >= :start
              AND (data->>'active_threat')::boolean = true
            GROUP BY 1
        """)
        ul_counts = {r.d.isoformat(): int(r.c) for r in conn.execute(q_ul, {"start": start_dt}).fetchall()}

        # Active threats per day from model_logs (predicted)
        q_ml = text("""
            SELECT DATE("timestamp") AS d, COUNT(*) AS c
            FROM devl.model_logs
            WHERE "timestamp" >= :start
              AND predicted_active_threat = true
            GROUP BY 1
        """)
        ml_counts = {r.d.isoformat(): int(r.c) for r in conn.execute(q_ml, {"start": start_dt}).fetchall()}

    # Tactic counts -> per-day buckets
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

    # Merge active threats (ul + ml) into buckets
    for d in buckets.keys():
        buckets[d]["active_threats"] = ul_counts.get(d, 0) + ml_counts.get(d, 0)

    # Return points ordered by date (oldest → newest)
    points = [
        {"date": d, **buckets[d]}
        for d in sorted(buckets.keys())
    ]
    return jsonify({"points": points})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)

    
