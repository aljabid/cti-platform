"""
dashboard/app.py
SOC Dashboard built with Streamlit.
Shows: threat feed, severity charts, IOC lookup, risk timeline, MITRE heatmap.
Gap filled: auth, IOC lookup panel, MITRE ATT&CK view, report export.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta, timezone
import sys
import os
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../"))

from src.database.db import init_db
from src.database.models import (
    Threat, IOC, Alert, SeverityLevel, AlertStatus, ThreatCategory
)
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

# ─── Page Config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="CTI Platform — SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Auth ─────────────────────────────────────────────────────────────────────

DASHBOARD_USER = os.getenv("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASS = os.getenv("DASHBOARD_PASSWORD", "admin")


def check_auth(username: str, password: str) -> bool:
    return username == DASHBOARD_USER and password == DASHBOARD_PASS


def login_page():
    st.markdown("## 🛡️ CTI Platform — SOC Dashboard")
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("### Sign In")
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Sign in", use_container_width=True, type="primary"):
            if check_auth(username, password):
                st.session_state["authenticated"] = True
                st.session_state["user"] = username
                st.rerun()
            else:
                st.error("Invalid credentials")


if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    login_page()
    st.stop()

# ─── DB Session ───────────────────────────────────────────────────────────────

@st.cache_resource
def get_engine():
    from src.database.db import engine
    init_db()
    return engine


engine = get_engine()


def get_session() -> Session:
    from src.database.db import SessionLocal
    return SessionLocal()


# ─── Data Loading ─────────────────────────────────────────────────────────────

@st.cache_data(ttl=60)
def load_threats(days_back: int = 30):
    """Load threats from DB into DataFrame."""
    with get_session() as db:
        since = datetime.now(timezone.utc) - timedelta(days=days_back)
        threats = db.query(Threat).filter(Threat.collected_at >= since)\
            .order_by(Threat.risk_score.desc()).limit(500).all()

        rows = []
        for t in threats:
            rows.append({
                "ID": t.id,
                "CVE": t.cve_id or "N/A",
                "Title": (t.title or "")[:80],
                "Category": t.category.value if t.category else "Unknown",
                "Severity": t.severity.value if t.severity else "Medium",
                "Risk Score": round(t.risk_score or 0, 2),
                "CVSS": t.cvss_score or 0,
                "Velocity": round(t.threat_velocity or 0, 2),
                "Exploit": "✅" if t.exploit_available else "❌",
                "In Wild": "🔴" if t.in_the_wild else "—",
                "MITRE Tactic": t.mitre_tactic or "—",
                "MITRE Technique": t.mitre_technique or "—",
                "Source": t.source or "—",
                "Collected": t.collected_at.strftime("%Y-%m-%d %H:%M") if t.collected_at else "—",
            })
        return pd.DataFrame(rows)


@st.cache_data(ttl=60)
def load_stats():
    with get_session() as db:
        return {
            "total": db.query(Threat).count(),
            "critical": db.query(Threat).filter_by(severity=SeverityLevel.CRITICAL).count(),
            "high": db.query(Threat).filter_by(severity=SeverityLevel.HIGH).count(),
            "exploits": db.query(Threat).filter_by(exploit_available=True).count(),
            "in_wild": db.query(Threat).filter_by(in_the_wild=True).count(),
            "open_alerts": db.query(Alert).filter_by(status=AlertStatus.NEW).count(),
            "total_iocs": db.query(IOC).count(),
        }


@st.cache_data(ttl=120)
def load_category_dist():
    with get_session() as db:
        rows = db.query(Threat.category, func.count(Threat.id))\
            .group_by(Threat.category).all()
        return {str(c.value if c else "Unknown"): n for c, n in rows}


@st.cache_data(ttl=120)
def load_timeline(days_back: int = 14):
    with get_session() as db:
        since = datetime.now(timezone.utc) - timedelta(days=days_back)
        rows = db.query(
            func.date(Threat.collected_at).label("date"),
            Threat.severity,
            func.count(Threat.id).label("count"),
        ).filter(Threat.collected_at >= since)\
         .group_by(func.date(Threat.collected_at), Threat.severity).all()

        data = []
        for row in rows:
            data.append({
                "Date": str(row.date),
                "Severity": row.severity.value if row.severity else "Unknown",
                "Count": row.count,
            })
        return pd.DataFrame(data)


def search_ioc(query: str):
    with get_session() as db:
        results = db.query(IOC).filter(IOC.value.ilike(f"%{query}%")).limit(50).all()
        return [
            {
                "Type": ioc.ioc_type.value,
                "Value": ioc.value,
                "Malicious": ioc.is_malicious,
                "Threat ID": ioc.threat_id or "—",
                "First Seen": ioc.first_seen.strftime("%Y-%m-%d") if ioc.first_seen else "—",
            }
            for ioc in results
        ]


# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ CTI Platform")
    st.markdown(f"**User:** {st.session_state.get('user', 'admin')}")
    st.markdown("---")

    page = st.radio(
        "Navigation",
        ["📊 Overview", "🔍 Threat Feed", "🧬 IOC Lookup",
         "⚔️ MITRE ATT&CK", "🚨 Alerts", "📄 Reports"],
        label_visibility="collapsed",
    )

    st.markdown("---")
    days_filter = st.slider("Days to show", 1, 90, 30)

    st.markdown("---")
    if st.button("🔄 Refresh data"):
        st.cache_data.clear()
        st.rerun()

    if st.button("🚪 Sign out"):
        st.session_state.clear()
        st.rerun()

# ─── Header ───────────────────────────────────────────────────────────────────

stats = load_stats()
now = datetime.now(timezone.utc)

st.markdown(f"## {page}")
st.markdown(
    f"<small style='color: #6b7280;'>Last updated: {now.strftime('%Y-%m-%d %H:%M UTC')}</small>",
    unsafe_allow_html=True,
)
st.markdown("---")

# ─── KPI Row (always visible) ─────────────────────────────────────────────────

k1, k2, k3, k4, k5, k6, k7 = st.columns(7)
k1.metric("Total Threats", stats["total"])
k2.metric("🔴 Critical", stats["critical"])
k3.metric("🟠 High", stats["high"])
k4.metric("💣 With Exploits", stats["exploits"])
k5.metric("🌐 In The Wild", stats["in_wild"])
k6.metric("🔔 Open Alerts", stats["open_alerts"])
k7.metric("🧬 IOCs", stats["total_iocs"])

st.markdown("---")

# ─── Pages ────────────────────────────────────────────────────────────────────

if page == "📊 Overview":
    df = load_threats(days_filter)
    cat_dist = load_category_dist()
    timeline_df = load_timeline(min(days_filter, 30))

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Threats by Category")
        if cat_dist:
            fig = px.pie(
                values=list(cat_dist.values()),
                names=list(cat_dist.keys()),
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Set3,
            )
            fig.update_layout(margin=dict(t=20, b=20), height=320)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data yet — run the pipeline to collect threats.")

    with col2:
        st.subheader("Severity Distribution")
        if not df.empty:
            sev_counts = df["Severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            color_map = {
                "Critical": "#dc2626", "High": "#ea580c",
                "Medium": "#ca8a04", "Low": "#16a34a", "Informational": "#6b7280"
            }
            fig = px.bar(
                sev_counts, x="Severity", y="Count",
                color="Severity", color_discrete_map=color_map,
            )
            fig.update_layout(showlegend=False, margin=dict(t=20, b=20), height=320)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data yet.")

    st.subheader("Threat Timeline")
    if not timeline_df.empty:
        fig = px.bar(
            timeline_df, x="Date", y="Count", color="Severity",
            color_discrete_map={
                "Critical": "#dc2626", "High": "#ea580c",
                "Medium": "#ca8a04", "Low": "#16a34a",
            },
            barmode="stack",
        )
        fig.update_layout(height=260, margin=dict(t=10, b=20))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Timeline data will appear after threats are collected.")

    st.subheader("Top 10 Highest Risk Threats")
    if not df.empty:
        top10 = df.head(10)[["CVE", "Category", "Severity", "Risk Score", "CVSS", "Exploit", "In Wild", "MITRE Tactic"]]
        st.dataframe(top10, use_container_width=True, hide_index=True)

elif page == "🔍 Threat Feed":
    df = load_threats(days_filter)

    # Filters
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        sev_filter = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=[])
    with col2:
        cat_filter = st.multiselect("Category", list(set(df["Category"].tolist())) if not df.empty else [], default=[])
    with col3:
        exploit_filter = st.checkbox("Exploit available only")
    with col4:
        wild_filter = st.checkbox("In the wild only")

    filtered = df.copy()
    if sev_filter:
        filtered = filtered[filtered["Severity"].isin(sev_filter)]
    if cat_filter:
        filtered = filtered[filtered["Category"].isin(cat_filter)]
    if exploit_filter:
        filtered = filtered[filtered["Exploit"] == "✅"]
    if wild_filter:
        filtered = filtered[filtered["In Wild"] == "🔴"]

    st.markdown(f"**Showing {len(filtered)} threats**")

    if not filtered.empty:
        display_cols = ["CVE", "Title", "Category", "Severity", "Risk Score",
                        "CVSS", "Exploit", "In Wild", "Collected"]
        st.dataframe(
            filtered[display_cols],
            use_container_width=True,
            hide_index=True,
            column_config={
                "Risk Score": st.column_config.ProgressColumn(
                    min_value=0, max_value=10, format="%.2f"
                ),
            },
        )

        # Export
        csv = filtered.to_csv(index=False).encode()
        st.download_button("📥 Export CSV", csv, "threats.csv", "text/csv")
    else:
        st.info("No threats match filters, or pipeline hasn't run yet.")

elif page == "🧬 IOC Lookup":
    st.subheader("Search Indicators of Compromise")
    st.markdown("Search for IPs, domains, file hashes, CVE IDs, or email addresses across all threats.")

    ioc_query = st.text_input("🔍 Enter IOC value", placeholder="e.g. 192.168.1.1, malicious.example.com, abc123...")

    if ioc_query and len(ioc_query) >= 3:
        with st.spinner("Searching..."):
            results = search_ioc(ioc_query)
        if results:
            st.success(f"Found {len(results)} matching IOCs")
            ioc_df = pd.DataFrame(results)
            st.dataframe(ioc_df, use_container_width=True, hide_index=True)
        else:
            st.info("No IOCs found matching that query.")
    elif ioc_query:
        st.warning("Enter at least 3 characters to search.")

    st.markdown("---")
    st.subheader("IOC Type Distribution")
    with get_session() as db:
        ioc_types = db.query(IOC.ioc_type, func.count(IOC.id))\
            .group_by(IOC.ioc_type).all()
        if ioc_types:
            ioc_df = pd.DataFrame(
                [(t.value, n) for t, n in ioc_types],
                columns=["Type", "Count"]
            )
            fig = px.bar(ioc_df, x="Type", y="Count", color="Type")
            fig.update_layout(showlegend=False, height=280)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No IOCs yet. Run the pipeline first.")

elif page == "⚔️ MITRE ATT&CK":
    df = load_threats(days_filter)
    st.subheader("MITRE ATT&CK Coverage")
    st.markdown("Threats mapped to MITRE ATT&CK tactics and techniques.")

    if not df.empty:
        mitre_df = df[df["MITRE Tactic"] != "—"][["CVE", "Category", "Severity", "Risk Score", "MITRE Tactic", "MITRE Technique"]]

        # Tactic distribution
        tactic_counts = mitre_df["MITRE Tactic"].value_counts().reset_index()
        tactic_counts.columns = ["Tactic", "Count"]

        col1, col2 = st.columns([1, 2])
        with col1:
            fig = px.pie(tactic_counts, values="Count", names="Tactic", hole=0.35,
                         title="By Tactic")
            fig.update_layout(height=320, margin=dict(t=30, b=10))
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            fig = px.bar(tactic_counts, x="Tactic", y="Count",
                         color="Count", color_continuous_scale="Reds",
                         title="Threat Count per Tactic")
            fig.update_layout(height=320, margin=dict(t=30, b=10), showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Technique Breakdown")
        st.dataframe(
            mitre_df.sort_values("Risk Score", ascending=False),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No data yet.")

elif page == "🚨 Alerts":
    with get_session() as db:
        alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(100).all()

    if alerts:
        for alert in alerts:
            color = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(
                alert.severity.value if alert.severity else "Low", "⚪"
            )
            with st.expander(f"{color} {alert.title} — {alert.created_at.strftime('%Y-%m-%d %H:%M') if alert.created_at else ''}"):
                st.text(alert.message)
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Status:** {alert.status.value if alert.status else 'new'}")
                    st.markdown(f"**Triggered by:** {alert.triggered_by or '—'}")
                with col2:
                    st.markdown(f"**Notified via:** {', '.join(alert.notified_via or []) or 'console'}")
    else:
        st.info("No alerts yet. Alerts are triggered when threats exceed configured thresholds.")

elif page == "📄 Reports":
    st.subheader("Generate Threat Intelligence Report")

    col1, col2 = st.columns(2)
    with col1:
        report_days = st.slider("Report period (days)", 1, 90, 7)
        include_critical = st.checkbox("Include only Critical/High", value=True)
    with col2:
        format_choice = st.radio("Format", ["Markdown", "CSV"])

    if st.button("📄 Generate Report", type="primary"):
        df = load_threats(report_days)
        if include_critical:
            df = df[df["Severity"].isin(["Critical", "High"])]

        if df.empty:
            st.warning("No threats found for selected criteria.")
        else:
            if format_choice == "Markdown":
                lines = [
                    f"# Cyber Threat Intelligence Report",
                    f"**Period:** Last {report_days} days",
                    f"**Generated:** {now.strftime('%Y-%m-%d %H:%M UTC')}",
                    f"**Total threats:** {len(df)}",
                    f"**Critical:** {(df['Severity'] == 'Critical').sum()}",
                    f"**High:** {(df['Severity'] == 'High').sum()}",
                    f"**With Exploits:** {(df['Exploit'] == '✅').sum()}",
                    f"**In The Wild:** {(df['In Wild'] == '🔴').sum()}",
                    "\n---\n## Top Threats\n",
                ]
                for _, row in df.head(20).iterrows():
                    lines.append(
                        f"### {row['CVE']} — {row['Category']}\n"
                        f"- **Severity:** {row['Severity']}\n"
                        f"- **Risk Score:** {row['Risk Score']}\n"
                        f"- **CVSS:** {row['CVSS']}\n"
                        f"- **Exploit Available:** {row['Exploit']}\n"
                        f"- **MITRE:** {row['MITRE Tactic']} / {row['MITRE Technique']}\n"
                        f"- **Collected:** {row['Collected']}\n"
                    )
                report_content = "\n".join(lines)
                st.markdown(report_content)
                st.download_button(
                    "📥 Download Report",
                    report_content.encode(),
                    f"cti_report_{now.strftime('%Y%m%d')}.md",
                    "text/markdown",
                )
            else:
                csv = df.to_csv(index=False).encode()
                st.download_button(
                    "📥 Download CSV",
                    csv,
                    f"cti_report_{now.strftime('%Y%m%d')}.csv",
                    "text/csv",
                )
                st.dataframe(df, use_container_width=True, hide_index=True)
