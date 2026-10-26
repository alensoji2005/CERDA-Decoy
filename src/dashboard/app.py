import json
import os
import time
from datetime import datetime
from src.analytics.validation import score_clusters
from typing import Dict, Any, Tuple

import pandas as pd
import streamlit as st
from src.analytics.telemetry_io import read_telemetry
from streamlit_autorefresh import st_autorefresh

from .visualizations import (
    build_cerf_network_figure,
    build_tactics_figure,
    build_regime_timeline_figure
)

RETRO_CLI_CSS = """
<style>
    .stApp { background-color: #000000; color: #00FF66; font-family: 'Courier New', Courier, monospace; }
    h1, h2, h3, h4, h5, h6, p, div, span, label { color: #00FF66 !important; font-family: 'Courier New', Courier, monospace !important; }
    .stDataFrame { border: 1px solid #00FF66; }
    div[data-baseweb="select"] > div { background-color: #050505; border: 1px solid #FFB000; color: #FFB000; }
    .stButton>button { background-color: #000000; border: 1px solid #FFB000; color: #FFB000; }
    .stButton>button:hover { background-color: #FFB000; color: #000000; }
</style>
"""

NEO_BRUTALISM_CSS = """
<style>
    .stApp { background-color: #f4f4f0; color: #000000; font-family: 'Space Grotesk', sans-serif; }
    h1, h2, h3, h4, h5, h6, p, div, span, label { color: #000000 !important; font-family: 'Space Grotesk', sans-serif !important; font-weight: 800; }
    .stDataFrame { border: 4px solid #000000; box-shadow: 6px 6px 0px 0px #000000; }
    div[data-baseweb="select"] > div { background-color: #ffffff; border: 4px solid #000000; color: #000000; box-shadow: 4px 4px 0px 0px #000000; border-radius: 0px; }
    .stButton>button { background-color: #ff3b3b; border: 4px solid #000000; color: #000000; font-weight: 900; box-shadow: 4px 4px 0px 0px #000000; border-radius: 0px; text-transform: uppercase; }
    .stButton>button:hover { background-color: #ffea00; box-shadow: 2px 2px 0px 0px #000000; transform: translate(2px, 2px); }
    [data-testid="stMetricValue"] { font-size: 2.5rem !important; border-bottom: 4px solid #000; display: block; padding-bottom: 5px; word-wrap: break-word; }
    .css-1544g2n { padding: 2rem; border: 4px solid #000; box-shadow: 8px 8px 0px 0px #000; background: #fff; margin-bottom: 2rem; overflow: hidden; }
    hr { border-top: 4px solid #000 !important; }
</style>
"""

class CERDDashboard:
    def __init__(self, sessions_path: str = "sessions.csv", telemetry_path: str = "telemetry.csv"):
        self.sessions_path = sessions_path
        self.telemetry_path = telemetry_path
        self.sessions_df = pd.DataFrame()
        self.telemetry_df = pd.DataFrame()
        
    def load_data(self) -> None:
        if os.path.exists(self.sessions_path):
            self.sessions_df = pd.read_csv(self.sessions_path)
        else:
            self.sessions_df = pd.DataFrame(columns=[
                "session_id", "source_ip", "cerf", "threat_actor_id", 
                "embedding_norm", "num_commands", "dominant_regime"
            ])
            
        if os.path.exists(self.telemetry_path):
            self.telemetry_df = read_telemetry(self.telemetry_path)
        else:
            self.telemetry_df = pd.DataFrame(columns=[
                "session_id", "timestamp_ns", "source_ip", "protocol",
                "command_index", "command_raw", "command_root",
                "current_path", "regime", "delta_t_ns", "response_sent"
            ])

    def render_theme_toggle(self) -> str:
        theme = st.sidebar.radio("UI Theme", ["Neo-Brutalism", "Retro CLI / Console"])
        if theme == "Retro CLI / Console":
            st.markdown(RETRO_CLI_CSS, unsafe_allow_html=True)
            return "retro"
        else:
            st.markdown(NEO_BRUTALISM_CSS, unsafe_allow_html=True)
            return "academic"

    def render_sidebar(self) -> Dict[str, Any]:
        st.sidebar.header("Filter Controls")
        protocols = ["All"]
        if not self.telemetry_df.empty:
            protocols += self.telemetry_df["protocol"].unique().tolist()
        selected_protocol = st.sidebar.selectbox("Protocol", protocols)
        
        ta_ids = []
        if not self.sessions_df.empty:
            ta_ids = self.sessions_df["threat_actor_id"].unique().tolist()
        selected_tas = st.sidebar.multiselect("Threat Actor ID", ta_ids, default=ta_ids)
        
        cerf_search = st.sidebar.text_input("CERF Hash Search")
        
        date_range = None
        if not self.telemetry_df.empty:
            min_ts = pd.to_datetime(self.telemetry_df["timestamp_ns"].min(), unit='ns').date()
            max_ts = pd.to_datetime(self.telemetry_df["timestamp_ns"].max(), unit='ns').date()
            date_range = st.sidebar.date_input("Date Range", [min_ts, max_ts])
        
        return {
            "protocol": selected_protocol,
            "threat_actors": selected_tas,
            "cerf_search": cerf_search,
            "date_range": date_range
        }

    def get_filtered_data(self, filters: Dict[str, Any]) -> Tuple[pd.DataFrame, pd.DataFrame]:
        sdf = self.sessions_df.copy()
        tdf = self.telemetry_df.copy()
        
        if not sdf.empty:
            if filters["threat_actors"]:
                sdf = sdf[sdf["threat_actor_id"].isin(filters["threat_actors"])]
            if filters["cerf_search"]:
                sdf = sdf[sdf["cerf"].str.contains(filters["cerf_search"], na=False)]
                
        if not tdf.empty:
            if filters["protocol"] != "All":
                tdf = tdf[tdf["protocol"] == filters["protocol"]]
            if filters["date_range"] and len(filters["date_range"]) == 2:
                start_date, end_date = filters["date_range"]
                tdf_dates = pd.to_datetime(tdf["timestamp_ns"], unit='ns').dt.date
                tdf = tdf[(tdf_dates >= start_date) & (tdf_dates <= end_date)]
            
        return sdf, tdf

    def render_live_sessions(self, sdf: pd.DataFrame) -> None:
        st.subheader("Captured Sessions Registry")
        if sdf.empty:
            st.info("No sessions captured yet.")
            return
        display_df = sdf[["threat_actor_id", "session_id", "source_ip", "cerf", "num_commands", "dominant_regime"]]
        st.dataframe(display_df, use_container_width=True, hide_index=True)

    def render_cerf_graph(self, sdf: pd.DataFrame, theme: str) -> None:
        st.subheader("CERF Threat Actor Topology")
        if sdf.empty:
            st.info("Insufficient data for graph.")
            return
        fig = build_cerf_network_figure(sdf, theme)
        st.plotly_chart(fig, use_container_width=True)

    def render_tactics_plot(self, sdf: pd.DataFrame, theme: str) -> None:
        st.subheader("Tactics Embedding Projection")
        if sdf.empty or "embedding_norm" not in sdf.columns:
            st.info("Insufficient data.")
            return
        fig = build_tactics_figure(sdf, theme)
        st.plotly_chart(fig, use_container_width=True)

    def render_regime_timeline(self, tdf: pd.DataFrame, theme: str) -> None:
        st.subheader("Counterfactual Regime Timeline")
        if tdf.empty:
            st.info("No telemetry data available.")
            return
        session_list = tdf["session_id"].unique().tolist()
        selected_session = st.selectbox("Select Session for Timeline Analysis", session_list)
        if not selected_session:
            return
        session_tdf = tdf[tdf["session_id"] == selected_session].sort_values("command_index")
        if session_tdf.empty:
            return
        fig = build_regime_timeline_figure(session_tdf, theme)
        st.plotly_chart(fig, use_container_width=True)

    def export_threat_intel(self) -> str:
        if self.sessions_df.empty:
            return "{}"
        actors = []
        for ta_id, group in self.sessions_df.groupby("threat_actor_id"):
            session_ids = group["session_id"].tolist()
            tdf_group = self.telemetry_df[self.telemetry_df["session_id"].isin(session_ids)]
            
            first_seen = datetime.utcnow().isoformat() + "Z"
            last_seen = datetime.utcnow().isoformat() + "Z"
            tactics = set(["Command Execution"])
            
            if not tdf_group.empty:
                first_seen = pd.to_datetime(tdf_group["timestamp_ns"].min(), unit='ns').isoformat() + "Z"
                last_seen = pd.to_datetime(tdf_group["timestamp_ns"].max(), unit='ns').isoformat() + "Z"
                
                cmds = " ".join(tdf_group["command_raw"].astype(str).tolist())
                if "wget" in cmds or "curl" in cmds:
                    tactics.add("Dropper")
                if "ls" in cmds or "whoami" in cmds or "pwd" in cmds:
                    tactics.add("Reconnaissance")
                
            actors.append({
                "threat_actor_id": ta_id,
                "cerf": group["cerf"].iloc[0],
                "associated_ips": group["source_ip"].unique().tolist(),
                "num_sessions": len(group),
                "tactics": list(tactics),
                "first_seen": first_seen,
                "last_seen": last_seen
            })
        payload = {
            "export_timestamp": datetime.utcnow().isoformat() + "Z",
            "threat_actors": actors
        }
        return json.dumps(payload, indent=2)


def main():
    st.set_page_config(page_title="CERDA Dashboard", layout="wide")
    st_autorefresh(interval=3000, key="datarefresh")
    
    dash = CERDDashboard()
    dash.load_data()
    theme = dash.render_theme_toggle()
    
    st.title("CERDA: Counterfactual Execution-Rhythm Decoy Architecture")
    
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Active Decoy Listeners", "Ports 2222, 8080", "Online")
    kpi2.metric("Total Captured Sessions", len(dash.sessions_df))
    kpi3.metric("Attributed Threat Actors", dash.sessions_df["threat_actor_id"].nunique() if not dash.sessions_df.empty else 0)
    score = score_clusters(dash.sessions_df) if not dash.sessions_df.empty else {"ari": None, "labelled": 0, "sessions": 0}
    # Measured against weak labels (shared dropper URL / SSH key); n/a until sessions carry such links.
    kpi4.metric("Cluster Agreement (ARI)", "n/a" if score["ari"] is None else f"{score['ari']:.2f}",
                f"{score['labelled']}/{score['sessions']} sessions labelled", delta_color="off")
    
    st.markdown("---")
    filters = dash.render_sidebar()
    sdf, tdf = dash.get_filtered_data(filters)
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Live Sessions", "CERF Network Graph", "Tactics Scatter Plot", "Regime Timeline", "Export Intel"
    ])
    
    with tab1:
        dash.render_live_sessions(sdf)
    with tab2:
        dash.render_cerf_graph(sdf, theme)
    with tab3:
        dash.render_tactics_plot(sdf, theme)
    with tab4:
        dash.render_regime_timeline(tdf, theme)
    with tab5:
        st.subheader("Threat Intelligence Output")
        json_payload = dash.export_threat_intel()
        st.code(json_payload, language="json")
        st.download_button(
            label="Download STIX/JSON Intel",
            data=json_payload,
            file_name="cerda_threat_intel.json",
            mime="application/json"
        )
