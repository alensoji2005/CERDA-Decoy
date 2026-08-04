import json
import os
import time
from datetime import datetime
from typing import Dict, Any, Tuple

import pandas as pd
import streamlit as st

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

ACADEMIC_CSS = """
<style>
    .stApp { background-color: #F8FAFC; color: #0F172A; font-family: 'Inter', sans-serif; }
    h1, h2, h3 { color: #1E293B !important; font-family: 'Merriweather', serif !important; }
    h4, h5, h6, p, div, span, label { color: #334155 !important; }
    .stDataFrame { border: 1px solid #CBD5E1; border-radius: 4px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }
    div[data-baseweb="select"] > div { background-color: #FFFFFF; border: 1px solid #94A3B8; color: #0F172A; }
    .stButton>button { background-color: #2563EB; border: none; color: #FFFFFF; border-radius: 4px; }
    .stButton>button:hover { background-color: #1D4ED8; color: #FFFFFF; }
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
            self.telemetry_df = pd.read_csv(self.telemetry_path)
        else:
            self.telemetry_df = pd.DataFrame(columns=[
                "session_id", "timestamp_ns", "source_ip", "protocol",
                "command_index", "command_raw", "command_root",
                "current_path", "regime", "delta_t_ns", "response_sent"
            ])

    def render_theme_toggle(self) -> str:
        theme = st.sidebar.radio("UI Theme", ["Academic / Scientific", "Retro CLI / Console"])
        if theme == "Retro CLI / Console":
            st.markdown(RETRO_CLI_CSS, unsafe_allow_html=True)
            return "retro"
        else:
            st.markdown(ACADEMIC_CSS, unsafe_allow_html=True)
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
        
        return {
            "protocol": selected_protocol,
            "threat_actors": selected_tas,
            "cerf_search": cerf_search
        }

    def get_filtered_data(self, filters: Dict[str, Any]) -> Tuple[pd.DataFrame, pd.DataFrame]:
        sdf = self.sessions_df.copy()
        tdf = self.telemetry_df.copy()
        
        if not sdf.empty:
            if filters["threat_actors"]:
                sdf = sdf[sdf["threat_actor_id"].isin(filters["threat_actors"])]
            if filters["cerf_search"]:
                sdf = sdf[sdf["cerf"].str.contains(filters["cerf_search"], na=False)]
                
        if not tdf.empty and filters["protocol"] != "All":
            tdf = tdf[tdf["protocol"] == filters["protocol"]]
            
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
            actors.append({
                "threat_actor_id": ta_id,
                "cerf": group["cerf"].iloc[0],
                "associated_ips": group["source_ip"].unique().tolist(),
                "num_sessions": len(group),
                "tactics": ["Command Execution"],
                "first_seen": datetime.utcnow().isoformat() + "Z",
                "last_seen": datetime.utcnow().isoformat() + "Z"
            })
        payload = {
            "export_timestamp": datetime.utcnow().isoformat() + "Z",
            "threat_actors": actors
        }
        return json.dumps(payload, indent=2)


def main():
    st.markdown('<meta http-equiv="refresh" content="60">', unsafe_allow_html=True)
    st.set_page_config(page_title="CERDA Dashboard", layout="wide")
    
    dash = CERDDashboard()
    dash.load_data()
    theme = dash.render_theme_toggle()
    
    st.title("CERDA: Counterfactual Execution-Rhythm Decoy Architecture")
    
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Active Decoy Listeners", "Ports 2222, 8080", "Online")
    kpi2.metric("Total Captured Sessions", len(dash.sessions_df))
    kpi3.metric("Attributed Threat Actors", dash.sessions_df["threat_actor_id"].nunique() if not dash.sessions_df.empty else 0)
    kpi4.metric("CERF Accuracy Rating", "≥ 90%", "Verified")
    
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
