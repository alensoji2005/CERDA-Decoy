import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

def build_cerf_network_figure(sdf: pd.DataFrame, theme: str) -> go.Figure:
    G = nx.Graph()
    for _, row in sdf.iterrows():
        G.add_node(row["session_id"], ta=row["threat_actor_id"], cerf=row["cerf"], ip=row["source_ip"])
        
    for ta in sdf["threat_actor_id"].unique():
        ta_nodes = sdf[sdf["threat_actor_id"] == ta]["session_id"].tolist()
        for i in range(len(ta_nodes)):
            for j in range(i+1, len(ta_nodes)):
                G.add_edge(ta_nodes[i], ta_nodes[j])
                
    pos = nx.spring_layout(G, seed=42)
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        
    edge_color = "#00FF66" if theme == "retro" else "#94A3B8"
    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color=edge_color), hoverinfo='none', mode='lines')
    
    node_x, node_y, hover_text, colors = [], [], [], []
    ta_colors = px.colors.qualitative.Plotly
    ta_list = sdf["threat_actor_id"].unique().tolist()
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        ta = G.nodes[node]["ta"]
        hover_text.append(f"TA: {ta}<br>IP: {G.nodes[node]['ip']}<br>CERF: {G.nodes[node]['cerf']}")
        colors.append(ta_colors[ta_list.index(ta) % len(ta_colors)])
        
    node_trace = go.Scatter(
        x=node_x, y=node_y, mode='markers', hoverinfo='text', text=hover_text,
        marker=dict(showscale=False, color=colors, size=15, line_width=2)
    )
    
    bg_color = "rgba(0,0,0,0)"
    font_color = "#00FF66" if theme == "retro" else "#0F172A"
    
    fig = go.Figure(data=[edge_trace, node_trace], layout=go.Layout(
        showlegend=False, hovermode='closest',
        margin=dict(b=0, l=0, r=0, t=0),
        paper_bgcolor=bg_color, plot_bgcolor=bg_color,
        font=dict(color=font_color),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    ))
    return fig

def build_tactics_figure(sdf: pd.DataFrame, theme: str) -> go.Figure:
    bg_color = "rgba(0,0,0,0)"
    font_color = "#00FF66" if theme == "retro" else "#0F172A"
    
    fig = px.scatter(
        sdf, x="num_commands", y="embedding_norm", color="threat_actor_id",
        hover_data=["session_id", "source_ip", "dominant_regime"],
        title="Session Vectors (Num Commands vs Embedding Norm)"
    )
    fig.update_layout(
        paper_bgcolor=bg_color, plot_bgcolor=bg_color, font=dict(color=font_color)
    )
    return fig

def build_regime_timeline_figure(session_tdf: pd.DataFrame, theme: str) -> go.Figure:
    bg_color = "rgba(0,0,0,0)"
    font_color = "#00FF66" if theme == "retro" else "#0F172A"
    line_color = "#FFB000" if theme == "retro" else "#EF4444"
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=session_tdf["command_index"], 
        y=session_tdf["delta_t_ns"] / 1e6,
        mode='lines+markers', name='Response Latency (ms)',
        line=dict(color=line_color, width=2)
    ))
    
    colors = {"baseline": "#10B981", "slowdown": "#F59E0B", "jitter": "#F97316", "fs_latency": "#8B5CF6"}
    shapes = []
    current_reg = None
    start_idx = 0
    
    for i, row in session_tdf.iterrows():
        if row["regime"] != current_reg:
            if current_reg is not None:
                shapes.append(dict(
                    type="rect", xref="x", yref="paper",
                    x0=start_idx - 0.5, y0=0, x1=row["command_index"] - 0.5, y1=1,
                    fillcolor=colors.get(current_reg, "#cccccc"), opacity=0.1, layer="below", line_width=0
                ))
            current_reg = row["regime"]
            start_idx = row["command_index"]
            
    if current_reg is not None and not session_tdf.empty:
        shapes.append(dict(
            type="rect", xref="x", yref="paper",
            x0=start_idx - 0.5, y0=0, x1=session_tdf["command_index"].max() + 0.5, y1=1,
            fillcolor=colors.get(current_reg, "#cccccc"), opacity=0.1, layer="below", line_width=0
        ))
        
    fig.update_layout(
        shapes=shapes,
        title="Attacker Response Latency vs Forced Decoy Perturbation",
        xaxis_title="Command Index", yaxis_title="Latency Δt (ms)",
        paper_bgcolor=bg_color, plot_bgcolor=bg_color, font=dict(color=font_color)
    )
    return fig
