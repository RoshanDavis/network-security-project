"""
🛡️ Network IDS — Live Dashboard
================================
Real-time packet sniffing and intrusion detection using a trained Random Forest model
combined with rule-based anomaly detection.

Hybrid approach (mirrors real IDS systems like Snort):
  • ML Model  — classifies per-flow feature vectors against CICIDS2017 patterns
  • Rules     — catches volumetric anomalies (SYN floods, traffic spikes)

Run with: streamlit run app.py   (from an Administrator PowerShell)
"""

import os
import time
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

import streamlit as st
import numpy as np
import pandas as pd
import joblib

# ---------------------------------------------------------------------------
# Page Config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="🛡️ Network IDS — Live Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
WINDOW_SECONDS = 2
MAX_HISTORY = 60
FEATURE_NAMES = [
    "Destination Port",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "SYN Flag Count",
    "ACK Flag Count",
]
ML_ATTACK_PROBA_THRESHOLD = 0.35  # lower than 0.5 to improve recall on live synthetic attacks

# Rule-based thresholds
SYN_FLOOD_THRESHOLD = 50       # SYN packets per window to consider suspicious
SYN_ACK_RATIO_THRESHOLD = 3.0  # SYN/ACK ratio above this → likely SYN flood
VOLUME_SPIKE_THRESHOLD = 200   # Packets per window considered a traffic spike
PORT_SCAN_THRESHOLD = 15       # Unique dest ports in one window → port scan
XMAS_FLAG_MASK = 0x29          # FIN+PSH+URG flags (Christmas Tree attack)

# ---------------------------------------------------------------------------
# Load Model & Scaler
# ---------------------------------------------------------------------------
@st.cache_resource
def load_model_and_scaler():
    model_path = os.path.join(MODELS_DIR, "best_model.joblib")
    scaler_path = os.path.join(MODELS_DIR, "scaler.joblib")
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        return None, None
    m = joblib.load(model_path)
    # Suppress verbose parallel output from RandomForest
    m.verbose = 0
    return m, joblib.load(scaler_path)

model, scaler = load_model_and_scaler()

# ---------------------------------------------------------------------------
# Scapy Import
# ---------------------------------------------------------------------------
SCAPY_AVAILABLE = False
try:
    from scapy.all import AsyncSniffer, TCP, IP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Shared Sniffer State (persists across Streamlit reruns via cache_resource)
# ---------------------------------------------------------------------------
@dataclass
class SnifferState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    packet_buffer: list = field(default_factory=list)
    sniffer_started: bool = False
    sniffer_instance: object = None
    sniffer_iface: str = "unknown"
    sniffer_error: str = ""
    capture_count: int = 0


@st.cache_resource
def get_sniffer_state():
    return SnifferState()


shared = get_sniffer_state()


# ---------------------------------------------------------------------------
# Packet Callback (runs in Scapy's sniffer thread)
# ---------------------------------------------------------------------------
def _packet_callback(pkt):
    if TCP in pkt:
        with shared.lock:
            shared.packet_buffer.append(pkt)
            shared.capture_count += 1


# ---------------------------------------------------------------------------
# Feature Extraction — PER FLOW (not per window)
#
# CICIDS2017 features are per-flow, so we group packets bidirectionally
# and infer a stable forward/backward direction per flow.
# This produces feature vectors on the same scale the model was trained on.
# ---------------------------------------------------------------------------
def _infer_forward_direction(flow_packets, endpoint_a, endpoint_b):
    """Infer stable client->server orientation for a bidirectional flow."""
    # Best signal: connection initiator packet (SYN without ACK).
    for pkt in flow_packets:
        tcp = pkt[TCP]
        has_syn = bool(tcp.flags & 0x02)
        has_ack = bool(tcp.flags & 0x10)
        if has_syn and not has_ack:
            return (pkt[IP].src, int(tcp.sport)), (pkt[IP].dst, int(tcp.dport))

    a_port = int(endpoint_a[1])
    b_port = int(endpoint_b[1])

    # If one side is a likely service port, treat high->low as client->server.
    if a_port <= 1024 < b_port:
        return endpoint_b, endpoint_a
    if b_port <= 1024 < a_port:
        return endpoint_a, endpoint_b

    # General fallback: lower destination port is usually the service side.
    if a_port < b_port:
        return endpoint_b, endpoint_a
    if b_port < a_port:
        return endpoint_a, endpoint_b

    # Deterministic last fallback.
    return endpoint_a, endpoint_b


def _split_flow_packets_into_sessions(flow_packets):
    """Split one 4-tuple packet stream into session-like chunks by SYN starts."""
    if not flow_packets:
        return []

    sessions = []
    current_session = []

    for pkt in flow_packets:
        tcp = pkt[TCP]
        has_syn = bool(tcp.flags & 0x02)
        has_ack = bool(tcp.flags & 0x10)
        syn_start = has_syn and not has_ack

        # A fresh SYN after traffic likely indicates a new logical session.
        if syn_start and current_session:
            sessions.append(current_session)
            current_session = [pkt]
        else:
            current_session.append(pkt)

    if current_session:
        sessions.append(current_session)

    return sessions


def extract_flows(packets):
    """Group packets into bidirectional flows and extract per-flow features."""
    if not packets:
        return [], {}

    # Group packets by bidirectional 4-tuple.
    flows = {}
    for pkt in packets:
        if TCP not in pkt or IP not in pkt:
            continue

        src_endpoint = (pkt[IP].src, int(pkt[TCP].sport))
        dst_endpoint = (pkt[IP].dst, int(pkt[TCP].dport))
        flow_key = (
            (src_endpoint, dst_endpoint)
            if src_endpoint <= dst_endpoint
            else (dst_endpoint, src_endpoint)
        )

        if flow_key not in flows:
            flows[flow_key] = {
                "endpoint_a": flow_key[0],
                "endpoint_b": flow_key[1],
                "packets": [],
            }

        flows[flow_key]["packets"].append(pkt)

    flow_features_list = []
    for flow in flows.values():
        sessions = _split_flow_packets_into_sessions(flow["packets"])
        for session_packets in sessions:
            forward_src, forward_dst = _infer_forward_direction(
                session_packets,
                flow["endpoint_a"],
                flow["endpoint_b"],
            )
            forward_src_ip, forward_src_port = forward_src
            forward_dst_ip, forward_dst_port = forward_dst

            fwd_count = 0
            bwd_count = 0
            fwd_lengths = []
            bwd_lengths = []
            syn_count = 0
            ack_count = 0

            for pkt in session_packets:
                tcp = pkt[TCP]
                # Use full packet length (header + payload), not payload-only length.
                pkt_len = len(pkt)
                is_fwd = (
                    pkt[IP].src == forward_src_ip
                    and int(tcp.sport) == forward_src_port
                    and pkt[IP].dst == forward_dst_ip
                    and int(tcp.dport) == forward_dst_port
                )

                if is_fwd:
                    fwd_count += 1
                    fwd_lengths.append(pkt_len)
                else:
                    bwd_count += 1
                    bwd_lengths.append(pkt_len)

                if tcp.flags & 0x02:
                    syn_count += 1
                if tcp.flags & 0x10:
                    ack_count += 1

            features = [
                forward_dst_port,
                fwd_count,
                bwd_count,
                float(np.mean(fwd_lengths)) if fwd_lengths else 0.0,
                float(np.mean(bwd_lengths)) if bwd_lengths else 0.0,
                syn_count,
                ack_count,
            ]
            flow_features_list.append(features)

    # Window-level summary stats for rules engine
    total_syn = sum(f[5] for f in flow_features_list)
    total_ack = sum(f[6] for f in flow_features_list)

    # Count unique destination ports and xmas-flagged packets
    unique_dst_ports = set()
    xmas_count = 0
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            unique_dst_ports.add(pkt[TCP].dport)
            if (pkt[TCP].flags & XMAS_FLAG_MASK) == XMAS_FLAG_MASK:
                xmas_count += 1

    window_stats = {
        "total_packets": len(packets),
        "total_flows": len(flow_features_list),
        "total_syn": total_syn,
        "total_ack": total_ack,
        "syn_ack_ratio": total_syn / max(total_ack, 1),
        "unique_dst_ports": len(unique_dst_ports),
        "xmas_count": xmas_count,
    }

    return flow_features_list, window_stats


# ---------------------------------------------------------------------------
# Rule-Based Anomaly Detection
# ---------------------------------------------------------------------------
def rule_based_check(window_stats):
    """
    Apply heuristic rules for volumetric and flag-based attacks.
    Returns (is_attack: bool, reason: str).
    """
    reasons = []

    # Rule 1: SYN Flood — high SYN count with few ACKs
    if (window_stats["total_syn"] > SYN_FLOOD_THRESHOLD
            and window_stats["syn_ack_ratio"] > SYN_ACK_RATIO_THRESHOLD):
        reasons.append(
            f"SYN Flood (SYN={window_stats['total_syn']}, "
            f"ratio={window_stats['syn_ack_ratio']:.1f})"
        )

    # Rule 2: Port Scan — many unique destination ports from one source
    if window_stats["unique_dst_ports"] > PORT_SCAN_THRESHOLD:
        reasons.append(
            f"Port Scan ({window_stats['unique_dst_ports']} unique ports)"
        )

    # Rule 3: Christmas Tree Attack — packets with FIN+PSH+URG flags set
    if window_stats["xmas_count"] > 10:
        reasons.append(
            f"Xmas Tree Attack ({window_stats['xmas_count']} flagged pkts)"
        )

    # Rule 4: Volume spike with many unique flows (DDoS)
    if (window_stats["total_packets"] > VOLUME_SPIKE_THRESHOLD
            and window_stats["total_flows"] > VOLUME_SPIKE_THRESHOLD * 0.5):
        reasons.append(
            f"Volume Spike ({window_stats['total_packets']} pkts, "
            f"{window_stats['total_flows']} flows)"
        )

    if reasons:
        return True, " | ".join(reasons)
    return False, ""


# ---------------------------------------------------------------------------
# Start the Sniffer
# ---------------------------------------------------------------------------
def start_sniffer():
    if shared.sniffer_started:
        return

    iface = None
    if hasattr(conf, "loopback_name") and conf.loopback_name:
        iface = conf.loopback_name
    if iface is None:
        iface = "\\Device\\NPF_Loopback"

    shared.sniffer_iface = iface

    try:
        sniffer = AsyncSniffer(
            iface=iface,
            prn=_packet_callback,
            filter="tcp",
            store=False,
        )
        sniffer.start()
        shared.sniffer_instance = sniffer
        shared.sniffer_started = True
    except Exception as e:
        shared.sniffer_error = str(e)


# ---------------------------------------------------------------------------
# Session State
# ---------------------------------------------------------------------------
if "history" not in st.session_state:
    st.session_state.history = deque(maxlen=MAX_HISTORY)
    st.session_state.latest_prediction = "WAITING"
    st.session_state.latest_features = None
    st.session_state.latest_reason = ""
    st.session_state.latest_detection_layer = "N/A"
    st.session_state.total_packets = 0


# ---------------------------------------------------------------------------
# Process Window (sequential filter: Rules -> ML)
# ---------------------------------------------------------------------------
def process_window():
    with shared.lock:
        packets = list(shared.packet_buffer)
        shared.packet_buffer.clear()

    st.session_state.total_packets += len(packets)

    if not packets:
        return

    flow_features_list, window_stats = extract_flows(packets)

    if not flow_features_list:
        return

    # ---- Step 1: Rule-based check on window-level stats ----
    rule_attack, rule_reason = rule_based_check(window_stats)

    label = "BENIGN"
    reason_str = "Sequential filter passed: rules clear and ML clear"
    detection_layer = "No Detection"

    # ---- Step 2: Short-circuit on rules to skip ML compute entirely ----
    if rule_attack:
        label = "ATTACK"
        detection_layer = "Caught by Volumetric Rules"
        reason_str = f"{detection_layer}: {rule_reason}"
    else:
        # ---- Step 3: ML inference only for rule-benign traffic ----
        ml_attack = False
        ml_attack_mask = np.array([], dtype=bool)
        ml_attack_scores = np.array([], dtype=float)

        if model and scaler:
            X = np.array(flow_features_list, dtype=float)
            X_scaled = scaler.transform(X)

            if hasattr(model, "predict_proba"):
                ml_attack_scores = model.predict_proba(X_scaled)[:, 1]
                ml_attack_mask = ml_attack_scores >= ML_ATTACK_PROBA_THRESHOLD
            else:
                predictions = model.predict(X_scaled)
                ml_attack_mask = predictions == 1

            ml_attack = bool(np.any(ml_attack_mask))

        if ml_attack:
            label = "ATTACK"
            detection_layer = "Caught by ML Inference"
            attack_flows = int(np.sum(ml_attack_mask))
            if ml_attack_scores.size:
                max_score = float(np.max(ml_attack_scores))
                reason_str = (
                    f"{detection_layer}: {attack_flows}/{len(flow_features_list)} flows "
                    f"flagged (max p={max_score:.2f})"
                )
            else:
                reason_str = (
                    f"{detection_layer}: {attack_flows}/{len(flow_features_list)} flows flagged"
                )
        elif model and scaler:
            detection_layer = "Sequential Filter Passed (Benign)"
        else:
            detection_layer = "Rules-Only Mode (ML Unavailable)"
            reason_str = "Rules clear; ML inference unavailable"

    st.session_state.latest_prediction = label
    st.session_state.latest_reason = reason_str
    st.session_state.latest_detection_layer = detection_layer

    # Use the aggregate for display
    agg_features = [
        flow_features_list[0][0],  # dest port (first flow)
        sum(f[1] for f in flow_features_list),
        sum(f[2] for f in flow_features_list),
        float(np.mean([f[3] for f in flow_features_list])),
        float(np.mean([f[4] for f in flow_features_list])),
        window_stats["total_syn"],
        window_stats["total_ack"],
    ]
    st.session_state.latest_features = dict(zip(FEATURE_NAMES, agg_features))

    st.session_state.history.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "packets": len(packets),
        "flows": window_stats["total_flows"],
        "syn_count": window_stats["total_syn"],
        "ack_count": window_stats["total_ack"],
        "prediction": label,
        "layer": detection_layer,
        "reason": reason_str,
    })


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
def render_ui():
    st.markdown(
        "<h1 style='text-align:center;'>🛡️ Network Intrusion Detection System</h1>"
        "<p style='text-align:center; color:gray;'>"
        "Sequential Hybrid Detection: Volumetric Rules → ML Inference"
        "</p>",
        unsafe_allow_html=True,
    )

    if not SCAPY_AVAILABLE:
        st.error("❌ **Scapy is not installed.** Run `pip install scapy` and make sure Npcap is installed.")
        return

    if model is None or scaler is None:
        st.error(
            "❌ **Model files not found.** Run the training notebook first to generate:\n"
            "- `models/best_model.joblib`\n- `models/scaler.joblib`"
        )
        return

    if shared.sniffer_error:
        st.error(f"❌ **Sniffer failed:** `{shared.sniffer_error}`")
        return

    # --- Debug sidebar ---
    with st.sidebar:
        st.caption("🔧 Sniffer Debug Info")
        st.text(f"Interface:  {shared.sniffer_iface}")
        st.text(f"Running:    {shared.sniffer_started}")
        st.text(f"Captured:   {shared.capture_count}")
        st.text(f"Processed:  {st.session_state.total_packets}")
        st.text(f"Layer:      {st.session_state.get('latest_detection_layer', 'N/A')}")
        st.divider()
        st.caption("🧠 Pipeline")
        st.text("Rules -> ML (short-circuit)")
        st.divider()
        st.caption("⚙️ Detection Thresholds")
        st.text(f"ML Attack p: >={ML_ATTACK_PROBA_THRESHOLD:.2f}")
        st.text(f"SYN Flood:  >{SYN_FLOOD_THRESHOLD} SYNs")
        st.text(f"SYN/ACK:    >{SYN_ACK_RATIO_THRESHOLD}x ratio")
        st.text(f"Vol. Spike: >{VOLUME_SPIKE_THRESHOLD} pkts")

    # --- Status Card ---
    pred = st.session_state.latest_prediction
    reason = st.session_state.get("latest_reason", "")

    if pred == "ATTACK":
        st.markdown(
            f"""
            <div style="background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%);
                        padding: 30px; border-radius: 16px; text-align: center;
                        margin-bottom: 20px; box-shadow: 0 4px 15px rgba(255,0,0,0.3);">
                <h1 style="color: white; margin: 0; font-size: 3rem;">🚨 ATTACK DETECTED</h1>
                <p style="color: #ffcccc; margin: 5px 0 0 0; font-size: 1.1rem;">
                    {reason}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    elif pred == "BENIGN":
        st.markdown(
            """
            <div style="background: linear-gradient(135deg, #00c853 0%, #009624 100%);
                        padding: 30px; border-radius: 16px; text-align: center;
                        margin-bottom: 20px; box-shadow: 0 4px 15px rgba(0,200,0,0.3);">
                <h1 style="color: white; margin: 0; font-size: 3rem;">✅ BENIGN</h1>
                <p style="color: #ccffcc; margin: 5px 0 0 0; font-size: 1.2rem;">
                    Normal traffic — no threats detected
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div style="background: linear-gradient(135deg, #555 0%, #333 100%);
                        padding: 30px; border-radius: 16px; text-align: center;
                        margin-bottom: 20px;">
                <h1 style="color: white; margin: 0; font-size: 3rem;">⏳ WAITING FOR PACKETS</h1>
                <p style="color: #ccc; margin: 5px 0 0 0; font-size: 1.2rem;">
                    Sniffer running on <code>{shared.sniffer_iface}</code>
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # --- Metrics Row ---
    history = st.session_state.history
    if history:
        latest = history[-1]
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("📦 Packets", latest["packets"])
        col2.metric("🔄 SYN Flags", latest["syn_count"])
        col3.metric("✔️ ACK Flags", latest["ack_count"])
        col4.metric("🌐 Flows", latest["flows"])
        col5.metric("🧭 Layer", latest["layer"])

    # --- Traffic Chart ---
    if len(history) > 1:
        st.subheader("📈 Traffic Volume Over Time")
        chart_df = pd.DataFrame(list(history)).set_index("time")
        st.line_chart(chart_df[["packets", "syn_count"]], height=250)

    # --- Recent Predictions Table ---
    if history:
        st.subheader("📋 Recent Window Predictions")
        table_df = pd.DataFrame(list(history))
        table_df = table_df[["time", "packets", "flows", "syn_count", "ack_count", "prediction", "layer", "reason"]]
        st.dataframe(table_df.iloc[::-1], width="stretch", height=250)

    # --- Feature Debug ---
    if st.session_state.latest_features:
        with st.expander("🔬 Latest Feature Vector (Debug)"):
            st.json(st.session_state.latest_features)


# ---------------------------------------------------------------------------
# Main Loop
# ---------------------------------------------------------------------------
def main():
    start_sniffer()
    process_window()
    render_ui()
    time.sleep(WINDOW_SECONDS)
    st.rerun()

if __name__ == "__main__":
    main()
