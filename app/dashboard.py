import os

import pandas as pd
import streamlit as st


REPORT_FILE = "reports/soc_investigation_report.csv"


st.set_page_config(
    page_title="Mini Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ Mini Threat Intelligence Platform")
st.subheader("SOC Threat Intelligence Dashboard")


# --------------------------------------------------
# Load Investigation Data
# --------------------------------------------------

if not os.path.exists(REPORT_FILE):

    st.error(
        "SOC investigation report not found."
    )

    st.info(
        "Run the main application first to generate "
        "reports/soc_investigation_report.csv"
    )

    st.stop()


df = pd.read_csv(REPORT_FILE)


# --------------------------------------------------
# Handle Empty Dataset
# --------------------------------------------------

if df.empty:

    st.warning(
        "No investigation data is available."
    )

    st.stop()


# --------------------------------------------------
# Clean Missing Values
# --------------------------------------------------

df["Risk Level"] = (
    df["Risk Level"]
    .fillna("UNKNOWN")
)

df["Priority"] = (
    df["Priority"]
    .fillna("P4")
)

df["Investigation Status"] = (
    df["Investigation Status"]
    .fillna("NEW")
)

df["Enrichment Status"] = (
    df["Enrichment Status"]
    .fillna("UNKNOWN")
)


# --------------------------------------------------
# Dashboard Metrics
# --------------------------------------------------

total_iocs = len(df)

critical_count = (
    df["Risk Level"]
    .eq("CRITICAL")
    .sum()
)

high_count = (
    df["Risk Level"]
    .eq("HIGH")
    .sum()
)

medium_count = (
    df["Risk Level"]
    .eq("MEDIUM")
    .sum()
)

low_count = (
    df["Risk Level"]
    .eq("LOW")
    .sum()
)

unknown_count = (
    df["Risk Level"]
    .eq("UNKNOWN")
    .sum()
)


# --------------------------------------------------
# KPI Cards
# --------------------------------------------------

st.markdown("### Overview")

col1, col2, col3, col4, col5, col6 = st.columns(6)


col1.metric(
    "Total IOCs",
    total_iocs
)

col2.metric(
    "Critical",
    critical_count
)

col3.metric(
    "High",
    high_count
)

col4.metric(
    "Medium",
    medium_count
)

col5.metric(
    "Low",
    low_count
)

col6.metric(
    "Unknown",
    unknown_count
)


# --------------------------------------------------
# Risk and Priority Charts
# --------------------------------------------------

st.markdown("---")

chart_col1, chart_col2 = st.columns(2)


with chart_col1:

    st.markdown("### Risk Distribution")

    risk_counts = (
        df["Risk Level"]
        .value_counts()
        .reindex(
            [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNKNOWN"
            ],
            fill_value=0
        )
    )

    st.bar_chart(risk_counts)


with chart_col2:

    st.markdown("### Alert Priority")

    priority_counts = (
        df["Priority"]
        .value_counts()
        .reindex(
            [
                "P1",
                "P2",
                "P3",
                "P4"
            ],
            fill_value=0
        )
    )

    st.bar_chart(priority_counts)


# --------------------------------------------------
# Enrichment and Investigation Status
# --------------------------------------------------

st.markdown("---")

chart_col3, chart_col4 = st.columns(2)


with chart_col3:

    st.markdown(
        "### Enrichment Status"
    )

    enrichment_counts = (
        df["Enrichment Status"]
        .value_counts()
    )

    st.bar_chart(
        enrichment_counts
    )


with chart_col4:

    st.markdown(
        "### Investigation Status"
    )

    status_counts = (
        df["Investigation Status"]
        .value_counts()
    )

    st.bar_chart(
        status_counts
    )


# --------------------------------------------------
# Investigation Queue
# --------------------------------------------------

st.markdown("---")

st.markdown(
    "### Investigation Queue"
)


queue_columns = [
    "IOC",
    "Type",
    "Risk Level",
    "Priority",
    "Detection Ratio",
    "Malicious",
    "Suspicious",
    "Reputation",
    "Enrichment Status",
    "OTX Pulses",
    "Investigation Status",
    "Analyst Note"
]


available_columns = [
    column
    for column in queue_columns
    if column in df.columns
]


queue_df = df[available_columns].copy()


# --------------------------------------------------
# Filters
# --------------------------------------------------

st.markdown("#### Filters")


filter_col1, filter_col2, filter_col3 = st.columns(3)


with filter_col1:

    risk_filter = st.selectbox(
        "Risk Level",
        [
            "ALL",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN"
        ]
    )


with filter_col2:

    priority_filter = st.selectbox(
        "Priority",
        [
            "ALL",
            "P1",
            "P2",
            "P3",
            "P4"
        ]
    )


with filter_col3:

    status_filter = st.selectbox(
        "Investigation Status",
        [
            "ALL",
            "NEW",
            "IN PROGRESS",
            "CLOSED"
        ]
    )


# --------------------------------------------------
# Apply Filters
# --------------------------------------------------

filtered_df = queue_df.copy()


if risk_filter != "ALL":

    filtered_df = filtered_df[
        filtered_df["Risk Level"]
        == risk_filter
    ]


if priority_filter != "ALL":

    filtered_df = filtered_df[
        filtered_df["Priority"]
        == priority_filter
    ]


if status_filter != "ALL":

    filtered_df = filtered_df[
        filtered_df["Investigation Status"]
        == status_filter
    ]


# --------------------------------------------------
# Display Queue
# --------------------------------------------------

st.dataframe(
    filtered_df,
    width="stretch",
    hide_index=True
)


st.caption(
    f"Showing {len(filtered_df)} of "
    f"{len(queue_df)} investigation records."
)