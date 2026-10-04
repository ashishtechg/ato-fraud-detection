"""
UI Helper Components for ATO Fraud Analyst Dashboard
Provides executive KPI cards, status badges, and color formatters.
"""

import streamlit as st


def render_kpi_card(title: str, value: str, subtext: str = "", delta: str = "", delta_color: str = "normal"):
    """Render a styled executive metric card."""
    with st.container(border=True):
        st.caption(title.upper())
        st.markdown(f"### {value}")
        if subtext:
            st.caption(subtext)
        if delta:
            st.markdown(f"**{delta}**")


def get_risk_tier_badge(tier: str) -> str:
    """Format risk tier badge HTML."""
    tier_upper = str(tier).upper()
    if tier_upper == "BLOCK":
        return f":red-background[**⛔ {tier_upper}**]"
    elif tier_upper == "STEP-UP":
        return f":orange-background[**⚠️ {tier_upper}**]"
    elif tier_upper == "SAFE":
        return f":green-background[**✅ {tier_upper}**]"
    return f"**{tier_upper}**"


def get_severity_badge(severity: str) -> str:
    """Format severity badge markdown."""
    s_upper = str(severity).upper()
    if s_upper == "CRITICAL":
        return ":red-background[CRITICAL]"
    elif s_upper == "HIGH":
        return ":orange-background[HIGH]"
    elif s_upper == "MEDIUM":
        return ":blue-background[MEDIUM]"
    return ":green-background[LOW]"
