"""
Page 3: Agent & Regulatory Search
Tab 1: Cortex Agent chat (routed via DATA_AGENT_RUN)
Tab 2: Direct Cortex Search for internal policies
Tab 3: Direct Federal Register lookup (standalone)
"""

import streamlit as st
import json
import os
import sys
import importlib.util
import pandas as pd


def _import_from_app_root(module_name):
    """Import a module from the app root directory, handling container runtime paths."""
    for base in [
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        os.getcwd(),
        "/opt/streamlit-runtime",
    ]:
        path = os.path.join(base, f"{module_name}.py")
        if os.path.exists(path):
            spec = importlib.util.spec_from_file_location(module_name, path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)
            return mod
    raise ImportError(f"Cannot find {module_name}.py in any known app directory")


_fed_mod = _import_from_app_root("federal_register_mcp")
search_regulations = _fed_mod.search_regulations
get_regulation = _fed_mod.get_regulation

_agent_mod = _import_from_app_root("agent_runner")
ATOFraudAgent = _agent_mod.ATOFraudAgent

conn = st.connection("snowflake", ttl=os.getenv("SNOWFLAKE_CONNECTION_TTL"))

st.title("Unified Policy & Regulatory Intelligence")
st.markdown("Query internal risk management policies via Cortex Search, or search external US Federal Regulations via the Cortex Agent.")

tab1, tab2, tab3 = st.tabs(["Cortex Agent (All Channels)", "Internal Policy Search (Cortex)", "Federal Register Lookup (Direct)"])

# ---------------------------------------------------------
# Tab 1: Cortex Agent Chat — powered by DATA_AGENT_RUN
# ---------------------------------------------------------
with tab1:
    st.markdown("#### Ask the ATO Fraud & Regulatory Intelligence Agent")
    st.caption("Routes questions across Cortex Analyst (fraud analytics), Cortex Search (internal policies), and Federal Register (regulatory procedures).")

    col_header, col_reset = st.columns([4, 1])
    with col_reset:
        if st.button("New Conversation", key="btn_reset"):
            ATOFraudAgent.reset_thread()
            st.session_state.agent_messages = []
            st.rerun()

    if "agent_messages" not in st.session_state:
        st.session_state.agent_messages = [
            {"role": "assistant", "content": "Hello! I am your ATO Fraud & Regulatory Intelligence Agent. Ask me about:\n- **Fraud analytics** — risk scores, decision tiers, login events\n- **Internal policies** — MFA, lockouts, investigation SOPs\n- **Federal regulations** — FTC Safeguards, CFPB circulars, FinCEN CDD"}
        ]

    # Scrollable chat history container
    chat_container = st.container(height=500)

    # Chat input at the bottom (rendered below the container)
    user_query = st.chat_input("Enter your fraud, policy, or regulatory question...")

    # Render existing messages inside the scrollable container
    with chat_container:
        for msg in st.session_state.agent_messages:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

    if user_query:
        st.session_state.agent_messages.append({"role": "user", "content": user_query})
        with chat_container:
            with st.chat_message("user"):
                st.markdown(user_query)

            with st.chat_message("assistant"):
                with st.spinner("Agent is reasoning and routing..."):
                    agent = ATOFraudAgent()
                    resp = agent.answer(user_query)

                    if resp.get("status") == "error":
                        out_text = f"**Error:** {resp.get('error', 'Unknown error')}"
                        st.error(out_text)
                    else:
                        out_text = resp.get("text", "No response from agent.")

                        # Show tools used
                        tools = resp.get("tools_used", [])
                        if tools:
                            tool_names = ", ".join(f"`{t['name']}`" for t in tools)
                            st.caption(f"Tools used: {tool_names}")

                        # Show SQL if Cortex Analyst was used
                        for sql in resp.get("sql_statements", []):
                            with st.expander("Generated SQL"):
                                st.code(sql, language="sql")

                        # Show warnings
                        for w in resp.get("warnings", []):
                            st.warning(f"Agent warning ({w.get('code', '')}): {w.get('message', '')}")

                        st.markdown(out_text)

                    st.session_state.agent_messages.append({"role": "assistant", "content": out_text})

# ---------------------------------------------------------
# Tab 2: Internal Policy Search (direct Cortex Search)
# ---------------------------------------------------------
with tab2:
    st.markdown("#### Search Internal Risk & Fraud SOPs")
    st.caption("Powered by `ATO_POLICY_SEARCH` Cortex Search Service with `snowflake-arctic-embed-m-v1.5` embeddings.")

    policy_q = st.text_input("Search internal policies:", value="What are the step-up MFA and account lockout thresholds?")
    if st.button("Search Policies", key="btn_policy"):
        with st.spinner("Searching internal knowledge base..."):
            safe_q = policy_q.replace("'", "''")
            search_sql = f"""
            SELECT SNOWFLAKE.CORTEX.SEARCH_PREVIEW(
                'ATO_FRAUD_DB.SEMANTIC.ATO_POLICY_SEARCH',
                '{{"query": "{safe_q}", "columns": ["DOCUMENT_TITLE", "SECTION_NUMBER", "SECTION_TITLE", "OWNER_ROLE", "REGULATORY_REFERENCES"], "limit": 4}}'
            ) AS RES;
            """
            try:
                res_df = conn.query(search_sql)
                raw = json.loads(res_df["RES"].iloc[0])
                results = raw.get("results", [])

                if results:
                    for i, r in enumerate(results, 1):
                        with st.container(border=True):
                            st.markdown(f"##### {i}. {r.get('DOCUMENT_TITLE')} — {r.get('SECTION_NUMBER')}: {r.get('SECTION_TITLE')}")
                            st.caption(f"Role: {r.get('OWNER_ROLE')} | Regulatory Reference: {r.get('REGULATORY_REFERENCES')}")
                            scores = r.get("@scores", {})
                            st.markdown(f"**Similarity Score:** `{scores.get('cosine_similarity', 0.0):.3f}`")
                else:
                    st.info("No policy sections matched your search.")
            except Exception as e:
                st.error(f"Error querying Cortex Search: {e}")

# ---------------------------------------------------------
# Tab 3: Federal Register Direct Search (standalone)
# ---------------------------------------------------------
with tab3:
    st.markdown("#### Federal Register Public Regulatory Lookup")
    st.caption("Direct access to FederalRegister.gov API for identity verification, MFA, and GLBA Safeguards.")

    col_q, col_agency = st.columns([3, 1])
    with col_q:
        fed_q = st.text_input("Regulatory topic / keywords:", value="multi-factor authentication account takeover")
    with col_agency:
        fed_agency = st.selectbox("Agency filter (optional):", ["All Agencies", "ftc", "cfpb", "fincen", "occ", "cisa"])

    agency_param = None if fed_agency == "All Agencies" else fed_agency

    if st.button("Search Federal Register", key="btn_fed"):
        with st.spinner("Connecting to Federal Register..."):
            fed_res = search_regulations(fed_q, agency=agency_param)
            docs = fed_res.get("documents", [])
            st.success(f"Found {fed_res.get('total_results', len(docs))} regulatory documents.")

            for doc in docs:
                with st.container(border=True):
                    is_final = doc.get("is_final_rule", False)
                    badge = ":green-background[FINAL BINDING RULE]" if is_final else ":blue-background[PROPOSED RULE / CIRCULAR]"
                    st.markdown(f"### {doc.get('title')}")
                    st.markdown(f"{badge} • **Document #:** `{doc.get('document_number')}` • **Action:** {doc.get('action')}")
                    st.markdown(f"**Citation:** `{doc.get('citation')}` | **Effective Date:** `{doc.get('effective_on')}`")
                    st.markdown(f"> {doc.get('abstract')}")
                    st.markdown(f"[View Official Publication on FederalRegister.gov]({doc.get('official_url')})")
