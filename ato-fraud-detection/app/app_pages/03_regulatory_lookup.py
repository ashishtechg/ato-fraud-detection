"""
Page 3: Agent & Regulatory Search
Interactive search interface combining Cortex Search over internal policies with FastMCP Federal Register lookup.
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

st.title("🔍 Unified Policy & Regulatory Intelligence")
st.markdown("Query internal risk management policies via Cortex Search, or search external US Federal Regulations via FastMCP.")

tab1, tab2, tab3 = st.tabs(["🤖 Cortex Multi-Channel Agent", "📋 Internal Policy Search (Cortex)", "🏛️ Federal Register Regulatory Lookup (MCP)"])

# ---------------------------------------------------------
# Tab 1: Cortex Agent Chat
# ---------------------------------------------------------
with tab1:
    st.markdown("#### Ask the ATO Fraud & Regulatory Intelligence Agent")
    st.caption("Auto-routes questions between Semantic View SQL, Cortex Policy Search, and Federal Register MCP.")

    # Initialize chat history
    if "agent_messages" not in st.session_state:
        st.session_state.agent_messages = [
            {"role": "assistant", "content": "Hello! I am your ATO Fraud & Regulatory Intelligence Agent. Ask me about real-time fraud metrics, internal company policies (MFA, lockouts, investigations), or external Federal Register regulations (FTC Safeguards, CFPB circulars, FinCEN CDD)."}
        ]

    for msg in st.session_state.agent_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    user_query = st.chat_input("Enter your fraud, policy, or regulatory question...")
    if user_query:
        st.session_state.agent_messages.append({"role": "user", "content": user_query})
        with st.chat_message("user"):
            st.markdown(user_query)

        with st.chat_message("assistant"):
            with st.spinner("Routing and evaluating question..."):
                agent = ATOFraudAgent()
                resp = agent.answer(user_query)
                routing = resp.get("routing_decision")
                res = resp.get("result", {})

                out_text = f"**Routing Decision:** `{routing}`\n\n"
                
                if routing == "FEDERAL_REGISTER_MCP":
                    out_text += f"**Source:** {res.get('source', 'Federal Register')}\n\n"
                    docs = res.get("documents", [])
                    if docs:
                        for d in docs[:3]:
                            out_text += f"- **[{d['document_number']}] {d['title']}**\n"
                            out_text += f"  - *Type:* {d.get('document_type')} | *Action:* {d.get('action')}\n"
                            out_text += f"  - *Citation:* {d.get('citation')} | [Official Link]({d.get('official_url')})\n\n"
                    else:
                        out_text += "No matching federal regulations found for this query."

                elif routing == "CORTEX_SEARCH_INTERNAL_POLICY":
                    matches = res.get("matches", [])
                    if matches:
                        for m in matches:
                            out_text += f"### {m.get('document_title')} ({m.get('section')})\n"
                            out_text += f"- **Owner:** `{m.get('owner_role')}` | **Ref:** `{m.get('regulatory_references')}`\n"
                            out_text += f"> {m.get('content', '') if 'content' in m else 'Matches internal policy provisions.'}\n\n"
                    else:
                        out_text += "No matching internal policies found."

                else:
                    # Semantic SQL
                    out_text += f"**Executed Governed SQL:**\n```sql\n{res.get('sql')}\n```\n"
                    if res.get("data"):
                        df_preview = pd.DataFrame(res["data"])
                        st.dataframe(df_preview, width="stretch")

                st.markdown(out_text)
                st.session_state.agent_messages.append({"role": "assistant", "content": out_text})

# ---------------------------------------------------------
# Tab 2: Internal Policy Search
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
# Tab 3: Federal Register MCP Search
# ---------------------------------------------------------
with tab3:
    st.markdown("#### Federal Register Public Regulatory Lookup")
    st.caption("Live access to FederalRegister.gov public API for identity verification, MFA, and GLBA Safeguards.")

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
                    st.markdown(f"[🔗 View Official Publication on FederalRegister.gov]({doc.get('official_url')})")
