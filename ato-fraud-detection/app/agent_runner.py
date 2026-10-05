"""
ATO Fraud Agent Runner — Cortex Agent Integration
Calls the deployed Cortex Agent (ATO_FRAUD_DB.APP.ATO_FRAUD_AGENT) via
SNOWFLAKE.CORTEX.DATA_AGENT_RUN. The agent handles all routing across:
  1. Cortex Analyst (Semantic View)
  2. Cortex Search (Internal Policies)
  3. Federal Register (Stored Procedures via EAI)
"""

import json
import os
import streamlit as st
from typing import Any, Dict, List, Optional


AGENT_FQN = "ATO_FRAUD_DB.APP.ATO_FRAUD_AGENT"


class ATOFraudAgent:
    """Calls the deployed Cortex Agent for all question routing."""

    def __init__(self):
        self.conn = st.connection("snowflake", ttl=os.getenv("SNOWFLAKE_CONNECTION_TTL"))
        self._thread_id = st.session_state.get("agent_thread_id")
        self._parent_msg_id = st.session_state.get("agent_parent_msg_id", 0)

    def _build_request(self, question: str) -> str:
        messages = [{"role": "user", "content": [{"type": "text", "text": question}]}]
        body: Dict[str, Any] = {"messages": messages}
        if self._thread_id is not None:
            body["thread_id"] = self._thread_id
            body["parent_message_id"] = self._parent_msg_id
        return json.dumps(body)

    def answer(self, user_question: str) -> Dict[str, Any]:
        """Send question to the Cortex Agent and parse the response."""
        request_body = self._build_request(user_question)

        sql = f"""
        SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN(
            '{AGENT_FQN}',
            $${request_body}$$,
            TRUE
        ) AS resp
        """
        try:
            df = self.conn.query(sql)
            # Column name may be upper or lower case depending on driver
            raw = df.iloc[0, 0]

            # DATA_AGENT_RUN returns a JSON string; parse it
            if isinstance(raw, str):
                resp = json.loads(raw)
            elif isinstance(raw, dict):
                resp = raw
            else:
                resp = json.loads(str(raw))

            # Check for API-level errors (e.g. missing warehouse, tool issues)
            if "error_code" in resp or ("code" in resp and "message" in resp and "content" not in resp):
                return {
                    "question": user_question,
                    "status": "error",
                    "error": resp.get("message", "Unknown agent error"),
                    "text": f"Agent error: {resp.get('message', 'Unknown error')}",
                    "tools_used": [],
                    "sql_statements": [],
                    "citations": [],
                    "warnings": [],
                }

            # Persist thread state for multi-turn conversations
            metadata = resp.get("metadata", {})
            if metadata.get("thread_id"):
                st.session_state["agent_thread_id"] = metadata["thread_id"]
            if metadata.get("assistant_message_id"):
                st.session_state["agent_parent_msg_id"] = metadata["assistant_message_id"]

            return self._parse_response(resp, user_question)

        except Exception as e:
            return {
                "question": user_question,
                "status": "error",
                "error": str(e),
                "text": f"Agent call failed: {e}",
                "tools_used": [],
                "sql_statements": [],
                "citations": [],
                "warnings": [],
            }

    def _parse_response(self, resp: Dict[str, Any], question: str) -> Dict[str, Any]:
        """Extract text, tool calls, and citations from agent response."""
        content_blocks = resp.get("content", [])
        text_parts: List[str] = []
        tools_used: List[Dict[str, Any]] = []
        citations: List[Dict[str, Any]] = []
        sql_statements: List[str] = []

        for block in content_blocks:
            block_type = block.get("type", "")

            if block_type == "text":
                text_parts.append(block.get("text", ""))

            elif block_type == "tool_use":
                tool_info = block.get("tool_use", {})
                tools_used.append({
                    "name": tool_info.get("name", ""),
                    "type": tool_info.get("type", ""),
                    "tool_use_id": tool_info.get("tool_use_id", ""),
                })

            elif block_type == "tool_result":
                tool_result = block.get("tool_result", {})
                # Extract SQL from analyst tool results
                res_content = tool_result.get("content", [])
                for rc in res_content:
                    if rc.get("type") == "tool_result_content_analyst":
                        analyst_data = rc.get("tool_result_content_analyst", {})
                        sql_text = analyst_data.get("sql", "")
                        if sql_text:
                            sql_statements.append(sql_text)

            elif block_type == "citation":
                citations.append(block.get("citation", {}))

        warnings = resp.get("warnings", [])

        return {
            "question": question,
            "status": "success",
            "text": "\n\n".join(text_parts),
            "tools_used": tools_used,
            "sql_statements": sql_statements,
            "citations": citations,
            "warnings": warnings,
        }

    @staticmethod
    def reset_thread():
        """Clear thread state to start a new conversation."""
        st.session_state.pop("agent_thread_id", None)
        st.session_state.pop("agent_parent_msg_id", None)
