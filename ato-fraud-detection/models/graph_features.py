"""
=============================================================================
ATO Fraud Detection - Layer 3: Identity Graph Analytics & Ring Detection
Analyzes RAW_IDENTITY_GRAPH_EDGES to calculate:
- Degree centrality (connected devices, IPs, emails, phones)
- Shared infrastructure component size (device clusters)
- Graph risk score from purely structural signals (no label leakage)
=============================================================================
"""

import os
import sys
import json
import pandas as pd
from datetime import datetime, timezone
from snowflake.snowpark.context import get_active_session


def compute_and_materialize_graph_features():
    session = get_active_session()
    session.use_database("ATO_FRAUD_DB")
    session.use_schema("FEATURES")
    print("Computing Identity Graph Analytics with Snowpark...")

    # NOTE: is_fraud_edge is EXCLUDED — it is a label-derived column that
    # causes target leakage when used as a feature (fraud_link_count was
    # a perfect separator: 100% of fraud customers had fraud_link_count > 0).
    # graph_risk_score now uses only structural topology signals.
    graph_query = """
    CREATE OR REPLACE TABLE ATO_FRAUD_DB.FEATURES.CUSTOMER_GRAPH_FEATURES AS
    WITH
    -- 1. Degree counts per customer (structural only — no is_fraud_edge)
    cust_degrees AS (
        SELECT
            entity_a_id::INT AS customer_id,
            COUNT(DISTINCT CASE WHEN entity_b_type = 'device' THEN entity_b_id END) AS linked_device_count,
            COUNT(DISTINCT CASE WHEN entity_b_type = 'ip' THEN entity_b_id END) AS linked_ip_count,
            COUNT(DISTINCT CASE WHEN entity_b_type = 'email' THEN entity_b_id END) AS linked_email_count,
            COUNT(DISTINCT CASE WHEN entity_b_type = 'phone' THEN entity_b_id END) AS linked_phone_count
        FROM ATO_FRAUD_DB.RAW.RAW_IDENTITY_GRAPH_EDGES
        WHERE entity_a_type = 'customer'
        GROUP BY entity_a_id
    ),

    -- 2. Ring infrastructure: devices shared across multiple accounts
    shared_devices AS (
        SELECT
            entity_a_id AS shared_device_id,
            COUNT(DISTINCT entity_b_id) AS accounts_sharing_device
        FROM ATO_FRAUD_DB.RAW.RAW_IDENTITY_GRAPH_EDGES
        WHERE entity_a_type = 'device' AND entity_b_type = 'customer'
        GROUP BY entity_a_id
        HAVING COUNT(DISTINCT entity_b_id) >= 2
    ),

    -- 3. Map shared device cluster size back to customer
    cust_ring_size AS (
        SELECT
            e.entity_b_id::INT AS customer_id,
            MAX(sd.accounts_sharing_device) AS max_shared_ring_size
        FROM ATO_FRAUD_DB.RAW.RAW_IDENTITY_GRAPH_EDGES e
        JOIN shared_devices sd ON e.entity_a_id = sd.shared_device_id
        WHERE e.entity_a_type = 'device' AND e.entity_b_type = 'customer'
        GROUP BY e.entity_b_id
    ),

    -- 4. Shared IPs: IPs used by multiple customers (infrastructure reuse)
    shared_ips AS (
        SELECT
            entity_a_id AS shared_ip_id,
            COUNT(DISTINCT entity_b_id) AS accounts_sharing_ip
        FROM ATO_FRAUD_DB.RAW.RAW_IDENTITY_GRAPH_EDGES
        WHERE entity_a_type = 'ip' AND entity_b_type = 'customer'
        GROUP BY entity_a_id
        HAVING COUNT(DISTINCT entity_b_id) >= 3
    ),

    cust_shared_ip AS (
        SELECT
            e.entity_b_id::INT AS customer_id,
            MAX(si.accounts_sharing_ip) AS max_shared_ip_cluster
        FROM ATO_FRAUD_DB.RAW.RAW_IDENTITY_GRAPH_EDGES e
        JOIN shared_ips si ON e.entity_a_id = si.shared_ip_id
        WHERE e.entity_a_type = 'ip' AND e.entity_b_type = 'customer'
        GROUP BY e.entity_b_id
    )

    SELECT
        c.customer_id,
        COALESCE(cd.linked_device_count, 1) AS linked_device_count,
        COALESCE(cd.linked_ip_count, 1) AS linked_ip_count,
        COALESCE(cd.linked_email_count, 1) AS linked_email_count,
        COALESCE(cd.linked_phone_count, 1) AS linked_phone_count,
        COALESCE(crs.max_shared_ring_size, 1) AS graph_component_size,
        COALESCE(csi.max_shared_ip_cluster, 1) AS shared_ip_cluster_size,
        -- Graph Risk Score (0 - 100) — purely structural, no label-derived inputs
        LEAST(100, GREATEST(0,
            -- Shared device ring size (strongest structural signal)
            (CASE WHEN COALESCE(crs.max_shared_ring_size, 1) >= 10 THEN 40
                  WHEN COALESCE(crs.max_shared_ring_size, 1) >= 5 THEN 25
                  WHEN COALESCE(crs.max_shared_ring_size, 1) >= 3 THEN 15 ELSE 0 END) +
            -- High device count per customer (device cycling)
            (CASE WHEN COALESCE(cd.linked_device_count, 1) >= 5 THEN 20
                  WHEN COALESCE(cd.linked_device_count, 1) >= 3 THEN 10 ELSE 0 END) +
            -- Shared IP infrastructure
            (CASE WHEN COALESCE(csi.max_shared_ip_cluster, 1) >= 10 THEN 20
                  WHEN COALESCE(csi.max_shared_ip_cluster, 1) >= 5 THEN 10
                  WHEN COALESCE(csi.max_shared_ip_cluster, 1) >= 3 THEN 5 ELSE 0 END) +
            -- High IP diversity (many distinct IPs = possible proxy rotation)
            (CASE WHEN COALESCE(cd.linked_ip_count, 1) >= 200 THEN 20
                  WHEN COALESCE(cd.linked_ip_count, 1) >= 100 THEN 10 ELSE 0 END)
        )) AS graph_risk_score,
        -- Ring Flag (structural only)
        CASE WHEN COALESCE(crs.max_shared_ring_size, 1) >= 10 THEN TRUE ELSE FALSE END AS is_fraud_ring_member
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c
    LEFT JOIN cust_degrees cd ON c.customer_id = cd.customer_id
    LEFT JOIN cust_ring_size crs ON c.customer_id = crs.customer_id
    LEFT JOIN cust_shared_ip csi ON c.customer_id = csi.customer_id;
    """

    print("Executing graph materialization in ATO_FRAUD_DB.FEATURES.CUSTOMER_GRAPH_FEATURES...")
    session.sql(graph_query).collect()
    
    count_df = session.sql("SELECT COUNT(*) AS CNT, SUM(IS_FRAUD_RING_MEMBER::INT) AS RING_MEMBERS FROM ATO_FRAUD_DB.FEATURES.CUSTOMER_GRAPH_FEATURES").to_pandas()
    print("\nGraph Features Summary:")
    print(count_df)

    # Validate: check graph_risk_score distribution by fraud label
    leakage_check = session.sql("""
        SELECT
            l.IS_FRAUD,
            AVG(gf.graph_risk_score) AS avg_risk,
            MIN(gf.graph_risk_score) AS min_risk,
            MAX(gf.graph_risk_score) AS max_risk,
            COUNT(DISTINCT l.CUSTOMER_ID) AS customers
        FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS l
        JOIN ATO_FRAUD_DB.FEATURES.CUSTOMER_GRAPH_FEATURES gf
            ON l.CUSTOMER_ID = gf.CUSTOMER_ID
        GROUP BY l.IS_FRAUD
    """).to_pandas()
    print("\nLeakage Validation (graph_risk_score by IS_FRAUD):")
    print(leakage_check)

    fraud_avg = leakage_check.loc[leakage_check["IS_FRAUD"] == True, "AVG_RISK"].values
    legit_avg = leakage_check.loc[leakage_check["IS_FRAUD"] == False, "AVG_RISK"].values
    if len(fraud_avg) > 0 and len(legit_avg) > 0:
        ratio = fraud_avg[0] / max(legit_avg[0], 0.01)
        if ratio > 50:
            print(f"\n*** WARNING: graph_risk_score ratio (fraud/legit) = {ratio:.1f}x — possible residual leakage ***")
        else:
            print(f"\n  Risk score ratio (fraud/legit): {ratio:.1f}x — within expected range")

    artifact_dir = "/tmp/ato-fraud-detection/models/artifacts"
    os.makedirs(artifact_dir, exist_ok=True)
    with open(os.path.join(artifact_dir, "graph_analytics_metrics.json"), "w") as f:
        json.dump({
            "table_created": "ATO_FRAUD_DB.FEATURES.CUSTOMER_GRAPH_FEATURES",
            "total_customers": int(count_df["CNT"][0]),
            "fraud_ring_members_flagged": int(count_df["RING_MEMBERS"][0]),
            "leakage_fix": "Removed fraud_link_count (is_fraud_edge); risk score uses only structural topology",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, f, indent=2)

    return count_df


if __name__ == "__main__":
    compute_and_materialize_graph_features()
