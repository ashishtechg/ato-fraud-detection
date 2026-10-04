"""
=============================================================================
ATO Fraud Detection - Deploy Semantic View to Snowflake
Reads ato_fraud_analytics_sv.yaml and calls SYSTEM$CREATE_SEMANTIC_VIEW_FROM_YAML
=============================================================================
"""

import os
from snowflake.snowpark.context import get_active_session


def deploy_semantic_view():
    session = get_active_session()
    session.use_database("ATO_FRAUD_DB")
    session.use_schema("SEMANTIC")
    print("Snowpark session connected for Semantic View deployment.")

    yaml_path = "/workspace/ato-fraud-detection/semantic/ato_fraud_analytics_sv.yaml"
    with open(yaml_path, "r") as f:
        yaml_content = f.read()

    # Escape single quotes in YAML for SQL literal
    escaped_yaml = yaml_content.replace("'", "''")

    schema_fqn = "ATO_FRAUD_DB.SEMANTIC"
    print(f"Deploying Semantic View into schema {schema_fqn} via SYSTEM$CREATE_SEMANTIC_VIEW_FROM_YAML...")

    deploy_sql = f"""
    CALL SYSTEM$CREATE_SEMANTIC_VIEW_FROM_YAML(
        '{schema_fqn}',
        '{escaped_yaml}'
    );
    """

    try:
        result = session.sql(deploy_sql).collect()
        view_fqn = f"{schema_fqn}.ATO_FRAUD_ANALYTICS_SV"
        print(f"\nDeployment Result: {result}")
        print(f"\nSemantic View {view_fqn} successfully deployed!")
        return result
    except Exception as e:
        print(f"Error deploying semantic view: {e}")
        raise e


if __name__ == "__main__":
    deploy_semantic_view()
