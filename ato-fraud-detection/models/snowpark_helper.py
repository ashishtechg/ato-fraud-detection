import os
from snowflake.snowpark import Session

def get_session(database="ATO_FRAUD_DB", schema="SCORING"):
    token_path = os.environ.get("SNOWFLAKE_TOKEN_FILE_PATH", "/snowflake/session/token")
    account = os.environ.get("SNOWFLAKE_ACCOUNT", "")
    host = os.environ.get("SNOWFLAKE_HOST", f"{account}.snowflakecomputing.com")
    
    if os.path.exists(token_path):
        token = open(token_path).read().strip()
        connection_params = {
            "account": account,
            "host": host,
            "authenticator": "oauth",
            "token": token,
            "role": "ACCOUNTADMIN",
            "warehouse": "COMPUTE_WH",
            "database": database,
            "schema": schema
        }
        return Session.builder.configs(connection_params).create()
    else:
        return Session.builder.getOrCreate()
