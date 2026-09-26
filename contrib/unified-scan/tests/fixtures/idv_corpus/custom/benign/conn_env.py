import os

import pyodbc


def connect():
    pw = os.environ["REPORT_DB_PASSWORD"]
    return pyodbc.connect(f"DRIVER={{ODBC Driver 18 for SQL Server}};SERVER=db01;UID=report;PWD={pw}")
