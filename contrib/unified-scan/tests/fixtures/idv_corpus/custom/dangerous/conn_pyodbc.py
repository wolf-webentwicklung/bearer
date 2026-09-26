import pyodbc


def connect():
    return pyodbc.connect("DRIVER={ODBC Driver 18 for SQL Server};SERVER=db01;DATABASE=report;UID=report;PWD=Sommer2026!")
