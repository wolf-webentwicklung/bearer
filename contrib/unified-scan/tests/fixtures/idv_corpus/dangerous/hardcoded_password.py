import pyodbc

PASSWORD = "Sommer2026!"


def connect():
    return pyodbc.connect("DRIVER={SQL Server};SERVER=db01;UID=report;PWD=" + PASSWORD)
