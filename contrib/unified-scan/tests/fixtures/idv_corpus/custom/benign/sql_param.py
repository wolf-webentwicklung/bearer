import sqlite3


def report(db_path, year):
    con = sqlite3.connect(db_path)
    return con.execute("SELECT abteilung, SUM(betrag) FROM buchungen WHERE jahr = ?", (year,)).fetchall()


def by_name(con, name):
    cur = con.cursor()
    cur.execute("SELECT * FROM kunden WHERE name = %s", (name,))
    return cur.fetchall()


def fixed(con):
    return con.execute("SELECT COUNT(*) FROM kunden").fetchone()
