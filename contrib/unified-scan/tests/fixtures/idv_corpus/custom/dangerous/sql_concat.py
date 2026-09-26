import sqlite3
import sys


def report(db_path, year):
    con = sqlite3.connect(db_path)
    return con.execute("SELECT abteilung, SUM(betrag) FROM buchungen WHERE jahr = " + year).fetchall()


def by_name(con, name):
    cur = con.cursor()
    cur.execute(f"SELECT * FROM kunden WHERE name = '{name}'")
    return cur.fetchall()


def by_city(con, city):
    cur = con.cursor()
    cur.execute("SELECT * FROM kunden WHERE ort = '%s'" % city)
    return cur.fetchall()


if __name__ == "__main__":
    print(report(sys.argv[1], sys.argv[2]))
