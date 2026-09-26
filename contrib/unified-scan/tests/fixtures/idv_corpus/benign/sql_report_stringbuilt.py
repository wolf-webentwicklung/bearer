import sqlite3
import sys


def report(db_path, year):
    con = sqlite3.connect(db_path)
    query = "SELECT abteilung, SUM(betrag) FROM buchungen WHERE jahr = " + year + " GROUP BY abteilung"
    return con.execute(query).fetchall()


if __name__ == "__main__":
    for row in report(sys.argv[1], sys.argv[2]):
        print(row)
