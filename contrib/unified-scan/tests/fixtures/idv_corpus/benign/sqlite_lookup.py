import sqlite3
import sys


def find_customer(db_path, customer_id):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT name, city FROM kunden WHERE id = ?", (customer_id,))
    return cur.fetchone()


if __name__ == "__main__":
    print(find_customer(sys.argv[1], sys.argv[2]))
