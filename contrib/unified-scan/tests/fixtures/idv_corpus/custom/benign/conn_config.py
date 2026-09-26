import configparser

import psycopg2
from sqlalchemy import create_engine

cfg = configparser.ConfigParser()
cfg.read("db.ini")
conn = psycopg2.connect(host="db01", dbname="report", user="report", password=cfg["db"]["password"])
engine = create_engine(cfg["db"]["url"])
trusted = "DRIVER={SQL Server};SERVER=db01;Trusted_Connection=yes"
