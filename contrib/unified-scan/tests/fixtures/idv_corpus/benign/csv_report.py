"""Monthly report: reads a CSV export and writes an Excel summary."""
import argparse
import logging

import pandas as pd

log = logging.getLogger(__name__)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("input")
    p.add_argument("output")
    args = p.parse_args()
    df = pd.read_csv(args.input, sep=";")
    summary = df.groupby("Abteilung")["Betrag"].sum().reset_index()
    summary.to_excel(args.output, index=False)
    log.info("wrote %s rows to %s", len(summary), args.output)


if __name__ == "__main__":
    main()
