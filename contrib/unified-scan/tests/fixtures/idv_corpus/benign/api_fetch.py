import json
import os

import requests

API = "https://intranet.example.internal/api/v1/tickets"


def open_tickets(team):
    token = os.environ["TICKET_API_TOKEN"]
    r = requests.get(API, params={"team": team, "status": "open"},
                     headers={"Authorization": f"Bearer {token}"}, timeout=30)
    r.raise_for_status()
    return r.json()


if __name__ == "__main__":
    print(json.dumps(open_tickets("it"), indent=2))
