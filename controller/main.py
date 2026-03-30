from core.connect import Controller
from core.shell import Shell
from core.errors import exception_handler
from threading import Thread
import json, sys

sys.excepthook = exception_handler

if __name__ == "__main__":
    try:
        with open("data/nodes.json", "r", encoding="utf-8") as f:
            nodes_json = json.load(f)
        nodes = [tuple(lst) for lst in nodes_json]
    except FileNotFoundError:
        print("[ERROR] data/nodes.json not found")
        raise
    except json.JSONDecodeError as e:
        print(f"[ERROR] data/nodes.json invalid JSON: {e}")
        raise

    client = Controller(
        nodes=nodes,
        debug=False
    )
    client.setup_sockets()

    Shell(client).run()