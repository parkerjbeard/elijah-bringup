#!/usr/bin/env python3
import argparse
import os
import subprocess
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]


def run(cmd, cwd=None):
    print("$", " ".join(cmd))
    subprocess.check_call(cmd, cwd=cwd)


def dcompose(*args):
    run(["docker", "compose"] + list(args), cwd=ROOT)


def cmd_up(args):
    dcompose("up", "--build", "-d")
    print("Simulation is up. Export ELIJAH_SIM_LEASES_FILE to use the shim:")
    print(f"  export ELIJAH_SIM_LEASES_FILE=\"{ROOT}/services/leases/leases.json\"")


def cmd_down(args):
    dcompose("down", "-v")


def cmd_logs(args):
    dcompose("logs", "-f", "--tail=100")


def cmd_status(args):
    # Print a tiny snapshot of sim states
    air = Path(ROOT / "services/microhard_sim/state_air.json")
    ground = Path(ROOT / "services/microhard_sim/state_ground.json")
    jetson = Path(ROOT / "services/jetson_sim/state.json")
    unifi = Path(ROOT / "services/unifi_sim")
    def load(p):
        try:
            return json.loads(Path(p).read_text())
        except Exception:
            return {}
    a = load(air)
    g = load(ground)
    j = load(jetson)
    print("Microhard (air):", a.get("system", {}).get("@system[0]", {}).get("hostname"), a.get("ip"))
    print("Microhard (ground):", g.get("system", {}).get("@system[0]", {}).get("hostname"), g.get("ip"))
    print("Jetson tailscale:", j.get("tailscale", {}))
    print("Services:", j.get("services", {}))


def cmd_reset(args):
    # Reset leases and restore microhard states to initial values
    leases = Path(ROOT / "services/leases/leases.json")
    leases.write_text(json.dumps({
        "00:11:22:33:44:55": "172.28.0.110",
        "00:11:22:33:44:66": "172.28.0.111"
    }, indent=2))
    print("State reset. Restart services if needed: docker compose restart")


def cmd_fault(args):
    print("Fault injection not implemented in MVP. Toggle state files manually if needed.")


def main():
    parser = argparse.ArgumentParser(description="Elijah sim control")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("up").set_defaults(func=cmd_up)
    sub.add_parser("down").set_defaults(func=cmd_down)
    sub.add_parser("logs").set_defaults(func=cmd_logs)
    sub.add_parser("status").set_defaults(func=cmd_status)
    sub.add_parser("reset").set_defaults(func=cmd_reset)
    fault_p = sub.add_parser("fault")
    fault_p.add_argument("spec", nargs="?", help="e.g., jetson.service=mavlink-router:down")
    fault_p.set_defaults(func=cmd_fault)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()

