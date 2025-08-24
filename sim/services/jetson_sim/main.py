import asyncssh
import json
import os
from pathlib import Path

STATE_PATH = Path(os.environ.get("STATE_PATH", "/sim/state.json"))
USERNAME = "jetson"
PASSWORD = "jetson"


def load_state():
    try:
        return json.loads(STATE_PATH.read_text())
    except Exception:
        return {
            "tailscale": {"online": True, "dns_name": "el-012.tail-scale.ts.net"},
            "services": {
                "mavlink-router": True,
                "radio-stats": True,
                "seraph": True,
                "elijah": True
            },
            "versions": {
                "seraph": "abc123def4567890abcdef1234567890abcdef12",
                "elijah": "fed654cba3210987abcdef6543210fedcba98765",
                "fc_fw": "v1.2.3"
            },
            "pth": {"pressure": 1013.2, "temperature": 22.5, "humidity": 45.0}
        }


STATE = load_state()


class SSHServer(asyncssh.SSHServer):
    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == USERNAME and password == PASSWORD


async def handle_process(process: asyncssh.SSHServerProcess):
    cmd = (process.command or "").strip()
    try:
        # tailscale status --json
        if cmd.startswith("tailscale status --json"):
            j = {
                "Self": {
                    "Online": bool(STATE.get("tailscale", {}).get("online", True)),
                    "DNSName": STATE.get("tailscale", {}).get("dns_name", "")
                }
            }
            process.stdout.write(json.dumps(j) + "\n")
            process.exit(0)
            return
        # systemctl is-active X
        if cmd.startswith("systemctl is-active "):
            svc = cmd.split()[-1]
            active = bool(STATE.get("services", {}).get(svc, True))
            process.stdout.write("active\n" if active else "inactive\n")
            process.exit(0)
            return
        # git rev-parse
        if cmd.endswith("git rev-parse HEAD"):
            if "/opt/seraph" in cmd:
                process.stdout.write(STATE.get("versions", {}).get("seraph", "unknown") + "\n")
            elif "/opt/elijah" in cmd:
                process.stdout.write(STATE.get("versions", {}).get("elijah", "unknown") + "\n")
            else:
                process.stdout.write("unknown\n")
            process.exit(0)
            return
        # cat files
        if cmd.startswith("cat "):
            path = cmd.split(" ", 1)[1].strip()
            if path.startswith("/opt/firmware/version.txt"):
                process.stdout.write(STATE.get("versions", {}).get("fc_fw", "unknown") + "\n")
            elif path.startswith("/var/log/seraph/pth.json"):
                process.stdout.write(json.dumps(STATE.get("pth", {})) + "\n")
            else:
                process.stdout.write("\n")
            process.exit(0)
            return
        # default OK
        process.exit(0)
    except Exception as e:
        process.stderr.write(str(e) + "\n")
        process.exit(1)


async def start_ssh():
    key = asyncssh.generate_private_key("ssh-rsa")
    await asyncssh.create_server(
        lambda: SSHServer(),
        host="0.0.0.0",
        port=22,
        server_host_keys=[key],
        process_factory=handle_process,
        sftp_factory=asyncssh.SFTPServer,
    )


if __name__ == "__main__":
    import asyncio

    asyncio.run(start_ssh())

