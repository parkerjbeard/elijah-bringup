import asyncio
import json
import os
import time
from pathlib import Path
from typing import Dict, Any

import asyncssh
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
import telnetlib3


STATE_PATH = Path(os.environ.get("STATE_PATH", "/sim/state.json"))
LEASES_FILE = Path(os.environ.get("LEASES_FILE", "/leases/leases.json"))
USERNAME = os.environ.get("USER", "admin")
PASSWORD = os.environ.get("PASS", "admin")
ROLE = os.environ.get("ROLE", "air")


class SimState:
    def __init__(self, path: Path):
        self.path = path
        self.state: Dict[str, Any] = {}
        self._dirty = False
        self.reboot_at: float | None = None
        self.load()

    def load(self):
        try:
            self.state = json.loads(self.path.read_text())
        except Exception:
            self.state = {
                "system": {"@system[0]": {"hostname": f"elijah-000-{ROLE}", "description": ""}},
                "network": {"lan": {"proto": "static"}},
                "mh_radio": {"@mh[0]": {"mode": "Slave" if ROLE == "air" else "Master"}},
                "mh_stats": {"@stats[0]": {"enable": "0", "port": "22222", "interval": "1000", "fields": "rf,rssi,snr,associated_ip"}},
                "mac": os.environ.get("MAC", "00:11:22:33:44:55"),
                "ip": os.environ.get("IP", "172.28.0.10"),
            }
            self.save()

    def save(self):
        self.path.write_text(json.dumps(self.state, indent=2))

    def uci_show(self) -> str:
        lines: list[str] = []
        for cfg, sections in self.state.items():
            if cfg in ("mac", "ip"):
                continue
            if isinstance(sections, dict):
                for sec, opts in sections.items():
                    if isinstance(opts, dict):
                        for k, v in opts.items():
                            lines.append(f"{cfg}.{sec}.{k}='{v}'")
        return "\n".join(lines) + "\n"

    def uci_set(self, cfg: str, sec: str, opt: str, val: str):
        self.state.setdefault(cfg, {}).setdefault(sec, {})[opt] = val
        self._dirty = True

    def commit(self, cfg: str):
        # DHCP flip emulation
        if cfg == "network":
            proto = self.state.get("network", {}).get("lan", {}).get("proto")
            if proto == "dhcp":
                # move to a new IP and update leases
                new_ip = "172.28.0.110" if self.state.get("ip") == "172.28.0.10" else "172.28.0.111"
                self.state["ip"] = new_ip
                try:
                    mapping = {}
                    if LEASES_FILE.exists():
                        mapping = json.loads(LEASES_FILE.read_text())
                    mapping[self.state.get("mac", "").lower()] = new_ip
                    LEASES_FILE.parent.mkdir(parents=True, exist_ok=True)
                    LEASES_FILE.write_text(json.dumps(mapping, indent=2))
                except Exception:
                    pass
        self.save()
        self._dirty = False

    def schedule_reboot(self):
        self.reboot_at = time.time() + 1.5

    def is_rebooting(self) -> bool:
        if self.reboot_at and time.time() < self.reboot_at:
            return True
        self.reboot_at = None
        return False


SIM = SimState(STATE_PATH)


# ---------------- SSH server -----------------
class SSHServer(asyncssh.SSHServer):
    def __init__(self):
        super().__init__()

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == USERNAME and password == PASSWORD


async def handle_process(process: asyncssh.SSHServerProcess):
    cmd = process.command or ""
    if SIM.is_rebooting():
        process.stderr.write("system is rebooting\n")
        process.exit(1)
        return
    try:
        if cmd.startswith("uci show"):
            process.stdout.write(SIM.uci_show())
            process.exit(0)
            return
        if cmd.startswith("uci set "):
            # uci set cfg.sec.opt='val'
            try:
                tail = cmd[len("uci set "):].strip()
                lhs, rhs = tail.split("=", 1)
                val = rhs.strip().strip("'")
                cfg, sec, opt = lhs.split(".", 2)
                SIM.uci_set(cfg, sec, opt, val)
                process.exit(0)
                return
            except Exception:
                process.stderr.write("bad uci set\n")
                process.exit(1)
                return
        if cmd.startswith("uci commit"):
            cfg = cmd.split()[-1]
            SIM.commit(cfg)
            process.exit(0)
            return
        if cmd.strip() == "sync; reboot":
            SIM.schedule_reboot()
            process.exit(0)
            return
        # default: ok
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


# ---------------- HTTP (ubus/LuCI) -----------------
app = FastAPI()


@app.post("/cgi-bin/luci/rpc/auth")
async def luci_auth(request: Request):
    body = await request.json()
    params = body.get("params", [])
    if params == [USERNAME, PASSWORD]:
        return JSONResponse({"result": [0, {"ubus_rpc_session": "simtoken"}]})
    return JSONResponse({"error": "invalid"}, status_code=403)


@app.post("/ubus")
async def ubus_call(request: Request):
    if SIM.is_rebooting():
        return JSONResponse({"error": "rebooting"}, status_code=503)
    body = await request.json()
    params = body.get("params", [])
    if len(params) < 4:
        return JSONResponse({"error": "bad request"}, status_code=400)
    _token, service, method, args = params
    try:
        if service == "uci" and method == "set":
            cfg = args.get("config")
            sec = args.get("section")
            values = args.get("values", {})
            for k, v in values.items():
                SIM.uci_set(cfg, sec, k, str(v))
            return JSONResponse({"result": [0, {}]})
        if service == "uci" and method == "commit":
            cfg = args.get("config")
            SIM.commit(cfg)
            return JSONResponse({"result": [0, {}]})
        if service == "uci" and method == "get_all":
            cfg = args.get("config")
            values = SIM.state.get(cfg, {})
            return JSONResponse({"result": [0, {"values": values}]})
        if service == "system" and method == "reboot":
            SIM.schedule_reboot()
            return JSONResponse({"result": [0, {}]})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse({"error": "unknown"}, status_code=404)


async def start_http():
    config = uvicorn.Config(app=app, host="0.0.0.0", port=80, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()


# ---------------- Telnet (AT+MSRTF) -----------------
class TelnetShell:
    def __init__(self):
        self._stage = 0

    async def __call__(self, reader, writer):
        writer.write("login: ")
        user = (await reader.readline()).strip()
        writer.write("Password: ")
        pw = (await reader.readline()).strip()
        writer.write("\r\n")
        if user != USERNAME or pw != PASSWORD:
            writer.write("Login incorrect\r\n")
            await asyncio.sleep(0.5)
            return
        writer.write("# ")
        while True:
            line = await reader.readline()
            if not line:
                break
            cmd = line.strip().upper()
            if cmd.startswith("AT+MSRTF="):
                writer.write("OK\r\n")
                SIM.state.setdefault("telnet", {})["last_reset_ts"] = time.time()
                SIM.save()
            writer.write("# ")


async def start_telnet():
    await telnetlib3.create_server(host="0.0.0.0", port=23, shell=TelnetShell())


async def main():
    await asyncio.gather(start_ssh(), start_http(), start_telnet())


if __name__ == "__main__":
    asyncio.run(main())

