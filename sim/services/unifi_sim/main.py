from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Dict, Any

app = FastAPI()

# In-memory state
STATE: Dict[str, Any] = {
    "devices": [
        {
            "_id": "dev1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "type": "uap",
            "adopted": False,
            "hostname": "uap-sim",
            "name": "uap-sim",
        }
    ],
    "wlans": [
        {"_id": "w1", "name": "Rainmaker 5G", "wlan_band": "5g", "wlan_bands": ["5g"], "enabled": True},
        {"_id": "w2", "name": "Rainmaker 2G", "wlan_band": "2g", "wlan_bands": ["2g"], "enabled": True},
    ],
    "auto_optimize": True,
}


@app.get("/status")
async def status():
    return {"meta": {"server_version": "8.0.0"}}


@app.post("/api/auth/login")
async def login(request: Request):
    resp = JSONResponse({"ok": True})
    resp.headers["x-csrf-token"] = "sim-csrf"
    return resp


def _data(items):
    return {"data": items}


@app.get("/proxy/network/api/s/{site}/stat/device")
async def stat_device(site: str):
    return _data(STATE["devices"])  # type: ignore


@app.post("/proxy/network/api/s/{site}/cmd/devmgr")
async def cmd_devmgr(site: str, request: Request):
    body = await request.json()
    if body.get("cmd") == "adopt":
        mac = (body.get("mac") or "").lower()
        for d in STATE["devices"]:
            if (d.get("mac") or "").lower() == mac:
                d["adopted"] = True
                return JSONResponse({"meta": {"rc": "ok"}})
    return JSONResponse({"meta": {"rc": "error"}}, status_code=400)


@app.put("/proxy/network/api/s/{site}/rest/device/{dev_id}")
async def rest_device_update(site: str, dev_id: str, request: Request):
    body = await request.json()
    for d in STATE["devices"]:
        if d.get("_id") == dev_id:
            d.update({k: v for k, v in body.items() if k in ("name", "config_network")})
            return JSONResponse({"meta": {"rc": "ok"}})
    return JSONResponse({"meta": {"rc": "error"}}, status_code=404)


@app.get("/proxy/network/api/s/{site}/rest/wlanconf")
async def wlanconf(site: str):
    return _data(STATE["wlans"])  # type: ignore


@app.put("/proxy/network/api/s/{site}/rest/wlanconf/{wlan_id}")
async def wlanconf_update(site: str, wlan_id: str, request: Request):
    body = await request.json()
    for w in STATE["wlans"]:
        if w.get("_id") == wlan_id:
            # Only update a few keys we care about
            for k in ("name", "enabled", "wlan_band", "wlan_bands"):
                if k in body:
                    w[k] = body[k]
            return JSONResponse({"meta": {"rc": "ok"}})
    return JSONResponse({"meta": {"rc": "error"}}, status_code=404)


@app.post("/proxy/network/api/s/{site}/set/setting/auto_optimize")
async def auto_opt(site: str, request: Request):
    body = await request.json()
    STATE["auto_optimize"] = bool(body.get("enabled", False))
    return JSONResponse({"meta": {"rc": "ok"}})

