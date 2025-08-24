import os
import socket
import time
import threading


def radio_stats_loop():
    dst = ("127.0.0.1", 22222)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        payload = "rf:100 rssi:-65 snr:25 associated_ip:172.28.0.20"
        try:
            s.sendto(payload.encode(), dst)
        except Exception:
            pass
        time.sleep(1)


def video_loop():
    port = int(os.environ.get("VIDEO_PORT", "5600"))
    dst = ("127.0.0.1", port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = bytes([0xAA] * 512)
    while True:
        try:
            s.sendto(data, dst)
        except Exception:
            pass
        time.sleep(0.5)


if __name__ == "__main__":
    threads = []
    if os.environ.get("RADIO_STATS_ENABLED", "1") == "1":
        threads.append(threading.Thread(target=radio_stats_loop, daemon=True))
    if os.environ.get("VIDEO_ENABLED", "1") == "1":
        threads.append(threading.Thread(target=video_loop, daemon=True))
    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

