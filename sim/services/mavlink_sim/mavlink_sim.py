import time
import threading

from pymavlink import mavutil


class MavSim:
    def __init__(self, sysid: int = 1, port: int = 14550):
        self.sysid = sysid
        self.port = port
        # Sender emits to localhost:14550
        self.sender = mavutil.mavlink_connection(f"udpout:127.0.0.1:{self.port}")
        # Receiver binds to all
        self.recv = mavutil.mavlink_connection(f"udpin:0.0.0.0:{self.port}")
        self._running = True
        self._pause_heartbeats_until = 0.0

    def send_heartbeat(self):
        self.sender.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_QUADROTOR,
            mavutil.mavlink.MAV_AUTOPILOT_PX4,
            0,
            0,
            3,
        )

    def hb_loop(self):
        while self._running:
            if time.time() >= self._pause_heartbeats_until:
                try:
                    self.send_heartbeat()
                except Exception:
                    pass
            time.sleep(1.0)

    def handle_messages(self):
        while self._running:
            try:
                msg = self.recv.recv_match(blocking=True, timeout=1)
            except Exception:
                msg = None
            if not msg:
                continue
            mtype = msg.get_type()
            if mtype == "PARAM_SET" and msg.param_id.strip("\x00") == "MAV_SYS_ID":
                try:
                    self.sysid = int(msg.param_value)
                except Exception:
                    pass
                # echo value back
                self.sender.mav.param_value_send(
                    b"MAV_SYS_ID",
                    float(self.sysid),
                    mavutil.mavlink.MAV_PARAM_TYPE_INT32,
                    1,
                    0,
                )
            elif mtype == "PARAM_REQUEST_READ" and msg.param_id.strip("\x00") == "MAV_SYS_ID":
                self.sender.mav.param_value_send(
                    b"MAV_SYS_ID",
                    float(self.sysid),
                    mavutil.mavlink.MAV_PARAM_TYPE_INT32,
                    1,
                    0,
                )
            elif mtype == "COMMAND_LONG" and msg.command == mavutil.mavlink.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN:
                # Ack and pause heartbeats for a few seconds
                self.sender.mav.command_ack_send(
                    mavutil.mavlink.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN,
                    mavutil.mavlink.MAV_RESULT_ACCEPTED,
                )
                self._pause_heartbeats_until = time.time() + 4.0

    def run(self):
        t1 = threading.Thread(target=self.hb_loop, daemon=True)
        t2 = threading.Thread(target=self.handle_messages, daemon=True)
        t1.start()
        t2.start()
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self._running = False


if __name__ == "__main__":
    MavSim().run()

