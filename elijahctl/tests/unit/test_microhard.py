import pytest
from unittest.mock import Mock, patch, MagicMock
import json

from elijahctl.drivers.microhard import MicrohardDriver, MicrohardConnection
from elijahctl.drivers.mh_profile import MHProfile
from elijahctl.config import RadioConfig, RadioRole


class TestMicrohardDriver:

    @pytest.fixture
    def driver(self):
        return MicrohardDriver("192.168.168.1", "admin", "supercool")

    @pytest.fixture
    def air_config(self):
        return RadioConfig(
            role=RadioRole.AIR,
            drone_id="012",
            hostname="elijah-012-air",
            description="Elijah 012 Air Radio",
            aes_key="test_aes_key_128",
        )

    @pytest.fixture
    def ground_config(self):
        return RadioConfig(
            role=RadioRole.GROUND,
            drone_id="001",
            hostname="rainmaker-ground-001",
            description="Rainmaker Ground Radio 001",
            aes_key="test_aes_key_128",
        )

    def test_radio_config_initialization(self, air_config, ground_config):
        assert air_config.mode == "Slave"
        assert air_config.hostname == "elijah-012-air"
        assert ground_config.mode == "Master"
        assert ground_config.hostname == "rainmaker-ground-001"

    @patch("elijahctl.drivers.microhard.discover_services")
    @patch("elijahctl.drivers.microhard.get_mac_address")
    def test_discover(self, mock_get_mac, mock_discover_services, driver):
        mock_discover_services.return_value = {"ssh": True, "http": True, "telnet": True}
        mock_get_mac.return_value = "00:11:22:33:44:55"

        connection = driver.discover()

        assert isinstance(connection, MicrohardConnection)
        assert connection.ssh_available is True
        assert connection.http_available is True
        assert connection.telnet_available is True
        assert connection.mac_address == "00:11:22:33:44:55"

    @patch("elijahctl.drivers.microhard.discover_services")
    def test_discover_no_services(self, mock_discover_services, driver):
        mock_discover_services.return_value = {"ssh": False, "http": False, "telnet": False}

        with pytest.raises(ConnectionError):
            driver.discover()

    @patch("paramiko.SSHClient")
    def test_ssh_execute_success(self, mock_ssh_client, driver):
        mock_client = MagicMock()
        mock_ssh_client.return_value = mock_client
        # Stub exec_command (fast path)
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b"success"
        mock_stderr.read.return_value = b""
        # Paramiko uses a channel to report status
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        success, output = driver._ssh_execute("echo success", try_exec_first=True)

        assert success is True
        assert output == "success"
        mock_client.connect.assert_called_once()
        mock_client.close.assert_called_once()

    @patch("requests.post")
    def test_ubus_login(self, mock_post, driver):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": [None, {"ubus_rpc_session": "test_token_123"}]}
        mock_post.return_value = mock_response

        token = driver._ubus_login()

        assert token == "test_token_123"
        mock_post.assert_called_once()

    def test_stage_config(self, driver, air_config):
        driver.stage_config(air_config)
        # System and network configs staged for generic UCI
        assert "system" in driver.staged_config
        assert "network" in driver.staged_config
        assert driver.staged_config["system"]["@system[0]"]["hostname"] == "elijah-012-air"
        assert driver.staged_config["network"]["lan"]["proto"] == "dhcp"
        # Semantic radio params prepared for profile-based application
        assert driver._radio_params["net_id"] == "rainmaker"
        assert int(driver._radio_params["bw_mhz"]) == 5

    def test_freq_to_channel(self, driver):
        assert driver._freq_to_channel(2412) == 1
        assert driver._freq_to_channel(2427) == 4
        assert driver._freq_to_channel(2462) == 11
        assert driver._freq_to_channel(9999) == 4

    def test_build_at_commands_skip_dhcp_when_stats_staged(self, driver, air_config):
        # Stage config with stats enabled and DHCP requested
        driver.stage_config(air_config)
        # When include_dhcp=False, AT list should not contain MNIFACE
        at_cmds = driver._build_at_commands_from_staged(include_dhcp=False)
        assert all("AT+MNIFACE" not in c for c in at_cmds)
        assert any(c.strip().upper() == "AT&W" for c in at_cmds)
        # When include_dhcp=True, MNIFACE should appear for DHCP
        at_cmds2 = driver._build_at_commands_from_staged(include_dhcp=True)
        assert any(c.startswith("AT+MNIFACE=lan,EDIT,0") for c in at_cmds2)

    @patch("elijahctl.drivers.microhard.port_open", return_value=True)
    @patch.object(MicrohardDriver, "_run_uci_batch_ssh", return_value=(True, ""))
    @patch.object(MicrohardDriver, "_apply_stats_via_uci_ssh", return_value=True)
    def test_apply_via_ssh_defers_dhcp_and_switches_via_uci(
        self, mock_apply_stats, mock_batch, mock_port_open, driver, air_config
    ):
        # Capture AT command list passed into the AT session
        captured = {}

        def _fake_at_session(cmds):
            captured["at_cmds"] = cmds
            return True, "OK"

        # Make readiness probe succeed
        with patch.object(MicrohardDriver, "_ssh_execute", return_value=(True, "")):
            with patch.object(
                MicrohardDriver, "_ssh_execute_at_session", side_effect=_fake_at_session
            ):
                driver.stage_config(air_config)
                ok = driver.apply_via_ssh()

        assert ok is True
        # AT should not include DHCP flip when stats are staged
        assert "at_cmds" in captured
        assert all("AT+MNIFACE" not in c for c in captured["at_cmds"])
        # After stats, we should switch LAN to DHCP via UCI
        assert mock_batch.called
        args, kwargs = mock_batch.call_args
        sent = "\n".join(args[0]) if args and args[0] else ""
        assert "uci set network.lan.proto=dhcp" in sent
        assert "uci commit network" in sent

    @patch.object(MicrohardDriver, "_ssh_execute_at_session")
    def test_apply_via_ssh(self, mock_at_session, driver, air_config):
        mock_at_session.return_value = (True, "OK")

        driver.stage_config(air_config)
        result = driver.apply_via_ssh()

        assert result is True
        assert mock_at_session.call_count == 1

    @patch.object(MicrohardDriver, "_ubus_call")
    @patch.object(MicrohardDriver, "_ubus_login")
    def test_apply_via_http(self, mock_login, mock_ubus_call, driver, air_config):
        mock_login.return_value = "test_token"
        mock_ubus_call.return_value = {"status": "ok"}
        # Provide a detected profile so radio params/stats can be applied
        driver.profile = MHProfile(
            name="mh_radio_v1",
            uci_keys={
                "role": ("mh_radio", "@mh[0]", "mode"),
                "freq_mhz": ("mh_radio", "@mh[0]", "freq_mhz"),
                "bw_mhz": ("mh_radio", "@mh[0]", "bw_mhz"),
                "net_id": ("mh_radio", "@mh[0]", "net_id"),
                "aes_key": ("mh_radio", "@mh[0]", "aes_key"),
                "stats_enable": ("mh_stats", "@stats[0]", "enable"),
                "stats_port": ("mh_stats", "@stats[0]", "port"),
                "stats_interval": ("mh_stats", "@stats[0]", "interval"),
                "stats_fields": ("mh_stats", "@stats[0]", "fields"),
            },
        )

        driver.stage_config(air_config)
        result = driver.apply_via_http()

        assert result is True
        assert mock_ubus_call.call_count > 0

    @patch("telnetlib3.open_connection")
    def test_safe_reset(self, mock_open_conn, driver):
        class FakeReader:
            def __init__(self):
                self._prompt_given = False

            async def readuntil(self, s):
                # Accept bytes or str separator
                sep_text = s.decode() if isinstance(s, (bytes, bytearray)) else str(s)
                if "UserDevice>" in sep_text and not self._prompt_given:
                    self._prompt_given = True
                    return s if isinstance(s, (bytes, bytearray)) else "UserDevice>"
                return ""

            async def read(self, n):
                # Always acknowledge with OK for simplicity
                return "OK"

        class FakeWriter:
            def __init__(self):
                self.buf = []

            def write(self, s):
                self.buf.append(s)

            async def drain(self):
                return None

            def close(self):
                pass

            async def wait_closed(self):
                return None

        captured = {}

        async def _fake(host, port, encoding):
            r, w = FakeReader(), FakeWriter()
            captured["writer"] = w
            return (r, w)

        mock_open_conn.side_effect = _fake

        with patch.object(driver, "discover") as mock_discover:
            mock_discover.return_value = MicrohardConnection(
                ip="192.168.168.1", ssh_available=False, http_available=False, telnet_available=True
            )
            assert driver.safe_reset() is True
            # Verify ordered AT sequence
            b = "".join(captured["writer"].buf)
            assert b.find("AT+MSRTF=0\r\n") != -1
            assert b.find("AT+MSRTF=1\r\n") != -1
            assert b.find("AT+MSRTF=0\r\n") < b.find("AT+MSRTF=1\r\n")

    @patch("elijahctl.drivers.microhard.find_mac_in_leases")
    @patch("time.sleep")
    def test_wait_for_dhcp_flip(self, mock_sleep, mock_find_mac, driver):
        driver.original_mac = "00:11:22:33:44:55"
        mock_find_mac.side_effect = [None, None, "10.0.0.100"]

        new_ip = driver.wait_for_dhcp_flip(timeout=10)

        assert new_ip == "10.0.0.100"
        assert driver.ip == "10.0.0.100"
        assert mock_find_mac.call_count == 3
