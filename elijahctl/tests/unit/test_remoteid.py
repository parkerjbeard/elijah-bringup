#!/usr/bin/env python3
import csv
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from elijahctl.drivers.remoteid import RemoteIDConfig, RemoteIDDriver, ensure_did_params


class TestRemoteIDDriver(unittest.TestCase):
    """Unit tests for RemoteID driver."""

    def setUp(self):
        """Set up test fixtures."""
        self.driver = RemoteIDDriver(
            mavproxy_path="/usr/bin/mavproxy",
            private_key_path="/tmp/test_key.dat",
        )

    def test_remoteid_config_creation(self):
        """Test RemoteIDConfig dataclass creation."""
        config = RemoteIDConfig(
            uas_id="EL-0123456789ABCDEF01",
            uas_id_type=1,
            uas_type=2,
            connection="udp:el-012:14550",
            lock_level=1,
            private_key_path="/tmp/key.dat",
        )

        self.assertEqual(config.uas_id, "EL-0123456789ABCDEF01")
        self.assertEqual(config.uas_id_type, 1)
        self.assertEqual(config.uas_type, 2)
        self.assertEqual(config.connection, "udp:el-012:14550")
        self.assertEqual(config.lock_level, 1)
        self.assertEqual(config.private_key_path, "/tmp/key.dat")

    @patch("subprocess.run")
    def test_find_mavproxy_windows(self, mock_run):
        """Test finding MAVProxy on Windows."""
        with patch("platform.system", return_value="Windows"):
            with patch("pathlib.Path.exists", return_value=True):
                driver = RemoteIDDriver()
                self.assertIsNotNone(driver.mavproxy_path)

    @patch("subprocess.run")
    def test_find_mavproxy_linux(self, mock_run):
        """Test finding MAVProxy on Linux."""
        mock_run.return_value = Mock(returncode=0, stdout="/usr/local/bin/mavproxy\n")
        with patch("platform.system", return_value="Linux"):
            driver = RemoteIDDriver()
            self.assertIsNotNone(driver.mavproxy_path)

    def test_create_mavproxy_script(self):
        """Test MAVProxy script creation."""
        commands = [
            "securecommand getsessionkey",
            "securecommand setconfig UAS_ID=TEST123",
        ]

        script_path = self.driver._create_mavproxy_script(commands)

        self.assertTrue(script_path.exists())
        content = script_path.read_text()

        # Check required content
        self.assertIn("set shownoise false", content)
        self.assertIn("set requireexit True", content)
        self.assertIn("module load SecureCommand", content)
        self.assertIn("securecommand getsessionkey", content)
        self.assertIn("securecommand setconfig UAS_ID=TEST123", content)
        self.assertIn("exit", content)

        # Clean up
        script_path.unlink()

    @patch("subprocess.run")
    def test_run_mavproxy_script_success(self, mock_run):
        """Test successful MAVProxy script execution."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Session key obtained\nConfiguration applied",
            stderr="",
        )

        commands = ["securecommand getsessionkey"]
        return_code, output = self.driver._run_mavproxy_script("udp:localhost:14550", commands)

        self.assertEqual(return_code, 0)
        self.assertIn("Session key obtained", output)
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_run_mavproxy_script_omits_baud_for_udp(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
        self.driver._run_mavproxy_script("udp:localhost:14550", ["wait HEARTBEAT 1"], timeout=5)
        called_cmd = mock_run.call_args.args[0]
        self.assertIn("--master=udp:localhost:14550", called_cmd)
        self.assertNotIn("--baudrate=", called_cmd)

    @patch("subprocess.run")
    def test_run_mavproxy_script_timeout(self, mock_run):
        """Test MAVProxy script timeout handling."""
        mock_run.side_effect = subprocess.TimeoutExpired("mavproxy", 90)

        commands = ["securecommand getsessionkey"]
        with self.assertRaises(subprocess.TimeoutExpired):
            self.driver._run_mavproxy_script("udp:localhost:14550", commands)

    def test_verify_configuration_success(self):
        """Test successful configuration verification."""
        config = RemoteIDConfig(
            uas_id="EL-TEST123",
            uas_id_type=1,
            uas_type=2,
            connection="udp:localhost:14550",
            lock_level=1,
        )

        output = """
        Getting session key...
        Session key obtained
        Setting configuration...
        UAS_ID_TYPE=1
        UAS_ID=EL-TEST123
        UAS_TYPE=2
        LOCK_LEVEL=1
        Configuration complete
        """

        result = self.driver._verify_configuration(config, output, 0)
        self.assertTrue(result)

    def test_verify_configuration_failure(self):
        """Test configuration verification failure."""
        config = RemoteIDConfig(
            uas_id="EL-TEST123",
            uas_id_type=1,
            uas_type=2,
            connection="udp:localhost:14550",
        )

        output = """
        monocypher missing - please install
        Failed to get session key
        """

        result = self.driver._verify_configuration(config, output, 1)
        self.assertFalse(result)

    def test_verify_configuration_mismatch(self):
        """Test configuration value mismatch detection."""
        config = RemoteIDConfig(
            uas_id="EL-TEST123",
            uas_id_type=1,
            uas_type=2,
            connection="udp:localhost:14550",
        )

        output = """
        UAS_ID_TYPE=2
        UAS_ID=WRONG-ID
        UAS_TYPE=1
        """

        result = self.driver._verify_configuration(config, output, 0)
        self.assertFalse(result)

    @patch.object(RemoteIDDriver, "_run_mavproxy_script")
    def test_configure_single_success(self, mock_run):
        """Test successful single module configuration."""
        mock_run.return_value = (
            0,
            "Session key: 0xABCDEF\nUAS_ID_TYPE=1\nUAS_ID=EL-TEST123\nUAS_TYPE=2\n",
        )

        config = RemoteIDConfig(
            uas_id="EL-TEST123",
            uas_id_type=1,
            uas_type=2,
            connection="udp:localhost:14550",
        )

        with patch("pathlib.Path.exists", return_value=True):
            ok, output = self.driver.configure_single(config)

        self.assertTrue(ok)
        mock_run.assert_called_once()

    @patch.object(RemoteIDDriver, "_run_mavproxy_script")
    def test_configure_single_fails_without_session_key(self, mock_run):
        """Configuration should fail fast if no session key was obtained."""
        mock_run.return_value = (
            0,
            "UAS_ID_TYPE=1\nUAS_ID=EL-TEST123\nUAS_TYPE=2\n",
        )

        config = RemoteIDConfig(
            uas_id="EL-TEST123",
            uas_id_type=1,
            uas_type=2,
            connection="udp:localhost:14550",
        )

        with patch("pathlib.Path.exists", return_value=True):
            ok, _ = self.driver.configure_single(config)

        self.assertFalse(ok)

    @patch.object(RemoteIDDriver, "_run_mavproxy_script")
    def test_configure_single_no_private_key(self, mock_run):
        """Test configuration without private key."""
        driver = RemoteIDDriver(private_key_path=None)
        config = RemoteIDConfig(
            uas_id="EL-TEST123",
            uas_id_type=1,
            uas_type=2,
            connection="udp:localhost:14550",
        )

        ok, output = driver.configure_single(config)

        self.assertFalse(ok)
        self.assertEqual(output, "No private key path specified")
        mock_run.assert_not_called()

    def test_generate_sample_csv(self):
        """Test sample CSV generation."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            csv_path = Path(f.name)

        try:
            self.driver.generate_sample_csv(csv_path)

            self.assertTrue(csv_path.exists())

            # Read and verify CSV content
            with open(csv_path, newline="") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            self.assertEqual(len(rows), 2)
            self.assertIn("uas_id", rows[0])
            self.assertIn("uas_id_type", rows[0])
            self.assertIn("uas_type", rows[0])
            self.assertIn("conn", rows[0])
            self.assertIn("lock", rows[0])

        finally:
            csv_path.unlink()

    @patch.object(RemoteIDDriver, "configure_single")
    def test_configure_batch_success(self, mock_configure):
        """Test successful batch configuration."""
        mock_configure.return_value = (True, "Success")

        # Create test CSV
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_path = Path(f.name)
            writer = csv.DictWriter(
                f, fieldnames=["uas_id", "uas_id_type", "uas_type", "conn", "lock"]
            )
            writer.writeheader()
            writer.writerow(
                {
                    "uas_id": "EL-001",
                    "uas_id_type": "1",
                    "uas_type": "2",
                    "conn": "udp:localhost:14550",
                    "lock": "1",
                }
            )
            writer.writerow(
                {
                    "uas_id": "EL-002",
                    "uas_id_type": "1",
                    "uas_type": "2",
                    "conn": "COM7",
                    "lock": "",
                }
            )

        try:
            success_count, failures = self.driver.configure_batch(csv_path)

            self.assertEqual(success_count, 2)
            self.assertEqual(len(failures), 0)
            self.assertEqual(mock_configure.call_count, 2)

        finally:
            csv_path.unlink()

    @patch.object(RemoteIDDriver, "configure_single")
    def test_configure_batch_with_failures(self, mock_configure):
        """Test batch configuration with some failures."""
        mock_configure.side_effect = [
            (True, "Success"),
            (False, "Failed"),
        ]

        # Create test CSV
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_path = Path(f.name)
            writer = csv.DictWriter(
                f, fieldnames=["uas_id", "uas_id_type", "uas_type", "conn", "lock"]
            )
            writer.writeheader()
            writer.writerow(
                {
                    "uas_id": "EL-001",
                    "uas_id_type": "1",
                    "uas_type": "2",
                    "conn": "udp:localhost:14550",
                    "lock": "1",
                }
            )
            writer.writerow(
                {
                    "uas_id": "EL-002",
                    "uas_id_type": "1",
                    "uas_type": "2",
                    "conn": "COM7",
                    "lock": "",
                }
            )

        try:
            success_count, failures = self.driver.configure_batch(csv_path)

            self.assertEqual(success_count, 1)
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0], "EL-002")

        finally:
            csv_path.unlink()

    @patch("subprocess.run")
    def test_check_dependencies_all_available(self, mock_run):
        """Test dependency check with all dependencies available."""
        mock_run.return_value = Mock(returncode=0, stdout="MAVProxy 1.8.55", stderr="")

        with patch("builtins.__import__", return_value=Mock(__version__="3.1.3.2")):
            with patch("pathlib.Path.exists", return_value=True):
                deps = self.driver.check_dependencies()

        self.assertTrue(deps["mavproxy"])
        self.assertTrue(deps["monocypher"])
        self.assertTrue(deps["private_key"])

    def test_check_dependencies_missing(self):
        """Test dependency check with missing dependencies."""
        # Create a driver without a valid path
        driver = RemoteIDDriver(
            mavproxy_path="/nonexistent/mavproxy", private_key_path="/nonexistent/key.dat"
        )

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            with patch("pathlib.Path.exists", return_value=False):
                # Skip the monocypher import by mocking just that check result
                deps = driver.check_dependencies()

        self.assertFalse(deps["mavproxy"])
        # monocypher check may succeed or fail depending on whether it's installed
        # so we just check that it has a value
        self.assertIn("monocypher", deps)
        self.assertFalse(deps["private_key"])

    @patch.object(RemoteIDDriver, "_run_mavproxy_script")
    def test_test_connection_success(self, mock_run):
        """Test successful connection test."""
        mock_run.return_value = (
            0,
            "HEARTBEAT from system 1\nMAV_SYS_ID = 12\nDID_ENABLE = 1\n",
        )

        connected, fc_info = self.driver.test_connection("udp:localhost:14550")

        self.assertTrue(connected)
        self.assertIsNotNone(fc_info)
        self.assertEqual(fc_info["mav_sys_id"], 12)
        self.assertTrue(fc_info["did_enabled"])

    @patch.object(RemoteIDDriver, "_run_mavproxy_script")
    def test_test_connection_failure(self, mock_run):
        """Test failed connection test."""
        mock_run.return_value = (1, "No heartbeat received")

        connected, fc_info = self.driver.test_connection("udp:localhost:14550")

        self.assertFalse(connected)
        self.assertIsNone(fc_info)

    @patch("elijahctl.drivers.remoteid.MAVLinkDriver")
    def test_ensure_did_params_mavlink_path(self, mock_mav):
        m = mock_mav.return_value
        m.connect.return_value = True
        m.set_parameter.return_value = True

        ok = ensure_did_params("host", 14550, use_can=False, mav_port=2, can_driver=1)
        self.assertTrue(ok)
        # Expect DID_ENABLE, DID_OPTIONS, DID_MAVPORT=2, DID_CANDRIVER=0
        calls = [c.args[0] for c in m.set_parameter.call_args_list]
        self.assertIn("DID_ENABLE", calls)
        self.assertIn("DID_OPTIONS", calls)
        self.assertIn("DID_MAVPORT", calls)
        self.assertIn("DID_CANDRIVER", calls)

    @patch("elijahctl.drivers.remoteid.MAVLinkDriver")
    def test_ensure_did_params_can_path(self, mock_mav):
        m = mock_mav.return_value
        m.connect.return_value = True
        m.set_parameter.return_value = True

        ok = ensure_did_params("host", 14550, use_can=True, mav_port=-1, can_driver=2)
        self.assertTrue(ok)
        # For CAN, DID_MAVPORT should be -1 and DID_CANDRIVER set
        sent = {c.args[0]: c.args[1] for c in m.set_parameter.call_args_list}
        self.assertEqual(int(sent["DID_MAVPORT"]), -1)
        self.assertEqual(int(sent["DID_CANDRIVER"]), 2)


if __name__ == "__main__":
    unittest.main()
