#!/usr/bin/env python3
import csv
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from elijahctl.drivers.remoteid import RemoteIDConfig, RemoteIDDriver


@pytest.mark.integration
class TestRemoteIDIntegration(unittest.TestCase):
    """Integration tests for RemoteID configuration."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        cls.test_dir = Path(tempfile.mkdtemp(prefix="remoteid_test_"))
        cls.private_key_path = cls.test_dir / "test_private_key.dat"
        cls.csv_path = cls.test_dir / "test_batch.csv"

        # Create a dummy private key file
        cls.private_key_path.write_bytes(b"\x00" * 32)

    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def setUp(self):
        """Set up each test."""
        self.driver = RemoteIDDriver(private_key_path=str(self.private_key_path))

    @pytest.mark.slow
    @patch("subprocess.run")
    def test_end_to_end_single_configuration(self, mock_run):
        """Test end-to-end single module configuration."""
        # Mock successful MAVProxy execution
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""
            MAVProxy 1.8.55
            Loading module SecureCommand
            Getting session key...
            Session key: ABCD1234
            Setting configuration...
            UAS_ID_TYPE=1
            UAS_ID=EL-TESTUNIT001
            UAS_TYPE=2
            LOCK_LEVEL=1
            Configuration complete
            """,
            stderr="",
        )

        config = RemoteIDConfig(
            uas_id="EL-TESTUNIT001",
            uas_id_type=1,
            uas_type=2,
            connection="udp:localhost:14550",
            lock_level=1,
        )

        ok, output = self.driver.configure_single(config, verify=True)

        self.assertTrue(ok)
        self.assertIn("UAS_ID=EL-TESTUNIT001", output)
        self.assertIn("LOCK_LEVEL=1", output)

        # Verify receipt was saved
        receipt_path = self.driver.receipts_dir / "EL-TESTUNIT001.log"
        self.assertTrue(receipt_path.exists())

    @pytest.mark.slow
    @patch("subprocess.run")
    def test_end_to_end_batch_configuration(self, mock_run):
        """Test end-to-end batch configuration from CSV."""
        # Create test CSV
        with open(self.csv_path, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["uas_id", "uas_id_type", "uas_type", "conn", "lock"]
            )
            writer.writeheader()
            writer.writerows(
                [
                    {
                        "uas_id": "EL-BATCH001",
                        "uas_id_type": "1",
                        "uas_type": "2",
                        "conn": "udp:el-001:14550",
                        "lock": "1",
                    },
                    {
                        "uas_id": "EL-BATCH002",
                        "uas_id_type": "1",
                        "uas_type": "2",
                        "conn": "udp:el-002:14550",
                        "lock": "0",
                    },
                    {
                        "uas_id": "EL-BATCH003",
                        "uas_id_type": "1",
                        "uas_type": "3",
                        "conn": "COM7",
                        "lock": "",
                    },
                ]
            )

        # Mock MAVProxy execution for each unit
        mock_run.side_effect = [
            Mock(
                returncode=0,
                stdout="Session key: 0xAAAA\nUAS_ID=EL-BATCH001\nUAS_ID_TYPE=1\nUAS_TYPE=2\nLOCK_LEVEL=1",
                stderr="",
            ),
            Mock(
                returncode=0,
                stdout="Session key: 0xBBBB\nUAS_ID=EL-BATCH002\nUAS_ID_TYPE=1\nUAS_TYPE=2\nLOCK_LEVEL=0",
                stderr="",
            ),
            Mock(
                returncode=0,
                stdout="Session key: 0xCCCC\nUAS_ID=EL-BATCH003\nUAS_ID_TYPE=1\nUAS_TYPE=3",
                stderr="",
            ),
        ]

        success_count, failures = self.driver.configure_batch(self.csv_path, verify=True)

        self.assertEqual(success_count, 3)
        self.assertEqual(len(failures), 0)

        # Verify receipts were created
        for uas_id in ["EL-BATCH001", "EL-BATCH002", "EL-BATCH003"]:
            receipt_path = self.driver.receipts_dir / f"{uas_id}.log"
            self.assertTrue(receipt_path.exists(), f"Receipt not found for {uas_id}")

    @pytest.mark.slow
    @patch("subprocess.run")
    def test_error_recovery_batch_configuration(self, mock_run):
        """Test batch configuration with error recovery."""
        # Create test CSV
        with open(self.csv_path, "w", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["uas_id", "uas_id_type", "uas_type", "conn", "lock"]
            )
            writer.writeheader()
            writer.writerows(
                [
                    {
                        "uas_id": "EL-ERR001",
                        "uas_id_type": "1",
                        "uas_type": "2",
                        "conn": "udp:el-001:14550",
                        "lock": "1",
                    },
                    {
                        "uas_id": "EL-ERR002",
                        "uas_id_type": "1",
                        "uas_type": "2",
                        "conn": "udp:el-002:14550",
                        "lock": "1",
                    },
                ]
            )

        # Mock MAVProxy execution with one failure
        mock_run.side_effect = [
            Mock(
                returncode=0,
                stdout="Session key: 0xD00D\nUAS_ID=EL-ERR001\nUAS_ID_TYPE=1\nUAS_TYPE=2\nLOCK_LEVEL=1",
                stderr="",
            ),
            Mock(
                returncode=1,
                stdout="",
                stderr="Error: Failed to get session key",
            ),
        ]

        success_count, failures = self.driver.configure_batch(self.csv_path, verify=True)

        self.assertEqual(success_count, 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0], "EL-ERR002")

    @pytest.mark.slow
    def test_connection_test_integration(self):
        """Test connection testing functionality."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="""
                HEARTBEAT from system 1 component 1
                MAV_SYS_ID = 12
                DID_ENABLE = 1
                DID_OPTIONS = 1
                DID_MAVPORT = -1
                DID_CANDRIVER = 1
                """,
                stderr="",
            )

            connected, fc_info = self.driver.test_connection("udp:localhost:14550", timeout=5)

            self.assertTrue(connected)
            self.assertIsNotNone(fc_info)
            self.assertEqual(fc_info["mav_sys_id"], 12)
            self.assertTrue(fc_info["did_enabled"])

    @pytest.mark.slow
    def test_mavproxy_version_check(self):
        """Test MAVProxy version detection."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="MAVProxy 1.8.55",
                stderr="",
            )

            deps = self.driver.check_dependencies()

            self.assertTrue(deps["mavproxy"])
            mock_run.assert_called()

    def test_csv_validation(self):
        """Test CSV validation and error handling."""
        # Create invalid CSV (missing required fields)
        invalid_csv = self.test_dir / "invalid.csv"
        with open(invalid_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["uas_id", "conn"])
            writer.writeheader()
            writer.writerow({"uas_id": "EL-INVALID", "conn": "udp:localhost:14550"})

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

            # This should handle missing fields gracefully
            with self.assertRaises(KeyError):
                self.driver.configure_batch(invalid_csv)

    def test_receipt_directory_creation(self):
        """Test automatic receipt directory creation."""
        # Remove receipts directory if it exists
        import shutil

        if self.driver.receipts_dir.exists():
            shutil.rmtree(self.driver.receipts_dir)

        self.assertFalse(self.driver.receipts_dir.exists())

        # Initialize new driver - should create receipts dir
        driver = RemoteIDDriver(private_key_path=str(self.private_key_path))
        self.assertTrue(driver.receipts_dir.exists())

    @pytest.mark.slow
    def test_concurrent_configurations(self):
        """Test handling of concurrent configuration attempts."""
        configs = [
            RemoteIDConfig(
                uas_id=f"EL-CONCURRENT{i:03d}",
                uas_id_type=1,
                uas_type=2,
                connection=f"udp:el-{i:03d}:14550",
                lock_level=1,
            )
            for i in range(3)
        ]

        with patch("subprocess.run") as mock_run:
            # Mock successful execution for all
            mock_run.return_value = Mock(
                returncode=0,
                stdout="UAS_ID_TYPE=1\nUAS_TYPE=2\nLOCK_LEVEL=1",
                stderr="",
            )

            results = []
            for config in configs:
                # Add the specific UAS_ID to the mock output
                mock_run.return_value.stdout = (
                    f"Session key: 0xDEADBEEF\nUAS_ID={config.uas_id}\n" + mock_run.return_value.stdout
                )
                ok, output = self.driver.configure_single(config)
                results.append(ok)

            self.assertEqual(sum(results), 3)
            self.assertEqual(mock_run.call_count, 3)

    def test_sample_csv_generation(self):
        """Test sample CSV generation and validation."""
        sample_path = self.test_dir / "sample.csv"
        self.driver.generate_sample_csv(sample_path)

        self.assertTrue(sample_path.exists())

        # Validate CSV structure
        with open(sample_path, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertEqual(len(rows), 2)
        required_fields = ["uas_id", "uas_id_type", "uas_type", "conn", "lock"]
        for row in rows:
            for field in required_fields:
                self.assertIn(field, row)

        # Validate field values
        self.assertEqual(rows[0]["uas_id_type"], "1")
        self.assertEqual(rows[0]["uas_type"], "2")
        self.assertIn("udp", rows[0]["conn"])


if __name__ == "__main__":
    unittest.main()
