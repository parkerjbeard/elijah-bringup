import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

from elijahctl.cli import cli
from elijahctl.config import Config, RadioConfig, RadioRole
from elijahctl.drivers.microhard import MicrohardDriver
from elijahctl.health.checks import HealthCheck

class TestIntegration:
    
    @pytest.fixture
    def runner(self):
        return CliRunner()
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture(autouse=True)
    def setup_config(self, temp_dir):
        Config.BASE_DIR = temp_dir
        Config.STATE_DIR = temp_dir / "state"
        Config.RUNS_DIR = temp_dir / "runs"
        Config.INVENTORY_DIR = temp_dir / "inventory"
        Config.LOGS_DIR = temp_dir / "logs"
        Config.init_directories()
    
    @patch('elijahctl.utils.network.discover_services')
    def test_discover_command(self, mock_discover, runner):
        mock_discover.return_value = {
            'ssh': True,
            'http': True,
            'telnet': False
        }
        
        result = runner.invoke(cli, ['discover', '--ip', '192.168.168.1'])
        
        assert result.exit_code == 0
        assert "ssh" in result.output.lower()
        mock_discover.assert_called_once_with('192.168.168.1', 2.0)
    
    @patch.object(MicrohardDriver, 'provision')
    def test_provision_air_radio(self, mock_provision, runner):
        mock_provision.return_value = True
        
        result = runner.invoke(cli, [
            'provision',
            '--role', 'air',
            '--drone-id', '012',
            '--sysid', '12',
            '--aes-key', 'test_key_128',
            '--microhard-pass', 'admin'
        ])
        
        assert result.exit_code == 0
        assert "provisioned successfully" in result.output.lower()
        mock_provision.assert_called_once()
    
    @patch.object(MicrohardDriver, 'provision')
    def test_provision_ground_radio(self, mock_provision, runner):
        mock_provision.return_value = True
        
        result = runner.invoke(cli, [
            'provision',
            '--role', 'ground',
            '--drone-id', '001',
            '--aes-key', 'test_key_128'
        ])
        
        assert result.exit_code == 0
        mock_provision.assert_called_once()
    
    def test_provision_air_without_sysid(self, runner):
        result = runner.invoke(cli, [
            'provision',
            '--role', 'air',
            '--drone-id', '012',
            '--aes-key', 'test_key_128'
        ])
        
        assert result.exit_code == 1
        assert "sysid is required" in result.output.lower()
    
    @patch.object(MicrohardDriver, 'safe_reset')
    def test_reset_radio(self, mock_reset, runner):
        mock_reset.return_value = True
        
        result = runner.invoke(cli, [
            'reset-radio',
            '--ip', '192.168.168.1'
        ], input='y\n')
        
        assert result.exit_code == 0
        assert "reset successfully" in result.output.lower()
        mock_reset.assert_called_once()
    
    @patch.object(HealthCheck, 'run_all_checks')
    @patch.object(HealthCheck, 'save_results')
    def test_health_check(self, mock_save, mock_run_checks, runner):
        mock_run_checks.return_value = [
            Mock(status=True),
            Mock(status=True),
            Mock(status=False)
        ]
        mock_save.return_value = "/tmp/results.json"
        
        result = runner.invoke(cli, [
            'health',
            '--jetson', 'el-012',
            '--radio-ip', '10.0.0.100'
        ])
        
        assert result.exit_code == 0
        mock_run_checks.assert_called_once()
        mock_save.assert_called_once()
    
    def test_checklist_update(self, runner, temp_dir):
        checklist_data = {
            "serial_qr": "ABC123",
            "air_radio_fw_kept_factory": True,
            "air_radio_configured": True,
            "remoteid_configured": True,
            "remoteid_serial_20d": "12345678901234567890",
            "remoteid_faa_entered": True,
            "jetson_git_hash": "abc123",
            "px4_fw_ref": "v1.2.3",
            "param_set_version": "v2_standard",
            "sysid_set": 12,
            "seraph_hitl_ok": True,
            "esc_fw_ref": "v1.0",
            "esc_params_ref": "v2_standard.cfg",
            "motor_map_ok": True,
            "ads_power_ok": True,
            "arm_no_props_ok": True,
            "arm_safety_param_ok": True,
            "elrs_configured": False,
            "hitl_signed_by": "operator",
            "hitl_date": "2024-01-01"
        }
        
        checklist_file = temp_dir / "checklist.json"
        with open(checklist_file, 'w') as f:
            json.dump(checklist_data, f)
        
        result = runner.invoke(cli, [
            'checklist',
            '--update', str(checklist_file),
            '--drone-id', '012',
            '--phase', 'hitl'
        ])
        
        assert result.exit_code == 0
        assert "saved" in result.output.lower()
    
    def test_checklist_export(self, runner, temp_dir):
        export_file = temp_dir / "export.json"
        
        result = runner.invoke(cli, [
            'checklist',
            '--drone-id', '012',
            '--export', str(export_file)
        ])
        
        assert result.exit_code == 0
        assert export_file.exists()
        
        with open(export_file, 'r') as f:
            data = json.load(f)
            assert data['drone_id'] == '012'
    
    @patch('elijahctl.drivers.mavlink.MAVLinkDriver.set_sysid')
    def test_set_sysid(self, mock_set_sysid, runner):
        mock_set_sysid.return_value = True
        
        result = runner.invoke(cli, [
            'set-sysid',
            '--host', 'el-012',
            '--sysid', '12'
        ])
        
        assert result.exit_code == 0
        assert "set to 12" in result.output.lower()
        mock_set_sysid.assert_called_once_with(12)
    
    def test_version_command(self, runner):
        result = runner.invoke(cli, ['version'])
        
        assert result.exit_code == 0
        assert "elijahctl version" in result.output
    
    @patch('elijahctl.drivers.unifi.UniFiDriver.provision')
    def test_unifi_command(self, mock_provision, runner):
        mock_provision.return_value = True
        
        result = runner.invoke(cli, [
            'unifi',
            '--controller', 'https://unifi.local',
            '--user', 'admin',
            '--pass', 'password',
            '--name', 'rainmakerGCSX',
            '--ip', '10.101.252.1/16',
            '--disable-24ghz',
            '--disable-autolink'
        ])
        
        assert result.exit_code == 0
        assert "configured successfully" in result.output.lower()
        mock_provision.assert_called_once()
    
    def test_cli_keyboard_interrupt(self, runner):
        with patch('elijahctl.cli.cli', side_effect=KeyboardInterrupt()):
            result = runner.invoke(cli, ['version'])
            assert result.exit_code != 0