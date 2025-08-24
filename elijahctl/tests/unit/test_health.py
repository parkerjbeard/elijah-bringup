import pytest
from unittest.mock import Mock, patch, MagicMock
import json
import socket

from elijahctl.health.checks import HealthCheck
from elijahctl.config import HealthCheckResult

class TestHealthCheck:
    
    @pytest.fixture
    def health_check(self):
        return HealthCheck("test-jetson", "192.168.1.100")
    
    @patch('elijahctl.health.checks.ping_host')
    def test_check_connectivity_success(self, mock_ping, health_check):
        mock_ping.side_effect = [(True, 10.5), (True, 5.2)]
        
        results = health_check.check_connectivity()
        
        assert "jetson" in results
        assert "radio" in results
        assert results["jetson"].status is True
        assert results["radio"].status is True
        assert results["jetson"].data["rtt"] == 10.5
        assert results["radio"].data["rtt"] == 5.2
    
    @patch('elijahctl.health.checks.ping_host')
    def test_check_connectivity_failure(self, mock_ping, health_check):
        mock_ping.side_effect = [(False, None), (False, None)]
        
        results = health_check.check_connectivity()
        
        assert results["jetson"].status is False
        assert results["radio"].status is False
    
    @patch('paramiko.SSHClient')
    def test_check_tailscale_online(self, mock_ssh_client, health_check):
        mock_client = MagicMock()
        mock_ssh_client.return_value = mock_client
        
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = json.dumps({
            "Self": {
                "Online": True,
                "DNSName": "el-012.tail-scale.ts.net"
            }
        }).encode()
        
        mock_client.exec_command.return_value = (None, mock_stdout, None)
        
        result = health_check.check_tailscale()
        
        assert result.status is True
        assert "el-012" in result.message
        mock_client.connect.assert_called_once()
        mock_client.close.assert_called_once()
    
    @patch('socket.socket')
    def test_check_radio_stats_success(self, mock_socket_class, health_check):
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        
        mock_socket.recvfrom.return_value = (
            b"rf:100 rssi:-65 snr:25 ip:10.0.0.100",
            ("192.168.1.100", 22222)
        )
        
        result = health_check.check_radio_stats()
        
        assert result.status is True
        assert "Receiving data" in result.message
        mock_socket.bind.assert_called_once_with(("0.0.0.0", 22222))
        mock_socket.close.assert_called_once()
    
    @patch('socket.socket')
    def test_check_radio_stats_timeout(self, mock_socket_class, health_check):
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.recvfrom.side_effect = socket.timeout()
        
        result = health_check.check_radio_stats()
        
        assert result.status is False
        assert "No data received" in result.message
    
    @patch.object(HealthCheck, 'check_connectivity')
    @patch.object(HealthCheck, 'check_tailscale')
    @patch.object(HealthCheck, 'check_radio_stats')
    @patch.object(HealthCheck, 'check_mavlink')
    @patch.object(HealthCheck, 'check_video_stream')
    @patch.object(HealthCheck, 'check_pth_sensors')
    @patch.object(HealthCheck, 'check_versions')
    def test_run_all_checks(self, mock_versions, mock_pth, mock_video,
                           mock_mavlink, mock_radio, mock_tailscale,
                           mock_connectivity, health_check):
        
        mock_result = HealthCheckResult(
            component="Test",
            status=True,
            message="Success"
        )
        
        mock_connectivity.return_value = {"jetson": mock_result, "radio": mock_result}
        mock_tailscale.return_value = mock_result
        mock_radio.return_value = mock_result
        mock_mavlink.return_value = mock_result
        mock_video.return_value = mock_result
        mock_pth.return_value = mock_result
        mock_versions.return_value = {"seraph": mock_result}
        
        results = health_check.run_all_checks()
        
        assert len(results) > 0
        assert all(isinstance(r, HealthCheckResult) for r in results)
    
    @patch('socket.socket')
    def test_check_video_stream_success(self, mock_socket_class, health_check):
        # Default is udp:5600; simulate receiving UDP bytes
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.recvfrom.return_value = (b"video_data", ("127.0.0.1", 5600))

        result = health_check.check_video_stream()

        assert result.status is True
        assert "UDP 5600" in result.message
        mock_socket.bind.assert_called_once_with(("0.0.0.0", 5600))
    
    @patch('paramiko.SSHClient')
    def test_check_pth_sensors_success(self, mock_ssh_client, health_check):
        mock_client = MagicMock()
        mock_ssh_client.return_value = mock_client
        
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = json.dumps({
            "pressure": 1013.25,
            "temperature": 22.5,
            "humidity": 45.0
        }).encode()
        
        mock_client.exec_command.return_value = (None, mock_stdout, None)
        
        result = health_check.check_pth_sensors()
        
        assert result.status is True
        assert "P:1013.2" in result.message
        assert "T:22.5" in result.message
        assert "H:45.0" in result.message
    
    @patch('paramiko.SSHClient')
    def test_check_versions(self, mock_ssh_client, health_check):
        mock_client = MagicMock()
        mock_ssh_client.return_value = mock_client
        
        mock_stdouts = [
            MagicMock(read=lambda: b"abc123def456"),
            MagicMock(read=lambda: b"fed654cba321"),
            MagicMock(read=lambda: b"v1.2.3")
        ]
        
        mock_client.exec_command.side_effect = [
            (None, mock_stdouts[0], None),
            (None, mock_stdouts[1], None),
            (None, mock_stdouts[2], None)
        ]
        
        results = health_check.check_versions()
        
        assert "seraph" in results
        assert "elijah" in results
        assert "fc" in results
        assert results["seraph"].status is True
        assert "abc123de" in results["seraph"].message
    
    @patch('builtins.open', create=True)
    @patch('elijahctl.config.Config.RUNS_DIR')
    def test_save_results(self, mock_runs_dir, mock_open, health_check):
        mock_runs_dir.__truediv__.return_value = "test_path.json"
        
        health_check.results = [
            HealthCheckResult("Test1", True, "Success"),
            HealthCheckResult("Test2", False, "Failed")
        ]
        
        filepath = health_check.save_results()
        
        assert filepath == "test_path.json"
        mock_open.assert_called_once()
