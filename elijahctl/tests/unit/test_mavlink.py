import pytest
from unittest.mock import Mock, patch, MagicMock
import time

from elijahctl.drivers.mavlink import MAVLinkDriver
from pymavlink import mavutil

class TestMAVLinkDriver:
    
    @pytest.fixture
    def driver(self):
        return MAVLinkDriver("test-host", 14550)
    
    @patch('pymavlink.mavutil.mavlink_connection')
    def test_connect_success(self, mock_mavlink_connection, driver):
        mock_connection = MagicMock()
        mock_mavlink_connection.return_value = mock_connection
        
        mock_heartbeat = MagicMock()
        mock_heartbeat.autopilot = 12
        mock_heartbeat.type = 1
        mock_connection.wait_heartbeat.return_value = mock_heartbeat
        mock_connection.target_system = 1
        mock_connection.target_component = 1
        
        result = driver.connect()
        
        assert result is True
        assert driver.connection == mock_connection
        assert driver.target_system == 1
        assert driver.target_component == 1
        # First attempt should be a listening UDP endpoint
        mock_mavlink_connection.assert_called_with('udp:0.0.0.0:14550')
    
    @patch('pymavlink.mavutil.mavlink_connection')
    def test_connect_no_heartbeat(self, mock_mavlink_connection, driver):
        mock_connection = MagicMock()
        mock_mavlink_connection.return_value = mock_connection
        mock_connection.wait_heartbeat.return_value = None
        
        result = driver.connect()
        
        assert result is False
        assert driver.connection == mock_connection
    
    def test_get_autopilot_name(self, driver):
        assert driver._get_autopilot_name(3) == "ArduPilot"
        assert driver._get_autopilot_name(12) == "PX4"
        assert driver._get_autopilot_name(99) == "Unknown (99)"
    
    @patch('pymavlink.mavutil.mavlink_connection')
    def test_set_parameter(self, mock_mavlink_connection, driver):
        mock_connection = MagicMock()
        driver.connection = mock_connection
        driver.target_system = 1
        driver.target_component = 1
        
        mock_msg = MagicMock()
        mock_msg.param_id = "MAV_SYS_ID\x00\x00\x00\x00\x00\x00"
        mock_msg.param_value = 12.0
        mock_connection.recv_match.return_value = mock_msg
        
        result = driver.set_parameter("MAV_SYS_ID", 12.0)
        
        assert result is True
        mock_connection.mav.param_set_send.assert_called_once()
    
    @patch('pymavlink.mavutil.mavlink_connection')
    def test_get_parameter(self, mock_mavlink_connection, driver):
        mock_connection = MagicMock()
        driver.connection = mock_connection
        driver.target_system = 1
        driver.target_component = 1
        
        mock_msg = MagicMock()
        mock_msg.param_id = "MAV_SYS_ID\x00\x00\x00\x00\x00\x00"
        mock_msg.param_value = 12.0
        mock_connection.recv_match.return_value = mock_msg
        
        result = driver.get_parameter("MAV_SYS_ID")
        
        assert result == 12.0
        mock_connection.mav.param_request_read_send.assert_called_once()
    
    @patch('pymavlink.mavutil.mavlink_connection')
    def test_reboot_flight_controller(self, mock_mavlink_connection, driver):
        mock_connection = MagicMock()
        driver.connection = mock_connection
        driver.target_system = 1
        driver.target_component = 1
        
        mock_msg = MagicMock()
        mock_msg.command = mavutil.mavlink.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN
        mock_msg.result = mavutil.mavlink.MAV_RESULT_ACCEPTED
        mock_connection.recv_match.return_value = mock_msg
        
        result = driver.reboot_flight_controller()
        
        assert result is True
        mock_connection.mav.command_long_send.assert_called_once()
    
    @patch.object(MAVLinkDriver, 'connect')
    @patch('time.sleep')
    def test_wait_for_heartbeat_after_reboot(self, mock_sleep, mock_connect, driver):
        mock_connect.side_effect = [False, False, True]
        
        result = driver.wait_for_heartbeat_after_reboot(timeout=10)
        
        assert result is True
        assert mock_connect.call_count == 3
    
    @patch.object(MAVLinkDriver, 'connect')
    @patch.object(MAVLinkDriver, 'set_parameter')
    @patch.object(MAVLinkDriver, 'reboot_flight_controller')
    @patch.object(MAVLinkDriver, 'wait_for_heartbeat_after_reboot')
    @patch.object(MAVLinkDriver, 'get_parameter')
    def test_set_sysid(self, mock_get_param, mock_wait, mock_reboot, 
                       mock_set_param, mock_connect, driver):
        mock_connect.return_value = True
        mock_set_param.return_value = True
        mock_reboot.return_value = True
        mock_wait.return_value = True
        mock_get_param.return_value = 12.0
        
        result = driver.set_sysid(12)
        
        assert result is True
        mock_set_param.assert_called_once_with(
            "MAV_SYS_ID", 12.0, mavutil.mavlink.MAV_PARAM_TYPE_INT32
        )
        mock_reboot.assert_called_once()
        mock_wait.assert_called_once()
    
    @patch('pymavlink.mavutil.mavlink_connection')
    def test_monitor_heartbeats(self, mock_mavlink_connection, driver):
        mock_connection = MagicMock()
        driver.connection = mock_connection
        
        mock_msgs = [MagicMock() for _ in range(5)]
        mock_connection.recv_match.side_effect = mock_msgs + [None]
        
        with patch('time.time') as mock_time:
            mock_time.side_effect = [0, 1, 2, 3, 4, 5, 6]
            ok, count = driver.monitor_heartbeats(duration=5)
        
        assert ok is True
        assert count == 5
    
    def test_close(self, driver):
        mock_connection = MagicMock()
        driver.connection = mock_connection
        
        driver.close()
        
        mock_connection.close.assert_called_once()
        assert driver.connection is None
