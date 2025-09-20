#!/usr/bin/env python3
"""
Comprehensive test suite for uhubctl Home Assistant add-on.

This test suite validates:
1. Syntax and imports
2. Core class functionality
3. uhubctl output parsing
4. MQTT message generation
5. Diagnostic methods
6. Error handling
7. Mock integration testing
"""

import json
import os
import sys
import unittest
from unittest.mock import Mock, patch, mock_open, MagicMock
from io import StringIO
import logging
import datetime
import subprocess

# Add the current directory to the path to import main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Check if paho-mqtt is available
PAHO_MQTT_AVAILABLE = True
try:
    import paho.mqtt.client as mqtt_client
except ImportError:
    PAHO_MQTT_AVAILABLE = False
    print("⚠ paho-mqtt not available - mocking MQTT functionality")

# Mock paho.mqtt if not available
if not PAHO_MQTT_AVAILABLE:
    class MockMQTTClient:
        def __init__(self):
            self.on_connect = None
            self.message_callback_add = Mock()
            self.username_pw_set = Mock()
            self.will_set = Mock()
            self.connect = Mock()
            self.subscribe = Mock(return_value=(0, 1))
            self.publish = Mock()
            self.loop_forever = Mock()

    class MockMQTTModule:
        MQTT_ERR_SUCCESS = 0
        Client = MockMQTTClient

    class MockPaho:
        class mqtt:
            client = MockMQTTModule()

    # Set up the module hierarchy
    sys.modules['paho'] = MockPaho()
    sys.modules['paho.mqtt'] = MockPaho.mqtt()
    sys.modules['paho.mqtt.client'] = MockMQTTModule()

try:
    import main
    from main import USBHUB, USBPORT, UHUBCTL, run_in_shell

    # Try to import USBHUB_MQTT - it may fail if paho isn't available
    try:
        from main import USBHUB_MQTT
        MQTT_CLASS_AVAILABLE = True
    except (ImportError, NameError):
        MQTT_CLASS_AVAILABLE = False
        print("⚠ USBHUB_MQTT class not available - will skip MQTT tests")

    print("✓ Successfully imported main.py and core classes")
except ImportError as e:
    print(f"✗ Failed to import main.py: {e}")
    sys.exit(1)


class TestImportsAndSyntax(unittest.TestCase):
    """Test that all required modules can be imported."""

    def test_all_imports_successful(self):
        """Test that all imports in main.py work correctly."""
        # These should all be available if main.py imported successfully
        required_modules = [
            'argparse', 'datetime', 'glob', 'json', 'logging',
            'os', 'os.path', 're', 'stat', 'subprocess'
        ]

        for module_name in required_modules:
            with self.subTest(module=module_name):
                self.assertTrue(hasattr(sys.modules['main'], module_name) or
                              module_name in sys.modules)

    def test_paho_mqtt_import(self):
        """Test that paho.mqtt can be imported."""
        if PAHO_MQTT_AVAILABLE:
            import paho.mqtt.client as mqtt
            self.assertTrue(hasattr(mqtt, 'Client'))
        else:
            self.skipTest("paho-mqtt library is not available")


class TestUSBHubClass(unittest.TestCase):
    """Test USBHUB data class functionality."""

    def setUp(self):
        """Set up test data."""
        self.hub = USBHUB(
            location="1-1",
            vid=0x2109,
            pid=0x3431,
            usbversion=2,
            nports=4,
            ports=[]
        )

    def test_hub_creation(self):
        """Test basic hub creation and properties."""
        self.assertEqual(self.hub.location, "1-1")
        self.assertEqual(self.hub.vid, 0x2109)
        self.assertEqual(self.hub.pid, 0x3431)
        self.assertEqual(self.hub.usbversion, 2)
        self.assertEqual(self.hub.nports, 4)

    def test_add_port(self):
        """Test adding ports to hub."""
        self.hub.add_port(1, True)
        self.hub.add_port(2, False)

        self.assertEqual(len(self.hub._ports), 2)
        self.assertEqual(self.hub._ports[0].number, 1)
        self.assertTrue(self.hub._ports[0].enabled)
        self.assertEqual(self.hub._ports[1].number, 2)
        self.assertFalse(self.hub._ports[1].enabled)


class TestUSBPortClass(unittest.TestCase):
    """Test USBPORT data class functionality."""

    def setUp(self):
        """Set up test data."""
        self.port = USBPORT("1-1", 1, True)

    def test_port_creation(self):
        """Test basic port creation and properties."""
        self.assertEqual(self.port.hub_location, "1-1")
        self.assertEqual(self.port.number, 1)
        self.assertTrue(self.port.enabled)

    def test_port_control(self):
        """Test port on/off control."""
        self.port.off()
        self.assertFalse(self.port.enabled)

        self.port.on()
        self.assertTrue(self.port.enabled)


class TestUHUBCTLParser(unittest.TestCase):
    """Test UHUBCTL parser functionality with realistic uhubctl output."""

    def setUp(self):
        """Set up test UHUBCTL instance."""
        self.uhubctl = UHUBCTL()

    def get_sample_uhubctl_output(self):
        """Return sample uhubctl command output."""
        return """Current status for hub 1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 1: 0503 power highspeed enable connect [0bda:8153 Realtek USB 10/100/1000 LAN 000001000000]
  Port 2: 0100 power
  Port 3: 0100 power
  Port 4: 0100 power
Current status for hub 1-1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 1: 0103 power enable connect [046d:c52b Logitech, Inc. Unifying Receiver]
  Port 2: 0100 power
  Port 3: 0100 power
  Port 4: 0100 power
Current status for hub 2 [1d6b:0003 Linux Foundation 3.0 root hub, USB 3.00, 4 ports, ppps]
  Port 1: 02a0 power Rx.Detect
  Port 2: 02a0 power Rx.Detect
  Port 3: 02a0 power Rx.Detect
  Port 4: 02a0 power Rx.Detect """

    def get_sample_usb3_output(self):
        """Return sample USB 3.0 hub output."""
        return """Current status for hub 2 [1d6b:0003 Linux Foundation 3.0 root hub, USB 3.00, 4 ports, ppps]
  Port 1: 02e1 power Rx.Detect SuperSpeed enable connect [0781:5590 SanDisk Corp. Ultra USB 3.0]
  Port 2: 02a0 power Rx.Detect
  Port 3: 02a0 power Rx.Detect
  Port 4: 02a0 power Rx.Detect """

    def test_parse_basic_hub_info(self):
        """Test parsing basic hub information."""
        output = self.get_sample_uhubctl_output()
        hubs = self.uhubctl._parser(output)

        self.assertIsInstance(hubs, list)
        self.assertEqual(len(hubs), 3)  # Should find 3 hubs

        # Test first hub
        hub1 = hubs[0]
        self.assertEqual(hub1.location, "1")
        self.assertEqual(hub1.vid, 0x2109)
        self.assertEqual(hub1.pid, 0x3431)
        self.assertEqual(hub1.usbversion, 2)
        self.assertEqual(hub1.nports, 4)

    def test_parse_hub_locations(self):
        """Test parsing different hub location formats."""
        output = self.get_sample_uhubctl_output()
        hubs = self.uhubctl._parser(output)

        locations = [hub.location for hub in hubs]
        self.assertIn("1", locations)
        self.assertIn("1-1", locations)
        self.assertIn("2", locations)

    def test_parse_usb2_port_status(self):
        """Test parsing USB 2.0 port power status."""
        output = self.get_sample_uhubctl_output()
        hubs = self.uhubctl._parser(output)

        # Find hub 1-1
        hub1_1 = next((h for h in hubs if h.location == "1-1"), None)
        self.assertIsNotNone(hub1_1)

        # Check port statuses (0x0100 = power bit set for USB 2.0)
        ports = hub1_1._ports
        self.assertEqual(len(ports), 4)

        # Port 1 should be ON (0x0103 has power bit 0x0100)
        port1 = next((p for p in ports if p.number == 1), None)
        self.assertIsNotNone(port1)
        self.assertTrue(port1.enabled)

        # Ports 2-4 should be ON (0x0100 has power bit set)
        for port_num in [2, 3, 4]:
            port = next((p for p in ports if p.number == port_num), None)
            self.assertIsNotNone(port)
            self.assertTrue(port.enabled)

    def test_parse_usb3_port_status(self):
        """Test parsing USB 3.0 port power status."""
        output = self.get_sample_usb3_output()
        hubs = self.uhubctl._parser(output)

        self.assertEqual(len(hubs), 1)
        hub = hubs[0]
        self.assertEqual(hub.usbversion, 3)

        # Check port statuses (0x0200 = power bit for USB 3.0)
        ports = hub._ports
        self.assertEqual(len(ports), 4)

        # Port 1 should be ON (0x02e1 has power bit 0x0200)
        port1 = next((p for p in ports if p.number == 1), None)
        self.assertIsNotNone(port1)
        self.assertTrue(port1.enabled)

        # Ports 2-4 should be ON (0x02a0 has power bit 0x0200)
        for port_num in [2, 3, 4]:
            port = next((p for p in ports if p.number == port_num), None)
            self.assertIsNotNone(port)
            self.assertTrue(port.enabled)

    def test_parse_invalid_output(self):
        """Test parser with invalid/empty output."""
        # Empty output
        result = self.uhubctl._parser("")
        self.assertFalse(result)

        # No hub headers
        result = self.uhubctl._parser("Some random text\nNo hubs here")
        self.assertFalse(result)

    def test_parse_action_output(self):
        """Test parser with action=True (single port response)."""
        action_output = """Current status for hub 1-1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 2: 0000 power
Sent power off request
New status for hub 1-1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 2: 0000"""

        hubs = self.uhubctl._parser(action_output, action=True)
        self.assertIsInstance(hubs, list)
        self.assertEqual(len(hubs), 2)  # Current and new status

        # Should only parse one port per hub in action mode
        for hub in hubs:
            self.assertEqual(len(hub._ports), 1)
            self.assertEqual(hub._ports[0].number, 2)


class TestRunInShell(unittest.TestCase):
    """Test the run_in_shell utility function."""

    @patch('subprocess.run')
    def test_successful_command(self, mock_run):
        """Test successful command execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "test output"
        mock_run.return_value = mock_result

        result = run_in_shell("echo test")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "test output")
        mock_run.assert_called_once_with(
            "echo test", shell=True, timeout=10, stdout=subprocess.PIPE, text=True
        )

    @patch('subprocess.run')
    def test_command_with_timeout(self, mock_run):
        """Test command execution with custom timeout."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        run_in_shell("sleep 1", timeout=5)

        mock_run.assert_called_once_with(
            "sleep 1", shell=True, timeout=5, stdout=subprocess.PIPE, text=True
        )

    @patch('subprocess.run')
    def test_command_exception(self, mock_run):
        """Test command execution with exception."""
        mock_run.side_effect = subprocess.TimeoutExpired("test", 10)

        with self.assertRaises(subprocess.TimeoutExpired):
            run_in_shell("sleep 100", timeout=1)


class TestUHUBCTLDiagnostics(unittest.TestCase):
    """Test UHUBCTL diagnostic methods."""

    def setUp(self):
        """Set up test UHUBCTL instance."""
        self.uhubctl = UHUBCTL()

    @patch('main.run_in_shell')
    @patch('main.glob.glob')
    @patch('main.os.path.exists')
    @patch('main.os.access')
    @patch('main.os.getuid')
    @patch('main.os.getgid')
    @patch('main.pwd.getpwuid')
    @patch('main.grp.getgrgid')
    @patch('main.os.getgroups')
    def test_diagnose_permissions(self, mock_getgroups, mock_getgrgid, mock_getpwuid,
                                  mock_getgid, mock_getuid, mock_access, mock_exists,
                                  mock_glob, mock_run):
        """Test the diagnose_permissions method."""
        # Mock run_in_shell responses
        mock_run.side_effect = [
            Mock(returncode=0, stdout="/usr/bin/uhubctl\n"),  # which uhubctl
            Mock(returncode=0, stdout="uhubctl 2.4.0\n"),     # uhubctl --version
            Mock(returncode=0, stdout="Current status for hub 1 [2109:3431]\n  Port 1: 0100"),  # uhubctl basic
            Mock(returncode=0, stdout="verbose output")        # uhubctl -v
        ]

        # Mock file system
        mock_exists.side_effect = lambda path: path in ["/dev/bus/usb", "/sys/bus/usb/devices"]
        mock_glob.side_effect = lambda pattern: {
            "/dev/bus/usb/*/": ["/dev/bus/usb/001/", "/dev/bus/usb/002/"],
            "/dev/bus/usb/001/*": ["/dev/bus/usb/001/001", "/dev/bus/usb/001/002"],
            "/dev/bus/usb/002/*": ["/dev/bus/usb/002/001"],
            "/sys/bus/usb/devices/*": ["/sys/bus/usb/devices/1-1", "/sys/bus/usb/devices/2-1"],
            "/sys/bus/usb/devices/1-1/usb*-port*/disable": ["/sys/bus/usb/devices/1-1/usb1-port1/disable"],
            "/sys/bus/usb/devices/2-1/usb*-port*/disable": [],
            "/usr/lib/libusb*": ["/usr/lib/libusb-1.0.so"],
            "/usr/local/lib/libusb*": [],
            "/lib/libusb*": []
        }.get(pattern, [])

        mock_access.return_value = True

        # Mock user info
        mock_getuid.return_value = 1000
        mock_getgid.return_value = 1000
        mock_user = Mock()
        mock_user.pw_name = "testuser"
        mock_getpwuid.return_value = mock_user
        mock_group = Mock()
        mock_group.gr_name = "testgroup"
        mock_getgrgid.return_value = mock_group
        mock_getgroups.return_value = [1000, 20, 44]

        # Capture log output
        with self.assertLogs('main', level='INFO') as log:
            self.uhubctl.diagnose_permissions()

        # Verify key log messages are present
        log_output = '\n'.join(log.output)
        self.assertIn("USB Diagnostics Starting", log_output)
        self.assertIn("uhubctl binary found at", log_output)
        self.assertIn("uhubctl version: uhubctl 2.4.0", log_output)
        self.assertIn("Found 1 smart hubs", log_output)
        self.assertIn("USB Diagnostics Complete", log_output)

    @patch('main.run_in_shell')
    def test_diagnose_hub_access(self, mock_run):
        """Test the diagnose_hub_access method."""
        # Mock successful hub detection
        hub_output = """Current status for hub 1-1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 1: 0103 power enable connect
  Port 2: 0100 power
  Port 3: 0100 power
  Port 4: 0100 power"""

        mock_run.side_effect = [
            Mock(returncode=0, stdout=hub_output),  # uhubctl -l 1-1
            Mock(returncode=0, stdout="dry run success"),  # dry run test
        ]

        with self.assertLogs('main', level='INFO') as log:
            self.uhubctl.diagnose_hub_access("1-1")

        log_output = '\n'.join(log.output)
        self.assertIn("Hub Access Diagnostics for 1-1", log_output)
        self.assertIn("Hub 1-1 detected successfully", log_output)
        self.assertIn("Successfully parsed hub 1-1", log_output)

    @patch('main.run_in_shell')
    def test_diagnose_hub_access_failure(self, mock_run):
        """Test diagnose_hub_access with hub detection failure."""
        mock_run.return_value = Mock(returncode=1, stdout="No hubs found")

        with self.assertLogs('main', level='INFO') as log:
            self.uhubctl.diagnose_hub_access("nonexistent")

        log_output = '\n'.join(log.output)
        self.assertIn("Failed to detect hub nonexistent", log_output)


class TestUHUBCTLActions(unittest.TestCase):
    """Test UHUBCTL action execution."""

    def setUp(self):
        """Set up test UHUBCTL instance and port."""
        self.uhubctl = UHUBCTL()
        self.port = USBPORT("1-1", 2, True)

    @patch('main.run_in_shell')
    def test_successful_action(self, mock_run):
        """Test successful port action."""
        action_output = """Current status for hub 1-1 [2109:3431]
  Port 2: 0100 power
Sent power off request
New status for hub 1-1 [2109:3431]
  Port 2: 0000"""

        mock_run.return_value = Mock(returncode=0, stdout=action_output)

        result = self.uhubctl.do_action(self.port, "off")
        self.assertTrue(result)
        self.assertFalse(self.port.enabled)

    def test_invalid_action(self):
        """Test invalid action parameter."""
        result = self.uhubctl.do_action(self.port, "invalid")
        self.assertFalse(result)

    @patch('main.run_in_shell')
    @patch.object(UHUBCTL, 'diagnose_hub_access')
    def test_action_failure_runs_diagnostics(self, mock_diagnose, mock_run):
        """Test that failed actions trigger diagnostics."""
        mock_run.side_effect = Exception("Command failed")

        result = self.uhubctl.do_action(self.port, "on")
        self.assertFalse(result)
        mock_diagnose.assert_called_once_with("1-1")


class TestMQTTFunctionality(unittest.TestCase):
    """Test MQTT-related functionality."""

    def setUp(self):
        """Set up test data."""
        if not MQTT_CLASS_AVAILABLE:
            self.skipTest("MQTT functionality not available")

        self.config = {
            "STATUS_TOPIC": "tele/uhubctl/localhost",
            "COMMAND_TOPIC": "cmnd/uhubctl/localhost",
            "AVAILABILITY_TOPIC": "tele/uhubctl/localhost/LWT"
        }

        # Mock config file
        self.mock_config_file = mock_open(read_data=json.dumps(self.config))

        # Create test hub with ports
        self.hub = USBHUB("1-1", 0x2109, 0x3431, 2, 4, [])
        self.hub.add_port(1, True)
        self.hub.add_port(2, False)
        self.hub.add_port(3, True)
        self.hub.add_port(4, False)

    def test_make_json_portstatus(self):
        """Test JSON status generation."""
        if not MQTT_CLASS_AVAILABLE:
            self.skipTest("MQTT functionality not available")

        with patch('builtins.open', self.mock_config_file):
            mqtt_handler = USBHUB_MQTT(self.mock_config_file)

        json_status = mqtt_handler.make_json_portstatus(self.hub)
        status_data = json.loads(json_status)

        # Verify structure
        self.assertIn("Time", status_data)
        self.assertEqual(status_data["Location"], "1-1")
        self.assertEqual(status_data["Vid"], 0x2109)
        self.assertEqual(status_data["Pid"], 0x3431)
        self.assertEqual(status_data["USBVersion"], 2)

        # Verify port statuses
        self.assertEqual(status_data["POWER1"], "ON")
        self.assertEqual(status_data["POWER2"], "OFF")
        self.assertEqual(status_data["POWER3"], "ON")
        self.assertEqual(status_data["POWER4"], "OFF")

        # Verify time format
        time_str = status_data["Time"]
        datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")  # Should not raise

    @patch('main.UHUBCTL')
    def test_mqtt_connect_callback(self, mock_uhubctl_class):
        """Test MQTT connect callback."""
        if not MQTT_CLASS_AVAILABLE:
            self.skipTest("MQTT functionality not available")

        # Mock UHUBCTL instance
        mock_uhubctl = Mock()
        mock_uhubctl.fetch_allinfo.return_value = [self.hub]
        mock_uhubctl_class.return_value = mock_uhubctl

        # Mock MQTT client
        mock_client = Mock()
        mock_client.subscribe.return_value = (0, 1)  # (result, mid)

        with patch('builtins.open', self.mock_config_file):
            mqtt_handler = USBHUB_MQTT(self.mock_config_file)

        # Test successful connection
        mqtt_handler.on_mqtt_connect(mock_client, None, None, 0)

        # Verify subscription
        mock_client.subscribe.assert_called_once_with("cmnd/uhubctl/localhost/#", 1)

        # Verify diagnostics ran
        mock_uhubctl.diagnose_permissions.assert_called_once()

        # Verify hub status published
        self.assertTrue(mock_client.publish.called)

    def test_mqtt_connect_failure(self):
        """Test MQTT connect failure."""
        if not MQTT_CLASS_AVAILABLE:
            self.skipTest("MQTT functionality not available")

        with patch('builtins.open', self.mock_config_file):
            mqtt_handler = USBHUB_MQTT(self.mock_config_file)

        with self.assertRaises(main.USBHUB_MQTT_Error):
            mqtt_handler.on_mqtt_connect(None, None, None, 1)  # Non-zero return code

    @patch('main.UHUBCTL')
    def test_mqtt_message_parsing(self, mock_uhubctl_class):
        """Test MQTT control message parsing."""
        if not MQTT_CLASS_AVAILABLE:
            self.skipTest("MQTT functionality not available")

        # Set up mock UHUBCTL
        mock_uhubctl = Mock()
        mock_uhubctl_class.return_value = mock_uhubctl

        with patch('builtins.open', self.mock_config_file):
            mqtt_handler = USBHUB_MQTT(self.mock_config_file)
            mqtt_handler._usbhubs = [self.hub]

        # Mock MQTT message
        mock_message = Mock()
        mock_message.topic = "cmnd/uhubctl/localhost/HUB1-1/POWER2"
        mock_message.payload.decode.return_value = "ON"

        # Mock client
        mock_client = Mock()

        # Test message handling
        mqtt_handler.on_mqtt_ctrl_message(mock_client, None, mock_message)

        # Verify action was attempted
        mock_uhubctl.do_action.assert_called_once()

        # Verify status was published
        mock_client.publish.assert_called()


class TestErrorHandling(unittest.TestCase):
    """Test error handling throughout the application."""

    def setUp(self):
        self.uhubctl = UHUBCTL()

    @patch('main.run_in_shell')
    @patch.object(UHUBCTL, 'diagnose_permissions')
    def test_fetch_allinfo_with_exception(self, mock_diagnose, mock_run):
        """Test fetch_allinfo handles exceptions and runs diagnostics."""
        mock_run.side_effect = Exception("Command failed")

        result = self.uhubctl.fetch_allinfo()
        self.assertIsNone(result)
        mock_diagnose.assert_called_once()

    def test_invalid_mqtt_config(self):
        """Test handling of invalid MQTT configuration."""
        if not MQTT_CLASS_AVAILABLE:
            self.skipTest("MQTT functionality not available")

        invalid_config = mock_open(read_data='{"invalid": "config"}')

        with patch('builtins.open', invalid_config):
            with self.assertRaises(KeyError):
                mqtt_handler = USBHUB_MQTT(invalid_config)
                # This should raise KeyError when accessing required config keys
                mqtt_handler._cfg["STATUS_TOPIC"]


class TestIntegrationScenarios(unittest.TestCase):
    """Test integration scenarios with mocked dependencies."""

    @patch.dict(os.environ, {
        'MQTT_HOST': 'localhost',
        'MQTT_PORT': '1883',
        'MQTT_USERNAME': 'test',
        'MQTT_PASSWORD': 'test'
    })
    @patch('main.mqtt.Client')
    @patch('main.run_in_shell')
    def test_full_mqtt_workflow(self, mock_run, mock_mqtt_client):
        """Test a complete MQTT workflow from start to message handling."""
        if not MQTT_CLASS_AVAILABLE:
            self.skipTest("MQTT functionality not available")

        # Mock uhubctl output
        uhubctl_output = """Current status for hub 1-1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 1: 0103 power enable connect
  Port 2: 0100 power
  Port 3: 0100 power
  Port 4: 0100 power"""

        mock_run.return_value = Mock(returncode=0, stdout=uhubctl_output)

        # Mock MQTT client
        mock_client_instance = Mock()
        mock_client_instance.subscribe.return_value = (0, 1)
        mock_mqtt_client.return_value = mock_client_instance

        config = {
            "STATUS_TOPIC": "tele/uhubctl/localhost",
            "COMMAND_TOPIC": "cmnd/uhubctl/localhost",
            "AVAILABILITY_TOPIC": "tele/uhubctl/localhost/LWT"
        }

        mock_config_file = mock_open(read_data=json.dumps(config))

        with patch('builtins.open', mock_config_file):
            mqtt_handler = USBHUB_MQTT(mock_config_file)

        # Test the connection workflow
        mqtt_handler.on_mqtt_connect(mock_client_instance, None, None, 0)

        # Verify client was configured properly
        mock_client_instance.subscribe.assert_called()
        mock_client_instance.publish.assert_called()  # Should publish status and availability


def run_comprehensive_tests():
    """Run all tests and provide a comprehensive report."""
    print("=" * 80)
    print("COMPREHENSIVE UHUBCTL ADD-ON TEST SUITE")
    print("=" * 80)
    print()

    # Test 1: Basic syntax and import validation
    print("1. SYNTAX AND IMPORTS TEST")
    print("-" * 40)

    try:
        # Try to compile the main module
        import py_compile
        py_compile.compile('/Users/spooner/repos/hassio-uhubctl/uhubctl/main.py', doraise=True)
        print("✓ main.py compiles without syntax errors")
    except py_compile.PyCompileError as e:
        print(f"✗ Syntax error in main.py: {e}")
        return False

    # Test 2: Import all required modules
    try:
        import main
        print("✓ Successfully imported main module")

        required_classes = ['USBHUB', 'USBPORT', 'UHUBCTL', 'USBHUB_MQTT']
        for class_name in required_classes:
            if hasattr(main, class_name):
                print(f"✓ {class_name} class available")
            else:
                print(f"✗ {class_name} class missing")

    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

    print()

    # Test 3: Run unit tests
    print("2. UNIT TESTS")
    print("-" * 40)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    test_classes = [
        TestImportsAndSyntax,
        TestUSBHubClass,
        TestUSBPortClass,
        TestUHUBCTLParser,
        TestRunInShell,
        TestUHUBCTLDiagnostics,
        TestUHUBCTLActions,
        TestMQTTFunctionality,
        TestErrorHandling,
        TestIntegrationScenarios
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)

    print()
    print("3. TEST SUMMARY")
    print("-" * 40)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")

    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.splitlines()[-1]}")

    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.splitlines()[-1]}")

    success = len(result.failures) == 0 and len(result.errors) == 0

    print()
    print("4. CODE QUALITY CHECKS")
    print("-" * 40)

    # Check for potential issues
    with open('/Users/spooner/repos/hassio-uhubctl/uhubctl/main.py', 'r') as f:
        code_content = f.read()

    # Basic code quality checks
    issues = []

    if 'TODO' in code_content or 'FIXME' in code_content:
        issues.append("Contains TODO/FIXME comments")

    if code_content.count('except:') > 0:
        bare_excepts = code_content.count('except:')
        issues.append(f"Contains {bare_excepts} bare 'except:' statements (should be more specific)")

    if 'print(' in code_content and 'logger' in code_content:
        issues.append("Mix of print() and logger usage (should use consistent logging)")

    if len(issues) == 0:
        print("✓ No obvious code quality issues found")
    else:
        print("⚠ Code quality issues:")
        for issue in issues:
            print(f"  - {issue}")

    print()
    print("5. DEPENDENCY VERIFICATION")
    print("-" * 40)

    if PAHO_MQTT_AVAILABLE:
        print("✓ paho-mqtt library available")
    else:
        print("⚠ paho-mqtt library not available (tests ran with mocks)")
        # Don't fail the tests since we successfully mocked it

    # Check if uhubctl binary would be available (can't test without it)
    print("ℹ uhubctl binary availability cannot be tested in this environment")

    if MQTT_CLASS_AVAILABLE:
        print("✓ MQTT functionality was testable")
    else:
        print("⚠ MQTT functionality was skipped due to missing dependencies")

    print()
    print("=" * 80)
    if success:
        print("🎉 ALL TESTS PASSED! The code appears to be working correctly.")
    else:
        print("❌ SOME TESTS FAILED. Please review the issues above.")
    print("=" * 80)

    return success


if __name__ == '__main__':
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)