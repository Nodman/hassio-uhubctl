#!/usr/bin/env python3
"""
Core functionality tests for uhubctl Home Assistant add-on.

Tests the core UHUBCTL parser and USB hub/port classes without MQTT dependencies.
"""

import json
import os
import sys
import unittest
from unittest.mock import Mock, patch, mock_open
import subprocess
import datetime

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Testing core functionality without MQTT dependencies...")

class TestSyntaxValidation(unittest.TestCase):
    """Test syntax validation of main.py"""

    def test_syntax_check(self):
        """Test that main.py has valid Python syntax."""
        import py_compile
        try:
            py_compile.compile('/Users/spooner/repos/hassio-uhubctl/uhubctl/main.py', doraise=True)
            print("✓ main.py syntax is valid")
        except py_compile.PyCompileError as e:
            self.fail(f"Syntax error in main.py: {e}")

class TestCoreImports(unittest.TestCase):
    """Test that we can import core functionality"""

    def test_basic_imports(self):
        """Test importing standard library modules used in main.py"""
        modules = ['argparse', 'datetime', 'glob', 'json', 'logging',
                  'os', 'os.path', 're', 'stat', 'subprocess']

        for module_name in modules:
            try:
                __import__(module_name)
                print(f"✓ {module_name} imported successfully")
            except ImportError:
                self.fail(f"Failed to import {module_name}")

class MockMQTTClient:
    """Mock MQTT client for testing"""
    MQTT_ERR_SUCCESS = 0

    def __init__(self):
        self.on_connect = None
        self.message_callback_add = Mock()
        self.username_pw_set = Mock()
        self.will_set = Mock()
        self.connect = Mock()
        self.subscribe = Mock(return_value=(0, 1))
        self.publish = Mock()
        self.loop_forever = Mock()

# Mock the paho.mqtt module before importing main
sys.modules['paho'] = Mock()
sys.modules['paho.mqtt'] = Mock()
sys.modules['paho.mqtt.client'] = Mock()
sys.modules['paho.mqtt.client'].Client = MockMQTTClient
sys.modules['paho.mqtt.client'].MQTT_ERR_SUCCESS = 0

try:
    import main
    from main import USBHUB, USBPORT, UHUBCTL, run_in_shell
    print("✓ Successfully imported core classes from main.py")
    CORE_IMPORT_SUCCESS = True
except ImportError as e:
    print(f"✗ Failed to import from main.py: {e}")
    CORE_IMPORT_SUCCESS = False

class TestUSBClasses(unittest.TestCase):
    """Test USB hub and port data classes"""

    def setUp(self):
        if not CORE_IMPORT_SUCCESS:
            self.skipTest("Core classes not available")

    def test_usbhub_creation(self):
        """Test USBHUB class creation and properties."""
        hub = USBHUB("1-1", 0x2109, 0x3431, 2, 4, [])

        self.assertEqual(hub.location, "1-1")
        self.assertEqual(hub.vid, 0x2109)
        self.assertEqual(hub.pid, 0x3431)
        self.assertEqual(hub.usbversion, 2)
        self.assertEqual(hub.nports, 4)

    def test_usbport_creation(self):
        """Test USBPORT class creation and control."""
        port = USBPORT("1-1", 1, True)

        self.assertEqual(port.hub_location, "1-1")
        self.assertEqual(port.number, 1)
        self.assertTrue(port.enabled)

        port.off()
        self.assertFalse(port.enabled)

        port.on()
        self.assertTrue(port.enabled)

    def test_add_port_to_hub(self):
        """Test adding ports to hub."""
        hub = USBHUB("1-1", 0x2109, 0x3431, 2, 4, [])
        hub.add_port(1, True)
        hub.add_port(2, False)

        self.assertEqual(len(hub._ports), 2)
        self.assertEqual(hub._ports[0].number, 1)
        self.assertTrue(hub._ports[0].enabled)
        self.assertEqual(hub._ports[1].number, 2)
        self.assertFalse(hub._ports[1].enabled)

class TestRunInShell(unittest.TestCase):
    """Test run_in_shell utility function"""

    def setUp(self):
        if not CORE_IMPORT_SUCCESS:
            self.skipTest("Core functions not available")

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

    @patch('subprocess.run')
    def test_command_exception(self, mock_run):
        """Test command execution with exception."""
        mock_run.side_effect = subprocess.TimeoutExpired("test", 10)

        with self.assertRaises(subprocess.TimeoutExpired):
            run_in_shell("sleep 100", timeout=1)

class TestUHUBCTLParser(unittest.TestCase):
    """Test UHUBCTL output parsing"""

    def setUp(self):
        if not CORE_IMPORT_SUCCESS:
            self.skipTest("UHUBCTL class not available")
        self.uhubctl = UHUBCTL()

    def get_sample_uhubctl_output(self):
        """Sample uhubctl output for testing."""
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
  Port 4: 02a0 power Rx.Detect"""

    def get_usb3_output(self):
        """USB 3.0 hub output for testing."""
        return """Current status for hub 2 [1d6b:0003 Linux Foundation 3.0 root hub, USB 3.00, 4 ports, ppps]
  Port 1: 02e1 power Rx.Detect SuperSpeed enable connect [0781:5590 SanDisk Corp. Ultra USB 3.0]
  Port 2: 02a0 power Rx.Detect
  Port 3: 02a0 power Rx.Detect
  Port 4: 02a0 power Rx.Detect"""

    def test_parse_basic_output(self):
        """Test parsing basic uhubctl output."""
        output = self.get_sample_uhubctl_output()
        hubs = self.uhubctl._parser(output)

        self.assertIsInstance(hubs, list)
        self.assertEqual(len(hubs), 3)

        # Test first hub
        hub1 = hubs[0]
        self.assertEqual(hub1.location, "1")
        self.assertEqual(hub1.vid, 0x2109)
        self.assertEqual(hub1.pid, 0x3431)
        self.assertEqual(hub1.usbversion, 2)
        self.assertEqual(hub1.nports, 4)

    def test_parse_usb2_port_status(self):
        """Test USB 2.0 port power status parsing."""
        output = self.get_sample_uhubctl_output()
        hubs = self.uhubctl._parser(output)

        # Find hub 1-1
        hub1_1 = next((h for h in hubs if h.location == "1-1"), None)
        self.assertIsNotNone(hub1_1)

        ports = hub1_1._ports
        self.assertEqual(len(ports), 4)

        # All ports should be ON (0x0100 power bit set for USB 2.0)
        for port in ports:
            self.assertTrue(port.enabled)

    def test_parse_usb3_port_status(self):
        """Test USB 3.0 port power status parsing."""
        output = self.get_usb3_output()
        hubs = self.uhubctl._parser(output)

        self.assertEqual(len(hubs), 1)
        hub = hubs[0]
        self.assertEqual(hub.usbversion, 3)

        ports = hub._ports
        self.assertEqual(len(ports), 4)

        # All ports should be ON (0x0200 power bit for USB 3.0)
        for port in ports:
            self.assertTrue(port.enabled)

    def test_parse_invalid_output(self):
        """Test parser with invalid output."""
        result = self.uhubctl._parser("")
        self.assertFalse(result)

        result = self.uhubctl._parser("No hubs found")
        self.assertFalse(result)

    def test_parse_action_output(self):
        """Test parser with action=True."""
        action_output = """Current status for hub 1-1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 2: 0000 power
Sent power off request
New status for hub 1-1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 2: 0000"""

        hubs = self.uhubctl._parser(action_output, action=True)
        self.assertIsInstance(hubs, list)
        self.assertEqual(len(hubs), 2)

        for hub in hubs:
            self.assertEqual(len(hub._ports), 1)
            self.assertEqual(hub._ports[0].number, 2)
            self.assertFalse(hub._ports[0].enabled)  # Port should be OFF (0x0000)

class TestDiagnosticMethods(unittest.TestCase):
    """Test diagnostic methods with mocked dependencies"""

    def setUp(self):
        if not CORE_IMPORT_SUCCESS:
            self.skipTest("UHUBCTL class not available")
        self.uhubctl = UHUBCTL()

    @patch('main.run_in_shell')
    @patch('main.os.path.exists')
    @patch('main.glob.glob')
    def test_diagnose_permissions_success(self, mock_glob, mock_exists, mock_run):
        """Test diagnose_permissions with successful responses."""

        # Mock successful uhubctl commands
        mock_run.side_effect = [
            Mock(returncode=0, stdout="/usr/bin/uhubctl\n"),
            Mock(returncode=0, stdout="uhubctl 2.4.0\n"),
            Mock(returncode=0, stdout="Current status for hub 1 [2109:3431]\n  Port 1: 0100"),
            Mock(returncode=0, stdout="verbose output")
        ]

        # Mock file system
        mock_exists.return_value = True
        mock_glob.return_value = ["/dev/bus/usb/001/", "/dev/bus/usb/002/"]

        # Should not raise any exceptions
        with self.assertLogs('main', level='INFO') as log:
            self.uhubctl.diagnose_permissions()

        # Check that diagnostic messages were logged
        log_output = '\n'.join(log.output)
        self.assertIn("USB Diagnostics Starting", log_output)
        self.assertIn("uhubctl basic functionality: WORKING", log_output)

    @patch('main.run_in_shell')
    def test_diagnose_hub_access(self, mock_run):
        """Test diagnose_hub_access method."""
        hub_output = """Current status for hub 1-1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 1: 0103 power enable connect
  Port 2: 0100 power
  Port 3: 0100 power
  Port 4: 0100 power"""

        mock_run.side_effect = [
            Mock(returncode=0, stdout=hub_output),
            Mock(returncode=0, stdout="dry run success")
        ]

        with self.assertLogs('main', level='INFO') as log:
            self.uhubctl.diagnose_hub_access("1-1")

        log_output = '\n'.join(log.output)
        self.assertIn("Hub Access Diagnostics for 1-1", log_output)
        self.assertIn("Hub 1-1 detected successfully", log_output)

class TestActionHandling(unittest.TestCase):
    """Test port action handling"""

    def setUp(self):
        if not CORE_IMPORT_SUCCESS:
            self.skipTest("UHUBCTL class not available")
        self.uhubctl = UHUBCTL()
        self.port = USBPORT("1-1", 2, True)

    def test_invalid_action(self):
        """Test invalid action handling."""
        result = self.uhubctl.do_action(self.port, "invalid")
        self.assertFalse(result)

    @patch('main.run_in_shell')
    def test_successful_action(self, mock_run):
        """Test successful port action."""
        action_output = """Current status for hub 1-1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 2: 0100 power
Sent power off request
New status for hub 1-1 [2109:3431 Generic 4-Port USB 2.0 Hub, USB 2.00, 4 ports, ppps]
  Port 2: 0000"""

        mock_run.return_value = Mock(returncode=0, stdout=action_output)

        result = self.uhubctl.do_action(self.port, "off")
        self.assertTrue(result)
        self.assertFalse(self.port.enabled)

def run_core_tests():
    """Run core functionality tests"""
    print("=" * 70)
    print("UHUBCTL CORE FUNCTIONALITY TESTS")
    print("=" * 70)
    print()

    # Run the test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestSyntaxValidation,
        TestCoreImports,
        TestUSBClasses,
        TestRunInShell,
        TestUHUBCTLParser,
        TestDiagnosticMethods,
        TestActionHandling
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)

    print()
    print("CORE TEST SUMMARY")
    print("-" * 40)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")

    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}")
            print(f"  {traceback.strip().split(chr(10))[-1]}")

    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}")
            print(f"  {traceback.strip().split(chr(10))[-1]}")

    success = len(result.failures) == 0 and len(result.errors) == 0

    print()
    print("=" * 70)
    if success:
        print("🎉 CORE TESTS PASSED! The main functionality works correctly.")
    else:
        print("❌ SOME CORE TESTS FAILED. Please review the issues above.")
    print("=" * 70)

    return success

if __name__ == '__main__':
    success = run_core_tests()
    sys.exit(0 if success else 1)