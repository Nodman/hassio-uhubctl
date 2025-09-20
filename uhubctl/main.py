import argparse
import datetime
import glob
import json
import logging
import os
import os.path
import re
import stat
import subprocess

import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
logger.addHandler(handler)
handler.setFormatter(logging.Formatter("[%(asctime)s] [%(funcName)s] %(message)s"))
logger.propagate = False


def run_in_shell(command, timeout=10):
    try:
        logger.debug("Command kicked: {command}".format(command=command))
        ret = subprocess.run(
            command, shell=True, timeout=timeout, stdout=subprocess.PIPE, text=True
        )
        logger.debug(
            "Command exited with exit code {exit_code}".format(exit_code=ret.returncode)
        )
        return ret
    except Exception:
        logger.exception("Fatal error in running a command")
        raise


class USBHUB:
    def __init__(self, location, vid, pid, usbversion, nports, ports):
        self._location = location
        self._vid = vid
        self._pid = pid
        self._usbversion = usbversion
        self._nports = nports
        self._ports = ports

    def add_port(self, number, status):
        self._ports.append(USBPORT(self.location, number, status))

    @property
    def location(self):
        return self._location

    @property
    def vid(self):
        return self._vid

    @property
    def pid(self):
        return self._pid

    @property
    def usbversion(self):
        return self._usbversion

    @property
    def nports(self):
        return self._nports


class USBPORT:
    def __init__(self, hub_location, number, status):
        self._hub_location = hub_location
        self._number = number
        self._enabled = status

    def on(self):
        self._enabled = True

    def off(self):
        self._enabled = False

    @property
    def hub_location(self):
        return self._hub_location

    @property
    def number(self):
        return self._number

    @property
    def enabled(self):
        return self._enabled


class UHUBCTL:
    def _parser(self, stdout, action=False):
        ret = []

        result = stdout.strip().split("\n")

        try:
            lineidxs_hubheader = [
                index for index, line in enumerate(result) if "status for hub" in line
            ]
            if not len(lineidxs_hubheader) > 0:
                raise ValueError
        except ValueError:
            logger.error("Failed to find any smart hubs")
            return False

        for lineidx_hubheader in lineidxs_hubheader:
            parsed_line = re.search(
                r"status for hub ([0-9-]+) \[([0-9a-f]{4}):([0-9a-f]{4}).*USB (\d)\.\d{2}, (\d+) ports, ppps",
                result[lineidx_hubheader],
            )
            if parsed_line is None:
                continue

            hub = USBHUB(
                location=parsed_line.group(1),
                vid=int(parsed_line.group(2), 16),
                pid=int(parsed_line.group(3), 16),
                usbversion=int(parsed_line.group(4)),
                nports=int(parsed_line.group(5)),
                ports=[],
            )

            lineidx_port_start = lineidx_hubheader + 1
            lineidx_port_end = (
                lineidx_port_start + hub.nports
                if not action
                else lineidx_port_start + 1
            )

            for lineidx in range(lineidx_port_start, lineidx_port_end):
                # Port Information
                parsed_line = re.search(r"Port (\d+): ([0-9a-fA-F]{4})", result[lineidx])
                if parsed_line is None:
                    continue
                port_number = int(parsed_line.group(1))
                port_status_bit = int(parsed_line.group(2), 16)
                logger.debug(
                    "Hub {location} Port {port_number} = {port_status_bit:#06x}".format(
                        location=hub.location,
                        port_number=port_number,
                        port_status_bit=port_status_bit,
                    )
                )

                if hub.usbversion == 3:
                    # USB 3.0 spec Table 10-10
                    # USB_SS_PORT_STAT_POWER = 0x0200
                    POWER_ON_BIT = 0x0200
                else:
                    # USB 2.0 spec Table 11-21
                    # USB_PORT_STAT_POWER = 0x0100
                    POWER_ON_BIT = 0x0100

                if port_status_bit & POWER_ON_BIT:
                    port_status = True
                else:
                    port_status = False

                hub.add_port(port_number, port_status)

            ret.append(hub)

        return ret

    def diagnose_permissions(self):
        """Diagnose USB permissions and access capabilities."""
        logger.info("=== USB Diagnostics Starting ====")

        # Check uhubctl binary version and functionality
        logger.info("1. Testing uhubctl binary:")
        try:
            ret = run_in_shell("which uhubctl", timeout=5)
            if ret.returncode == 0:
                logger.info(f"   uhubctl binary found at: {ret.stdout.strip()}")
            else:
                logger.error("   uhubctl binary not found in PATH")

            ret = run_in_shell("uhubctl --version", timeout=5)
            if ret.returncode == 0:
                logger.info(f"   uhubctl version: {ret.stdout.strip()}")
            else:
                logger.warning("   Could not get uhubctl version")

            # Test basic uhubctl functionality
            ret = run_in_shell("uhubctl", timeout=10)
            if ret.returncode == 0:
                logger.info("   uhubctl basic functionality: WORKING")
                hub_count = ret.stdout.count("status for hub")
                logger.info(f"   Found {hub_count} smart hubs")
            else:
                logger.error(f"   uhubctl basic functionality: FAILED (exit code: {ret.returncode})")
                if ret.stdout:
                    logger.error(f"   stdout: {ret.stdout.strip()}")

        except Exception as e:
            logger.error(f"   Exception testing uhubctl: {e}")

        # Check USB device access in /dev/bus/usb/
        logger.info("2. Checking USB device access:")
        try:
            usb_dev_path = "/dev/bus/usb"
            if os.path.exists(usb_dev_path):
                logger.info(f"   USB device path exists: {usb_dev_path}")

                # List USB buses
                buses = glob.glob(f"{usb_dev_path}/*/")
                logger.info(f"   Found {len(buses)} USB buses")

                # Check permissions on USB devices
                device_count = 0
                accessible_count = 0
                for bus_path in buses:
                    devices = glob.glob(f"{bus_path}*")
                    for device in devices:
                        if os.path.isfile(device):
                            device_count += 1
                            try:
                                # Check if we can read the device
                                with open(device, 'rb') as f:
                                    f.read(1)
                                accessible_count += 1
                            except PermissionError:
                                pass  # Expected for most devices
                            except Exception:
                                pass  # Other errors, continue

                logger.info(f"   Total USB devices: {device_count}")
                logger.info(f"   Accessible devices: {accessible_count}")

            else:
                logger.error(f"   USB device path does not exist: {usb_dev_path}")

        except Exception as e:
            logger.error(f"   Exception checking USB device access: {e}")

        # Check sysfs paths for write access
        logger.info("3. Checking sysfs write access:")
        try:
            sysfs_usb_path = "/sys/bus/usb/devices"
            if os.path.exists(sysfs_usb_path):
                logger.info(f"   sysfs USB path exists: {sysfs_usb_path}")

                # Look for hub control files
                hub_devices = glob.glob(f"{sysfs_usb_path}/*")
                port_disable_files = []

                for device_path in hub_devices:
                    if os.path.isdir(device_path):
                        # Look for port disable files
                        port_files = glob.glob(f"{device_path}/usb*-port*/disable")
                        port_disable_files.extend(port_files)

                logger.info(f"   Found {len(port_disable_files)} port disable files")

                # Test write access to a few port files
                writable_count = 0
                for port_file in port_disable_files[:5]:  # Test first 5
                    try:
                        # Check if file is writable
                        if os.access(port_file, os.W_OK):
                            writable_count += 1
                            logger.debug(f"   Writable: {port_file}")
                        else:
                            logger.debug(f"   Not writable: {port_file}")
                    except Exception as e:
                        logger.debug(f"   Error checking {port_file}: {e}")

                logger.info(f"   Writable port control files: {writable_count}/{min(len(port_disable_files), 5)}")

                if writable_count == 0 and len(port_disable_files) > 0:
                    logger.warning("   No sysfs port control files are writable - this may cause uhubctl to fail")

            else:
                logger.error(f"   sysfs USB path does not exist: {sysfs_usb_path}")

        except Exception as e:
            logger.error(f"   Exception checking sysfs access: {e}")

        # Check current user and groups
        logger.info("4. Checking user permissions:")
        try:
            import pwd
            import grp

            uid = os.getuid()
            gid = os.getgid()
            user_info = pwd.getpwuid(uid)
            group_info = grp.getgrgid(gid)

            logger.info(f"   Running as user: {user_info.pw_name} (uid={uid})")
            logger.info(f"   Primary group: {group_info.gr_name} (gid={gid})")

            # Get all groups for current user
            groups = os.getgroups()
            group_names = []
            for group_id in groups:
                try:
                    group_names.append(grp.getgrgid(group_id).gr_name)
                except KeyError:
                    group_names.append(str(group_id))

            logger.info(f"   Member of groups: {', '.join(group_names)}")

        except Exception as e:
            logger.error(f"   Exception checking user permissions: {e}")

        # Check libusb capabilities
        logger.info("5. Testing libusb capabilities:")
        try:
            # Try to run uhubctl with verbose output to see libusb messages
            ret = run_in_shell("uhubctl -v", timeout=10)
            if "libusb" in ret.stdout.lower() or "libusb" in ret.stderr.lower():
                logger.info("   libusb messages detected in uhubctl output")

            # Look for libusb-related files
            libusb_paths = ["/usr/lib/libusb*", "/usr/local/lib/libusb*", "/lib/libusb*"]
            found_libusb = False
            for path_pattern in libusb_paths:
                libusb_files = glob.glob(path_pattern)
                if libusb_files:
                    found_libusb = True
                    logger.info(f"   Found libusb files: {libusb_files}")

            if not found_libusb:
                logger.warning("   No libusb library files found")

        except Exception as e:
            logger.error(f"   Exception testing libusb: {e}")

        logger.info("=== USB Diagnostics Complete ====")

    def diagnose_hub_access(self, hub_location):
        """Diagnose access issues for a specific hub."""
        logger.info(f"=== Hub Access Diagnostics for {hub_location} ====")

        try:
            # Test basic hub detection
            logger.info("1. Testing hub detection:")
            ret = run_in_shell(f"uhubctl -l {hub_location}", timeout=10)
            if ret.returncode == 0:
                logger.info(f"   Hub {hub_location} detected successfully")
                if "status for hub" in ret.stdout:
                    logger.info("   Hub status information available")
                else:
                    logger.warning("   Hub detected but no status information")
            else:
                logger.error(f"   Failed to detect hub {hub_location} (exit code: {ret.returncode})")
                if ret.stdout:
                    logger.error(f"   stdout: {ret.stdout.strip()}")
                return

            # Try to read current port states
            logger.info("2. Testing port state reading:")
            try:
                hubs = self._parser(ret.stdout)
                if hubs:
                    target_hub = next((h for h in hubs if h.location == hub_location), None)
                    if target_hub:
                        logger.info(f"   Successfully parsed hub {hub_location}")
                        logger.info(f"   Hub details: VID={target_hub.vid:04x}, PID={target_hub.pid:04x}, USB{target_hub.usbversion}, {target_hub.nports} ports")

                        for port in target_hub._ports:
                            status = "ON" if port.enabled else "OFF"
                            logger.info(f"   Port {port.number}: {status}")
                    else:
                        logger.error(f"   Hub {hub_location} not found in parsed results")
                else:
                    logger.error("   Failed to parse any hubs from output")

            except Exception as e:
                logger.error(f"   Exception parsing hub information: {e}")

            # Test port control (dry run style - try to get current state)
            logger.info("3. Testing port control access:")
            try:
                # Try to "toggle" a port (this will show if we have permission issues)
                ret = run_in_shell(f"uhubctl -l {hub_location} -p 1 -a off --dry-run", timeout=5)
                if ret.returncode == 0:
                    logger.info("   Port control access appears functional")
                else:
                    # Try without dry-run flag (some versions may not support it)
                    logger.info("   Testing actual port control (will attempt to read current state)")
                    ret = run_in_shell(f"uhubctl -l {hub_location} -p 1 -a on -r 0", timeout=5)
                    if "permission" in ret.stdout.lower() or "permission" in ret.stderr.lower():
                        logger.error("   Permission denied for port control")
                    elif "read-only" in ret.stdout.lower() or "read-only" in ret.stderr.lower():
                        logger.error("   Read-only filesystem preventing port control")
                    elif ret.returncode != 0:
                        logger.warning(f"   Port control test failed (exit code: {ret.returncode})")
                        if ret.stdout:
                            logger.warning(f"   stdout: {ret.stdout.strip()}")
                    else:
                        logger.info("   Port control appears to be working")

            except Exception as e:
                logger.error(f"   Exception testing port control: {e}")

            # Check for specific sysfs paths for this hub
            logger.info("4. Checking sysfs paths for this hub:")
            try:
                sysfs_pattern = f"/sys/bus/usb/devices/{hub_location}*"
                hub_paths = glob.glob(sysfs_pattern)

                if hub_paths:
                    logger.info(f"   Found sysfs paths for hub: {hub_paths}")

                    for hub_path in hub_paths:
                        port_paths = glob.glob(f"{hub_path}/usb*-port*/disable")
                        if port_paths:
                            logger.info(f"   Port control files: {len(port_paths)} found")

                            # Test accessibility
                            for port_file in port_paths[:3]:  # Test first 3
                                try:
                                    if os.access(port_file, os.R_OK):
                                        logger.debug(f"   Readable: {os.path.basename(port_file)}")
                                    if os.access(port_file, os.W_OK):
                                        logger.debug(f"   Writable: {os.path.basename(port_file)}")
                                    else:
                                        logger.debug(f"   Not writable: {os.path.basename(port_file)}")
                                except Exception:
                                    pass
                        else:
                            logger.info(f"   No port control files found for {hub_path}")
                else:
                    logger.warning(f"   No sysfs paths found for hub {hub_location}")

            except Exception as e:
                logger.error(f"   Exception checking sysfs paths: {e}")

        except Exception as e:
            logger.error(f"   Exception in hub access diagnostics: {e}")

        logger.info(f"=== Hub Access Diagnostics Complete for {hub_location} ====")

    def fetch_allinfo(self):
        try:
            logger.debug("Fetch current status for all smart hubs")
            ret = run_in_shell("uhubctl")
            stdout = ret.stdout

            return self._parser(stdout)
        except:
            logger.exception("Failed to fetch current status")
            # Run diagnostics when hub access fails
            logger.info("Running diagnostics due to hub access failure...")
            self.diagnose_permissions()
            return None

    def do_action(self, port, action):
        try:
            action = action.lower()
            if action not in ["on", "off"]:
                raise ValueError
        except ValueError:
            logger.error(
                "Illegal action to the port: action={action}".format(action=action)
            )
            return False

        logger.debug(
            "Send command to the port: hub={location}, port={port}, action={action}".format(
                location=port.hub_location, port=port.number, action=action
            )
        )

        try:
            ret = run_in_shell(
                "uhubctl -l {location} -p {port} -a {action} -r 100".format(
                    location=port.hub_location, port=port.number, action=action
                )
            )
            stdout = ret.stdout

            # _parser returns [Current status, New status]
            newstatus_hub = self._parser(stdout, action=True)[-1]
            newstatus_port = newstatus_hub._ports[0]

            if newstatus_port.enabled:
                port.on()
            else:
                port.off()

            return True
        except:
            logger.exception(
                "Failed to change port status: hub={location}, port={port}, action={action}".format(
                    location=port.hub_location, port=port.number, action=action
                )
            )
            # Run hub-specific diagnostics when port control fails
            logger.info(f"Running hub diagnostics due to port control failure for hub {port.hub_location}...")
            self.diagnose_hub_access(port.hub_location)
            return False


class USBHUB_MQTT_Error(Exception):
    pass


class USBHUB_MQTT:
    def __init__(self, opt_file):
        with opt_file:
            self._cfg = json.load(opt_file)
            self._usbhubs = []
            self._will = (self._cfg["AVAILABILITY_TOPIC"], "Offline", 1, True)

    def make_json_portstatus(self, usbhub):
        ret = {
            "Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Location": usbhub.location,
            "Vid": usbhub.vid,
            "Pid": usbhub.pid,
            "USBVersion": usbhub.usbversion,
        }

        for port in usbhub._ports:
            idx = "POWER{number}".format(number=port.number)
            ret[idx] = "ON" if port.enabled else "OFF"

        return json.dumps(ret)

    def send_mqtt_hubstatus(self, client, usbhub=None):
        usbhubs = self._usbhubs if usbhub is None else [usbhub]

        for usbhub in usbhubs:
            topic = "{prefix}/HUB{location}/STATE".format(
                prefix=self._cfg["STATUS_TOPIC"], location=usbhub.location
            )
            payload = self.make_json_portstatus(usbhub)

            logger.debug(
                "MQTT Publish current status: topic={topic}, payload={payload}".format(
                    topic=topic, payload=payload
                )
            )

            client.publish(
                topic=topic,
                payload=payload,
                qos=1,
                retain=True,
            )

    def on_mqtt_connect(self, client, userdata, flags, rc):
        if rc != 0:
            raise USBHUB_MQTT_Error(
                "Error while connecting to the MQTT broker. Reason code: {}".format(
                    str(rc)
                )
            )
        else:
            logger.info("MQTT Connected successfully")

        result, mid = client.subscribe(self._cfg["COMMAND_TOPIC"] + "/#", 1)
        logger.info(
            "MQTT Subscribe: topic={topic}, result={result}".format(
                topic=self._cfg["COMMAND_TOPIC"] + "/#",
                result="Success" if result == mqtt.MQTT_ERR_SUCCESS else "Failed",
            )
        )

        # Run initial diagnostics
        uhubctl_instance = UHUBCTL()
        uhubctl_instance.diagnose_permissions()

        self._usbhubs = uhubctl_instance.fetch_allinfo()

        self.send_mqtt_hubstatus(client)
        client.publish(
            topic=self._cfg["AVAILABILITY_TOPIC"], payload="Online", qos=1, retain=True
        )

    def on_mqtt_ctrl_message(self, client, userdata, message):
        logger.info(
            "Received a control message: topic={topic}, payload={payload}".format(
                topic=message.topic, payload=message.payload.decode()
            )
        )

        # Topic will be "hoge/usbhub/HUB1-3/POWER1
        parsed_topic = message.topic.split("/")
        try:
            command = parsed_topic[-1]
            hub_name = parsed_topic[-2]
            hub_location = re.search(r"HUB([0-9-]+)", hub_name).group(1)
        except IndexError:
            logger.error("Failed to parse the topic string")
            return False

        parsed_command = re.search(r"([A-Z]+)(\d+)", command)

        if parsed_command.group(1) == "POWER":
            try:
                port_number = int(parsed_command.group(2))
                hub = [hub for hub in self._usbhubs if hub.location == hub_location][0]
                port = [port for port in hub._ports if port.number == port_number][0]
            except IndexError:
                logger.error("Illigal action request to unknown hub / port")
                return False

            try:
                action = message.payload.decode()
                UHUBCTL().do_action(port, action)
            except:
                logger.exception("Failed to execute an action")

        self.send_mqtt_hubstatus(client, hub)

    def loop_forever(self):
        try:
            mqtt_hostname = os.environ["MQTT_HOST"]
            mqtt_port = int(os.environ["MQTT_PORT"])
            mqtt_username = os.environ["MQTT_USERNAME"]
            mqtt_password = os.environ["MQTT_PASSWORD"]
            logger.debug(
                "MQTT Server: mqtt://{username}:<secret>@{host}:{port}".format(
                    username=mqtt_username,
                    host=mqtt_hostname,
                    port=mqtt_port,
                )
            )
        except KeyError:
            logger.exception("Failed to fetch local MQTT configurations")
            return False

        mqc = mqtt.Client()
        mqc.on_connect = self.on_mqtt_connect
        mqc.message_callback_add(
            self._cfg["COMMAND_TOPIC"] + "/#", self.on_mqtt_ctrl_message
        )
        mqc.username_pw_set(mqtt_username, mqtt_password)
        mqc.will_set(*self._will)

        mqc.connect(mqtt_hostname, mqtt_port)

        mqc.loop_forever()


if __name__ == "__main__":
    argp = argparse.ArgumentParser(description="MQTT - uhubctl bridge")
    argp.add_argument(
        "-c",
        "--config",
        type=argparse.FileType(),
        default="/data/options.json",
        help="User configuration file genereted by Home Assistant",
    )

    log_levels = ["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"]
    log_levels = log_levels + list(map(lambda w: w.lower(), log_levels))
    argp.add_argument("--log", choices=log_levels, default="INFO", help="Logging level")

    args = vars(argp.parse_args())

    logger.setLevel(level=args["log"].upper())
    handler.setLevel(level=args["log"].upper())

    usbhub_mqtt = USBHUB_MQTT(args["config"])
    usbhub_mqtt.loop_forever()
