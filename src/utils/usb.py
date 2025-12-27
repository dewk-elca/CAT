import os
import time
import logging
import subprocess
import json
import threading
from dataclasses import dataclass, field
from typing import Set, List, Optional
import uuid
from utils.ui import Color

logger = logging.getLogger(__name__)


class USBDeviceError(Exception):
    """Exception raised for errors related to USBDevice operations."""

    def __init__(self, message: str, device_name: str = None):
        super().__init__(message)
        self.device_name = device_name


@dataclass
class USBDevice:
    """
    Should only be mounted as a Context manager, or through a USBContext
    Represents a USB storage device with its properties and mount state.
    Thread-safe implementation with proper locking mechanisms.

    Attributes:
        name (str): The name assigned by the kernel to the usb
        label (str): The device label or 'unknown' if no label
        serial (str): The device's serial umber
        base_mount_dir (str): Base directory where USB devices are mounted
        mount_path (str, optional): Full path where device is/will be mounted
        _mount_id (str): Unique identifier to prevent mount point conflicts
    """

    name: str
    label: str
    serial: str
    base_mount_dir: str = "/media/usb"
    mount_path: str = None
    _mount_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8], init=False)

    def __post_init__(self):
        """Set the mount path after initialization with unique identifier."""
        # Add unique ID to prevent conflicts with same-label devices
        safe_label = self.label.replace("/", "_").replace(" ", "_") or "unlabeled"
        if not self.mount_path:
            self.mount_path = os.path.join(
                self.base_mount_dir, f"{self.name}-{safe_label}-{self._mount_id}"
            )

    def __hash__(self):
        return hash((self.name, self.label, self.serial))

    def __eq__(self, other):
        if not isinstance(other, USBDevice):
            return NotImplemented
        return (self.serial, self.name, self.label) == (
            other.serial,
            other.name,
            other.label,
        )

    @property
    def mounted(self):
        """Checks the linux kernel's table to see if it is mounted.
        Note that it can be mounted even if the device is removed.
        """
        # Check that there is a mount entry for this device name and mount path exactly
        result = subprocess.run(["mount"], capture_output=True, check=True, text=True)
        stdout = result.stdout.split("\n")
        filtered = [
            line for line in stdout if self.name in line and self.mount_path in line
        ]

        return True if filtered else False

    @property
    def available(self) -> bool:
        """Check if the device is still listed in /dev.
        Note that this alone is not enough to conclude that the device is plugged in. Use with mounted()"""

        return os.path.exists(f"/dev/{self.name}")

    def mount(self) -> bool:
        """
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.available:
            logger.debug(f"Device {self.name} is not available (anymore) at /dev")
            return False

        if self.mounted:
            logger.debug(f"Device {self.name} is already mounted at {self.mount_path}")
            return True

        if os.path.exists(self.mount_path):
            logger.debug(
                f"Mount path {self.mount_path} already exists. This device had been mounted in the past. Create a new USBDevice instance to mount it, it should only be mounted once."
            )
            return False

        os.makedirs(self.mount_path)

        try:
            logger.debug(f"Mounting /dev/{self.name} to {self.mount_path}")
            subprocess.run(
                ["mount", f"/dev/{self.name}", self.mount_path],
                check=True,
                timeout=30,
                text=True,
            )

            logger.info(
                f"{Color.GREEN}USB mounted: {Color.RESET}{self.name} -> {self.mount_path}"
            )
            return True

        except subprocess.TimeoutExpired:
            logger.error(f"Mount timeout for {self.name}")
            self._cleanup_mount_dir()
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Mount failed for {self.name}: {e.stderr}")
            self._cleanup_mount_dir()
            return False
        except Exception as e:
            logger.error(f"Unexpected error mounting {self.name}: {e}")
            self._cleanup_mount_dir()
            return False

    def unmount(self) -> bool:
        """
        Returns:
            bool: True if successful, False otherwise
        """

        if not self.mounted:
            logger.debug(f"Device {self.name} is already unmounted. Cleaning up...")

        else:
            try:
                subprocess.run(
                    ["umount", self.mount_path], check=True, capture_output=True
                )

            except subprocess.CalledProcessError:
                # Regular unmount failed, try force unmount
                logger.warning(
                    f"Regular unmount failed for {self.name}, trying force unmount"
                )
                time.sleep(1)

                try:
                    subprocess.run(
                        ["umount", "-f", self.mount_path],
                        check=True,
                        capture_output=True,
                    )

                except subprocess.CalledProcessError as e:
                    logger.error(f"Force unmount failed for {self.name}: {e}")
                    return False

                except Exception as e:
                    logger.error(
                        f"Unexpected error during force unmount for {self.name}: {e}"
                    )
                    return False

            except Exception as e:
                logger.error(f"Unexpected error during unmount for {self.name}: {e}")
                return False

        # Unmount succeeded, clean up
        try:
            self._cleanup_mount_dir()
            logger.info(f"{Color.BLUE}USB unmounted:{Color.RESET} {self.mount_path}")
            return True

        except Exception as e:
            logger.error(f"Error during unmount cleanup for {self.name}: {e}")
            return False

    def _cleanup_mount_dir(self):
        """Safely remove mount directory if empty."""
        try:
            if os.path.exists(self.mount_path):
                os.rmdir(self.mount_path)
        except OSError as e:
            logger.debug(f"Could not remove mount directory {self.mount_path}: {e}")


class USBContext:
    """
    Thread-safe USB monitor. ONLY instanciate through get_instance() to avoid multiple contexts active at the same time.
    Here: uniqueness = dev.name + "-" + dev.serial
    """

    _instance = None
    _instance_lock = threading.Lock()

    def __init__(self, poll_interval: float = 1, base_mount_dir: str = "/media/usb"):
        """
        Initialize the USB monitor with thread-safe operations.
        Note: Use get_instance() instead of direct instantiation to ensure singleton behavior.

        Args:
            poll_interval (float): How often to check for USB changes (seconds)
            base_mount_dir (str): Base directory for mounting USB devices
        """
        self.poll_interval = max(
            1, poll_interval
        )  # Minimum 1s to avoid excessive polling
        self.known_devices_set: Set[str] = (
            set()
        )  # For uniqueness guarantee use name-serial
        self.base_mount_dir = base_mount_dir
        self.__mounted_devices: Set[USBDevice] = set()
        self._running = False
        self._thread = None
        self._devices_lock = (
            threading.Lock()
        )  # Protects _mounted_devices and known_devices
        self._operation_lock = (
            threading.Lock()
        )  # Prevents concurrent mount/unmount operations

    @classmethod
    def get_instance(
        cls, poll_interval: float = 1, base_mount_dir: str = "/media/usb"
    ) -> Optional["USBContext"]:
        """
        Get the singleton instance of USBContext.

        Args:
            poll_interval (float): How often to check for USB changes (seconds) - only used for first instance
            base_mount_dir (str): Base directory for mounting USB devices - only used for first instance

        Returns:
            USBContext: The existing instance if one already exists, a new one if not.
        """
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(
                    poll_interval=poll_interval, base_mount_dir=base_mount_dir
                )
            return cls._instance  # First instance created

    @classmethod
    def destroy_instance(cls):
        """
        Destroy the singleton instance. This will stop monitoring and clean up.
        """
        with cls._instance_lock:
            if cls._instance is not None:
                if cls._instance._running:
                    cls._instance.__exit__(None, None, None)
                cls._instance = None

    @classmethod
    def has_instance(cls) -> bool:
        """
        Check if an instance already exists without creating one.

        Returns:
            bool: True if an instance exists, False otherwise
        """
        with cls._instance_lock:
            return cls._instance is not None

    def __enter__(self):
        """Starts the monitoring thread."""
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("USB monitoring started")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Stops monitoring and cleanly unmounts all devices."""
        self._running = False

        # Wait for monitor thread to finish
        if self._thread and self._thread.is_alive():
            self._thread.join()
            if self._thread.is_alive():
                logger.warning("Monitor thread did not exit cleanly")

        # Unmount all devices
        self._unmount_all_tracked_devices()
        logger.info("USB monitoring stopped")

    def get_mounted_devices(self) -> set[USBDevice]:
        """Get a copy of currently mounted devices."""
        with self._devices_lock:
            return self.__mounted_devices.copy()

    def add_to_mounted_devices(self, device: USBDevice) -> set[USBDevice]:
        """Get a copy of currently mounted devices."""
        with self._devices_lock:
            self.__mounted_devices.add(device)

    def mount_device_manual(self, usb_device: USBDevice) -> bool:
        return self._handle_device_insertion(usb_device)

    def unmount_device_manual(self, usb_device: USBDevice) -> bool:
        return self._handle_device_removal(usb_device)

    def format_usb_fat32_and_mount(self, usb_device: USBDevice, new_label):
        if not self._handle_device_removal(usb_device):
            logger.error("Error while formatting usb: Failed to unmount")
            raise Exception("Format to usb failed: failed to unmount")

        logger.info(f"Formatting USB {usb_device.serial} to fat32 (timeout 10min)...")

        try:
            subprocess.run(
                ["mkfs.vfat", "-F", "32", "-n", new_label, f"/dev/{usb_device.name}"],
                check=True,
                timeout=600,
                text=True,
            )
            logger.info("Formatting succesfull.")
        except Exception as e:
            logger.error(e)

        if not self._handle_device_insertion(usb_device):
            logger.error("Failed to mount")
            raise Exception("Format to usb failed: failed to mount")

    def _unmount_all_tracked_devices(self):
        """Unmount all currently tracked mounted devices."""
        with self._devices_lock:
            devices_to_unmount = list(self.__mounted_devices)

            for device in devices_to_unmount:
                if not device.unmount():
                    logger.warning(
                        f"USBContext: Failed to cleanly unmount {device.name}"
                    )

            self.__mounted_devices.clear()

    def _monitor_loop(self):
        """
        Main monitoring loop with improved error handling and debouncing.
        """
        logger.debug("USB monitoring loop started")

        # Initialize known devices
        with self._devices_lock:
            self.known_devices_set = set(self.list_available_usb_drives())

        consecutive_errors = 0
        max_consecutive_errors = 5

        while self._running:
            try:
                time.sleep(self.poll_interval)

                if not self._running:
                    break

                currently_connected_devices_set = set(self.list_available_usb_drives())

                with self._devices_lock:
                    old_connected_devices_set = self.known_devices_set.copy()

                # Process changes
                self._process_device_changes(
                    currently_connected_devices_set, old_connected_devices_set
                )

                with self._devices_lock:
                    self.known_devices_set = currently_connected_devices_set

                consecutive_errors = 0  # Reset error counter on success

            except Exception as e:
                consecutive_errors += 1
                logger.error(f"Error in monitoring loop: {e}")

                if consecutive_errors >= max_consecutive_errors:
                    logger.critical(
                        f"Too many consecutive errors ({consecutive_errors}), stopping monitor"
                    )
                    break

                # Exponential backoff on errors
                time.sleep(min(self.poll_interval * (2**consecutive_errors), 30))

    def _process_device_changes(
        self,
        currently_connected_devices_set: set[USBDevice],
        old_connected_devices_set: Set[USBDevice],
    ):
        """Process device insertion and removal events."""
        new_devices = currently_connected_devices_set - old_connected_devices_set
        removed_devices = old_connected_devices_set - currently_connected_devices_set

        # Handle new devices

        for device in new_devices:
            logger.info(
                f"{Color.GREEN}USB inserted:{Color.RESET} {device.name} ({device.label}) - {device.serial}"
            )
            self._handle_device_insertion(device)

        # Handle removed devices
        for device in removed_devices:
            logger.info(
                f"{Color.BLUE}USB removed:{Color.RESET} {device.name} ({device.label}) - {device.serial}"
            )
            self._handle_device_removal(device)

    def _handle_device_insertion(self, device: USBDevice) -> bool:
        """Handle insertion of a new USB device."""

        with self._operation_lock:
            # Double-check device isn't already mounted
            with self._devices_lock:
                if device.serial in [dev.serial for dev in self.__mounted_devices]:
                    logger.debug(
                        f"Device with name: {device.name}, label: {device.label}, serial: {device.serial} is already tracked by USBContext."
                    )
                    return True

            try:
                # Attempt to mount
                if device.mount():
                    with self._devices_lock:
                        self.__mounted_devices.add(device)
                    return True
                else:
                    logger.warning(
                        f"Failed to mount newly inserted device at {device.name}: {device.serial}"
                    )
                    return False

            except Exception as e:
                logger.error(f"Error handling device insertion {device.serial}: {e}")
                return False

    def _handle_device_removal(self, device: USBDevice) -> bool:
        with self._operation_lock:
            with self._devices_lock:
                tracked_same_device = next(
                    (
                        dev
                        for dev in self.__mounted_devices
                        if dev.__hash__() == device.__hash__()
                    ),
                    None,
                )
                if not tracked_same_device:
                    logger.debug(
                        f"Device with name: {device.name}, label: {device.label}, serial: {device.serial} is not tracked by USBContext."
                    )
                    return True

            try:
                # Attempt unmount
                if tracked_same_device.unmount():
                    with self._devices_lock:
                        self.__mounted_devices.remove(tracked_same_device)
                    return True
                else:
                    logger.warning(
                        f"Failed to unmount newly removed device at {device.name}: {device.serial}"
                    )
                    return False

            except Exception as e:
                logger.error(
                    f"Error handling device removal {tracked_same_device.serial}: {e}"
                )
                return False

    @staticmethod
    def list_available_usb_drives() -> List[USBDevice]:
        """
        USB device discovery with error handling.
        If device has n label, wait 1 seconds

        Returns:
            List[Dict]: List of dictionaries containing device info
        """
        try:
            output = subprocess.check_output(
                ["lsblk", "-J", "-o", "NAME,LABEL,RM,SERIAL,MOUNTPOINTS"],
                text=True,
                timeout=10,  # Prevent hanging
            )
            devices = json.loads(output).get("blockdevices", [])
            filtered = []

            for dev in devices:
                children = dev.get("children", [])
                # Filter for removable SCSI devices (USB drives) with partitions
                if (
                    dev.get("name", "").startswith("sd")
                    and dev.get("rm") is True
                    and children
                    and isinstance(children, list)
                ):
                    name = dev.get("name")
                    if not children[0].get("label"):
                        # Wait a bit and scan again. If label exists after 1, take this device.
                        time.sleep(1.5)
                        output = subprocess.check_output(
                            ["lsblk", "-J", "-o", "NAME,LABEL,RM,SERIAL,MOUNTPOINTS"],
                            text=True,
                            timeout=10,  # Prevent hanging
                        )
                        devices2 = json.loads(output).get("blockdevices", [])
                        dev2 = next(
                            (
                                dev2
                                for dev2 in devices2
                                if dev2.get("name") == name
                                and dev2.get("rm") is True
                                and dev2.get("children", [])
                                and isinstance(dev.get("children", []), list)
                                and dev2.get("children", [])[0].get("label")
                            ),
                            None,
                        )
                        if dev2:
                            dev = dev2

                    # Use the first partition that has a recognizable filesystem
                    child = dev.get("children", [])[0]
                    if child.get("name") and dev.get(
                        "serial"
                    ):  # Must have a name and serial
                        filtered.append(
                            USBDevice(
                                name=child.get("name"),
                                label=child.get("label")
                                if child.get("label")
                                else "unlabeled",
                                serial=dev.get("serial"),
                                mount_path=child.get("mountpoints")[0]
                                if len(child.get("mountpoints")) > 0
                                else None,
                            )
                        )

            return filtered

        except subprocess.TimeoutExpired:
            logger.error("lsblk command timed out")
            return []
        except subprocess.CalledProcessError as e:
            logger.error(f"lsblk command failed: {e}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse lsblk output: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing USB drives: {e}")
            return []

    @staticmethod
    def is_device_name_mounted(name: str):
        """Checks the linux kernel's table to see if it is mounted.
        Note that it can be mounted even if the device is removed.
        """
        # Check that there is a mount entry for this device name and mount path exactly
        result = subprocess.run(["mount"], capture_output=True, check=True, text=True)
        stdout = result.stdout.split("\n")
        filtered = [line for line in stdout if name in line]

        return True if filtered else False
