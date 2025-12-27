import re
import logging
import requests
from requests.adapters import HTTPAdapter
from colorama import Fore, Style


class ColorFormatter(logging.Formatter):
    def format(self, record):
        # Add red color to ERROR and CRITICAL messages
        if record.levelno >= logging.ERROR:
            record.msg = f"{Fore.RED}{Style.BRIGHT}{record.msg}{Style.RESET_ALL}"
        record.msg = f"{record.msg}{Style.RESET_ALL}"
        return super().format(record)


class PlainTextFormatter(logging.Formatter):
    """Formatter that removes ANSI color codes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ansi_escape = re.compile(r"\x1b\[[0-9;]*m")

    def format(self, record):
        # Get the formatted message
        formatted = super().format(record)
        # Remove ANSI codes
        return self.ansi_escape.sub("", formatted)


class VaultLogger:
    def __init__(self, log_file="/tmp/log.txt"):
        self._enabled = False

        # Logger setup (named logger)
        self.logger = logging.getLogger("vault-traffic")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        # File handler WITH timestamps
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            PlainTextFormatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        file_handler.setLevel(logging.DEBUG)

        # Console handler WITHOUT timestamps
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            ColorFormatter("%(levelname)s - %(message)s")  # Removed %(asctime)s
        )
        console_handler.setLevel(logging.INFO)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        # Session with adapter
        self.session = requests.Session()
        adapter = self._create_http_adapter()
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def unseal(self):
        self._enabled = True
        self.logger.debug("Vault Unsealed, enabling HTTP logging.")

    def seal(self):
        self._enabled = False
        self.logger.debug("Vault Sealed, disabling HTTP logging.")

    def is_enabled(self):
        return self._enabled

    def _create_http_adapter(self):
        vault_logger = self

        class LoggingAdapter(HTTPAdapter):
            def send(self, request, **kwargs):
                if vault_logger.is_enabled():
                    vault_logger.logger.debug("----- REQUEST BEGIN -----")
                    vault_logger.logger.debug(f"{request.method} {request.url}")
                    vault_logger.logger.debug(f"Headers: {request.headers}")
                    if request.body:
                        try:
                            body = (
                                request.body.decode()
                                if isinstance(request.body, bytes)
                                else request.body
                            )
                            vault_logger.logger.debug(f"Body: {body}")
                        except Exception:
                            vault_logger.logger.debug(
                                f"Body (decode failed): {request.body}"
                            )
                    vault_logger.logger.debug("----- REQUEST END -----")

                response = super().send(request, **kwargs)

                if vault_logger.is_enabled():
                    vault_logger.logger.debug("----- RESPONSE BEGIN -----")
                    vault_logger.logger.debug(f"Status: {response.status_code}")
                    vault_logger.logger.debug(f"Headers: {response.headers}")
                    try:
                        vault_logger.logger.debug(f"Body: {response.text}")
                    except Exception:
                        vault_logger.logger.debug("Body: [could not decode]")
                    vault_logger.logger.debug("----- RESPONSE END -----")

                return response

        return LoggingAdapter()


def configure_root_logger(log_file="/tmp/log.txt"):
    """Call once in main.py to configure the root logger globally."""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # File handler WITH timestamps and WITHOUT colors
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(
        PlainTextFormatter("%(asctime)s - %(levelname)s - %(message)s")
    )
    file_handler.setLevel(logging.DEBUG)

    # Console handler WITHOUT timestamps but WITH colors
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        ColorFormatter("%(levelname)s - %(message)s")  # Removed %(asctime)s
    )
    console_handler.setLevel(logging.INFO)

    if not root_logger.handlers:
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
