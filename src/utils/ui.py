import logging
import os
import re
import string
import sys
import termios
import tty
import yaml
import pytz
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import qrcode
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

from colorama import Fore, Style
from prompt_toolkit import prompt
from prompt_toolkit.completion import FuzzyWordCompleter, PathCompleter
from prompt_toolkit.validation import ValidationError, Validator
from thefuzz import process


# --- ANSI Color / Style Constants ---
class Color:
    """A collection of ANSI color and style codes for modern terminal UIs."""

    # Reset
    RESET = Style.RESET_ALL

    # Styles
    BRIGHT = Style.BRIGHT
    DIM = Style.DIM

    # Foreground Colors
    BLUE = Fore.BLUE
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    BLACK = Fore.BLACK

    # Roles
    HEADER = BRIGHT + BLUE
    TITLE = BRIGHT + WHITE
    PROMPT = BRIGHT + CYAN
    SUCCESS = BRIGHT + GREEN
    WARNING = BRIGHT + YELLOW
    ERROR = BRIGHT + RED
    HIGHLIGHT = BRIGHT + WHITE
    PARAM = BRIGHT + CYAN
    VALUE = RESET + WHITE
    BORDER = DIM + WHITE
    DESCRIPTION = DIM + WHITE


# --- Logging Setup ---
class SecretRegistry:
    """Registry for tracking secrets that should be redacted from logs."""

    def __init__(self):
        self._secrets: Dict[str, str] = {}  # name -> value

    def register_secret(self, name: str, value: str) -> None:
        """Register a secret value to be redacted from logs."""
        if value and len(value.strip()) > 0:  # Only register non-empty secrets
            self._secrets[value] = name

    def redact_message(self, message: str) -> str:
        """Replace all registered secret values with [REDACTED: name] in the message."""
        redacted_message = message

        # Sort secrets by length (longest first) to handle overlapping secrets properly
        for secret_value, name in sorted(
            self._secrets.items(), key=lambda x: len(x[0]), reverse=True
        ):
            if secret_value in redacted_message:
                redacted_message = redacted_message.replace(
                    secret_value, f"[REDACTED: {name}]"
                )

        return redacted_message


# Global secret registry instance
_secret_registry = SecretRegistry()


class PlainTextFormatter(logging.Formatter):
    """Formatter that removes ANSI color codes and redacts secrets for file logging."""

    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")

    def format(self, record):
        formatted_message = super().format(record)

        # Remove ANSI color codes
        clean_message = self.ansi_escape.sub("", formatted_message)

        # Redact secrets
        redacted_message = _secret_registry.redact_message(clean_message)

        return redacted_message


class ConsoleFormatter(logging.Formatter):
    """Formatter that preserves ANSI colors but redacts secrets for console logging."""

    def format(self, record):
        # First apply the standard formatting
        formatted_message = super().format(record)

        # Redact secrets
        redacted_message = _secret_registry.redact_message(formatted_message)

        return redacted_message


def register_secret(name: str, value: str) -> None:
    """Register a secret value to be automatically redacted from all log messages."""
    _secret_registry.register_secret(name, value)
    logging.debug(f"Secret registered: {name}")


def setup_logging():
    """Configures logging to both a file and the console with separate log levels and secret redaction."""
    log_dir = "/out/public/logs"
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = os.path.join(log_dir, f"key-ceremony-{timestamp}.log")

    console_log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    file_log_level = os.getenv("FILE_LOG_LEVEL", "DEBUG").upper()

    logger = logging.getLogger()

    # Set logger to the lowest level so both handlers can filter appropriately
    logger.setLevel(logging.DEBUG)

    if logger.hasHandlers():
        logger.handlers.clear()

    # File handler gets clean, plain text with DEBUG level by default and secret redaction
    file_handler = logging.FileHandler(log_file)
    real_file_log_level = getattr(logging, file_log_level, logging.DEBUG)
    file_handler.setLevel(real_file_log_level)
    file_formatter = PlainTextFormatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler gets the styled message with secret redaction
    console_handler = logging.StreamHandler(sys.stdout)
    real_console_log_level = getattr(logging, console_log_level, logging.INFO)
    console_handler.setLevel(real_console_log_level)
    console_formatter = ConsoleFormatter("%(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    logging.info(f"Logging initialized with secret redaction. Log file: {log_file}")
    logging.info(
        f"Console log level: {real_console_log_level}, File log level: {real_file_log_level}"
    )


# --- UI Helper Functions ---
def print_header(text: str):
    """Prints a main header, centered with a border."""
    width = 80
    border_char = "─"
    logging.info("\n" + Color.BORDER + border_char * width + Color.RESET)
    logging.info(f"{Color.HEADER}{text.center(width)}{Color.RESET}")
    logging.info(Color.BORDER + border_char * width + Color.RESET)


def print_step_title(prefix: str, name: str, description: Optional[str] = None):
    """Prints a formatted title for a ceremony step."""
    logging.info(f"{Color.TITLE}{prefix}{name}{Color.RESET}")
    if description:
        # Indent description for clarity
        for line in description.strip().split("\n"):
            logging.info(f"{Color.DESCRIPTION}  {line}{Color.RESET}")
    logging.info("")  # Add spacing


def print_param_block(data: Dict[str, Any], title: str = "Parameters"):
    """Prints a formatted block of parameters using YAML for readability."""
    if not data:
        return
    param_str = yaml.dump(data, indent=2, sort_keys=True, allow_unicode=True)
    logging.info(f"{Color.PARAM}{title}:{Color.RESET}")
    for line in param_str.strip().split("\n"):
        logging.info(f"  {Color.VALUE}{line}{Color.RESET}")
    logging.info("")


def print_success(message: str):
    logging.info(f"{Color.SUCCESS}✓ {message}{Color.RESET}")


def print_warning(message: str):
    logging.warning(f"{Color.WARNING}⚠ {message}{Color.RESET}")


def print_error(message: str):
    logging.error(f"{Color.ERROR}✗ {message}{Color.RESET}")


def ask_confirm(prompt_text: str, default_yes: bool = True) -> bool:
    """Asks a styled Y/n or y/N confirmation question."""
    options_display = (
        f"{Color.BRIGHT}(Y/n){Color.RESET}"
        if default_yes
        else f"{Color.BRIGHT}(y/N){Color.RESET}"
    )
    full_prompt = f"{Color.PROMPT}{prompt_text} {options_display} {Color.RESET}"

    try:
        choice = input(full_prompt).strip().lower()
    except EOFError:  # Handles case where script is run non-interactively
        return default_yes

    if default_yes:
        return choice not in ["n", "no"]
    else:
        return choice in ["y", "yes"]


# --- Interactive Prompts ---
class PathValidator(Validator):
    def validate(self, document):
        text = document.text
        if not os.path.isdir(os.path.expanduser(text)):
            raise ValidationError(
                message="This is not a valid directory.", cursor_position=len(text)
            )


class Password:
    """An interactive password prompt that masks input."""

    def __init__(
        self,
        prompt_text: str,
        length: Optional[int] = None,
        alphabet: str = string.ascii_letters + string.digits,
    ):
        self.prompt_text = prompt_text
        self.length = length if length else None
        self.alphabet = alphabet
        self.error_message = ""

    def _getch(self):
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

    def _display_prompt(self, current_input=""):
        sys.stdout.write("\r" + " " * 80 + "\r")
        if self.error_message:
            sys.stdout.write(f"{Color.WARNING}{self.error_message}{Color.RESET}\n")
            self.error_message = ""

        password_mask = "*" * len(current_input)
        if self.length is not None:
            password_mask += " " * (self.length - len(current_input))

        prompt_line = f"{Color.PROMPT}{self.prompt_text}:{Color.RESET} [{Color.WHITE}{password_mask}{Color.RESET}]"
        sys.stdout.write(prompt_line)
        sys.stdout.flush()

    def prompt(self) -> str:
        result = ""
        self._display_prompt(result)
        while True:
            char = self._getch()
            if char in ("\r", "\n"):
                if self.length and len(result) != self.length:
                    self.error_message = (
                        f"Input must be exactly {self.length} characters long."
                    )
                else:
                    sys.stdout.write("\n")
                    return result
            elif char in ("\x7f", "\x08"):
                result = result[:-1]
            elif ord(char) == 3:
                print_warning("\n\nInput cancelled by user.")
                raise SystemExit("User aborted.")
            else:
                if self.alphabet and char not in self.alphabet:
                    self.error_message = (
                        f"Invalid character. Must be in: {self.alphabet}"
                    )
                elif self.length and len(result) >= self.length:
                    self.error_message = (
                        f"Input cannot exceed {self.length} characters."
                    )
                else:
                    result += char
            self._display_prompt(result)


# --- Core Fuzzy Search Logic ---
@dataclass(frozen=True)
class SearchableItem:
    display_value: str
    search_value: str
    original_object: Any


class FuzzySearchAborted(Exception):
    """Custom exception for retrying fuzzy search."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def display_mappings(
    mappings: Dict[str, Dict[str, Any]],
    unmapped_available: Optional[List[SearchableItem]] = None,
    show_unmapped=False,
):
    logging.info(f"{Color.TITLE}Proposed Mappings:{Color.RESET}")
    max_len = max((len(key) for key in mappings.keys()), default=20)

    sorted_expected_items = sorted(mappings.keys())
    for i, expected_item in enumerate(sorted_expected_items):
        data = mappings[expected_item]
        found_item = data.get("found")
        status_color, status_icon = (
            (Color.SUCCESS, "✓") if found_item else (Color.WARNING, "✗")
        )
        score_info = f"({data['score']:.0f}%)" if data.get("score") is not None else ""
        display_text = found_item.display_value if found_item else "Not yet mapped"

        logging.info(
            f"  {Color.PROMPT}{i + 1}.{Color.RESET} "
            f"{expected_item:<{max_len}} → {status_color}{display_text} {status_icon} {Color.DESCRIPTION}{score_info}{Color.RESET}"
        )

    if show_unmapped and unmapped_available:
        logging.info(f"\n{Color.WARNING}Unmapped Available Items:{Color.RESET}")
        for item in unmapped_available:
            logging.info(f"  - {item.display_value}")


def fuzzy_match_and_confirm(
    expected_items: List[str],
    available_items: List[SearchableItem],
    prompt_header: str,
    show_unmapped=False,
) -> Dict[str, Any]:
    mappings = {expected: {"found": None, "score": None} for expected in expected_items}
    available_map = {item.search_value: item for item in available_items}

    # Auto-match pass
    for expected_item in expected_items:
        if not available_map:
            continue
        result = process.extractOne(expected_item, available_map.keys())
        if result and result[1] > 60:
            best_match_key = result[0]
            matched_item = available_map[best_match_key]
            mappings[expected_item]["found"] = matched_item
            mappings[expected_item]["score"] = result[1]

    # Interactive correction loop
    while True:
        mapped_items = {m["found"] for m in mappings.values() if m["found"]}
        unmapped_available = [
            item for item in available_items if item not in mapped_items
        ]
        display_mappings(mappings, unmapped_available, show_unmapped=show_unmapped)

        all_mapped = all(m["found"] for m in mappings.values())
        prompt_msg = f"\n{Color.PROMPT}Press ENTER to approve, a number to correct, or X to chose your directory again:{Color.RESET} "

        choice = input(prompt_msg).strip()

        if not choice or choice in [""]:
            if all_mapped:
                break
            else:
                print_warning(
                    "Not all required items are mapped. Please correct them or re-scan."
                )
                continue

        if choice in ["X", "x"]:
            raise FuzzySearchAborted("Retrying choice of search directory")

        if not choice.isdigit():
            print_warning("Please type a valid input.")

        try:
            idx = int(choice) - 1
            sorted_expected_keys = sorted(mappings.keys())
            item_to_correct_key = sorted_expected_keys[idx]

            logging.info(
                f"Correcting mapping for: {Color.HIGHLIGHT}{item_to_correct_key}{Color.RESET}"
            )
            available_display_values = [item.display_value for item in available_items]
            completer = FuzzyWordCompleter(available_display_values)

            new_value_display = prompt(
                "Select new value: ", completer=completer, complete_while_typing=True
            )
            selected_item = next(
                (
                    item
                    for item in available_items
                    if item.display_value == new_value_display
                ),
                None,
            )

            if selected_item:
                mappings[item_to_correct_key]["found"] = selected_item
                mappings[item_to_correct_key]["score"] = 100
                print_success(
                    f"Mapped '{item_to_correct_key}' to '{new_value_display}'"
                )
            else:
                print_error("Invalid selection.")
        except (ValueError, IndexError):
            print_error("Invalid selection. Please enter a number from the list.")

    return {
        name: mapping["found"].original_object for name, mapping in mappings.items()
    }


_keepass_password_cache = {}


def get_keepass_entries(
    expected_entries: List[str],
    search_info: str = "KeePass database",
    expected_filename: str = ".kdbx",
    default_dir="/media",
    show_unmapped=True,
) -> List[Any]:
    logging.info(f"\n{Color.TITLE}--- Step 1: Locate KeePass Database ---{Color.RESET}")
    filename_mapping = find_files_with_fuzzy_search(
        expected_filenames=[expected_filename],
        search_info=search_info,
        default_dir=default_dir,
        extension=".kdbx",
        show_unmapped=show_unmapped,
    )
    keepass_filename = filename_mapping[expected_filename]
    print_success(f"Using KeePass file: {keepass_filename}")

    kp = None
    while not kp:
        try:
            password = (
                _keepass_password_cache.get(keepass_filename)
                or Password(
                    f"Password for {os.path.basename(keepass_filename)}",
                    None,
                    alphabet=None,
                ).prompt()
            )
            kp = PyKeePass(keepass_filename, password=password)
            _keepass_password_cache[keepass_filename] = password
        except CredentialsError:
            _keepass_password_cache.pop(keepass_filename, None)
            print_error("Invalid password or keyfile. Please try again.")
        except Exception as e:
            print_error(f"An unexpected error occurred: {e}")
            raise

    logging.info(f"\n{Color.TITLE}--- Step 2: Match KeePass Entries ---{Color.RESET}")
    db_entries = kp.entries
    if not db_entries:
        print_error("The KeePass database is empty.")
        return []

    available_searchable_entries = [
        SearchableItem(e.title, e.title, e) for e in db_entries
    ]
    final_mappings = fuzzy_match_and_confirm(
        expected_items=expected_entries,
        available_items=available_searchable_entries,
        prompt_header="Enter number to correct entry mapping",
        show_unmapped=show_unmapped,
    )
    return list(final_mappings.values())


def find_files_with_fuzzy_search(
    expected_filenames: List[str],
    search_info: str,
    default_dir: str = "/media",
    extension: Optional[str] = None,
    show_unmapped=False,
) -> Dict[str, str]:
    root_completer = PathCompleter(only_directories=True, expanduser=True)
    while True:
        logging.info(
            f"Please specify the directory to search for {Color.HIGHLIGHT}{search_info}{Color.RESET} (files ending in {Color.HIGHLIGHT}{extension or 'any'}{Color.RESET})."
        )
        search_path = prompt(
            "Search directory: \n",
            completer=root_completer,
            validator=PathValidator(),
            default=default_dir,
        )
        search_path = os.path.expanduser(search_path)
        found_files = get_files(search_path, extension)
        if found_files:
            available_searchable_files = [
                SearchableItem(path, os.path.basename(path), path)
                for path in found_files
            ]
            try:
                return fuzzy_match_and_confirm(
                    expected_items=expected_filenames,
                    available_items=available_searchable_files,
                    prompt_header="Enter number to correct file path",
                    show_unmapped=show_unmapped,
                )
            except FuzzySearchAborted:
                continue

        print_warning(
            f"No files with extension '{extension}' found in that directory. Please try again."
        )


def get_files(root_path: str, extension: str = None) -> list[str]:
    """Recursively finds all files of a given extension in a directory."""
    out_files = []
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if extension is None or ext == extension:
                out_files.append(os.path.join(dirpath, filename))
    return out_files


def datenow():
    timezone = pytz.timezone("Europe/Amsterdam")
    return datetime.now(timezone).strftime("%Y-%m-%d_%H-%M-%S")


def generate_qr(data, filename):
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
