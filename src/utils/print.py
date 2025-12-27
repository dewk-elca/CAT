import cups
import os
import logging
import platform
from utils.utils import datenow, input_yes_or_no
from utils.pdf import create_pdf


def print_file_loop(message, path):
    loop = input_yes_or_no(message)
    while loop:
        try:
            print_file(path)
            loop = False
        except ValueError as e:
            logging.error(f"Print failed with error: {e}")
            loop = input_yes_or_no(f"Retrying: {message}")


def print_file(path, server="cups:631"):
    if not os.path.isfile(path):
        raise ValueError(f"Error:  File not found: {path}")

    # Connect to CUPS at host cups, port 631
    cups.setServer(server)
    conn = cups.Connection()

    # Determine printer
    printer = conn.getDefault()
    if not printer:
        printers = conn.getPrinters()
        if not printers:
            raise ValueError(f"Error: No printers available on {server}")
        printer = next(iter(printers))
        logging.info(f"No default printer set; using '{printer}'")

    # Submit print job
    job_name = f"{datenow()}_{os.path.basename(path)}"

    job_id = conn.printFile(printer, path, job_name, {})
    logging.info(f"Print job submitted: ID {job_id}")


def test_print():
    current_time = datenow()
    os_info = f"{platform.system()} {platform.release()}"
    arch = platform.machine()
    python_version = platform.python_version()

    test_content = f"""Date: {current_time}

    -- System Info --
    OS: {os_info} ({arch})
    Python: {python_version}

    This test page verifies proper printer functionality and displays system configuration. All components operational.
    """

    create_pdf("/tmp/test.pdf", "Test Print", test_content)
    print_file("/tmp/test.pdf")
