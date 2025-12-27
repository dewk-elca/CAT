import yaml
import time
import qrcode  # type: ignore
import logging
import subprocess
import json
import hvac
import requests
from datetime import datetime
from colorama import Fore, Style  # type: ignore


class VaultWrapper:
    def __init__(self, client, keys, vault_logger):
        self.client = client
        self.keys = keys
        self.vault_logger = vault_logger

    def __enter__(self):
        logging.info("Unsealing vault with key shares...")
        resp_unseal = self.client.sys.submit_unseal_keys(self.keys)
        if resp_unseal.get("sealed"):
            logging.error("The provided key shares do not open the vault.")
            raise Exception("Generate root failed: Wrong vault key shares")
        logging.info("Vault unsealed.")
        self.vault_logger.unseal()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        logging.info("Sealing vault after ceremonies...")
        self.client.sys.seal()
        logging.info("Vault sealed.")
        self.vault_logger.seal()


def get_client(url, vault_logger):
    logging.info("Connecting to Vault...")

    while True:
        try:
            client = hvac.Client(url=url, session=vault_logger.session)
            client.sys.read_health_status()
            return client

        except requests.exceptions.ConnectionError:
            logging.info("Waiting for Vault...")
            time.sleep(1)


# --- Config parser ---
def parse_config(path):
    with open(path, "r") as file:
        return yaml.safe_load(file)


def input_yes_or_no(message):
    prinited_message = (
        Fore.BLUE + Style.BRIGHT + f"{message} \n Y/n:\n " + Style.RESET_ALL
    )
    logging.debug(prinited_message)
    response = input(prinited_message)
    if response in ["y", "Y", ""]:
        logging.debug("User chose YES")
        return True
    logging.debug("User chose NO")
    return False


def datenow():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def generate_qr(data, filename):
    qr = qrcode.QRCode(
        version=1,  # auto-size from 1 to 40
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)


def list_usb_drives():
    output = subprocess.check_output(["lsblk", "-J", "-o", "NAME,LABEL,RM"], text=True)
    devices = json.loads(output).get("blockdevices")
    filtered = [
        {
            "name": dev.get("children")[0].get("name"),
            "label": dev.get("children")[0].get("label"),
        }
        for dev in devices
        if dev.get("name", "").startswith("sd") and dev.get("rm") is True
    ]
    return filtered


def load_file_json(path):
    with open(path, "r") as file:
        return json.loads(file.read())


def csr_to_dict(csr_obj):
    return {
        "subject": {attr.oid._name: attr.value for attr in csr_obj.subject},
        "extensions": [ext.oid._name for ext in csr_obj.extensions],
    }


def csr_openssl_text(csr_pem: str) -> str:
    # spawn openssl, feed it the CSR on stdin
    proc = subprocess.run(
        ["openssl", "req", "-noout", "-text"],
        input=csr_pem.encode(),
        capture_output=True,
        check=True,
    )
    return proc.stdout.decode()


def config_to_oid_map(config):
    # Do not forget to tabulate crl: .
    # Do not forget: key_type, key_bits
    # Do not forget to tabulate mount and certificate, csr
    # Do not forget to show not before and after even if not included in csr
    res = {}
    if config.get("common_name"):
        res["2.5.4.3"] = config.get("common_name")
