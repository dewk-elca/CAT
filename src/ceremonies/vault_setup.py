import sys
import logging
from utils.utils import input_yes_or_no


def vault_setup(client, config):
    secret_shares = config["secret_shares"]
    secret_threshold = config["secret_threshold"]

    logging.info("Checking if vault is initialized")
    if client.sys.is_initialized():
        logging.info("Vault already initialized.")
        return None, False

    logging.info("Initializing vault with secret shares")
    if not input_yes_or_no(
        f"""==> Initialize Vault with configurations: ? 
        secret shares: {secret_shares}, 
        secret threshold: {secret_threshold}"""
    ):
        sys.exit(1)
    req_initialize = client.sys.initialize(secret_shares, secret_threshold)

    return req_initialize, True
