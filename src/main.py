import os
import sys
import json
import logging
import shutil
import cerberus  # type: ignore
from utils.project_logging import VaultLogger, configure_root_logger
from utils.config_checks import perform_vault_config_checks, VAULT_CONFIG_SCHEMA
from ceremonies.generate_root import generate_root
from ceremonies.generate_intermediate import generate_intermediate
from ceremonies.vault_setup import vault_setup
from ceremonies.revoke_certificate import revoke_certificate
from utils.usb import USBContext, USBDevice
from utils.utils import (
    parse_config,
    datenow,
    input_yes_or_no,
    generate_qr,
    get_client,
    VaultWrapper,
)
from colorama import Fore, Style  # type: ignore
from utils.print import print_file_loop
from utils.pdf import create_pdf
from utils.ui import Color
from utils.opencv import scan_qr_code, record_until_enter_and_feed
import hcl2  # type: ignore
import hvac
import threading

CEREM_CONFIG = os.getenv("CEREM_CONFIG")
TMP_FOLDER = "/tmp"
SOURCE_DIRECTORY = "/vault"
SOURCE_FILES = [
    "config",
    "config-vault",
    "docker-compose.yml",
    "input",
    "output",
    "scripts",
    "src",
]
VAULT_CONFIG_DIR = "/vault/config-vault/vault-config.hcl"
with open(VAULT_CONFIG_DIR) as f:
    hcl = hcl2.load(f)
VAULT_DIRECTORY = hcl.get("storage")[0].get("file").get("path")


def _validate_cerem_config(config, schema):
    v = cerberus.Validator(schema)
    if not v.validate(config):
        logging.error("Schema is not valid: ")
        logging.error(v.errors)
        sys.exit(1)
    if not perform_vault_config_checks(config):
        logging.error("Schema is not valid: ")
        sys.exit(1)


def _perform_ceremonies(client, vault_logger, config, vault_keys=None):
    results = []

    with VaultWrapper(client, vault_keys["keys"], vault_logger):
        for key, value in config.items():
            if key == "vault":
                pass
            elif key == "roots":
                for root in value:
                    try:
                        results += generate_root(client, root)
                    except Exception as e:
                        logging.error(e)
                        sys.exit(1)  # vault-seal-safe
            elif key == "intermediates":
                for intermediate in value:
                    try:
                        results += generate_intermediate(client, intermediate)
                    except Exception as e:
                        logging.error(e)
                        sys.exit(1)  # vault-seal-safe
            elif key == "revocation":
                for revocation in value:
                    try:
                        results += revoke_certificate(client, revocation)
                    except Exception as e:
                        logging.error(e)
                        sys.exit(1)  # vault-seal-safe

    return results


def _store_vault_data(destination, vault_dir=VAULT_DIRECTORY):
    dst = os.path.join(destination, "vault_data")
    os.makedirs(dst, exist_ok=True)
    for item in os.listdir(vault_dir):
        s = os.path.join(vault_dir, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, dirs_exist_ok=True)
        else:
            shutil.copy2(s, d)


def _store_source_directory(
    destination, items=SOURCE_FILES, source_dir=SOURCE_DIRECTORY
):
    dst_root = os.path.join(destination)
    os.makedirs(dst_root, exist_ok=True)

    for item in items:
        # Build full path to the source item
        src_path = os.path.join(source_dir, item)
        dest_path = os.path.join(dst_root, item)

        if os.path.isdir(src_path):
            shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
        else:
            shutil.copy2(src_path, dest_path)


def _store_pem_files(data, output_path, filename):
    data_json = json.loads(data)
    if "ca_chain" in data_json.keys():
        with open(
            f"{output_path}/{filename.replace('.json', '').replace('.txt', '')}.crt",
            "w",
        ) as file:
            for cert in data_json.get("ca_chain"):
                file.write(cert.strip() + "\n")
    elif "certificate" in data_json.keys():
        with open(
            f"{output_path}/{filename.replace('.json', '').replace('.txt', '')}.crt",
            "w",
        ) as file:
            file.write(data_json.get("certificate").strip())
    elif "crl" in data_json.keys():
        with open(
            f"{output_path}/{filename.replace('.json', '').replace('.txt', '')}.crl",
            "w",
        ) as file:
            file.write(data_json.get("crl").strip())


def _create_store_pdf_and_print(message, path, title, text, image_paths):
    create_pdf(
        path,
        title,
        text,
        image_paths,
    )

    print_file_loop(message, path)


def _store_keys_vault_and_ceremony_results(vault_config, key_data, ceremony_results):

    vault_name = vault_config["name"]
    secret_threshold = vault_config["secret_threshold"]
    secret_shares = vault_config["secret_shares"]
    root_token = key_data.get("root_token")
    print_queue = []

    if os.getenv("ENVIRONMENT") == "develop":
        TMP_RESULTS = "/vault/output"

        for i in range(len(key_data.get("keys"))): 
            logging.info("Storing Key share...")
            with open(
                f"{TMP_RESULTS}/{vault_name}_custodian{i + 1}_{secret_threshold}_{secret_shares}",
                "w",
            ) as file:
                file.write(key_data.get("keys")[i])
            with open(f"{TMP_RESULTS}/{vault_name}_roottoken", "w") as file:
                file.write(root_token)

        logging.info("Storing Ceremony Outputs...")
        for filename, data in ceremony_results:
            _store_pem_files(data, TMP_RESULTS, filename)
        
        return

    for i in range(len(key_data.get("keys"))):
        fresh_usb = False
        while not fresh_usb:
            logging.info(
                Fore.BLUE
                + Style.BRIGHT
                + f"Please connect the Key Custodian {i + 1}'s storage USB device..."
            )

            usb_context = USBContext.get_instance()
            usb_device = _select_usb_and_mount(usb_context)

            mounted_folder = usb_device.mount_path
            output_path = os.path.join(mounted_folder, f"Cerem - {datenow()}")
            os.mkdir(output_path)

            # Additional Folders
            output_path_documents = os.path.join(output_path, "documents")
            output_path_certificates = os.path.join(output_path, "certificates")
            output_path_source = os.path.join(output_path, "source")

            for item in [
                output_path_documents,
                output_path_certificates,
                output_path_source,
            ]:
                os.mkdir(item)

            if f"{vault_name}_custodian" in ",".join(os.listdir(mounted_folder)):
                logging.error(
                    "USB Device contains already a key share. Please connect a fresh USB."
                )
                _unmount_usb_device(usb_context, usb_device)
                continue
            else:
                fresh_usb = True

            logging.info("Storing Vault contents...")
            _store_vault_data(output_path)

            logging.info("Storing source contents...")
            _store_source_directory(output_path_source)

            logging.info("Storing Key share...")
            with open(
                f"{mounted_folder}/{vault_name}_custodian{i + 1}_{secret_threshold}_{secret_shares}",
                "w",
            ) as file:
                file.write(key_data.get("keys")[i])
            with open(f"{mounted_folder}/{vault_name}_roottoken", "w") as file:
                file.write(root_token)

            logging.info("Storing Ceremony Outputs...")
            for filename, data in ceremony_results:
                _store_pem_files(data, output_path_certificates, filename)
                filename_base, _ = os.path.splitext(filename)
                path_pdf = os.path.join(output_path_documents, f"{filename_base}.pdf")
                create_pdf(
                    path_pdf,
                    filename_base + " / " + datenow(),
                    data,
                )
                # print_queue.append(
                #     (Fore.BLUE + Style.BRIGHT + f"Would you like to print {path_pdf}?", os.path.join("/tmp", path_pdf.lstrip("/")))
                # )

            with open(os.path.join(TMP_FOLDER, "log.txt"), "r") as file:
                log_data = file.read()
            with open(os.path.join(TMP_FOLDER, ".bash_history"), "r") as file:
                bash_data = file.read()

            logging.info("Storing Logs...")
            with open(f"{output_path_documents}/log.txt", "w") as file:
                file.write(log_data)
            with open(f"{output_path_documents}/bash_log.txt", "w") as file:
                file.write(bash_data)

            create_pdf(
                f"{output_path_documents}/{'log' + '.pdf'}",
                "Ceremony Logs " + " / " + datenow(),
                log_data
                + "\n\n ==================== Bash history ==================== \n\n"
                + bash_data,
            )
            # print_queue.append(
            #     (Fore.BLUE + Style.BRIGHT + f"Would you like to print log.pdf?", os.path.join("/tmp", f"{output_path}/{'log' + '.pdf'}".lstrip("/"))))

            logging.info(Fore.GREEN + "Storing Done!")

            _unmount_usb_device(usb_context, usb_device)

        logging.info("Begin Printing process...")

        qr_image_filename = os.path.join(TMP_FOLDER, vault_name + "share-" + str(i + 1))
        generate_qr(key_data.get("keys")[i], qr_image_filename)
        _create_store_pdf_and_print(
            f"Would you like to print {vault_name}_custodian{i + 1}_{secret_threshold}_{secret_shares}.pdf ?",
            f"{TMP_FOLDER}/{vault_name}_custodian{i + 1}_{secret_threshold}_{secret_shares}.pdf",
            f"{vault_name} Custodian: \n#{i + 1} of {secret_threshold}-out-of-{secret_shares} secret sharing scheme",
            key_data.get("keys")[i],
            [qr_image_filename],
        )

        for prt_msg, prt_file in print_queue:
            print_file_loop(prt_msg, prt_file)

        logging.info(Fore.GREEN + "Printing Done!")
        print_queue = []


def _store_vault_and_ceremony_results(ceremony_results):
    print_queue = []

    if os.getenv("ENVIRONMENT") == "develop":
        TMP_RESULTS = "/vault/output"
        logging.info("Storing Ceremony Outputs...")
        for filename, data in ceremony_results:
            _store_pem_files(data, TMP_RESULTS, filename)
        
        return

    logging.info("Please connect your USB device...")

    usb_context = USBContext.get_instance()
    usb_device = _select_usb_and_mount(usb_context)

    mounted_folder = usb_device.mount_path
    output_path = os.path.join(mounted_folder, f"Cerem - {datenow()}")
    os.mkdir(output_path)

    # Additional Folders
    output_path_documents = os.path.join(output_path, "documents")
    output_path_certificates = os.path.join(output_path, "certificates")
    output_path_source = os.path.join(output_path, "source")

    for item in [output_path_documents, output_path_certificates, output_path_source]:
        os.mkdir(item)

    logging.info("Storing Vault contents...")
    _store_vault_data(output_path)

    logging.info("Storing source contents...")
    _store_source_directory(output_path_source)

    logging.info("Storing Ceremony Outputs...")
    for filename, data in ceremony_results:
        _store_pem_files(data, output_path_certificates, filename)
        filename_base, _ = os.path.splitext(filename)
        filename = f"{output_path_documents}/{datenow()}-{filename_base}.pdf"
        create_pdf(
            filename,
            filename_base + " / " + datenow(),
            data,
        )
        # print_queue.append(
        #     (f"Would you like to print {filename}?", os.path.join("/tmp", filename.lstrip("/"))))

    with open(os.path.join(TMP_FOLDER, "log.txt"), "r") as file:
        log_data = file.read()
    with open(os.path.join(TMP_FOLDER, ".bash_history"), "r") as file:
        bash_data = file.read()

    logging.info("Storing Logs...")
    with open(f"{output_path_documents}/log.txt", "w") as file:
        file.write(log_data)
    with open(f"{output_path_documents}/bash_log.txt", "w") as file:
        file.write(bash_data)

    create_pdf(
        f"{output_path_documents}/{'log' + '.pdf'}",
        "Ceremony Logs " + " / " + datenow(),
        log_data
        + "\n\n ==================== Bash history ==================== \n\n"
        + bash_data,
    )

    logging.info(Fore.GREEN + "Storing Done!")

    # print_queue.append(
    #     (f"Would you like to print log.pdf?", os.path.join("/tmp", os.path.join(output_path_documents, datenow() + "log" + ".pdf").lstrip("/"))))

    _unmount_usb_device(usb_context, usb_device)

    for prt_msg, prt_file in print_queue:
        print_file_loop(prt_msg, prt_file)

    logging.info(Fore.GREEN + "Printing Done!")


def _input_key_shares(vault_name, threshold, QR=False):
    root_token = None
    key_shares = []

    if QR: 
        for i in range(threshold):
            key_shares.append(scan_qr_code())
        return {"keys": key_shares}

    usb_context = USBContext.get_instance()

    while len(key_shares) < threshold:
        if not input_yes_or_no("You have the option to import the key share through USB or QR code. Press Y:  USB, N: QR."):
            key_shares.append(scan_qr_code())
            continue

        logging.info(
            Fore.BLUE
            + Style.BRIGHT
            + "Please connect a USB device containing a custodian's key share."
        )

        selected_device = _select_usb_and_mount(usb_context)
        mounted_folder = selected_device.mount_path

        if not root_token:
            rootstring = f"{vault_name}_roottoken"
            root_filename = key_filename = next(
                (s for s in os.listdir(mounted_folder) if rootstring in s), None
            )
            if root_filename:
                with open(os.path.join(mounted_folder, key_filename)) as file:
                    root_token = file.read()

        keystring = f"{vault_name}_custodian"
        key_filename = next(
            (s for s in os.listdir(mounted_folder) if keystring in s), None
        )
        if not key_filename:
            logging.error(
                f"Key file for vault {vault_name} not in the root of this USB device. Please connect another one."
            )
            _unmount_usb_device(usb_context, selected_device)
            continue
        with open(os.path.join(mounted_folder, key_filename), "r") as file:
            key_share = file.read()
            key_shares.append(key_share)
        logging.info(f"{Color.GREEN}Key recognized{Color.RESET}")
        _unmount_usb_device(usb_context, selected_device)
        
    return {"keys": key_shares, "root_token": root_token}


def _unmount_usb_device(usb_context, usb_device):
    logging.info("Unmounting the selected USB device...")

    if usb_context.unmount_device_manual(usb_device):
        logging.info(
            f"USB {usb_device.name} ({usb_device.label}) - Serial: {usb_device.serial} has been safely unmounted and can now be removed."
        )
    else:
        logging.info(
            f"{Fore.YELLOW}Warning: There may have been an issue unmounting {usb_device.name} ({usb_device.label}) - Serial: {usb_device.serial}. Check system logs and potentially unmount manually.{Style.RESET_ALL}"
        )


def _select_usb_and_mount(usb_context) -> USBDevice:
    input_yes_or_no("Confirm USB insertion.")
    usb_selected = False
    while not usb_selected:
        try:
            # Get list of available USB devices
            usb_devices = usb_context.list_available_usb_drives()

            if not usb_devices:
                if input_yes_or_no("No USB devices found! Try again?"):
                    continue
                else:
                    return

            logging.info(f"Found {len(usb_devices)} USB device(s)")
            for i, device in enumerate(usb_devices, 1):
                logging.info(
                    f"{i}. {device.name} ({device.label}) - Serial: {device.serial} - Mounted: {usb_context.is_device_name_mounted(device.name)}"
                )

            choice = input(
                f"Select a USB device (1-{len(usb_devices)}) or 'x' to re-scan: "
            ).strip()
            print("\n")
            if choice.lower() in ["", "x"]:
                continue

            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(usb_devices):
                selected_device = usb_devices[choice_idx]
                usb_selected = True
            else:
                logging.info(f"Please enter a number between 1 and {len(usb_devices)}")
        except ValueError:
            logging.info("Please enter a valid number or 'x' to re-scan")

        # Check if device is already mounted by USBContext using hash
        mounted_devices = usb_context.get_mounted_devices()

        selected_device_already_mounted_by_context = False
        for mounted_device in mounted_devices:
            if mounted_device == selected_device:
                selected_device = mounted_device
                selected_device_already_mounted_by_context = True
                break

        if usb_context.is_device_name_mounted(selected_device.name):
            if not selected_device_already_mounted_by_context:
                logging.info(
                    "Device mounted but not tracked by USBContext: Adding to tracked devices"
                )
                usb_context.add_to_mounted_devices(selected_device)
            # otherwise already mounted by context

        else:
            logging.info("Mounting USB device...")
            if not usb_context.mount_device_manual(selected_device):
                logging.info("Failed to mount the selected USB device!")
                usb_selected = False
                continue

        return selected_device

def _generate_new_root_token(keys, client, vault_logger):
    with VaultWrapper(client, keys, vault_logger) as vault_wrapper:
        start_gen = client.sys.start_root_token_generation()
        nonce = start_gen.get("nonce")
        otp = start_gen.get("otp")

        for i in range(len(keys)):
            res = client.sys.generate_root(
                key=keys[i],
                nonce=nonce,
            )
        
        if res.get("encoded_root_token"):
            # Create a new unauthenticated client for decoding
            decode_client = hvac.Client(url=client.url)
            # Make sure no token is set
            decode_client.token = None
            
            decoded_token = decode_client.write(
                "sys/decode-token", 
                encoded_token= res.get("encoded_root_token"), 
                otp=otp
            ).get("data").get("token")

            vault_wrapper.client.token = decoded_token
            return decoded_token
    return None

def main():
    # configure logger
    configure_root_logger()
    vault_logger = VaultLogger()

    # Initialize variables, parse config, validate config
    vault_config = None
    vault_keys = None
    vault_created = False
    full_config = parse_config(CEREM_CONFIG)
    _validate_cerem_config(full_config, VAULT_CONFIG_SCHEMA)
    full_config = full_config["ceremony"]
    vault_config = full_config.get("vault")
    utilities_config = full_config.get("utilities")

    # Wipe log.txt if present
    open(os.path.join(TMP_FOLDER, "log.txt"), "w").close()

    # disable http logging
    vault_logger.seal()

    # Define vault client
    vault_client = get_client(os.getenv("VAULT_ADDR"), vault_logger)

    if utilities_config and utilities_config.get("video_entropy"):
        input_yes_or_no("Press Enter to start recording to add entropy")
        record_until_enter_and_feed()

    with USBContext.get_instance():
        # If create == True, create a vault.
        if vault_config.get("create"):
            if vault_client.sys.is_initialized():
                logging.error(
                    "Cannot create new vault. This vault is already initialized."
                )
                sys.exit(1)
            vault_keys, vault_created = vault_setup(vault_client, vault_config)
            ceremony_config = {k: v for k, v in full_config.items() if k != "vault"}

        # Otherwise, read key shares from USB
        else:
            new_root_token = vault_config.get("new_root_token") #TODO 
            qr_secret = vault_config.get("qr_secret")

            vault_keys = _input_key_shares(
                vault_config.get("name"), vault_config.get("secret_threshold"), qr_secret
            )
            ceremony_config = {k: v for k, v in full_config.items() if k != "vault"}

        if not vault_keys["root_token"]:
            vault_keys["root_token"] = _generate_new_root_token(
                vault_keys["keys"], vault_client, vault_logger)
        vault_client.token = vault_keys["root_token"]
        ceremony_results = _perform_ceremonies(
            vault_client, vault_logger, ceremony_config, vault_keys
        )

        logging.info(Fore.GREEN + "=======Ceremony Complete!=======")
        logging.info("Output files ready to be stored.")

        if vault_created:
            logging.info(
                "New Key shares have been generated. Beginning storage process"
            )
            _store_keys_vault_and_ceremony_results(
                vault_config, vault_keys, ceremony_results
            )
            while input_yes_or_no(
                "==> Would you like to store the results on an additional device?"
            ):
                logging.info("Beginning storage process")
                _store_vault_and_ceremony_results(ceremony_results)

        else:
            more_storage_drives = True
            while more_storage_drives:
                logging.info("Beginning storage process")
                _store_vault_and_ceremony_results(ceremony_results)
                more_storage_drives = input_yes_or_no(
                    "==> Would you like to store the results on an additional device?"
                )

        logging.info(Fore.GREEN + "=======Storage Complete!=======")
    logging.info("Shutting down")


if __name__ == "__main__":
    main()
