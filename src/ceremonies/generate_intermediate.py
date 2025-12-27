import json
import sys
import logging
import subprocess
from utils.utils import input_yes_or_no
from utils.csr_linter import compare_csr_to_config, int_config_to_comparison_format
from colorama import Fore, Style
from utils.ui import find_files_with_fuzzy_search, Color

USE_CSR_VALUES = True

EXCLUDE_FROM_GENERATE_INTERMEDIATE = [
    "path",
    "common_name",
    "ttl",
    "max_path_length",
    "permitted_dns_domains",
    "excluded_dns_domains",
    "permitted_ip_ranges",
    "excluded_ip_ranges",
    "permitted_email_addresses",
    "excluded_email_addresses",
    "permitted_uri_domains",
    "excluded_uri_domains",
    "not_before_duration",
    "not_after",
]

EXCLUDE_FROM_SIGN_INTERMEDIATE = [
    "path",
    "common_name",
    "key_name",
    "key_type",
    "key_bits",
    "add_basic_constraints",
]


def generate_intermediate(client, config):
    vault_signing_mount_path_name = config.get("vault_signing_mount_path_name")
    config_mount = config.get("mount")
    config_csr = config.get("csr")

    if config_mount:
        vault_mount_path_name = config_mount.get("vault_mount_path_name")
        vault_mount_description = config_mount.get("vault_mount_description")
        vault_mount_default_lease_ttl = config_mount.get(
            "vault_mount_default_lease_ttl"
        )
        crl_expiry = config_mount.get("crl").get("expiry")
        crl_distribution_points = config_mount.get("crl").get("distribution_points")
        issuing_certificates = config_mount.get("issuing_certificates")
        merged_params = config_csr | config_mount.get(
            "keypair"
        )  # prio mount settings especially for key info
    else:
        vault_mount_path_name = None
        merged_params = config_csr

    common_name = config_csr.get("common_name")
    requested_distribution_points = config_csr.get("distribution_points")
    requested_issuing_certificates = config_csr.get("issuing_certificates")

    generate_intermediate_extra_params = {
        k: v
        for k, v in merged_params.items()
        if k not in EXCLUDE_FROM_GENERATE_INTERMEDIATE
    }
    sign_intermediate_extra_params = {
        k: v
        for k, v in merged_params.items()
        if k not in EXCLUDE_FROM_SIGN_INTERMEDIATE
    }
    sign_intermediate_extra_params["use_csr_values"] = USE_CSR_VALUES

    if not client.sys.is_initialized():
        logging.info("Vault not yet initialized or vault sealed")
        raise Exception("Generate Intermediate failed: vault is not initialized")

    intermediate_mount_open = (
        ({vault_mount_path_name} + "/" not in client.sys.list_mounted_secrets_engines())
        if vault_mount_path_name
        else False
    )

    logging.info(f"{Color.BLUE}Connect any USB drives containing CSRs{Color.RESET}")
    filename_mapping = find_files_with_fuzzy_search(
        expected_filenames=[config_csr.get("expected_filename")],
        search_info=f"CSR file location for Intermediate: {common_name}",
        default_dir="/media/usb",
    )
    for _, real_filename in filename_mapping.items():
        csr_location = real_filename

    output_filename = f"{common_name}"

    if csr_location:
        logging.info("Taking in provided CSR")
        with open(csr_location, "r") as file:
            csr = file.read()
            logging.info(
                f"CSR Loaded. {Color.BLUE}You may disconnect any USB drives{Color.RESET}"
            )

        config_comparison_format = int_config_to_comparison_format(config)
        summary, csr_to_config_comparison = compare_csr_to_config(
            csr, config_comparison_format, "csr"
        )

    else:
        if not intermediate_mount_open:
            logging.error(
                f"Vault mount {vault_mount_path_name} already exists in Vault."
            )
            raise Exception(
                f"Generate Intermediate failed: Intermediate vault mount path exists: {vault_mount_path_name}"
            )

        logging.info(f"Mounting a secrets engine to the path {vault_mount_path_name}")
        client.sys.enable_secrets_engine(
            backend_type="pki",
            path=vault_mount_path_name,
            description=vault_mount_description,
            config={"default_lease_ttl": vault_mount_default_lease_ttl},
        )

        # Add CRL configuration immediately after mounting
        logging.info("Configuring CRL settings for intermediate")
        client.secrets.pki.set_crl_configuration(
            expiry=crl_expiry, disable=False, mount_point=vault_mount_path_name
        )

        # Configure URLs for certificates issued by this intermediate
        logging.info("Configuring URLs for intermediate CA")
        client.secrets.pki.set_urls(
            {
                "issuing_certificates": [issuing_certificates],
                "crl_distribution_points": [crl_distribution_points],
            },
            mount_point=vault_mount_path_name,
        )

        logging.info(
            f"Generating new Intermediate key pair and Intermediate CSR at mount: {vault_mount_path_name}"
        )
        csr_response = client.secrets.pki.generate_intermediate(
            type="internal",
            common_name=common_name,
            mount_point=vault_mount_path_name,
            extra_params=generate_intermediate_extra_params,
        )
        csr = csr_response["data"]["csr"]

    if not input_yes_or_no(
        # f"""==> Sign CSR: {json.dumps(csr_to_dict(x509.load_pem_x509_csr(csr.encode())), indent=2)}
        f"""==> Sign this CSR with root at mount: {vault_signing_mount_path_name}?\n{Style.RESET_ALL}{csr_to_config_comparison}{Fore.BLUE + Style.BRIGHT}"""
    ):
        logging.info("User denied the signing request, shutting down")
        sys.exit(1)
    logging.info("Signing the scr with root")

    if csr_location and requested_distribution_points and requested_issuing_certificates:
        # Change the root's CRL and AIA
        logging.info("Configuring CRL settings for signer Root")
        client.secrets.pki.set_urls(
            {
                "issuing_certificates": [requested_issuing_certificates],
                "crl_distribution_points": [requested_distribution_points],
            },
            mount_point=vault_signing_mount_path_name,
        )

    signed_cert = client.secrets.pki.sign_intermediate(
        csr=csr,
        # use_csr_values=USE_CSR_VALUES, # Possible conflict
        common_name=common_name,
        mount_point=vault_signing_mount_path_name,
        extra_params=sign_intermediate_extra_params,
    )
    int_cert = signed_cert["data"]["certificate"]

    if not csr_location:
        logging.info(
            f"Setting the Intermediate Cert on the mount {vault_mount_path_name}"
        )
        client.secrets.pki.set_signed_intermediate(
            certificate=int_cert,
            mount_point=vault_mount_path_name,
        )

    logging.info(f"{Color.GREEN}Intermediate generation done!{Color.RESET}")
    logging.info("================== The resulting certificate: ================== ")

    result = subprocess.run(
        ["openssl", "x509", "-text", "-noout"],      # no -in option
        input="\n".join(signed_cert["data"]["ca_chain"]),                             # pass cert to stdin
        text=True,                                  # treat input/output as text (str)
        capture_output=True,                        # capture stdout/stderr
        check=True
    )
    logging.info(f"\n{result.stdout}")

    return [
        (
            (
                output_filename,
                json.dumps(signed_cert["data"], indent=4),
            )
        ),
    ]
