import sys
import json
import logging
import subprocess
from utils.utils import input_yes_or_no
from utils.ui import Color

EXCLUDE_FROM_ROOT_GENERATION_PARAMS = ["common_name"]


def generate_root(client, config):
    config_mount = config.get("mount")
    config_certificate = config.get("certificate")
    crl = config_mount.get("crl")
    crl_expiry = config_mount.get("crl").get("expiry")
    crl_distribution_points = config_mount.get("crl").get("distribution_points")

    vault_mount_path_name = config_mount.get("vault_mount_path_name")
    vault_mount_description = config_mount.get("vault_mount_description")
    vault_mount_default_lease_ttl = config_mount.get("vault_mount_default_lease_ttl")
    

    common_name = config_certificate.get("common_name")
    merged_params = config_mount.get("keypair") | config_certificate
    extra_params = {
        k: v
        for k, v in merged_params.items()
        if k not in EXCLUDE_FROM_ROOT_GENERATION_PARAMS
    }

    if not client.sys.is_initialized():
        logging.info("Vault not yet initialized or vault sealed")
        raise Exception("Generate root failed: vault is not initialized")

    logging.info("Checking configured mounts on secrets engine")
    if not vault_mount_path_name + "/" not in client.sys.list_mounted_secrets_engines():
        logging.error(f"Vault mount {vault_mount_path_name} already exists in Vault.")
        raise Exception(
            f"Generate root failed: vault mount path already exists: {vault_mount_path_name}"
        )

    logging.info(f"Mounting a secrets engine to the path {vault_mount_path_name}")
    client.sys.enable_secrets_engine(
        backend_type="pki",
        path=vault_mount_path_name,
        description=vault_mount_description,
        config={"default_lease_ttl": vault_mount_default_lease_ttl},
    )

    logging.info("Configuring CRL settings for root")
    client.secrets.pki.set_crl_configuration(
        expiry=crl_expiry, disable=False, mount_point=vault_mount_path_name
    )

    if crl_distribution_points:
        # Configure URLs for certificates issued by this intermediate
        logging.info("Configuring URLs for root CA")
        if crl_distribution_points:
            client.secrets.pki.set_urls(
                {
                    "crl_distribution_points": [crl_distribution_points],
                },
                mount_point=vault_mount_path_name,
            )
        message = f"""==> Generate Root key pair and certificate with config: 
        -mount: {vault_mount_path_name} 
        -common name: {common_name} 
        -crl: distribution points: {crl_distribution_points}, expiry: {crl_expiry}
        -extra params: \n            - {"\n            - ".join([f"{k}: {v}" for k, v in extra_params.items()])}?"""
    
    message = f"""==> Generate Root key pair and certificate with config: 
    -mount: {vault_mount_path_name} 
    -common name: {common_name} 
    -crl expiry: {crl_expiry}
    -extra params: \n            - {"\n            - ".join([f"{k}: {v}" for k, v in extra_params.items()])}?"""
    

    if not input_yes_or_no(message):
        logging.info("User denied the request, shutting down")
        sys.exit(1)

    logging.info(
        f"Generating new root key pair and root certificate at mount: {vault_mount_path_name}"
    )

    pki_response = client.secrets.pki.generate_root(
        type="internal",
        common_name=common_name,
        mount_point=vault_mount_path_name,
        extra_params=extra_params,
    )

    logging.info(f"{Color.GREEN}Root generation done!{Color.RESET}")
    logging.info("================== The resulting certificate: ==================")

    result = subprocess.run(
        ["openssl", "x509", "-text", "-noout"],      # no -in option
        input=pki_response["data"]["certificate"],                             # pass cert to stdin
        text=True,                                  # treat input/output as text (str)
        capture_output=True,                        # capture stdout/stderr
        check=True
    )
    logging.info(f"\n{result.stdout}")

    crl_info = client.secrets.pki.read_crl(mount_point=vault_mount_path_name)

    logging.info("================== The resulting CRL: ================== ")
    result = subprocess.run(
        ["openssl", "crl", "-text", "-noout"],      # no -in option
        input=crl_info,                             # pass cert to stdin
        text=True,                                  # treat input/output as text (str)
        capture_output=True,                        # capture stdout/stderr
        check=True
    )
    logging.info(f"\n{result.stdout}")

    return [
        (
            (
                f"{common_name}",
                json.dumps(pki_response["data"], indent=4),
            )
        ),
        (
            (
                f"CRL-{common_name}",
                json.dumps({"crl": crl_info}),
            )
        ),
    ]
