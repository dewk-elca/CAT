import sys
import json
import logging
import subprocess
from utils.utils import input_yes_or_no
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


def revoke_certificate(client, config):
    issuer_mount_path_name = config["issuer_mount_path_name"]
    certificate = (
        config["certificate"]
        .strip("'")
        .strip('"')
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )

    if not client.sys.is_initialized():
        logging.info("Vault not yet initialized or vault sealed")
        raise Exception("Revoke certificate failed: vault is not initialized")

    intermediate_mount_open = (
        issuer_mount_path_name + "/" not in client.sys.list_mounted_secrets_engines()
    )

    if intermediate_mount_open:
        logging.error(f"Vault mount {issuer_mount_path_name} does not exist in vault")
        raise Exception(
            f"Revoke certificate failed: Specified vault mount path dotes not exist: {issuer_mount_path_name}"
        )

    cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
    serial_hex = format(cert.serial_number, "x")

    if not input_yes_or_no(
        f"""Revoke cerificate with serial number: {serial_hex}
        from PKI mount: {issuer_mount_path_name}? """
    ):
        logging.info("User denied the signing request, shutting down")
        sys.exit(1)

    # Revoke certificate here
    logging.info(
        f"Revoking the cerificate {serial_hex} with mount {issuer_mount_path_name}... "
    )

    revoke_resp = client.write(
        certificate=certificate, path=f"{issuer_mount_path_name}/revoke"
    )

    if not revoke_resp.get("data") or not revoke_resp.get("data").get(
        "revocation_time"
    ):
        print("REVOCATION FAILED", revoke_resp)
        sys.exit(1)

    crl_info = client.secrets.pki.read_crl(mount_point=issuer_mount_path_name)

    logging.info("================== The resulting CRL: ================== ")

    result = subprocess.run(
        ["openssl", "crl", "-text", "-noout"],      # no -in option
        input=crl_info,                             # pass cert to stdin
        text=True,                                  # treat input/output as text (str)
        capture_output=True,                        # capture stdout/stderr
        check=True
    )
    logging.info(f"\n{result.stdout}")

    root_info = client.secrets.pki.read_ca_certificate(
        mount_point=issuer_mount_path_name
    )

    # Load the certificate
    cert = x509.load_pem_x509_certificate(root_info.encode(), default_backend())

    # Extract the Common Name (CN) from the Subject
    cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = cn_attributes[0].value

    return [
        (
            (
                f"CRL-{common_name}",
                json.dumps({"crl": crl_info}),
            )
        )
    ]
