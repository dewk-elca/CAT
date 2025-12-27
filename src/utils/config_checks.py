import logging
import re
from datetime import datetime

VAULT_CONFIG_SCHEMA = {
    "ceremony": {
        "type": "dict",
        "required": True,
        "schema": {
            "utilities": {
                "type": "dict",
                "required": False,
                "schema": {
                    "video_entropy": {"type": "boolean", "required": False},
                },
            },
            "vault": {
                "type": "dict",
                "required": True,
                "schema": {
                    "create": {"type": "boolean", "required": True},
                    "secret_shares": {"type": "integer", "required": True},
                    "secret_threshold": {"type": "integer", "required": True},
                    "name": {"type": "string", "required": True},
                    # "new_root_token": {"type": "integer", "required": False},
                    # "qr_secret": {"type": "string", "required": False},
                },
            },
            "roots": {
                "type": "list",
                "required": False,
                "schema": {
                    "type": "dict",
                    "schema": {
                        "mount": {
                            "type": "dict",
                            "required": True,
                            "schema": {
                                "vault_mount_path_name": {
                                    "type": "string",
                                    "required": True,
                                },
                                "vault_mount_description": {
                                    "type": "string",
                                    "required": True,
                                },
                                "vault_mount_default_lease_ttl": {
                                    "type": "string",
                                    "required": True,
                                },
                                "crl": {
                                    "type": "dict",
                                    "required": True,
                                    "schema": {
                                        "expiry": {"type": "string", "required": True},
                                        "distribution_points": {
                                            "type": "string",
                                            "required": False,
                                        },
                                    },
                                },
                                "keypair": {
                                    "type": "dict",
                                    "required": True,
                                    "schema": {
                                        "key_name": {
                                            "type": "string",
                                            "required": True,
                                        },
                                        "key_type": {
                                            "type": "string",
                                            "required": True,
                                        },
                                        "key_bits": {
                                            "type": "integer",
                                            "required": True,
                                        },
                                    },
                                },
                            },
                        },
                        "certificate": {
                            "type": "dict",
                            "required": True,
                            "schema": {
                                "common_name": {"type": "string", "required": True},
                                "alt_names": {"type": "string", "required": False},
                                "ip_sans": {"type": "string", "required": False},
                                "uri_sans": {"type": "string", "required": False},
                                "other_sans": {"type": "string", "required": False},
                                "ttl": {"type": "integer", "required": False},
                                "max_path_length": {
                                    "type": "integer",
                                    "required": False,
                                },
                                "key_usage": {
                                    "type": "list",
                                    "schema": {"type": "string"},
                                    "required": False,
                                },
                                "permitted_dns_domains": {
                                    "type": "string",
                                    "required": False,
                                },
                                "excluded_dns_domains": {
                                    "type": "string",
                                    "required": False,
                                },
                                "permitted_ip_ranges": {
                                    "type": "string",
                                    "required": False,
                                },
                                "excluded_ip_ranges": {
                                    "type": "string",
                                    "required": False,
                                },
                                "permitted_email_addresses": {
                                    "type": "string",
                                    "required": False,
                                },
                                "excluded_email_addresses": {
                                    "type": "string",
                                    "required": False,
                                },
                                "permitted_uri_domains": {
                                    "type": "string",
                                    "required": False,
                                },
                                "excluded_uri_domains": {
                                    "type": "string",
                                    "required": False,
                                },
                                "ou": {"type": "string", "required": False},
                                "organization": {"type": "string", "required": False},
                                "country": {"type": "string", "required": False},
                                "locality": {"type": "string", "required": False},
                                "province": {"type": "string", "required": False},
                                "street_address": {"type": "string", "required": False},
                                "postal_code": {"type": "string", "required": False},
                                "not_before_duration": {
                                    "type": "string",
                                    "required": False,
                                },
                                "not_after": {"type": "string", "required": False},
                            },
                        },
                    },
                },
            },
            "intermediates": {
                "type": "list",
                "required": False,
                "schema": {
                    "type": "dict",
                    "schema": {
                        "vault_signing_mount_path_name": {
                            "type": "string",
                            "required": True,
                        },
                        "mount": {
                            "type": "dict",
                            "required": False,
                            "schema": {
                                "vault_mount_path_name": {
                                    "type": "string",
                                    "required": True,
                                },
                                "vault_mount_description": {
                                    "type": "string",
                                    "required": True,
                                },
                                "vault_mount_default_lease_ttl": {
                                    "type": "string",
                                    "required": True,
                                },
                                "crl": {
                                    "type": "dict",
                                    "required": True,
                                    "schema": {
                                        "expiry": {"type": "string", "required": True},
                                        "distribution_points": {
                                            "type": "string",
                                            "required": True,
                                        },
                                    },
                                },
                                "issuing_certificates": {
                                    "type": "string",
                                    "required": True,
                                },
                                "keypair": {
                                    "type": "dict",
                                    "required": True,
                                    "schema": {
                                        "key_name": {
                                            "type": "string",
                                            "required": True,
                                        },
                                        "key_type": {
                                            "type": "string",
                                            "required": True,
                                        },
                                        "key_bits": {
                                            "type": "integer",
                                            "required": True,
                                        },
                                    },
                                },
                            },
                        },
                        "csr": {
                            "type": "dict",
                            "required": True,
                            "schema": {
                                "expected_filename": {
                                    "type": "string",
                                    "required": True,
                                },
                                "common_name": {"type": "string", "required": True},
                                "alt_names": {"type": "string", "required": False},
                                "ip_sans": {"type": "string", "required": False},
                                "uri_sans": {"type": "string", "required": False},
                                "other_sans": {"type": "string", "required": False},
                                "ttl": {"type": "integer", "required": False},
                                "key_type": {"type": "string", "required": False},
                                "key_bits": {"type": "integer", "required": False},
                                "add_basic_constraints": {
                                    "type": "boolean",
                                    "required": False,
                                },
                                "max_path_length": {
                                    "type": "integer",
                                    "required": False,
                                },
                                "key_usage": {
                                    "type": "list",
                                    "schema": {"type": "string"},
                                    "required": False,
                                },
                                "distribution_points": {
                                    "type": "string",
                                    "required": False,
                                },
                                "issuing_certificates": {"type": "string", "required": False},
                                "ou": {"type": "string", "required": False},
                                "organization": {"type": "string", "required": False},
                                "country": {"type": "string", "required": False},
                                "locality": {"type": "string", "required": False},
                                "province": {"type": "string", "required": False},
                                "street_address": {"type": "string", "required": False},
                                "postal_code": {"type": "string", "required": False},
                                "not_before_duration": {
                                    "type": "string",
                                    "required": False,
                                },
                                "not_after": {"type": "string", "required": False},
                                "permitted_dns_domains": {
                                    "type": "string",
                                    "required": False,
                                },
                                "excluded_dns_domains": {
                                    "type": "string",
                                    "required": False,
                                },
                                "permitted_ip_ranges": {
                                    "type": "string",
                                    "required": False,
                                },
                                "excluded_ip_ranges": {
                                    "type": "string",
                                    "required": False,
                                },
                                "permitted_email_addresses": {
                                    "type": "string",
                                    "required": False,
                                },
                                "excluded_email_addresses": {
                                    "type": "string",
                                    "required": False,
                                },
                                "permitted_uri_domains": {
                                    "type": "string",
                                    "required": False,
                                },
                                "excluded_uri_domains": {
                                    "type": "string",
                                    "required": False,
                                },
                            },
                        },
                    },
                },
            },
            "revocation": {
                "type": "list",
                "required": False,
                "schema": {
                    "type": "dict",
                    "schema": {
                        "issuer_mount_path_name": {"type": "string", "required": True},
                        "certificate": {"type": "string", "required": True},
                    },
                },
            },
        },
    }
}


def perform_vault_config_checks(config):
    return vault_check(config) and extra_params_check(config)


# 1. Filesystem & Paths
# Check if file paths are consistent across the config
# Ensure all files and folders exist
# def fs_checks(config):
#     if "intermediates" in config["ceremony"].keys():
#         intermediates = config["ceremony"]["intermediates"]
#         for inter in intermediates:
#             csr = inter.get("csr")
#             if csr and csr.get("path") and not os.path.isfile(csr.get("path")):
#                 logging.error("A specified Intermediate's csr file does not exist")
#                 return False
#     return True


# 2. Vault Ceremony Logic
# secret_shares >= secret_threshold
# Ensure no duplicate vault_mount_path_names.
def vault_check(config):
    if "vault" in config["ceremony"].keys() and config["ceremony"]["vault"]["create"]:
        if (
            config["ceremony"]["vault"]["secret_shares"]
            < config["ceremony"]["vault"]["secret_threshold"]
        ):
            logging.error("Vault secret_shares >=! secret_threshold")
            return False

    new_vault_mounts = []
    for cerem_type, cerem in config["ceremony"].items():
        if cerem_type == "vault" or cerem_type == "revocation" or cerem_type == "utilities":
            continue
        for cerem_conf in cerem:
            if cerem_conf.get("mount") and cerem_conf.get("mount").get(
                "vault_mount_path_name"
            ):
                new_vault_mounts.append(
                    cerem_conf.get("mount").get("vault_mount_path_name")
                )

    # If there are any duplicates
    if len(new_vault_mounts) != len(set(new_vault_mounts)):
        logging.error("There are duplicate new vault mounts in the config.")
        return False

    return True


# 4. Extra Params
# not_after must be in the future.
# If not_before_duration is set, validate format (e.g. 5m, 1h).
def extra_params_check(config):
    def is_duration_format(val):
        return bool(re.match(r"^\d+[smhdy]$", val))

    today = datetime.now()

    for block in config["ceremony"].get("roots", []) + config["ceremony"].get(
        "intermediates", []
    ):
        # Determine if it's a root (uses 'certificate') or intermediate (uses 'csr')
        cert_block = block.get("certificate") or block.get("csr")

        if not cert_block:
            continue  # skip if neither present

        common_name = cert_block.get("common_name", "UNKNOWN")

        if cert_block.get("ttl") and not isinstance(cert_block.get("ttl"), int):
            logging.error(f"Ceremony with common name: {common_name}: ttl must be int")
            return False

        if cert_block.get("ttl") and cert_block.get("not_after"):
            logging.error(
                f"Ceremony with common name: {common_name}: cannot set both ttl and not_after"
            )
            return False

        not_after = cert_block.get("not_after")
        if not_after:
            try:
                not_after_dt = datetime.fromisoformat(not_after.replace("Z", ""))
                if not_after_dt < today:
                    logging.error(
                        f"Ceremony with common name: {common_name}: not_after is in the past: {not_after}"
                    )
                    return False
            except Exception:
                logging.error(
                    f"Ceremony with common name: {common_name}: not_after must be ISO 8601 format: {not_after}"
                )
                return False

        not_before_duration = cert_block.get("not_before_duration")
        if not_before_duration and not is_duration_format(not_before_duration):
            logging.error(
                f"{common_name}: invalid duration format for not_before_duration: {not_before_duration}"
            )
            return False

        if block.get("csr") and block.get("csr").get("path") and block.get("mount"):
            logging.error(
                f"Ceremony with common name: {common_name}: Cannot set 'mount' and 'csr.path' at the same time."
            )
            return False

    return True
