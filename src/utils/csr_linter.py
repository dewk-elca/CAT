import os
import re
import ast
import yaml
import base64

# from termcolor import colored  # If you want actual terminal colors (optional)
from cryptography import x509  # type: ignore
from cryptography.x509 import KeyUsage, UnrecognizedExtension, BasicConstraints  # type: ignore
from collections import defaultdict
from cryptography.x509 import (  # type: ignore
    AuthorityInformationAccess,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
    NameConstraints,
    CRLDistributionPoints,
    SubjectAlternativeName,
)
from cryptography.x509.general_name import (  # type: ignore
    DNSName,
    IPAddress,
    RFC822Name,
    UniformResourceIdentifier,
    OtherName,
)

CONFIG_TO_OID = {
    "subject": {
        "common_name": "2.5.4.3",
        "ou": "2.5.4.11",
        "organization": "2.5.4.10",
        "country": "2.5.4.6",
        "locality": "2.5.4.7",
        "province": "2.5.4.8",
        "street_address": "2.5.4.9",
        "postal_code": "2.5.4.17",
    },
    "extentions": {
        "distribution_points": "2.5.29.31",
        "issuing_certificates": "1.3.6.1.5.5.7.1.1",
        "alt_names": "2.5.29.17-1",
        "ip_sans": "2.5.29.17-2",
        "uri_sans": "2.5.29.17-3",
        "other_sans": "2.5.29.17-4",  # Try not to forget this stack
        "max_path_length": "2.5.29.19-1",
        "key_usage": "2.5.29.15",
        "permitted_dns_domains": "2.5.29.30-0-0",
        "permitted_ip_ranges": "2.5.29.30-0-1",
        "permitted_email_addresses": "2.5.29.30-0-2",
        "permitted_uri_domains": "2.5.29.30-0-3",
        "excluded_dns_domains": "2.5.29.30-1-0",
        "excluded_ip_ranges": "2.5.29.30-1-1",
        "excluded_email_addresses": "2.5.29.30-1-2",
        "excluded_uri_domains": "2.5.29.30-1-3",
        "add_basic_constraints": "2.5.29.19-0",
    },
    "configurations": {
        "not_before_duration": "-0",
        "not_after": "-1",
        "ttl": "-2",
    },
}


def int_config_to_comparison_format(config):
    result = {"subject": {}, "extentions": {}, "configurations": {}}
    if config.get("mount") and config.get("mount").get("crl"):
        result["extentions"]["distribution_points"] = config.get("mount").get("crl")[
            "distribution_points"
        ]

    for key, value in config.get("csr").items():
        if key in CONFIG_TO_OID["subject"].keys():
            result["subject"][key] = value
        
        if key in CONFIG_TO_OID["configurations"].keys():
            result["configurations"][key] = value

        if key in CONFIG_TO_OID["extentions"].keys():
            result["extentions"][key] = value
            if key == "key_usage":
                result["extentions"][key] = {}
                #         {
                # "digital_signature": True,
                # "content_commitment": False,
                # "key_encipherment": False,
                # "data_encipherment": False,
                # "key_agreement": False,
                # "key_cert_sign": True,
                # "crl_sign": False,
                # "encipher_only": False,
                # "decipher_only": False
                # }
                result["extentions"][key]["digital_signature"] = (
                    True if "DigitalSignature" in value else False
                )
                result["extentions"][key]["content_commitment"] = (
                    True if "ContentCommitment" in value else False
                )
                result["extentions"][key]["key_encipherment"] = (
                    True if "KeyEncipherment" in value else False
                )
                result["extentions"][key]["data_encipherment"] = (
                    True if "DataEncipherment" in value else False
                )
                result["extentions"][key]["key_agreement"] = (
                    True if "KeyAgreement" in value else False
                )
                result["extentions"][key]["key_cert_sign"] = (
                    True if "CertSign" in value else False
                )
                result["extentions"][key]["crl_sign"] = (
                    True if "CRLSign" in value else False
                )
                result["extentions"][key]["encipher_only"] = (
                    True if "EncipherOnly" in value else False
                )
                result["extentions"][key]["decipher_only"] = (
                    True if "DecipherOnly" in value else False
                )

    return result


def parse_dumpasn1(path):
    with open(path, "r") as file:
        return yaml.safe_load(file)


OID_MAP = parse_dumpasn1(os.path.dirname(os.path.abspath(__file__)) + "/dumpasn1.yaml")


def strip_all_hex_prefixes(s: bytes) -> str:
    while s[0] < 0x20 or s[0] > 0x7E:
        s = s[1:]
    return s.decode("utf-8")


def normalize_item(item):
    if isinstance(item, list):
        return tuple(normalize_item(i) for i in item)
    if isinstance(item, str) and item.startswith("b'") and item.endswith("'"):
        try:
            val = eval(item)  # safely decode stringified bytes
            return val.decode("utf-8")
        except Exception:
            return item
    if isinstance(item, bytes):
        try:
            return item.decode("utf-8")
        except Exception:
            return base64.b64encode(item).decode("ascii")
    return item


def normalize_list(lst):
    return set(normalize_item(x) for x in lst)


def map_oid_to_name(data: dict, oid_name_map: dict) -> dict:
    result = {}
    for oid, value in data.items():
        name = oid_name_map.get(oid, "Unknown")
        result[f"{name} ({oid})"] = value
    return result


def display_csr_details(csr_pem: str):
    csr = x509.load_pem_x509_certificate(csr_pem.encode())

    print("\n=== Subject ===")
    # print("\n=== Attributes ===")
    for sub in csr.subject:
        print(
            sub.oid.dotted_string,
            OID_MAP.get(sub.oid.dotted_string).get("name"),
            sub.value,
        )
    # for attr in csr.attributes:
    #     print(OID_MAP.get(attr.oid.dotted_string).get("name"), attr.value if not isinstance(attr.value, bytes) else f"{attr.value[:10]}...")
    print("\n=== Extentions ===")
    for ext in csr.extensions:
        # Handle UnknownExtentions if, then print value. Else, do below
        if isinstance(ext.value, UnrecognizedExtension):
            # print(ext.oid.dotted_string, OID_MAP.get(ext.oid.dotted_string).get("name"), f"{ext.value._value[:10]}...")
            print(
                ext.oid.dotted_string,
                OID_MAP.get(ext.oid.dotted_string).get("name"),
                ext.value,
            )
        else:
            # print(ext.oid.dotted_string, OID_MAP.get(ext.oid.dotted_string).get("name"), {k.lstrip('_'): v for k, v in ext.value.__dict__.items()})
            print(
                ext.oid.dotted_string,
                OID_MAP.get(ext.oid.dotted_string).get("name"),
                ext.value,
            )


def pretty_print_summary(summary):
    def section(title, data_dict):
        print(f"---{title}---")
        if not data_dict:
            print("None")
        else:
            for k, v in data_dict.items():
                print(f"{k}: {v}")

    print("\n=== Matches ===")
    section("Subject", summary["matches"].get("subject", {}))
    section("Extensions", summary["matches"].get("extensions", {}))

    print("\n=== Mismatches ===")
    section("Subject", summary["mismatches"].get("subject", {}))
    section("Extensions", summary["mismatches"].get("extensions", {}))

    print("\n=== Only in CSR ===")
    section("Subject", summary["only_in_csr"].get("subject", {}))
    section("Extensions", summary["only_in_csr"].get("extensions", {}))

    print("\n=== Only in Config ===")
    section("Subject", summary["only_in_config"].get("subject", {}))
    section("Extensions", summary["only_in_config"].get("extensions", {}))


def extract_name_from_key(key):
    """Extract the name from a key like "{'name': 'streetAddress', 'description': 'X.520 DN component'} (2.5.4.9)" """
    match = re.search(r"'name': '([^']+)'", key)
    return match.group(1) if match else key


def format_extension_value(value, indent_level=6, color_code="", reset_code=""):
    """Format extension values with proper YAML formatting and custom tuple handling"""

    def format_value(v, current_indent=indent_level):
        indent = " " * current_indent

        if isinstance(v, dict):
            lines = []
            for k, val in v.items():
                if isinstance(val, (list, tuple)):
                    lines.append(f"{indent}{k}:")
                    lines.extend(format_value(val, current_indent + 2))
                elif isinstance(val, dict):
                    lines.append(f"{indent}{k}:")
                    lines.extend(format_value(val, current_indent + 2))
                else:
                    lines.append(f"{indent}{k}: {val}")
            return lines
        elif isinstance(v, (list, tuple)):
            lines = []
            for item in v:
                if isinstance(item, tuple) and len(item) == 2:
                    # Format tuples as key-value pairs
                    lines.append(f"{indent}- {item[0]}: {item[1]}")
                elif isinstance(item, (dict, list, tuple)):
                    lines.append(f"{indent}-")
                    lines.extend(format_value(item, current_indent + 2))
                else:
                    lines.append(f"{indent}- {item}")
            return lines
        else:
            return [f"{indent}{v}"]

    formatted_lines = format_value(value)

    # Apply color codes if provided
    if color_code and reset_code:
        formatted_lines = [
            f"{color_code}{line}{reset_code}" for line in formatted_lines
        ]

    return formatted_lines


def format_colored_yaml(data):
    """Convert the dictionary to a colored YAML string with merged sections"""

    # ANSI color codes
    RED = "\033[91m"
    GREEN = "\033[92m"
    RESET = "\033[0m"
    CYAN = "\033[96m"

    lines = []

    # Create unified section combining all certificate data
    lines.append("===== CSR Comparison with config values =====")

    # Merge all subject data
    subject_items = {}

    # Add matches first
    if data.get("matches", {}).get("subject"):
        for key, value in data["matches"]["subject"].items():
            name = extract_name_from_key(key)
            subject_items[name] = value

    # Add mismatches (will overwrite matches if same key exists)
    if data.get("mismatches", {}).get("subject"):
        for key, mismatch in data["mismatches"]["subject"].items():
            name = extract_name_from_key(key)
            csr_val = mismatch["csr"]
            config_val = mismatch["config"]
            subject_items[name] = (
                f"{GREEN}{csr_val} {RESET} <--- {RED}{config_val} (expected){RESET}"
            )

    # Add only_in_config (added to certificate)
    if data.get("only_in_config", {}).get("subject"):
        for key, value in data["only_in_config"]["subject"].items():
            name = extract_name_from_key(key)
            subject_items[name] = f"{GREEN}{value} (added){RESET}"

    # Add only_in_csr (additional parameters in csr)
    if data.get("only_in_csr", {}).get("subject"):
        for key, value in data["only_in_csr"]["subject"].items():
            name = extract_name_from_key(key)
            dict_part = key.split("}", 1)[0] + "}"
            parsed = ast.literal_eval(dict_part)
            description = parsed["description"]
            subject_items[name] = (
                f"{CYAN}{value} (additional) desctiption: {description}{RESET}"
            )
            if name == "domainComponent":
                subject_items[name] = (
                    f"{CYAN}{value} (additional) desctiption: used in LDAP{RESET}"
                )

    if subject_items:
        lines.append("  subject:")
        for name, value in subject_items.items():
            lines.append(f"    {name}: {value}")

    # Add configurations section if present in config
    config_items = data.get("configurations", {})
    if config_items:
        lines.append("  configurations:")
        for key, value in config_items.items():
            lines.append(f"    {GREEN}{key}: {value} (from config){RESET}")

    # Merge all extension data
    extension_items = {}

    # Add matches first
    if data.get("matches", {}).get("extensions"):
        for key, value in data["matches"]["extensions"].items():
            name = extract_name_from_key(key)
            extension_items[name] = {"type": "match", "value": value}

    # Add mismatches (will overwrite matches if same key exists)
    if data.get("mismatches", {}).get("extensions"):
        for key, mismatch in data["mismatches"]["extensions"].items():
            name = extract_name_from_key(key)

            if isinstance(mismatch, dict) and all(
                isinstance(v, dict) for v in mismatch.values()
            ):
                # Handle nested structure like: {'dns': {'csr': [...], 'config': [...]}, ...}
                for subkey, submismatch in mismatch.items():
                    csr_val = submismatch.get("csr")
                    config_val = submismatch.get("config")
                    extension_items[f"{name} ({subkey})"] = {
                        "type": "mismatch",
                        "value": f"{GREEN}{csr_val} {RESET} <--- {RED}{config_val} (expected){RESET}",
                    }
            else:
                # Handle flat mismatch: {'csr': ..., 'config': ...}
                csr_val = mismatch.get("csr")
                config_val = mismatch.get("config")
                extension_items[name] = {
                    "type": "mismatch",
                    "value": f"{GREEN}{csr_val} {RESET} <--- {RED}{config_val} (expected){RESET}",
                }

    # Add only_in_config (added to certificate)
    if data.get("only_in_config", {}).get("extensions"):
        for key, value in data["only_in_config"]["extensions"].items():
            name = extract_name_from_key(key)
            extension_items[name] = {"type": "added_to_cert", "value": value}

    # Add only_in_csr (additional parameters in csr)
    if data.get("only_in_csr", {}).get("extensions"):
        for key, value in data["only_in_csr"]["extensions"].items():
            name = extract_name_from_key(key)

            description = ""
            try:
                dict_part = key.split("}", 1)[0] + "}"
                parsed = ast.literal_eval(dict_part)
                description = parsed.get("description", "")
            except Exception:
                description = "unknown"

            extension_items[name] = {
                "type": "additional_in_csr",
                "value": value,
                "description": description,
            }

    if extension_items:
        lines.append("  extensions:")
        for name, item in extension_items.items():
            if name == "keyUsage":
                item["value"] = {k: v for k, v in item.get("value").items() if v}
            if item["type"] == "mismatch":
                # This is a mismatch, show as string
                lines.append(f"    {name}: {item['value']}")
            elif item["type"] == "added_to_cert":
                # This was added to certificate, show in green
                lines.append(f"    {GREEN}{name}: (added){RESET}")
                ext_lines = format_extension_value(
                    item["value"], color_code=GREEN, reset_code=RESET
                )
                lines.extend(ext_lines)
            elif item["type"] == "additional_in_csr":
                # This was additional in csr, show in cyan with description
                description = item.get("description")
                desc_str = f" description: {description}" if description else ""
                lines.append(f"    {CYAN}{name}: (additional){desc_str}{RESET}")
                ext_lines = format_extension_value(
                    item["value"], color_code=CYAN, reset_code=RESET
                )
                lines.extend(ext_lines)
            else:
                # This is a match, format as extension
                lines.append(f"    {name}:")
                ext_lines = format_extension_value(item["value"])
                lines.extend(ext_lines)

    if data.get("only_in_csr", {}).get("attributes"):
        lines.append("  attributes:")
        for key, value in data["only_in_csr"]["attributes"].items():
            name = extract_name_from_key(key)

            description = ""
            try:
                dict_part = key.split("}", 1)[0] + "}"
                parsed = ast.literal_eval(dict_part)
                description = parsed.get("description", "")
            except Exception:
                description = "unknown"
            lines.append(
                f"    {CYAN}{name}: {value} (additional) description: {description}{RESET}"
            )

    return "\n".join(lines)


def compare_csr_to_config(csr_pem: str, config: dict, type: str):
    if type == "csr":
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    elif type == "x509":
        csr = x509.load_pem_x509_certificate(csr_pem.encode())
    else:
        raise Exception("compare_csr_to_config: csr of x509 required.")

    # === SUBJECT COMPARISON ===
    csr_subject_oids = defaultdict(list)
    for attr in csr.subject:
        csr_subject_oids[attr.oid.dotted_string].append(attr.value)

    # Convert single-item lists back to single values for consistency
    csr_subject_oids = {
        oid: (values[0] if len(values) == 1 else values)
        for oid, values in csr_subject_oids.items()
    }

    config_subject = config.get("subject", {})
    config_subject_oids = {}
    for key, value in config_subject.items():
        oid = CONFIG_TO_OID["subject"].get(key)
        if oid:
            base_oid = oid.split("-")[0]
            config_subject_oids[base_oid] = value

    def compare_dicts(dict1, dict2):
        matches, mismatches, only1, only2 = {}, {}, {}, {}
        all_keys = set(dict1.keys()).union(set(dict2.keys()))
        for k in all_keys:
            v1, v2 = dict1.get(k), dict2.get(k)
            if v1 is not None and v2 is not None:
                # Normalize -1 and None as equivalent for path_length
                if isinstance(v1, dict) and isinstance(v2, dict):
                    mismatch_fields = {}
                    for subkey in set(v1) | set(v2):
                        a = v1.get(subkey, [])
                        b = v2.get(subkey, [])

                        # Normalize -1 to None
                        if a == -1:
                            a = None
                        if b == -1:
                            b = None

                        # Compare as unordered sets if lists
                        if isinstance(a, list) and isinstance(b, list):
                            if normalize_list(a) != normalize_list(b):
                                mismatch_fields[subkey] = {"csr": a, "config": b}
                        else:
                            if a != b:
                                mismatch_fields[subkey] = {"csr": a, "config": b}

                    if not mismatch_fields:
                        matches[k] = v1
                    else:
                        # Include matching subkeys too
                        matching_subkeys = {}
                        for subkey in set(v1) & set(v2):
                            a = v1.get(subkey, [])
                            b = v2.get(subkey, [])

                            # Normalize -1 to None
                            if a == -1:
                                a = None
                            if b == -1:
                                b = None

                            if isinstance(a, list) and isinstance(b, list):
                                if normalize_list(a) == normalize_list(b):
                                    matching_subkeys[subkey] = a
                            elif a == b:
                                matching_subkeys[subkey] = a

                        if matching_subkeys:
                            matches[k] = matching_subkeys
                        mismatches[k] = mismatch_fields
                else:
                    if (
                        v1 == v2
                        or (v1 is None and v2 == -1)
                        or (v2 is None and v1 == -1)
                    ):
                        matches[k] = v1
                    else:
                        mismatches[k] = {"csr": v1, "config": v2}

            elif v1 is not None:
                only1[k] = v1
            elif v2 is not None:
                only2[k] = v2
        return matches, mismatches, only1, only2

    # print("\n=== Subject OIDs in CSR ===")
    # print("None" if not csr_subject_oids else "\n".join([f"{k}: {v}" for k, v in csr_subject_oids.items()]))

    # print("\n=== Subject OIDs in Config ===")
    # print("None" if not config_subject_oids else "\n".join([f"{k}: {v}" for k, v in config_subject_oids.items()]))

    (
        subject_matches,
        subject_mismatches,
        only_in_csr_subjects,
        only_in_config_subjects,
    ) = compare_dicts(csr_subject_oids, config_subject_oids)
    # for title, d in [("Subject Matches", subject_matches), ("Subject Mismatches", subject_mismatches),
    #                  ("Subject Only in CSR", only_in_csr_subjects), ("Subject Only in Config", only_in_config_subjects)]:
    #     print(f"\n=== {title} ===")
    #     print("None" if not d else "\n".join([f"{k}: {v}" for k, v in d.items()]))

    # === EXTENSION COMPARISON ===

    def normalize_extension(ext):
        if isinstance(ext, KeyUsage):
            return {k[1:]: getattr(ext, k) for k in vars(ext)}
        elif isinstance(ext, BasicConstraints):
            return {"ca": ext.ca, "path_length": ext.path_length}
        elif isinstance(ext, SubjectKeyIdentifier):
            return {"digest": ext.digest.hex()}
        elif isinstance(ext, AuthorityKeyIdentifier):
            return {
                "key_identifier": ext.key_identifier.hex()
                if ext.key_identifier
                else None,
                "authority_cert_issuer": str(ext.authority_cert_issuer),
                "authority_cert_serial_number": str(ext.authority_cert_serial_number),
            }
        elif isinstance(ext, CRLDistributionPoints):
            return [dp.full_name[0].value for dp in ext if dp.full_name]
        elif isinstance(ext, SubjectAlternativeName):
            names = defaultdict(list)
            for gn in ext:
                if isinstance(gn, DNSName):
                    names["dns"].append(gn.value)
                elif isinstance(gn, IPAddress):
                    names["ip"].append(str(gn.value))
                elif isinstance(gn, RFC822Name):
                    names["email"].append(gn.value)
                elif isinstance(gn, UniformResourceIdentifier):
                    names["uri"].append(gn.value)
                elif isinstance(gn, OtherName):
                    names["other"].append(
                        (gn.type_id.dotted_string, strip_all_hex_prefixes(gn.value))
                    )
            return dict(names)
        elif isinstance(ext, NameConstraints):

            def extract_names(group):
                if not group:
                    return []
                if isinstance(group, str):
                    return [group]
                try:
                    return [str(getattr(g, "value", g)) for g in group]
                except TypeError:  # not iterable
                    return [str(getattr(group, "value", group))]

            return {
                "permitted": extract_names(ext.permitted_subtrees),
                "excluded": extract_names(ext.excluded_subtrees),
            }
        elif isinstance(ext, AuthorityInformationAccess):
            return [desc.access_location.value for desc in ext]
        elif isinstance(ext, UnrecognizedExtension):
            return ext.value
        else:
            return str(ext)

    # Extract and normalize extensions from CSR
    csr_extensions = {}
    for ext in csr.extensions:
        csr_extensions[ext.oid.dotted_string] = normalize_extension(ext.value)

    # Group config keys by their base OID
    config_extensions_raw = config.get("extentions", {})
    config_extensions_grouped = defaultdict(dict)
    for key, value in config_extensions_raw.items():
        full_oid = CONFIG_TO_OID["extentions"].get(key)
        if not full_oid:
            continue
        base_oid = full_oid.split("-")[0]
        sub_key = key  # Keep the config key to identify its semantic meaning
        config_extensions_grouped[base_oid][sub_key] = value

    # Map grouped config into a structure comparable to CSR
    def normalize_config_extensions(grouped_config):
        def split_commas_or_default(s, default=[]):
            return s.split(",") if s else default

        result = {}
        for oid, fields in grouped_config.items():
            if oid == "2.5.29.19":  # BasicConstraints
                result[oid] = {
                    "ca": fields.get("add_basic_constraints", False),
                    "path_length": fields.get("max_path_length", None),
                }
            elif oid == "2.5.29.15":  # KeyUsage
                result[oid] = fields.get("key_usage", {})
            elif oid == "2.5.29.17":  # SubjectAltName
                result[oid] = {
                    "dns": fields.get("alt_names", []),
                    "ip": fields.get("ip_sans", []),
                    "uri": fields.get("uri_sans", []),
                    "other": fields.get("other_sans", []),
                }
            elif oid == "2.5.29.30":  # NameConstraints
                result[oid] = {
                    "permitted": [
                        *split_commas_or_default(
                            (fields.get("permitted_dns_domains", ""))
                        ),
                        *split_commas_or_default(
                            (fields.get("permitted_ip_ranges", ""))
                        ),
                        *split_commas_or_default(
                            (fields.get("permitted_email_addresses", ""))
                        ),
                        *split_commas_or_default(
                            (fields.get("permitted_uri_domains", ""))
                        ),
                    ],
                    "excluded": [
                        *split_commas_or_default(
                            (fields.get("excluded_dns_domains", ""))
                        ),
                        *split_commas_or_default(
                            (fields.get("excluded_ip_ranges", ""))
                        ),
                        *split_commas_or_default(
                            (fields.get("excluded_email_addresses", ""))
                        ),
                        *split_commas_or_default(
                            (fields.get("excluded_uri_domains", ""))
                        ),
                    ],
                }
            else:
                result[oid] = list(fields.values())[0] if len(fields) == 1 else fields
        return result

    config_extensions = normalize_config_extensions(config_extensions_grouped)
    (
        extension_matches,
        extension_mismatches,
        only_in_csr_extensions,
        only_in_config_extensions,
    ) = compare_dicts(csr_extensions, config_extensions)

    # === ATTRIBUTES FROM CSR ===
    csr_attributes = {}
    for attr in csr.attributes:
        oid = attr.oid.dotted_string
        csr_attributes[oid] = (
            attr.value if not isinstance(attr.value, bytes) else f"{attr.value[:10]}..."
        )

    # === EXTRACT CONFIG VALUES ===
    configurations = {}
    for key in ["not_before_duration", "not_after", "ttl"]:
        if key in config.get("configurations"):
            configurations[key] = config.get("configurations")[key]

    summary = {"matches": {}, "mismatches": {}, "only_in_csr": {}, "only_in_config": {}}

    # Add subject results
    subject_matches, subject_mismatches, _, _ = compare_dicts(
        csr_subject_oids, config_subject_oids
    )
    summary["matches"]["subject"] = subject_matches
    summary["mismatches"]["subject"] = subject_mismatches

    # Add extension results
    extension_matches, extension_mismatches, _, _ = compare_dicts(
        csr_extensions, config_extensions
    )
    summary["matches"]["extensions"] = extension_matches
    summary["mismatches"]["extensions"] = extension_mismatches

    summary["only_in_csr"]["subject"] = only_in_csr_subjects
    summary["only_in_csr"]["extensions"] = only_in_csr_extensions
    summary["only_in_csr"]["attributes"] = csr_attributes
    summary["only_in_config"]["subject"] = only_in_config_subjects
    summary["only_in_config"]["extensions"] = only_in_config_extensions

    # Add config values to summary
    summary["configurations"] = configurations

    for category in summary.keys():
        if category != "configurations":  # Don't try to map config_values through OID_MAP
            for attr in summary[category].keys():
                summary[category][attr] = map_oid_to_name(summary[category][attr], OID_MAP)

    colored_yaml = format_colored_yaml(summary)
    return summary, colored_yaml


# csr_pem_data = """-----BEGIN CERTIFICATE-----
# MIIFKzCCBLGgAwIBAgIUbwcSmjW0ShpanbgohiET0phe/LYwCgYIKoZIzj0EAwMw
# gaoxEDAOBgNVBAYTB0NvdW50cnkxETAPBgNVBAgTCFByb3ZpbmNlMREwDwYDVQQH
# EwhMb2NhbGl0eTEUMBIGA1UECRMLU3RyZWV0IEFkZHkxEDAOBgNVBBETBzE5MTkx
# OTExFTATBgNVBAoTDE9yZ2luYXphdGlvbjEQMA4GA1UECxMHT1VPVU9VTzEfMB0G
# A1UEAxMWVGhpcyBpcyBteSBDb21tb24gbmFtZTAeFw0yNTA1MzAwOTQ1NDdaFw0z
# NTEyMzEyMzU5NTlaMIGqMRAwDgYDVQQGEwdDb3VudHJ5MREwDwYDVQQIEwhQcm92
# aW5jZTERMA8GA1UEBxMITG9jYWxpdHkxFDASBgNVBAkTC1N0cmVldCBBZGR5MRAw
# DgYDVQQREwcxOTE5MTkxMRUwEwYDVQQKEwxPcmdpbmF6YXRpb24xEDAOBgNVBAsT
# B09VT1VPVU8xHzAdBgNVBAMTFlRoaXMgaXMgbXkgQ29tbW9uIG5hbWUwdjAQBgcq
# hkjOPQIBBgUrgQQAIgNiAASLNi/ittbm5zsBrQ7tdRVNRYFehIFSDGEoYDjlCHeN
# b8FqXfCp0ffFyI//kjsrSwLExMQNqR9VUXZfhRIV4EJD54xqpNCATgNEI5S7HnUh
# 5hp/B2s+6x8r/L9O/prUMamjggKUMIICkDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0T
# AQH/BAUwAwEB/zAdBgNVHQ4EFgQUSdwnMwJfQchNosFeqSy0N1vuV18wHwYDVR0j
# BBgwFoAUSdwnMwJfQchNosFeqSy0N1vuV18wOAYIKwYBBQUHAQEELDAqMCgGCCsG
# AQUFBzAChhxodHRwOi8vZWxjYS1yb290LmNvbS9pc3N1ZXJzMIH/BgNVHR4BAf8E
# gfQwgfGggYIwEoIQcGVybWl0dGVkZG9tYWluMTASghBwZXJtaXR0ZWRkb21haW4y
# MBKCEHBlcm1pdHRlZGRvbWFpbjMwCocIwAACAP///wAwCocIwAACAP///wAwFYET
# cGVybWl0dGVkQGVtYWlsLmNvbTAVhhNwZXJtaXR0ZWR1cmlkb21haW4xoWowEYIP
# ZXhjbHVkZWRkb21haW4xMBGCD2V4Y2x1ZGVkZG9tYWluMjAKhwjAAAIA////ADAK
# hwjAAAIA////ADAUgRJleGNsdWRlZEBlbWFpbC5jb20wFIYSZXhjbHVkZWR1cmlk
# b21haW4xMCkGA1UdHwQiMCAwHqAcoBqGGGh0dHA6Ly9lbGNhLXJvb3QuY29tL2Ny
# bDCBxQYDVR0RBIG9MIG6oB8GCSqGSIb3DQEJAaASDBBjYS1hZG1pbkBlbGNhLmNo
# oB8GCSqGSIb3DQEJAaASDBBjYS1hZG1pbkBlbGNhLmNogghhbHRuYW1lMYIIYWx0
# bmFtZTKCCGFsdG5hbWUzhwR7AQEBhwR7AQEChh9odHRwczovL2NhLmVsY2EuY2gv
# aW50ZXJtZWRpYXRlhitsZGFwOi8vZGlyZWN0b3J5LmVsY2EuY2gvY249aW50ZXJt
# ZWRpYXRlLWNhMAoGCCqGSM49BAMDA2gAMGUCMGkcZhCxBSSO1ZIHy6PLwDShCqNS
# aTpQZ2E+sgnTEFT0qLwz3k+JJVFzOX2LututZAIxAMnUtU3l7Gvm28Bhd0gU5/84
# TeEjJujq0835vKXdKDBVVjOh2sX+BUV/ILW805rIfA==
# -----END CERTIFICATE-----"""

# summary, yamltxt = compare_csr_to_config(csr_pem_data, {
#     "subject": {
#         "common_name": "This is my Common name",
#         "ou": "OUOUOU",
#         "organization": "Organization",
#         "country": "Country",
#         "locality": "Locality",
#         "province": "Province",
#         "street_address": "Street Addy",
#         "postal_code": "191919"
#     },
#     "extentions": {
#         "add_basic_constraints": True,
#         "max_path_length": 2,
#         "key_usage": {
#         "digital_signature": True,
#         "content_commitment": False,
#         "key_encipherment": False,
#         "data_encipherment": False,
#         "key_agreement": False,
#         "key_cert_sign": True,
#         "crl_sign": False,
#         "encipher_only": False,
#         "decipher_only": False
#         },
#         "alt_names": [
#         "altname1",
#         "altname2",
#         "altname3"
#         ],
#         "ip_sans": [
#         "123.1.1.11",
#         "123.1.1.2"
#         ],
#         "uri_sans": [
#         "https://ca.elca.ch/intermediate",
#         "ldap://directory.elca.ch/cn=intermediate-ca"
#         ],
#         "other_sans": [
#         ["1.2.840.113549.1.9.1", "ca-admin@elca.ch"],
#         ["1.2.840.113549.1.9.1", "ca-admin@elca.ch"]
#         ],
#         "distribution_points": [
#         "http://elca-root.com/crll"
#         ],
#         "permitted_dns_domains": [
#         "permitteddomain1",
#         "permitteddomain2",
#         "permitteddomain3"
#         ],
#         "permitted_ip_ranges": [
#         "192.0.2.0/24",
#         "192.0.2.0/24"
#         ],
#         "permitted_email_addresses": [
#         "permitted@email.com"
#         ],
#         "permitted_uri_domains": [
#         "permitteduridomain1"
#         ],
#         "excluded_dns_domains": [
#         "excludeddomain1",
#         "excludeddomain2"
#         ],
#         "excluded_ip_ranges": [
#         "192.0.2.0/24",
#         "192.0.2.0/24"
#         ],
#         "excluded_email_addresses": [
#         "excluded@email.com"
#         ],
#         "excluded_uri_domains": [
#         "excludeduridomain1"
#         ]
#     }
#     }, "x509"
# )

# print(yamltxt)

# csr_pem_data = """-----BEGIN NEW CERTIFICATE REQUEST-----
# MIICXzCCAeQCAQAwVDEiMCAGA1UEAwwZRUxDQURFViBJbnRlcm1lZGlhdGUgQ0Eg
# MTEXMBUGCgmSJomT8ixkARkWB2VsY2FEZXYxFTATBgoJkiaJk/IsZAEZFgVsb2Nh
# bDB2MBAGByqGSM49AgEGBSuBBAAiA2IABE6lqYAfE93bekE7NC4Rx82bbufafC5z
# 9tcDZrH7hGhyrQNcwmni0a3+cgxk3JlFQqEJdfCG2ZLPkVddsViVflT5ORVGKDYK
# HvBiBUh1c13DFSZoYAsnDH4rFFL2g/98H6CCAQ8wggELBgkqhkiG9w0BCQ4xgf0w
# gfowEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwMQYDVR0eAQH/
# BCcwJaAjMA+CDWVsY2FkZXYubG9jYWwwEIIOLmVsY2FkZXYubG9jYWwwSgYDVR0f
# BEMwQTA/oD2gO4Y5aHR0cDovL2NybC5lbGNhLmNoL0NlcnRFbnJvbGwvRUxDQUNv
# cnBvcmF0ZVJvb3RDQS1FQ0MuY3JsMFUGCCsGAQUFBwEBBEkwRzBFBggrBgEFBQcw
# AoY5aHR0cDovL2NybC5lbGNhLmNoL0NlcnRFbnJvbGwvRUxDQUNvcnBvcmF0ZVJv
# b3RDQS1FQ0MuY3J0MAoGCCqGSM49BAMCA2kAMGYCMQDi02WqGziwAeF5iiuNb//F
# mlqZdoXz9xd3PsIkhCrs8yFl/hlbwhChgWqpBo/O3sECMQDZqO3PdtMiB8rXrKBW
# 2kRPTxj9zenq2ijACJaIjHm30tA1TfnbxnrqrmgXR4vkhaI=
# -----END NEW CERTIFICATE REQUEST-----"""

# summary, yamltxt = compare_csr_to_config(csr_pem_data, {
#     "subject": {
#         "common_name": "ELCA DEV Intermediate Issuing CA TEST",
#         "organization": "ELCASecurity",
#     },
#     "extentions": {
#         "permitted_dns_domains": ".elcadev.local,elcadev.local",
#         "add_basic_constraints": True,
#         "max_path_length": 1,
#         "key_usage": {
#         "digital_signature": True,
#         "content_commitment": False,
#         "key_encipherment": False,
#         "data_encipherment": False,
#         "key_agreement": False,
#         "key_cert_sign": True,
#         "crl_sign": False,
#         "encipher_only": False,
#         "decipher_only": False
#         },
#     },
#     "configurations": {
#         "not_before_duration": "5m",
#         "not_after": "2035-09-10T00:00:00Z"
#     }},
#     "csr"
# )

# print(yamltxt)