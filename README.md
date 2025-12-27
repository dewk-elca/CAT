# Ceremony Automation Tool: CAT

Scripts and configuration files to automate PKI key ceremonies using [HashiCorp Vault](https://www.vaultproject.io/).

---

## Project Structure

```
build/                     # Requirements for docker build
config/                    # Ceremony config files (YAML)
config-vault/              # Vault-specific configurations
vault_data                 # Vault encrypted data
scripts/                   # Helper and bootstrap scripts
src/                       # Source code
docker-compose.yml         
Dockerfile                 
Makefile                   
.gitignore
README.md                  # You're here!
```

---

## Configuration

All ceremony configurations are defined in the `config/ceremony_config.yml` file.
**These must be defined in the docker-compose.yml, line 42 prepended by "/vault/config/"**

A config YAML file should conform to the following schema:
+ See `/config` for examples.

```python
VAULT_CONFIG_SCHEMA = {
    "ceremony": {
        "type": "dict",
        "required": True,
        "schema": {
            "vault": {
                "type": "dict",
                "required": True,
                "schema": {
                    "create": {"type": "boolean", "required": True},
                    "secret_shares": {"type": "integer", "required": True},
                    "secret_threshold": {"type": "integer", "required": True},
                    "name": {"type": "string", "required": True},
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
```

### Configuration Schema Explained

#### Vault

- `create`: If False, the Vault will use existing content in /vault_data. If True, a new Vault will be initialized in /vault_data. ⚠️ Make sure this aligns with the actual contents of /vault_data.

- `secret_shares` / `secret_threshold`:  These values configure Shamir's Secret Sharing. The Vault master key will be split into secret_shares parts, and secret_threshold of them will be required to unseal the Vault.

- `name`:  A logical name used for naming folders and references. Be consistent across ceremonies.

#### Roots (can be multiple)

Each Root configuration defines a self-signed Root Certificate Authority (CA). The root pair is mounted in Vault through the defined vault_mount_path_name (must be unique) and will be used to sign certs.

- `mount` (required): Define the mount to be created
    - `vault_mount_path_name`: The mount point within Vault where this Root CA will reside. Must be consistent across re-runs.
    - `vault_mount_description`: A human-readable description of the mount.
    - `vault_mount_default_lease_ttl`: Default TTL for any certs issued by this root. Cannot 
    - `crl`: `expiry` of any certificate revocations issued by this mount, `distribution_points`: URL of CRL. If set here, the resulting Root certificate will include the CRL. If it is wished to be set only on Intermediates, set this on the intermediate.
    - `keypair`: `key_name`: name of the created key pair, `key_type`: rsa, ed25519 or ec, `key_bits`: key bits.

- `certificate` (required): The root certificate to be self-signed by the created root key pair.
    - `common_name`: The Common Name (CN)
    - `alt_names`: Comma separated alt names
    - `ip_sans`: Comma separated IP addresses
    - `uri_sans`: Comma separated URIs
    - `other_sans`: Comman separated <oid>;<type>:<value>
    - `ttl`: Time to live of the resulting certificate in seconds
    - `max_path_length`: Int, -1 for unlimited
    - `key_usage`: List of `DigitalSignature`, `ContentCommitment`, `KeyEncipherment`, `DataEncipherment`, `KeyAgreement`, `CertSign`, `CRLSign`, `EncipherOnly`, `DecipherOnly`
    - `permitted_dns_domains`, `excluded_dns_domains`, `permitted_ip_ranges`, `excluded_ip_ranges`, `permitted_email_addresses`, `excluded_email_addresses`, `permitted_uri_domains`, `excluded_uri_domains`: Comma separated values
    - `ou`, `organization`, `country`, `locality`, `province`, `street_address`, `postal_code`: Strings.
    - `not_before_duration`: int + s/m/h/d/y The start of certificate validity, backwards from now.
    - `not_after`: expiry of certificate, UTC format ex: "2035-12-31T23:59:59Z"

#### Intermediates (can be multiple)

Each entry defines an Intermediate CA that may be created internally and signed by a Root CA, or imported via a CSR and signed by a Root CA.

- `vault_signing_mount_path_name`: name of signer mount path in vault.
- `mount` (Define if csr is internally generated. Otherwise remove and set `csr.expected_filename`.): Same as in root, additionally:
    - `issuing certificates`: URL to AIA, issuer

- `csr`: Same as in root, additionally:
    - `expected_filename`: If not specified, the csr will be generated by the mount defined in `mount`.

#### Revocations (can be multiple)
Revocation of certificate by mount via serial number, and export of CRL of mount.
Condition: certificate must have been generated by issuer configured in vault. The CRL will include all revocations done on this mount.

- `issuer_mount_path_name`: The mount name of the certificate issuer
- `serial_number`: String, serial number of certificate to be revoked.

---

## Running the Ceremony

### 1. Set Your Config Path and environment

In `docker-compose.yml`, ensure the following line points to your desired config file:

```yaml
- CEREM_CONFIG=/vault/config/ceremony_config.yml
```

Adjust the file name if using a different config (e.g., `ceremony_config_prod.yml`).

If running on a windows host with wsl, set the `environment=develop` otherwise the scripts will expect USB insertions which cannnot be tracked if not on a Debian host.
Remove the `rshared` property on the /media map as well.

### 2. Start the Ceremony

Run the following script to build and start the environment:

```bash
sudo sh scripts/docker-run.sh
```

on develop, use:
```bash
sudo sh scripts/docker-run-desktop.sh
```

This will:

- Spin up the Vault container
- Inject your ceremony config
- Perform all configured root/intermediate operations

---

---

## RAMBO System Requirements

When using the **RAMBO system**, run `make` to generate the scripts and config bundles. The unpacker expects the bundles to be present **in the USB root** before unpacking:

Ensure these items are placed correctly on the USB device before running the unpack script.

### OUTPUT Structure on USB Example:

```
output/
├── Cerem - 2000-01-01_18-12-55/
├── Cerem - 2000-01-01_18-30-08/
├── elca-pki-vault_custodian1_2_2
└── elca-pki-vault_roottoken
```

### Output Contents:

- **Cerem - YYYY-MM-DD_HH-MM-SS/**:  
  Timestamped folders for each ceremony run. Contains assets such as:
  - Signed certificates
  - Intermediate/root CA files
  - Audit logs (if enabled)
  - Source code

- **elca-pki-vault_custodianX_Y_Z**:  
  Custodian key share files, labeled by ID.

- **elca-pki-vault_roottoken**:  
  Root token generated during the ceremony (handle securely!).

## Subsequent Ceremonies
After the sucessfull creation of a vault database with active mounts, here are instructions to perform any subsequest ceremonies.

**Requirements**
- Vault database: before `make`, make sure to include the vault database in the folder `vault_data`. 
- Take a look at the config `test-revocation` for an example. You may include additional certificate generations in the config as well.
- Custodian USBs: the Custodians must bring their key share in a USB, with the root token and key share present in the root of their USB.
- Make sure to check Previous configs for signer mount names, which should be used for any additional certificate signing. 


## Notes

- Output artifacts (e.g., signed certs) will be stored in USB devices.
- Use the `Makefile` to export project .tar.gz.

---

## License

MIT License.
