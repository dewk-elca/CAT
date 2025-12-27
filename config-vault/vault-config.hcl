storage "file" {
  path = "/vault/vault_data"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = 1
}

ui = false
default_lease_ttl = "175200h"
max_lease_ttl = "175200h"