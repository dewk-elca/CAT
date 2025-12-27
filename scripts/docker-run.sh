sudo chmod -R 777 /media/user
echo "Hash of hashicorp_vault_1.19.5:" && sha256sum hashicorp_vault_1.19.5.tar && docker load -i hashicorp_vault_1.19.5.tar
echo "Hash of elca-cups:" && sha256sum elca-cups.tar && docker load -i elca-cups.tar
echo "Hash of elca-vault-pki:" && sha256sum elca-vault-pki.tar && docker load -i elca-vault-pki.tar
sudo docker compose up -d vault cups
sudo docker compose run --rm elca-vault-pki
sudo docker compose down vault cups