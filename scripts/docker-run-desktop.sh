sudo docker compose up -d vault cups
sudo docker compose run --rm elca-vault-pki
sudo docker compose down vault cups