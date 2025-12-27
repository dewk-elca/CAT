# Makefile to export Docker Compose project for USB/offline use

# Where to save Docker image tarballs (in current dir)
IMAGE_DIR := .
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)
SCRIPTS_BUNDLE := scripts_bundle_$(TIMESTAMP).tar.gz
CONFIG_BUNDLE  := config_bundle_$(TIMESTAMP).tar.gz
INPUT_BUNDLE := input_bundle_$(TIMESTAMP).tar.gz
CHECKPHRASE_FILE := bundle_checkphrase_$(TIMESTAMP).txt

# List of required images (will be built or pulled)
IMAGES := \
	hashicorp/vault:1.19.5 \
	elca-cups \
	elca-vault-pki

.PHONY: all build pull save bundle checkphrase clean

# Full pipeline
all: build pull save bundle checkphrase

# Step 1: Build custom images
build:
	@echo "🔨 Building Docker Compose project..."
	docker compose build

# Step 2: Pull any images not built locally
pull:
	@echo "📥 Ensuring all required images are available locally..."
	@for img in $(IMAGES); do \
		if ! docker image inspect $$img >/dev/null 2>&1; then \
			echo "  ➤ Pulling $$img..."; \
			docker pull $$img; \
		else \
			echo "  ✔ $$img already available locally."; \
		fi \
	done

# Step 3: Save images as tar files in root dir
save:
	@echo "📦 Saving Docker images to current directory..."
	@for img in $(IMAGES); do \
		safe_name=$$(echo $$img | sed 's/[\/:]/_/g'); \
		echo "  ➤ Saving $$img as $$safe_name.tar..."; \
		docker save -o $(IMAGE_DIR)/$$safe_name.tar $$img; \
	done

# Step 4: Create separate bundles
bundle: $(SCRIPTS_BUNDLE) $(CONFIG_BUNDLE)

$(SCRIPTS_BUNDLE):
	@echo "🎁 Creating scripts bundle $@..."
	tar -czf $@ \
		*.tar \
		scripts/ \
		src/

$(CONFIG_BUNDLE):
	@echo "🎁 Creating config bundle $@..."
	tar -czf $@ \
		docker-compose.yml \
		config-vault/ \
		config/ \
		vault_data \
		input/

# Step 5: Generate check phrase for all bundles
checkphrase: $(CHECKPHRASE_FILE)

$(CHECKPHRASE_FILE): $(CONFIG_BUNDLE) $(SCRIPTS_BUNDLE)
	@echo "🔑 Generating check phrase for bundles..."
	@if [ ! -f "bip39_english.txt" ]; then \
		echo "Error: BIP39 wordlist not found at bip39_english.txt"; \
		exit 1; \
	fi
	@BUNDLE_FILES="$(CONFIG_BUNDLE) $(SCRIPTS_BUNDLE)"; \
	AGGREGATE_HASH=$$(cat $$BUNDLE_FILES | sha256sum | awk '{print $$1}'); \
	echo "$$AGGREGATE_HASH" | python3 -c "import sys; hex_hash = sys.stdin.read().strip(); entropy_binary = ''.join(format(int(c, 16), '04b') for c in hex_hash); wordlist = [line.strip() for line in open('bip39_english.txt', 'r')]; words = [wordlist[int(entropy_binary[i*11:(i+1)*11], 2)].upper() for i in range(24)]; [print('%-10s %-10s %-10s %-10s' % tuple(words[i:i+4])) for i in range(0, 24, 4)]" > $@
	@echo "  ✔ Check phrase saved to $(CHECKPHRASE_FILE)"

# Optional cleanup step
clean:
	@echo "🧹 Cleaning generated files..."
	rm -f *.tar
	rm -f scripts_bundle_*.tar.gz config_bundle_*.tar.gz input_bundle_*.tar.gz
	rm -f bundle_checkphrase_*.txt