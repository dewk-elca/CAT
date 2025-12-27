#!/bin/bash
set -e

# --- Universal Setup ---
PRINTER_TYPE=$1
PRINTER_DRIVER_10X_LASER="uld-hp/HP_Laser_10x_Series.ppd"

if [ -z "$PRINTER_TYPE" ]; then
    echo "Error: Printer type (pdf, hp, brother) not specified." >&2
    echo "Usage: entrypoint.sh <type>" >&2
    exit 1
fi

echo "Starting CUPS daemon for printer type: $PRINTER_TYPE"
/usr/sbin/cupsd -f &
CUPS_PID=$!

echo "Waiting for CUPS to become ready…"
n=0
timeout=30
until lpstat -r &>/dev/null || [ $n -ge $timeout ]; do
  sleep 1
  ((n++))
done

if ! lpstat -r &>/dev/null; then
  echo "Error: CUPS failed to start within $timeout seconds." >&2
  echo "--- CUPS error_log ---"
  cat /var/log/cups/error_log
  echo "----------------------"
  exit 1
fi

echo "CUPS is running. Proceeding with '$PRINTER_TYPE' setup..."


# --- Printer-Specific Setup Logic ---
case "$PRINTER_TYPE" in
  pdf)
    echo "Configuring CUPS-PDF printer..."
    lpadmin -p "PDF" -v "cups-pdf:/" -E -P /usr/share/ppd/cups-pdf/CUPS-PDF_opt.ppd
    cupsenable "PDF"
    cupsaccept "PDF"
    lpoptions -d "PDF"
    echo "CUPS-PDF printer 'PDF' is configured and ready."
    ;;

  hp)
    echo "Starting HP printer discovery loop..."
    echo "Connect a USB HP printer to the host to add it automatically."
    while true; do
      CONFIGURED_PRINTERS=$(lpstat -p | awk '{print $2}' || true)
      lpinfo -v | grep -E "usb://HP|hp:/" | while read -r _ device_uri _; do
        printer_name=$(echo "$device_uri" | cut -d'?' -f1 | sed 's|usb://||' | tr -c '[:alnum:]\n\r' '_')
        if ! echo "$CONFIGURED_PRINTERS" | grep -q "^${printer_name}$"; then
          echo "Found new HP printer: $printer_name at $device_uri"
          lpadmin -p "$printer_name" -v "$device_uri" -m $PRINTER_DRIVER_10X_LASER -E
          echo "Successfully added printer: $printer_name"
          if ! lpstat -d &>/dev/null; then
              lpadmin -d "$printer_name"
              echo "Set $printer_name as default."
          fi
          CONFIGURED_PRINTERS=$(lpstat -p | awk '{print $2}' || true)
        fi
      done
      sleep 5
    done &
    ;;

  brother)
    echo "Starting Brother printer discovery loop..."
    echo "Connect a USB Brother printer to the host to add it automatically."
    while true; do
      CONFIGURED_PRINTERS=$(lpstat -p | awk '{print $2}' || true)
      lpinfo -v | grep -E "usb://Brother" | while read -r _ device_uri _; do
        printer_name=$(echo "$device_uri" | cut -d'?' -f1 | sed 's|usb://||' | tr -c '[:alnum:]\n\r' '_')
        if ! echo "$CONFIGURED_PRINTERS" | grep -q "^${printer_name}$"; then
          echo "Found new Brother printer: $printer_name at $device_uri"
          # Find the appropriate PPD file for Brother
          ppd_file=$(find /opt/brother/Printers -name "*.ppd" | head -n 1)
          if [[ -n "$ppd_file" ]]; then
              echo "Using PPD file: $ppd_file"
              lpadmin -p "$printer_name" -v "$device_uri" -P "$ppd_file" -E
          else
              echo "Warning: No specific PPD found for Brother. Using generic driver."
              lpadmin -p "$printer_name" -v "$device_uri" -m everywhere -E
          fi
          echo "Successfully added printer: $printer_name"
          if ! lpstat -d &>/dev/null; then
              lpadmin -d "$printer_name"
              echo "Set $printer_name as default."
          fi
          CONFIGURED_PRINTERS=$(lpstat -p | awk '{print $2}' || true)
        fi
      done
      sleep 5
    done &
    ;;
esac

# Wait for the main CUPS process to exit to keep the container running
wait $CUPS_PID