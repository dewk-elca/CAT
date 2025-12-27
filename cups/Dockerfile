FROM debian:bookworm-slim AS base

# Install minimal CUPS and common dependencies
RUN apt-get update && apt-get install -y \
  cups \
  cups-client \
  cups-filters \
  wget \
  tar \
  gzip \
  libc6 \
  libcups2 \
  usbutils \
  libcupsimage2 \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Create remroot user and output directory
RUN useradd \
  --groups=lp,lpadmin \
  --create-home \
  --home-dir=/home/remroot \
  --shell=/bin/bash \
  remroot \
&& mkdir -p /home/remroot/PDF \
&& chown -R remroot:remroot /home/remroot

# Configure CUPS daemon for remote access
RUN sed -i 's/^Listen localhost:631/Listen 0.0.0.0:631/' /etc/cups/cupsd.conf \
&& sed -i 's|<Location />|<Location />\n  Allow all|' /etc/cups/cupsd.conf \
&& sed -i 's|<Location /admin>|<Location /admin>\n  Allow all|' /etc/cups/cupsd.conf \
&& echo "ServerAlias *" >> /etc/cups/cupsd.conf \
&& echo "User remroot" >> /etc/cups/cupsd.conf

# Copy and prepare the single, unified entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
&& chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]


# ==================================================================
# TARGET FOR CUPS-PDF
# ==================================================================
FROM base AS pdf

# Install cups-pdf specific packages
RUN apt-get update && apt-get install -y cups-pdf ghostscript \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure CUPS-PDF to output to our mounted volume and use our user
RUN sed -i 's|^Out.*|Out /home/remroot/PDF|' /etc/cups/cups-pdf.conf \
&& sed -i 's|^Owner.*|Owner remroot|' /etc/cups/cups-pdf.conf

# Set the default command for the entrypoint
CMD ["pdf"]


# ==================================================================
# TARGET FOR HP PRINTER
# ==================================================================
FROM base AS hp

# Download and install HP ULD driver
RUN wget -O /tmp/uld-hp.tar.gz https://ftp.hp.com/pub/softlib/software13/printers/CLP150/uld-hp_V1.00.39.12_00.15.tar.gz \
&& cd /tmp \
&& tar -xzf uld-hp.tar.gz \
&& cd uld \
&& AGREE_EULA="y" SKIP_EULA_PAGER=1 CONTINUE_INSTALL="y" QUIT_INSTALL="\n" UNINSTALL_LECAGY="y" sh ./install.sh \
&& cd / \
&& echo "ColorDevice No" >> /etc/cups/cupsd.conf


# Set the default command for the entrypoint
CMD ["hp"]


# ==================================================================
# TARGET FOR BROTHER PRINTER
# ==================================================================
FROM base AS brother

# Download and install Brother driver - Note the required multi-arch setup
RUN dpkg --add-architecture i386 \
&& apt-get update \
&& apt-get install -y libc6:i386 \
&& wget -O /tmp/printer_driver.deb https://download.brother.com/welcome/dlf105945/hll2400dpdrv-4.1.0-1.i386.deb \
&& dpkg -i /tmp/printer_driver.deb || apt-get -f install -y \
&& dpkg -i /tmp/printer_driver.deb \
&& rm /tmp/printer_driver.deb \
&& apt-get clean && rm -rf /var/lib/apt/lists/*

# Set the default command for the entrypoint
CMD ["brother"]