FROM kalilinux/kali-rolling:latest

LABEL description="Pegasus-Nexus - Automated wireless security auditing framework"
LABEL version="1.0.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    aircrack-ng \
    hashcat \
    crunch \
    reaver \
    hcxtools \
    wireless-tools \
    net-tools \
    iw \
    rfkill \
    pciutils \
    usbutils \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/pegasus-nexus

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

RUN pip3 install --no-cache-dir -e .

ENTRYPOINT ["pegasus-nexus"]
CMD ["--help"]
