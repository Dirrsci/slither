FROM ubuntu:bionic

LABEL name slither
LABEL src "https://github.com/trailofbits/slither"
LABEL creator trailofbits
LABEL dockerfile_maintenance trailofbits
LABEL desc "Static Analyzer for Solidity"

RUN apt update \
  && apt upgrade -y \
  && apt install -y git python3 python3-setuptools wget software-properties-common

RUN wget https://github.com/ethereum/solidity/releases/download/v0.5.2/solc-static-linux \
 && chmod +x solc-static-linux \
 && mv solc-static-linux /usr/bin/solc

RUN git clone https://github.com/Dirrsci/slither.git
WORKDIR slither

RUN python3 setup.py install
CMD /bin/bash
