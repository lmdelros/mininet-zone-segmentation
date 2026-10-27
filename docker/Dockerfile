# Live test environment: Mininet + Open vSwitch + POX + a C++ toolchain.
#
# The repo itself isn't baked in -- it's mounted at /src at run time, so
# code changes don't need a rebuild:
#
#   docker build -t zone-seg-live docker/
#   docker run --rm --privileged -v "$PWD:/src:ro" zone-seg-live
#
# --privileged is required: Mininet creates network namespaces and veth
# pairs. Open vSwitch runs with its userspace datapath (see
# run_live_tests.sh), so no OVS kernel module is needed on the host --
# this works under Docker Desktop on WSL2 and on stock CI runners.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        mininet openvswitch-switch \
        g++ make git ca-certificates \
        iputils-ping netcat-openbsd iproute2 tcpdump ethtool python3 \
    && rm -rf /var/lib/apt/lists/*

# POX ichthyosaur (Python 3), pinned for reproducibility.
ARG POX_COMMIT=341aef4911a2ace04c8a014abddd10b557be1fa7
RUN git clone https://github.com/noxrepo/pox /opt/pox \
    && git -C /opt/pox checkout -q "$POX_COMMIT"

COPY run_live_tests.sh /usr/local/bin/run_live_tests.sh
RUN chmod +x /usr/local/bin/run_live_tests.sh

ENTRYPOINT ["/usr/local/bin/run_live_tests.sh"]
