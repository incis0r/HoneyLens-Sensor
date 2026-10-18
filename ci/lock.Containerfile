# Environment for compiling the dependency lock — Rocky Linux 9, Python 3.12 from AppStream.
#
# Pinning must match the target, not the developer's machine: a lock made on macOS
# would resolve dependencies against a different interpreter and a different OS. Hence a container with exactly
# the Python the sensor will get in production: python3.12 from Rocky 9 AppStream,
# next to the system 3.9, which we do not touch (dnf, firewalld, semanage stand on it).
#
# Deliberately NOT under containers/ — that is where the honeypot images go, which the gate scans
# as production artifacts. This is a build tool, not an image to deploy.
#
# Usage: make lock  (see Makefile)
FROM quay.io/rockylinux/rockylinux:9

RUN dnf -y install python3.12 python3.12-pip python3.12-devel gcc libffi-devel openssl-devel \
    && dnf clean all \
    && python3.12 -m pip install --no-cache-dir --upgrade pip pip-tools pip-audit

WORKDIR /work
ENTRYPOINT ["/bin/bash", "/work/ci/lock.sh"]
