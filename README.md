# The Industrial Equipment Database (IEDB)

> Dataset availability: The IEDB dataset can be downloaded from the Releases section of this repository.

## Overview

IEDB is a real-world dataset collected over seven months from a single industrial production line. It records fine-grained equipment states and actions at the production takt-time granularity. The dataset spans multiple levels of the manufacturing hierarchy (from workshops to individual devices) and includes 86 devices (e.g., photoelectric sensors and motors), reflecting the heterogeneity of industrial workloads.

## Trace Adaptation for Storage Research

To support storage-system research, we convert the raw dataset into a block-level trace:

- Blockization: divide data into fixed-size 4 KB blocks.
- Content hashing: compute an SHA-256 digest per block (compatible with FIU traces).
- Timestamps: derive from source file creation times to provide an approximate ordering of data generation.

# Environment Setup and Build Guide

This guide explains how to build Linux kernel 5.10.50 with a customized F2FS and how to build FEMU (v9.0.1) with customized bbssd. All commands target Ubuntu/Debian on x86_64 Linux.

## 1) Prerequisites

- OS: Linux x86_64
- Tools: compilers and libraries for Linux kernel and FEMU/QEMU

```bash
sudo apt update
sudo apt install -y \
  build-essential gcc g++ make cmake pkg-config \
  libncurses-dev flex bison openssl libssl-dev libelf-dev dwarves bc ccache \
  git wget curl xz-utils tar \
  ninja-build meson python3 python3-pip \
  libglib2.0-dev libpixman-1-dev zlib1g-dev \
  libaio-dev liburing-dev libiscsi-dev libcap-ng-dev \
  libsdl2-dev libgtk-3-dev
```

Notes:

- On Fedora/RHEL, replace apt with dnf/yum and install equivalent packages. (Note: this setup has NOT been tested on Fedora/RHEL; commands may require adjustments).
- If building inside a VM without nested virtualization, skip KVM-related options later.

---

## 2) Build Linux Kernel 5.10.50 with Custom F2FS

This project uses Linux kernel 5.10.50. Copy the customized F2FS directory from this repository into the kernel source, then build.

```bash
# 2.1 Prepare workspace
mkdir -p ~/work && cd ~/work

# 2.2 Download Linux kernel 5.10.50
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.50.tar.xz
tar -xf linux-5.10.50.tar.xz
cd linux-5.10.50

# 2.3 Copy customized F2FS from this repository into the kernel source tree
# Adjust the source path if your repo layout differs.
cp -r /path/to/x-dedup/linux/fs/f2fs ./fs/

# 2.4 Configure the kernel (ensure F2FS is enabled)
# Option A: interactive config
make menuconfig
# Navigate: File systems -> F2FS filesystem support (enable as built-in or module)
# Option B: minimal config based on current system
# make localmodconfig

# 2.5 Build the kernel and modules
make -j"$(nproc)"

# 2.6 (Optional) Install modules and kernel to the host
# This modifies your system bootloader; skip if you only need build artifacts.
# sudo make modules_install install
```

Build artifacts:

- Kernel image: `arch/x86/boot/bzImage`
- Modules: under `./` and/or installed via `modules_install`

---

## 3) Build FEMU (v9.0.1) with Custom hw

Clone FEMU v9.0.1, copy the customized `hw` contents from this repository, then build.

```bash
# 3.1 Clone FEMU v9.0.1
cd ~/work
git clone -b femu-v9.0.1 https://github.com/MoatLab/FEMU.git
cd FEMU
git submodule update --init --recursive

# 3.2 Backup and replace 'hw' with project-customized files
mkdir -p hw.bak && cp -r hw/* hw.bak/
cp -r /path/to/x-dedup/femu/hw/* hw/

# 3.3 Configure and build (follow official FEMU document)
```
