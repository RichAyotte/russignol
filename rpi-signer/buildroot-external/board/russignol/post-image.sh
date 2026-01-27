#!/bin/bash
#
# Post-image script for Russignol
# Generates SD card image with F2FS rootfs using genimage
#
# Factory image contains only Boot + RootFS partitions.
# Keys (p3) and Data (p4) partitions are created at first boot by rpi-signer
# with hardware-adaptive alignment based on SD card's discard granularity.
#

set -e

BOARD_DIR="$(dirname $0)"
GENIMAGE_CFG="${BOARD_DIR}/genimage-raspberrypizero2w.cfg"
GENIMAGE_TMP="${BUILD_DIR}/genimage.tmp"

# Pass an empty rootpath. genimage makes a full copy of the given rootpath to
# ${GENIMAGE_TMP}/root so passing TARGET_DIR would be a waste of time and disk
# space. We don't rely on genimage to build the rootfs image, just to insert a
# pre-built one in the disk image.

trap 'rm -rf "${ROOTPATH_TMP}"' EXIT
ROOTPATH_TMP="$(mktemp -d)"

rm -rf "${GENIMAGE_TMP}"

genimage \
	--rootpath "${ROOTPATH_TMP}"   \
	--tmppath "${GENIMAGE_TMP}"    \
	--inputpath "${BINARIES_DIR}"  \
	--outputpath "${BINARIES_DIR}" \
	--config "${GENIMAGE_CFG}"

exit $?
