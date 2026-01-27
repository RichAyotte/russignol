#!/bin/sh

set -u
set -e

# This is a headless device, so we don't need tty1 getty (HDMI console)
# This script intentionally does nothing - we could remove BR2_ROOTFS_POST_BUILD_SCRIPT
# but keeping it here documents that we've explicitly chosen not to add tty1 console
