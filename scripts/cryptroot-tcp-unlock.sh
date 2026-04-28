#!/bin/sh
# Example: run the client during initramfs and pipe the unlock key straight
# into cryptsetup. Drop into /etc/initramfs-tools/scripts/init-premount/
# (or local-top, depending on your distro) and rebuild the initramfs.
#
# Adjust the device path and mapping name for your system.

set -e

CRYPT_DEV=/dev/sda3
MAPPING=cryptroot

/usr/sbin/luks-unlock-client -c /etc/luks-unlock/client.conf -1 \
    | /sbin/cryptsetup luksOpen --key-file=- "$CRYPT_DEV" "$MAPPING"
