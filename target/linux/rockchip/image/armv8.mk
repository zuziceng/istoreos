# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2020 Tobias Maedel

define Device/friendlyarm_nanopi-r2s
  DEVICE_VENDOR := FriendlyARM
  DEVICE_MODEL := NanoPi R2S
  SOC := rk3328
  UBOOT_DEVICE_NAME := nanopi-r2s-rk3328
  IMAGE/sysupgrade.img.gz := boot-common | boot-script nanopi-r2s | pine64-img | gzip | append-metadata
  DEVICE_PACKAGES := kmod-usb-net-rtl8152 ethtool
endef
TARGET_DEVICES += friendlyarm_nanopi-r2s

define Device/friendlyarm_nanopi-r4s
  DEVICE_VENDOR := FriendlyARM
  DEVICE_MODEL := NanoPi R4S
  DEVICE_VARIANT := 4GB LPDDR4
  SOC := rk3399
  UBOOT_DEVICE_NAME := nanopi-r4s-rk3399
  IMAGE/sysupgrade.img.gz := boot-common | boot-script nanopi-r4s | pine64-img | gzip | append-metadata
  DEVICE_PACKAGES := kmod-r8168 kmod-hwmon-pwmfan kmod-thermal
endef
TARGET_DEVICES += friendlyarm_nanopi-r4s

define Device/friendlyarm_nanopi-r4se
  DEVICE_VENDOR := FriendlyARM
  DEVICE_MODEL := NanoPi R4SE
  DEVICE_VARIANT := 4GB LPDDR4
  SOC := rk3399
  UBOOT_DEVICE_NAME := nanopi-r4se-rk3399
  IMAGE/sysupgrade.img.gz := boot-common | boot-script nanopi-r4s | pine64-img | gzip | append-metadata
  DEVICE_PACKAGES := kmod-r8168 kmod-hwmon-pwmfan kmod-thermal
endef
TARGET_DEVICES += friendlyarm_nanopi-r4se

define Device/pine64_rockpro64
  DEVICE_VENDOR := Pine64
  DEVICE_MODEL := RockPro64
  SOC := rk3399
  UBOOT_DEVICE_NAME := rockpro64-rk3399
  IMAGE/sysupgrade.img.gz := boot-common | boot-script | pine64-img | gzip | append-metadata
endef
TARGET_DEVICES += pine64_rockpro64

define Device/radxa_rock-pi-4a
  DEVICE_VENDOR := Radxa
  DEVICE_MODEL := ROCK Pi 4A
  SOC := rk3399
  SUPPORTED_DEVICES := radxa,rockpi4a radxa,rockpi4
  UBOOT_DEVICE_NAME := rock-pi-4-rk3399
  IMAGE/sysupgrade.img.gz := boot-common | boot-script | pine64-img | gzip | append-metadata
endef
TARGET_DEVICES += radxa_rock-pi-4a

define Device/rockchip_rk3308_evb
  DEVICE_VENDOR := Rochckip
  DEVICE_MODEL := RK3308 EVB
  SOC := rk3308
  UBOOT_DEVICE_NAME := evb-rk3308
  IMAGE/sysupgrade.img.gz := boot-common | boot-script rk3308 | pine64-img | gzip | append-metadata
  DEVICE_PACKAGES := kmod-usb-net-rtl8152 ethtool
endef
TARGET_DEVICES += rockchip_rk3308_evb

define Device/armsom_p2-pro
  DEVICE_VENDOR := ArmSoM
  DEVICE_MODEL := P2 Pro
  SOC := rk3308
  SUPPORTED_DEVICES := armsom,p2pro armsom,p2-pro
  UBOOT_DEVICE_NAME := easepi-rk3308
  IMAGE/sysupgrade.img.gz := boot-common | boot-script rk3308-uart2 | pine64-img | gzip | append-metadata
  DEVICE_PACKAGES := kmod-usb-net-rtl8152 ethtool kmod-rkwifi-bcmdhd rkwifi-firmware-ap6256 kmod-sound-soc-rk3308
endef
TARGET_DEVICES += armsom_p2-pro

define Device/xunlong_orangepi-5-plus
  DEVICE_VENDOR := Xunlong
  DEVICE_MODEL := Orange Pi 5 Plus
  SOC := rk3588
  UBOOT_DEVICE_NAME := orangepi-5-plus-rk3588
  IMAGE/sysupgrade.img.gz := boot-common | boot-script | pine64-img | gzip | append-metadata
  DEVICE_PACKAGES := kmod-r8125-rss
endef
TARGET_DEVICES += xunlong_orangepi-5-plus
