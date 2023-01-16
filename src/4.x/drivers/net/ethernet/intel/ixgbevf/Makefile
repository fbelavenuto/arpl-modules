# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 1999 - 2022 Intel Corporation.

obj-$(CONFIG_IXGBEVF) += ixgbevf.o

define ixgbevf-y
	ixgbevf_main.o
	ixgbevf_ethtool.o
	ixgbe_vf.o
	ixgbe_mbx.o
endef
ixgbevf-y := $(strip ${ixgbevf-y})
ixgbevf-${CONFIG_PCI_HYPERV:m=y} += ixgbe_hv_vf.o
ixgbevf-y += kcompat.o
