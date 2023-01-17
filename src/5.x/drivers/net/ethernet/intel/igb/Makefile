# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2007 - 2022 Intel Corporation.

#
# Makefile for the Intel(R) Gigabit Ethernet Linux Driver
#

obj-$(CONFIG_IGB) += igb.o

define igb-y
	igb_main.o
	e1000_api.o
	igb_ethtool.o
	igb_hwmon.o
	e1000_mbx.o
	e1000_mac.o
	e1000_manage.o
	e1000_nvm.o
	igb_param.o
	e1000_phy.o
	igb_procfs.o
	igb_vmdq.o
	e1000_82575.o
	e1000_i210.o
	e1000_base.o
endef
igb-y := $(strip ${igb-y})

igb-${CONFIG_DEBUG_FS} += igb_debugfs.o

igb-$(CONFIG_PTP_1588_CLOCK:m=y) += igb_ptp.o


igb-y += kcompat.o
