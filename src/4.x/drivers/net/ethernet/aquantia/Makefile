# SPDX-License-Identifier: GPL-2.0-only
################################################################################
#
# Marvell (aQuantia) Ethernet Controller AQtion Linux Driver
# Copyright (C) 2020 Marvell International Ltd.
#
################################################################################

#
# Makefile for the AQtion(tm) Ethernet driver
#
TARGET := atlantic

subdir-ccflags-y:=-I$(src)

ifneq ($(filter gcc cc,$(CC)),)
	#subdir-ccflags-y += -DPCI_DEBUG -ggdb
	#subdir-ccflags-y += -DDEBUG_DUMPREGS
	#subdir-ccflags-y += -DTSN_SUPPORT
	subdir-ccflags-y += -Wall
endif

ifneq ($(filter clang-%,$(CC)),)
	subdir-ccflags-y += -Wno-date-time -W --system-header-prefix=linux/ \
	-fsanitize=integer,address,undefined,alignment,bool,bounds,null,\
	enum,integer-divide-by-zero,shift,unreachable,unsigned-integer-overflow
endif

$(TARGET)-objs:=aq_main.o aq_nic.o aq_pci_func.o aq_nic.o aq_vec.o aq_ring.o aq_ptp.o aq_filters.o \
        aq_hw_utils.o aq_ethtool.o aq_drvinfo.o \
        aq_trace.o \
        aq_phy.o \
        aq_compat.o \
        aq_tsn.o \
        aq_sysfs.o \
        hw_atl/hw_atl_a0.o \
        hw_atl/hw_atl_b0.o \
        hw_atl/hw_atl_utils.o \
        hw_atl/hw_atl_utils_fw2x.o \
        hw_atl/hw_atl_llh.o \
        hw_atl/hw_atl_fw_hostboot.o \
        hw_atl/hw_atl_fw_image.o \
        hw_atl2/hw_atl2_llh.o \
        hw_atl2/hw_atl2.o \
        hw_atl2/hw_atl2_utils.o \
        hw_atl2/hw_atl2_utils_fw.o \
        hw_atl2/hw_atl2_fw_hostboot.o \
        macsec/macsec_api.o \
        aq_dash.o \

$(TARGET)-$(CONFIG_MACSEC) += aq_macsec.o

obj-$(CONFIG_AQTION):=$(TARGET).o
