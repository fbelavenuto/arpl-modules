# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2013, Intel Corporation.
#
# Makefile for the Intel(R) Ethernet Adaptive Virtual Function Driver
#

ccflags-y += -I$(src)
subdir-ccflags-y += -I$(src)

obj-m += iavf.o

iavf-y := iavf_main.o \
	iavf_ethtool.o \
	iavf_virtchnl.o \
	iavf_adminq.o	 \
	iavf_common.o	 \
	iavf_txrx.o \
	iavf_synce.o \
	iavf_idc.o


iavf-$(CONFIG_PTP_1588_CLOCK:m=y) += iavf_ptp.o

#ifeq (${NEED_AUX_BUS},2)
intel_auxiliary-objs := auxiliary.o
obj-m += intel_auxiliary.o
#endif

iavf-y += kcompat.o
