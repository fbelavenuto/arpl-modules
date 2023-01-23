# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 1999 - 2020 Intel Corporation.

# kbuild part of makefile
#
# Makefile for the e1000e
#

obj-$(CONFIG_E1000E) += e1000e.o

define e1000e-y
	netdev.o
	ethtool.o
	ich8lan.o
	mac.o
	nvm.o
	phy.o
	manage.o
	80003es2lan.o
	82571.o
	param.o
endef
e1000e-y := $(strip ${e1000e-y})

ifdef BUILD_PTP_SUPPORT
e1000e-$(CONFIG_PTP_1588_CLOCK:m=y) += ptp.o
else
ccflags-y += -DNO_PTP_SUPPORT
endif

ifndef REMOVE_COMPAT
e1000e-y += kcompat.o
endif
