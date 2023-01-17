# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2013 - 2022 Intel Corporation.

ccflags-y += -I$(src)
subdir-ccflags-y += -I$(src)

obj-m += i40e.o

i40e-y := i40e_main.o \
	i40e_ethtool.o \
	i40e_xsk.o \
	i40e_adminq.o \
	i40e_common.o \
	i40e_hmc.o \
	i40e_lan_hmc.o \
	i40e_nvm.o \
	i40e_debugfs.o \
	i40e_diag.o \
	i40e_txrx.o \
	i40e_ptp.o \
	i40e_filters.o \
	i40e_ddp.o \
	i40e_client.o \
	i40e_virtchnl_pf.o

i40e-$(CONFIG_DCB) += i40e_dcb.o i40e_dcb_nl.o
i40e-y += kcompat.o
i40e-y += kcompat_vfd.o

#ifeq (${NEED_AUX_BUS},2)
intel_auxiliary-objs := auxiliary.o
obj-m += intel_auxiliary.o
#$(warning ${NEED_AUX_BUS})
#endif
