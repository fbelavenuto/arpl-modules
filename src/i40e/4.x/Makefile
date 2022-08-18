ccflags-y += -I$(src) -DNO_PTP_SUPPORT
subdir-ccflags-y += -I$(src) -DNO_PTP_SUPPORT

obj-m += i40e.o

i40e-y := i40e_main.o i40e_txrx.o i40e_ethtool.o i40e_xsk.o \
	i40e_adminq.o i40e_common.o i40e_hmc.o i40e_lan_hmc.o \
	i40e_nvm.o i40e_debugfs.o i40e_diag.o i40e_filters.o \
	i40e_ddp.o i40e_client.o i40e_virtchnl_pf.o

i40e-n += i40e_ptp.o
i40e-$(CONFIG_DCB) += i40e_dcb.o i40e_dcb_nl.o
#i40e-$(BROADWELLNK-Y) += i40e_dcb.o i40e_dcb_nl.o
i40e-y += kcompat.o
i40e-y += kcompat_vfd.o

obj-m += auxiliary.o
