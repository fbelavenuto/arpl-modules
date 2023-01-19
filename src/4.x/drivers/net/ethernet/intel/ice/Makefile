ccflags-y += -I$(src) -DNETIF_F_HW_TC
subdir-ccflags-y += -I$(src)

obj-$(CONFIG_ICE) += ice.o auxiliary.o

ice-y := ice_main.o	\
	 ice_controlq.o	\
	 ice_common.o	\
	 ice_nvm.o	\
	 ice_switch.o	\
	 ice_sched.o	\
	 ice_base.o	\
	 ice_lib.o	\
	 ice_txrx_lib.o	\
	 ice_txrx.o	\
	 ice_fltr.o	\
	 ice_irq.o	\
	 ice_pf_vsi_vlan_ops.o \
	 ice_vsi_vlan_ops.o \
	 ice_vsi_vlan_lib.o \
	 ice_gnss.o	\
	 ice_tc_lib.o	\
	 ice_fdir.o	\
	 ice_ethtool_fdir.o	\
	 ice_acl_main.o		\
	 ice_acl.o		\
	 ice_acl_ctrl.o		\
	 ice_vlan_mode.o	\
	 ice_ddp.o		\
	 ice_flex_pipe.o	\
	 ice_flow.o		\
	 ice_lag.o		\
	 ice_fwlog.o		\
	 ice_ieps.o		\
	 ice_ethtool.o
ice-$(CONFIG_NET_DEVLINK:m=y) += ice_devlink.o ice_fw_update.o
ice-$(CONFIG_NET_DEVLINK:m=y) += ice_eswitch.o ice_repr.o
ice-y += ice_idc.o
ice-$(CONFIG_DEBUG_FS) += ice_debugfs.o

ice-$(CONFIG_PCI_IOV) +=		\
	ice_dcf.o			\
	ice_sriov.o			\
	ice_vf_mbx.o			\
	ice_vf_vsi_vlan_ops.o		\
	ice_virtchnl_allowlist.o	\
	ice_vf_adq.o			\
	ice_virtchnl.o			\
	ice_virtchnl_fdir.o		\
	ice_vf_lib.o

ifneq (${ENABLE_SIOV_SUPPORT},)
ice-$(CONFIG_VFIO_MDEV:m=y) += ice_vdcm.o ice_siov.o
endif
ice-$(CONFIG_PTP_1588_CLOCK:m=y) += ice_ptp.o ice_ptp_hw.o
ice-$(CONFIG_DCB) += ice_dcb.o ice_dcb_nl.o ice_dcb_lib.o
ice-$(CONFIG_RFS_ACCEL) += ice_arfs.o
ice-$(CONFIG_XDP_SOCKETS) += ice_xsk.o
ice-y += kcompat.o
# Use kcompat pldmfw.c if kernel does not provide CONFIG_PLDMFW
ifndef CONFIG_PLDMFW
ice-y += kcompat_pldmfw.o
endif
# Use kcompat DIMLIB if kernel doesn't provide it
ifndef CONFIG_DIMLIB
ice-y += kcompat_dim.o kcompat_net_dim.o
endif
