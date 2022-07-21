obj-m += ixgbe.o

ixgbe-y += ixgbe_main.o ixgbe_api.o ixgbe_common.o ixgbe_dcb.o \
	ixgbe_dcb_82598.o ixgbe_dcb_82599.o ixgbe_ethtool.o \
	ixgbe_lib.o ixgbe_mbx.o ixgbe_sriov.o ixgbe_param.o \
	ixgbe_phy.o ixgbe_procfs.o ixgbe_xsk.o ixgbe_82598.o \
	ixgbe_82599.o ixgbe_x540.o ixgbe_x550.o

ixgbe-$(BROADWELL-Y) += ixgbe_dcb_nl.o
ixgbe-$(BROADWELLNK-Y) += ixgbe_dcb_nl.o

ixgbe-y += ixgbe_debugfs.o
ixgbe-n += ixgbe_fcoe.o
ixgbe-n += ixgbe_ptp.o
ixgbe-y += ixgbe_sysfs.o
ixgbe-y += kcompat.o

ccflags-y += -DNO_PTP_SUPPORT
