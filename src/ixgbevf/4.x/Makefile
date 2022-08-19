obj-m += ixgbevf.o

ixgbevf-y := ixgbevf_main.o ixgbevf_ethtool.o ixgbe_vf.o ixgbe_mbx.o

ixgbevf-${CONFIG_PCI_HYPERV:m=y} += ixgbe_hv_vf.o
ixgbevf-y += kcompat.o
