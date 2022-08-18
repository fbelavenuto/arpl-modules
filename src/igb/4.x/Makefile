obj-m += igb.o

igb-y += igb_main.o e1000_api.o igb_ethtool.o igb_hwmon.o e1000_mbx.o \
	e1000_mac.o e1000_manage.o e1000_nvm.o igb_param.o e1000_phy.o \
	igb_procfs.o igb_vmdq.o e1000_82575.o e1000_i210.o e1000_base.o

igb-${CONFIG_DEBUG_FS} += igb_debugfs.o
igb-$(CONFIG_PTP_1588_CLOCK:m=y) += igb_ptp.o
igb-y += kcompat.o
