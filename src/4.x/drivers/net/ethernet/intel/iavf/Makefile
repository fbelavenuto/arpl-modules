obj-$(CONFIG_IAVF) += iavf.o auxiliary.o

iavf-y := iavf_main.o \
	iavf_ethtool.o \
	iavf_virtchnl.o \
	iavf_adminq.o	 \
	iavf_common.o	 \
	iavf_txrx.o \
	iavf_idc.o
iavf-$(CONFIG_PTP_1588_CLOCK:m=y) += iavf_ptp.o
iavf-y += kcompat.o

ccflags-y += -I$(src)
subdir-ccflags-y += -I$(src)
