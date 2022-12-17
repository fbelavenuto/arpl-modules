obj-m += e1000e.o

e1000e-y += netdev.o ethtool.o ich8lan.o mac.o nvm.o phy.o \
	manage.o 80003es2lan.o 82571.o param.o

ccflags-y += -DNO_PTP_SUPPORT
e1000e-n += ptp.o

e1000e-n += kcompat.o
