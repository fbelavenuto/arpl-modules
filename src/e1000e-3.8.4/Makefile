
obj-m += e1000e.o
e1000e-objs := 82571.o ich8lan.o 80003es2lan.o \
               mac.o manage.o nvm.o phy.o \
               param.o ethtool.o netdev.o ptp.o

ifndef REMOVE_COMPAT
#e1000e-y += kcompat.o
endif
