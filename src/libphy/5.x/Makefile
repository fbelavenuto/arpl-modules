# SPDX-License-Identifier: GPL-2.0
# Makefile for Linux PHY drivers

libphy-y			:= phy.o phy-c45.o phy-core.o phy_device.o \
				   linkmode.o
mdio-bus-y			+= mdio_bus.o mdio_device.o

# PHYLIB implies MDIO_DEVICE, in that case, we have a bunch of circular
# dependencies that does not make it possible to split mdio-bus objects into a
# dedicated loadable module, so we bundle them all together into libphy.ko
ifdef CONFIG_PHYLIB
libphy-y			+= $(mdio-bus-y)
else
obj-$(CONFIG_MDIO_DEVICE)	+= mdio-bus.o
endif
obj-$(CONFIG_MDIO_DEVRES)	+= mdio_devres.o
libphy-$(CONFIG_SWPHY)		+= swphy.o
libphy-$(CONFIG_LED_TRIGGER_PHY)	+= phy_led_triggers.o

obj-m		+= libphy.o

