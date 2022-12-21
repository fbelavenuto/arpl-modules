# SPDX-License-Identifier: GPL-2.0

obj-m += virtio.o virtio_ring.o
obj-m += virtio_mmio.o
obj-m += virtio_pci.o
virtio_pci-y := virtio_pci_modern.o virtio_pci_common.o
virtio_pci-n += virtio_pci_legacy.o
#obj-m += virtio_balloon.o
#obj-m += virtio_input.o
#obj-m += virtio_vdpa.o
#obj-m += virtio_mem.o
#obj-m += virtio_dma_buf.o
obj-m           += virtio_net.o net_failover.o failover.o

obj-m           += virtio_scsi.o
obj-m     += blk-mq-virtio.o

obj-m           += virtio_blk.o
#obj-m	+= blk-mq-cpumap.o
