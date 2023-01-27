/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2016-2017 Broadcom Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef BNXT_XDP_H
#define BNXT_XDP_H

void __bnxt_xmit_xdp(struct bnxt *bp, struct bnxt_tx_ring_info *txr,
		   dma_addr_t mapping, u32 len, u16 rx_prod);
void bnxt_tx_int_xdp(struct bnxt *bp, struct bnxt_napi *bnapi, int nr_pkts);
#ifdef HAVE_NDO_XDP
bool bnxt_rx_xdp(struct bnxt *bp, struct bnxt_rx_ring_info *rxr, u16 cons,
		 struct page *page, u8 **data_ptr, unsigned int *len,
		 u8 *event);
#else
bool bnxt_rx_xdp(struct bnxt *bp, struct bnxt_rx_ring_info *rxr, u16 cons,
		 void *page, u8 **data_ptr, unsigned int *len,
		 u8 *event);
#endif
int bnxt_xdp(struct net_device *dev, struct netdev_xdp *xdp);
int bnxt_xdp_xmit(struct net_device *dev, struct xdp_buff *xdp);
void bnxt_xdp_flush(struct net_device *dev);

#endif
