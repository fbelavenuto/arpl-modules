/*
 * This file is part of the Linux NIC driver for Emulex networking products.
 *
 * Copyright (C) 2005-2016 Broadcom. All rights reserved.
 *
 * EMULEX and SLI are trademarks of Emulex.
 * www.emulex.com
 * linux-drivers@emulex.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful.
 * ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES,
 * INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE DISCLAIMED, EXCEPT TO THE
 * EXTENT THAT SUCH DISCLAIMERS ARE HELD TO BE LEGALLY INVALID.
 * See the GNU General Public License for more details, a copy of which
 * can be found in the file COPYING included with this package
 */

#include "be.h"
#include "be_cmds.h"
#include <linux/ethtool.h>

struct be_ethtool_stat {
	char desc[ETH_GSTRING_LEN];
	int type;
	int size;
	int offset;
};

enum {DRVSTAT_TX, DRVSTAT_RX, DRVSTAT};
#define FIELDINFO(_struct, field) FIELD_SIZEOF(_struct, field), \
					offsetof(_struct, field)
#define DRVSTAT_TX_INFO(field)	#field, DRVSTAT_TX,\
					FIELDINFO(struct be_tx_stats, field)
#define DRVSTAT_RX_INFO(field)	#field, DRVSTAT_RX,\
					FIELDINFO(struct be_rx_stats, field)
#define	DRVSTAT_INFO(field)	#field, DRVSTAT,\
					FIELDINFO(struct be_drv_stats, field)

static const struct be_ethtool_stat et_stats[] = {
	{DRVSTAT_INFO(rx_crc_errors)},
	{DRVSTAT_INFO(rx_alignment_symbol_errors)},
	{DRVSTAT_INFO(rx_pause_frames)},
	{DRVSTAT_INFO(rx_control_frames)},
	/* Received packets dropped when the Ethernet length field
	 * is not equal to the actual Ethernet data length.
	 */
	{DRVSTAT_INFO(rx_in_range_errors)},
	/* Received packets dropped when their length field is >= 1501 bytes
	 * and <= 1535 bytes.
	 */
	{DRVSTAT_INFO(rx_out_range_errors)},
	/* Received packets dropped when they are longer than 9216 bytes */
	{DRVSTAT_INFO(rx_frame_too_long)},
	/* Received packets dropped when they don't pass the unicast or
	 * multicast address filtering.
	 */
	{DRVSTAT_INFO(rx_address_filtered)},
	/* Received packets dropped when IP packet length field is less than
	 * the IP header length field.
	 */
	{DRVSTAT_INFO(rx_dropped_too_small)},
	/* Received packets dropped when IP length field is greater than
	 * the actual packet length.
	 */
	{DRVSTAT_INFO(rx_dropped_too_short)},
	/* Received packets dropped when the IP header length field is less
	 * than 5.
	 */
	{DRVSTAT_INFO(rx_dropped_header_too_small)},
	/* Received packets dropped when the TCP header length field is less
	 * than 5 or the TCP header length + IP header length is more
	 * than IP packet length.
	 */
	{DRVSTAT_INFO(rx_dropped_tcp_length)},
	{DRVSTAT_INFO(rx_dropped_runt)},
	/* Number of received packets dropped when a fifo for descriptors going
	 * into the packet demux block overflows. In normal operation, this
	 * fifo must never overflow.
	 */
	{DRVSTAT_INFO(rxpp_fifo_overflow_drop)},
	/* Received packets dropped when the RX block runs out of space in
	 * one of its input FIFOs. This could happen due a long burst of
	 * minimum-sized (64b) frames in the receive path.
	 * This counter may also be erroneously incremented rarely.
	 */
	{DRVSTAT_INFO(rx_input_fifo_overflow_drop)},
	{DRVSTAT_INFO(rx_ip_checksum_errs)},
	{DRVSTAT_INFO(rx_tcp_checksum_errs)},
	{DRVSTAT_INFO(rx_udp_checksum_errs)},
	{DRVSTAT_INFO(rx_switched_unicast_packets)},
	{DRVSTAT_INFO(rx_switched_multicast_packets)},
	{DRVSTAT_INFO(rx_switched_broadcast_packets)},
	{DRVSTAT_INFO(tx_pauseframes)},
	{DRVSTAT_INFO(tx_controlframes)},
	{DRVSTAT_INFO(rx_priority_pause_frames)},
	{DRVSTAT_INFO(tx_priority_pauseframes)},
	/* Received packets dropped when an internal fifo going into
	 * main packet buffer tank (PMEM) overflows.
	 */
	{DRVSTAT_INFO(pmem_fifo_overflow_drop)},
	{DRVSTAT_INFO(jabber_events)},
	/* Received packets dropped due to lack of available HW packet buffers
	 * used to temporarily hold the received packets.
	 */
	{DRVSTAT_INFO(rx_drops_no_pbuf)},
	/* Received packets dropped due to input receive buffer
	 * descriptor fifo overflowing.
	 */
	{DRVSTAT_INFO(rx_drops_no_erx_descr)},
	/* Packets dropped because the internal FIFO to the offloaded TCP
	 * receive processing block is full. This could happen only for
	 * offloaded iSCSI or FCoE trarffic.
	 */
	{DRVSTAT_INFO(rx_drops_no_tpre_descr)},
	/* Received packets dropped when they need more than 8
	 * receive buffers. This cannot happen as the driver configures
	 * 2048 byte receive buffers.
	 */
	{DRVSTAT_INFO(rx_drops_too_many_frags)},
	{DRVSTAT_INFO(forwarded_packets)},
	/* Received packets dropped when the frame length
	 * is more than 9018 bytes
	 */
	{DRVSTAT_INFO(rx_drops_mtu)},
	/* Number of packets dropped due to dma mapping errors */
	{DRVSTAT_INFO(dma_map_errors)},
	/* Number of packets dropped due to random early drop function */
	{DRVSTAT_INFO(eth_red_drops)},
	{DRVSTAT_INFO(link_down_reason)}
};

#define ETHTOOL_STATS_NUM ARRAY_SIZE(et_stats)

/* Stats related to multi RX queues: get_stats routine assumes bytes, pkts
 * are first and second members respectively.
 */
static const struct be_ethtool_stat et_rx_stats[] = {
	{DRVSTAT_RX_INFO(rx_bytes)},/* If moving this member see above note */
	{DRVSTAT_RX_INFO(rx_pkts)}, /* If moving this member see above note */
	{DRVSTAT_RX_INFO(rx_vxlan_offload_pkts)},
	{DRVSTAT_RX_INFO(rx_compl)},
	{DRVSTAT_RX_INFO(rx_compl_err)},
	{DRVSTAT_RX_INFO(rx_mcast_pkts)},
	/* Number of page allocation failures while posting receive buffers
	 * to HW.
	 */
	{DRVSTAT_RX_INFO(rx_post_fail)},
	/* Recevied packets dropped due to skb allocation failure */
	{DRVSTAT_RX_INFO(rx_drops_no_skbs)},
	/* Received packets dropped due to lack of available fetched buffers
	 * posted by the driver.
	 */
	{DRVSTAT_RX_INFO(rx_drops_no_frags)}
};

#define ETHTOOL_RXSTATS_NUM (ARRAY_SIZE(et_rx_stats))

/* Stats related to multi TX queues: get_stats routine assumes compl is the
 * first member
 */
static const struct be_ethtool_stat et_tx_stats[] = {
	{DRVSTAT_TX_INFO(tx_compl)}, /* If moving this member see above note */
	/* This counter is incremented when the HW encounters an error while
	 * parsing the packet header of an outgoing TX request. This counter is
	 * applicable only for BE2, BE3 and Skyhawk based adapters.
	 */
	{DRVSTAT_TX_INFO(tx_hdr_parse_err)},
	/* This counter is incremented when an error occurs in the DMA
	 * operation associated with the TX request from the host
	 * to the device.
	 */
	{DRVSTAT_TX_INFO(tx_dma_err)},
	/* This counter is incremented when MAC or VLAN spoof checking is
	 * enabled on the interface and the TX request fails the spoof check
	 * in HW. For Lancer, incremented this when the tx-compl err is either
	 * 0x3 or 0x5.
	 */
	{DRVSTAT_TX_INFO(tx_spoof_check_err)},
	/* This counter is incremented when the HW encounters an error while
	 * performing TSO offload. This counter is applicable only for Lancer
	 * adapters.
	 */
	{DRVSTAT_TX_INFO(tx_tso_err)},
	/* This counter is incremented when the HW detects Q-in-Q style VLAN
	 * tagging in a packet and such tagging is not expected on the outgoing
	 * interface. This counter is applicable only for Lancer adapters.
	 */
	{DRVSTAT_TX_INFO(tx_qinq_err)},
	/* This counter is incremented when the HW detects parity errors in the
	 * packet data. This counter is applicable only for Lancer adapters.
	 */
	{DRVSTAT_TX_INFO(tx_internal_parity_err)},
	{DRVSTAT_TX_INFO(tx_bytes)},
	{DRVSTAT_TX_INFO(tx_pkts)},
	{DRVSTAT_TX_INFO(tx_vxlan_offload_pkts)},
	/* Number of skbs queued for trasmission by the driver */
	{DRVSTAT_TX_INFO(tx_reqs)},
	/* Number of times the TX queue was stopped due to lack
	 * of spaces in the TXQ.
	 */
	{DRVSTAT_TX_INFO(tx_stops)},
	/* Pkts dropped in the driver's transmit path */
	{DRVSTAT_TX_INFO(tx_drv_drops)}
};

#define ETHTOOL_TXSTATS_NUM (ARRAY_SIZE(et_tx_stats))

static const char et_self_tests[][ETH_GSTRING_LEN] = {
	"MAC Loopback test(offline)",
	"PHY Loopback test(offline)",
	"External Loopback test(offline)",
	"DDR DMA test(online/offline)",
	"Link test(online/offline)"
};

#define ETHTOOL_TESTS_NUM ARRAY_SIZE(et_self_tests)
#define BE_MAC_LOOPBACK 0x0
#define BE_PHY_LOOPBACK 0x1
#define BE_ONE_PORT_EXT_LOOPBACK 0x2
#define BE_NO_LOOPBACK 0xff

static void be_get_drvinfo(struct net_device *netdev,
			   struct ethtool_drvinfo *drvinfo)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	int len;

	strlcpy(drvinfo->driver, DRV_NAME, sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, DRV_VER, sizeof(drvinfo->version));

	strncpy(drvinfo->fw_version, adapter->fw_ver, FW_VER_LEN);
	if (memcmp(adapter->fw_ver, adapter->fw_on_flash,
		   FW_VER_LEN) != 0) {
		len = strlen(drvinfo->fw_version);
		strncpy(drvinfo->fw_version+len, " [",
			FW_VER_LEN-len-1);
		len = strlen(drvinfo->fw_version);
		strncpy(drvinfo->fw_version+len, adapter->fw_on_flash,
			FW_VER_LEN-len-1);
		len = strlen(drvinfo->fw_version);
		strncpy(drvinfo->fw_version+len, "]", FW_VER_LEN-len-1);
	}

	strlcpy(drvinfo->bus_info, pci_name(adapter->pdev),
		sizeof(drvinfo->bus_info));
	drvinfo->testinfo_len = 0;
	drvinfo->regdump_len = 0;
	drvinfo->eedump_len = 0;
}

static u32 lancer_cmd_get_file_len(struct be_adapter *adapter, u8 *file_name)
{
	u32 data_read = 0, eof;
	u8 addn_status;
	struct be_dma_mem data_len_cmd;

	memset(&data_len_cmd, 0, sizeof(data_len_cmd));

	/* data_offset and data_size should be 0 to get reg len */
	lancer_cmd_read_object(adapter, &data_len_cmd, 0, 0,
			       file_name, &data_read, &eof, &addn_status);
	return data_read;
}

static int be_get_dump_len(struct be_adapter *adapter)
{
	u32 dump_size = 0;

	if (lancer_chip(adapter))
		dump_size = lancer_cmd_get_file_len(adapter,
						    LANCER_FW_DUMP_FILE);
	else
		dump_size = adapter->fat_dump_len;

	return dump_size;
}

#ifndef ETHTOOL_SET_DUMP_defined
static int be_get_reg_len(struct net_device *netdev)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	if (!check_privilege(adapter, MAX_PRIVILEGES))
		return 0;

	return be_get_dump_len(adapter);
}
#endif

static int lancer_cmd_read_file(struct be_adapter *adapter, u8 *file_name,
				u32 buf_len, void *buf)
{
	struct device *dev = &adapter->pdev->dev;
	struct be_dma_mem read_cmd;
	u32 read_len = 0, total_read_len = 0, chunk_size;
	u32 eof = 0;
	u8 addn_status;
	int status = 0;

	read_cmd.size = LANCER_READ_FILE_CHUNK;
	read_cmd.va = dma_zalloc_coherent(dev, read_cmd.size, &read_cmd.dma,
					 GFP_KERNEL);

	if (!read_cmd.va) {
		dev_err(dev, "%s: Memory allocation failure\n", __func__);
		return -ENOMEM;
	}

	while ((total_read_len < buf_len) && !eof) {
		chunk_size = min_t(u32, (buf_len - total_read_len),
				   LANCER_READ_FILE_CHUNK);
		chunk_size = ALIGN(chunk_size, 4);
		status = lancer_cmd_read_object(adapter, &read_cmd, chunk_size,
						total_read_len, file_name,
						&read_len, &eof, &addn_status);
		if (!status) {
			memcpy(buf + total_read_len, read_cmd.va, read_len);
			total_read_len += read_len;
			eof &= LANCER_READ_FILE_EOF_MASK;
		} else {
			status = -EIO;
			break;
		}
	}
	dma_free_coherent(dev, read_cmd.size, read_cmd.va, read_cmd.dma);

	return status;
}

static int be_read_dump_data(struct be_adapter *adapter, u32 dump_len,
			     void *buf)
{
	int status = 0;

	if (lancer_chip(adapter))
		status = lancer_cmd_read_file(adapter, LANCER_FW_DUMP_FILE,
					      dump_len, buf);
	else
		status = be_cmd_get_fat_dump(adapter, dump_len, buf);

	return status;
}

#ifndef ETHTOOL_SET_DUMP_defined
static void be_get_regs(struct net_device *netdev, struct ethtool_regs *regs,
			void *buf)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	if (!check_privilege(adapter, MAX_PRIVILEGES))
		return;

	memset(buf, 0, regs->len);

	be_read_dump_data(adapter, regs->len, buf);
}
#endif

/* We don't have per-queue setting. So, just fetch the first queue's values */
static int be_get_coalesce(struct net_device *netdev,
			   struct ethtool_coalesce *et)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	struct be_aic_obj *aic = &adapter->aic_obj[0];

	et->rx_coalesce_usecs = aic->prev_eqd;
	et->rx_coalesce_usecs_high = aic->max_eqd;
	et->rx_coalesce_usecs_low = aic->min_eqd;

	et->tx_coalesce_usecs = aic->prev_eqd;
	et->tx_coalesce_usecs_high = aic->max_eqd;
	et->tx_coalesce_usecs_low = aic->min_eqd;

	et->use_adaptive_rx_coalesce = aic->enable;
	et->use_adaptive_tx_coalesce = aic->enable;

	return 0;
}

/* For now TX attributes are ignored. Only RX attributed are considered
 * eqd cmd is sent in the worker thread.
 */
static int be_set_coalesce(struct net_device *netdev,
			   struct ethtool_coalesce *et)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	struct be_aic_obj *aic = &adapter->aic_obj[0];
	struct be_eq_obj *eqo;
	int i;

	for_all_evt_queues(adapter, eqo, i) {
		aic->enable = et->use_adaptive_rx_coalesce;
		aic->max_eqd = min(et->rx_coalesce_usecs_high, BE_MAX_EQD);
		aic->min_eqd = min(et->rx_coalesce_usecs_low, aic->max_eqd);
		aic->et_eqd = min(et->rx_coalesce_usecs, aic->max_eqd);
		aic->et_eqd = max(aic->et_eqd, aic->min_eqd);
		aic++;
	}

	if (!et->use_adaptive_rx_coalesce && skyhawk_chip(adapter))
		be_eqd_update(adapter, true);

	return 0;
}

#ifndef NDO_SET_FEATURES_defined
static u32 be_get_rx_csum(struct net_device *netdev)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	return adapter->rx_csum;
}

static int be_set_rx_csum(struct net_device *netdev, uint32_t data)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	if (data)
		adapter->rx_csum = true;
	else
		adapter->rx_csum = false;

	return 0;
}

static int be_set_tx_csum(struct net_device *netdev, uint32_t data)
{
	if (data) {
		netdev->features |= NETIF_F_IP_CSUM;
		netdev->features |= NETIF_F_IPV6_CSUM;
	} else {
		netdev->features &= ~NETIF_F_IP_CSUM;
		netdev->features &= ~NETIF_F_IPV6_CSUM;
	}
	return 0;
}

static int be_set_tso(struct net_device *netdev, uint32_t data)
{
	if (data) {
		netdev->features |= NETIF_F_TSO;
		netdev->features |= NETIF_F_TSO6;
	} else {
		netdev->features &= ~NETIF_F_TSO;
		netdev->features &= ~NETIF_F_TSO6;
	}
	return 0;
}
#endif

static void be_get_ethtool_stats(struct net_device *netdev,
				 struct ethtool_stats *stats, uint64_t *data)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	struct be_rx_obj *rxo;
	struct be_tx_obj *txo;
	void *p;
	unsigned int i, j, base = 0, start;

	for (i = 0; i < ETHTOOL_STATS_NUM; i++) {
		p = (u8 *)&adapter->drv_stats + et_stats[i].offset;
		data[i] = *(u32 *)p;
	}
	base += ETHTOOL_STATS_NUM;

	for_all_rx_queues(adapter, rxo, j) {
		struct be_rx_stats *stats = rx_stats(rxo);

		do {
			start = u64_stats_fetch_begin_irq(&stats->sync);
			data[base] = stats->rx_bytes;
			data[base + 1] = stats->rx_pkts;
		} while (u64_stats_fetch_retry_irq(&stats->sync, start));

		for (i = 2; i < ETHTOOL_RXSTATS_NUM; i++) {
			p = (u8 *)stats + et_rx_stats[i].offset;
			data[base + i] =
				(et_rx_stats[i].size == sizeof(u64)) ?
					*(u64 *)p: *(u32 *)p;
		}
		base += ETHTOOL_RXSTATS_NUM;
	}

	for_all_tx_queues(adapter, txo, j) {
		struct be_tx_stats *stats = tx_stats(txo);

		do {
			start = u64_stats_fetch_begin_irq(&stats->sync_compl);
			data[base] = stats->tx_compl;
		} while (u64_stats_fetch_retry_irq(&stats->sync_compl, start));

		do {
			start = u64_stats_fetch_begin_irq(&stats->sync);
			for (i = 1; i < ETHTOOL_TXSTATS_NUM; i++) {
				p = (u8 *)stats + et_tx_stats[i].offset;
				data[base + i] =
					(et_tx_stats[i].size == sizeof(u64)) ?
						*(u64 *)p : *(u32 *)p;
			}
		} while (u64_stats_fetch_retry_irq(&stats->sync, start));
		base += ETHTOOL_TXSTATS_NUM;
	}
}

static const char be_priv_flags[][ETH_GSTRING_LEN] = {
	"disable-tpe-recovery"
};

static void be_get_stat_strings(struct net_device *netdev, uint32_t stringset,
				uint8_t *data)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	int i, j;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < ETHTOOL_STATS_NUM; i++) {
			memcpy(data, et_stats[i].desc, ETH_GSTRING_LEN);
			data += ETH_GSTRING_LEN;
		}
		for (i = 0; i < adapter->num_rx_qs; i++) {
			for (j = 0; j < ETHTOOL_RXSTATS_NUM; j++) {
				sprintf(data, "rxq%d: %s", i,
					et_rx_stats[j].desc);
				data += ETH_GSTRING_LEN;
			}
		}
		for (i = 0; i < adapter->num_tx_qs; i++) {
			for (j = 0; j < ETHTOOL_TXSTATS_NUM; j++) {
				sprintf(data, "txq%d: %s", i,
					et_tx_stats[j].desc);
				data += ETH_GSTRING_LEN;
			}
		}
		break;
	case ETH_SS_TEST:
		for (i = 0; i < ETHTOOL_TESTS_NUM; i++) {
			memcpy(data, et_self_tests[i], ETH_GSTRING_LEN);
			data += ETH_GSTRING_LEN;
		}
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < ARRAY_SIZE(be_priv_flags); i++)
			strcpy(data + i * ETH_GSTRING_LEN, be_priv_flags[i]);
		break;
	}
}

#ifdef ETHTOOL_SSET_COUNT_defined
static int be_get_sset_count(struct net_device *netdev, int stringset)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	switch (stringset) {
	case ETH_SS_TEST:
		return ETHTOOL_TESTS_NUM;
	case ETH_SS_STATS:
		return ETHTOOL_STATS_NUM +
			adapter->num_rx_qs * ETHTOOL_RXSTATS_NUM +
			adapter->num_tx_qs * ETHTOOL_TXSTATS_NUM;
	case ETH_SS_PRIV_FLAGS:
		return ARRAY_SIZE(be_priv_flags);
	default:
		return -EINVAL;
	}
}
#else

static int be_get_stats_count(struct net_device *netdev)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	return ETHTOOL_STATS_NUM + adapter->num_rx_qs * ETHTOOL_RXSTATS_NUM
		+ adapter->num_tx_qs * ETHTOOL_TXSTATS_NUM;
}

static int be_self_test_count(struct net_device *dev)
{
	return ETHTOOL_TESTS_NUM;
}
#endif /* ETHTOOL_SSET_COUNT */


static u32 be_get_port_type(struct be_adapter *adapter)
{
	u32 port;

	switch (adapter->phy.interface_type) {
	case PHY_TYPE_BASET_1GB:
	case PHY_TYPE_BASEX_1GB:
	case PHY_TYPE_SGMII:
		port = PORT_TP;
		break;
	case PHY_TYPE_SFP_PLUS_10GB:
		if (adapter->phy.cable_type & SFP_PLUS_COPPER_CABLE)
			port = PORT_DA;
		else
			port = PORT_FIBRE;
		break;
	case PHY_TYPE_QSFP:
		if (adapter->phy.cable_type & QSFP_PLUS_CR4_CABLE)
			port = PORT_DA;
		else
			port = PORT_FIBRE;
		break;
	case PHY_TYPE_XFP_10GB:
	case PHY_TYPE_SFP_1GB:
		port = PORT_FIBRE;
		break;
	case PHY_TYPE_BASET_10GB:
		port = PORT_TP;
		break;
	default:
		port = PORT_OTHER;
	}

	return port;
}

static u32 convert_to_et_setting(struct be_adapter *adapter, u32 if_speeds)
{
	u32 val = 0;

	switch (adapter->phy.interface_type) {
	case PHY_TYPE_BASET_1GB:
	case PHY_TYPE_BASEX_1GB:
	case PHY_TYPE_SGMII:
		val |= SUPPORTED_TP;
		if (if_speeds & BE_SUPPORTED_SPEED_1GBPS)
			val |= SUPPORTED_1000baseT_Full;
		if (if_speeds & BE_SUPPORTED_SPEED_100MBPS)
			val |= SUPPORTED_100baseT_Full;
		if (if_speeds & BE_SUPPORTED_SPEED_10MBPS)
			val |= SUPPORTED_10baseT_Full;
		break;
	case PHY_TYPE_KX4_10GB:
		val |= SUPPORTED_Backplane;
		if (if_speeds & BE_SUPPORTED_SPEED_1GBPS)
			val |= SUPPORTED_1000baseKX_Full;
		if (if_speeds & BE_SUPPORTED_SPEED_10GBPS)
			val |= SUPPORTED_10000baseKX4_Full;
		break;
	case PHY_TYPE_KR4_40GB:
		val |= SUPPORTED_Backplane;
		if (if_speeds & BE_SUPPORTED_SPEED_10GBPS)
			val |= SUPPORTED_10000baseKR_Full;
		if (if_speeds & BE_SUPPORTED_SPEED_40GBPS)
			val |= SUPPORTED_40000baseKR4_Full;
		break;
	case PHY_TYPE_KR2_20GB:
		val |= SUPPORTED_Backplane;
		if (if_speeds & BE_SUPPORTED_SPEED_1GBPS)
			val |= SUPPORTED_1000baseKX_Full;
		if (if_speeds & BE_SUPPORTED_SPEED_10GBPS)
			val |= SUPPORTED_10000baseKR_Full;
		if (if_speeds & BE_SUPPORTED_SPEED_20GBPS)
			val |= SUPPORTED_20000baseKR2_Full;
		break;
	case PHY_TYPE_KR_10GB:
		val |= SUPPORTED_Backplane;
		if (if_speeds & BE_SUPPORTED_SPEED_1GBPS)
			val |= SUPPORTED_1000baseKX_Full;
		if (if_speeds & BE_SUPPORTED_SPEED_10GBPS)
			val |= SUPPORTED_10000baseKR_Full;
		break;
	case PHY_TYPE_QSFP:
		val |= SUPPORTED_FIBRE;
		if (if_speeds & BE_SUPPORTED_SPEED_40GBPS) {
			switch (adapter->phy.cable_type) {
			case QSFP_PLUS_CR4_CABLE:
				val |= SUPPORTED_40000baseCR4_Full;
				break;
			case QSFP_PLUS_LR4_CABLE:
				val |= SUPPORTED_40000baseLR4_Full;
				break;
			default:
				val |= SUPPORTED_40000baseSR4_Full;
				break;
			}
		}
	case PHY_TYPE_SFP_PLUS_10GB:
	case PHY_TYPE_XFP_10GB:
	case PHY_TYPE_SFP_1GB:
		val |= SUPPORTED_FIBRE;
		if (if_speeds & BE_SUPPORTED_SPEED_10GBPS)
			val |= SUPPORTED_10000baseT_Full;
		if (if_speeds & BE_SUPPORTED_SPEED_1GBPS)
			val |= SUPPORTED_1000baseT_Full;
		break;
	case PHY_TYPE_BASET_10GB:
		val |= SUPPORTED_TP;
		if (if_speeds & BE_SUPPORTED_SPEED_10GBPS)
			val |= SUPPORTED_10000baseT_Full;
		if (if_speeds & BE_SUPPORTED_SPEED_1GBPS)
			val |= SUPPORTED_1000baseT_Full;
		if (if_speeds & BE_SUPPORTED_SPEED_100MBPS)
			val |= SUPPORTED_100baseT_Full;
		break;
	default:
		val |= SUPPORTED_TP;
	}

	return val;
}

bool be_pause_autoneg_supported(struct be_adapter *adapter)
{
	return (adapter->phy.interface_type == PHY_TYPE_SFP_PLUS_10GB ||
		adapter->phy.interface_type == PHY_TYPE_QSFP ||
		adapter->phy.interface_type == PHY_TYPE_XFP_10GB) ?
		false : true;
}

static int be_get_settings(struct net_device *netdev, struct ethtool_cmd *ecmd)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	u16 link_speed = 0;
	int status;
	u32 auto_speeds;
	u32 fixed_speeds;

	if (adapter->phy.link_speed < 0) {
		be_cmd_link_status_query(adapter, &link_speed, NULL, 0);

		status = be_cmd_get_phy_info(adapter);
		if (!status) {
			auto_speeds = adapter->phy.auto_speeds_supported;
			fixed_speeds = adapter->phy.fixed_speeds_supported;

			be_cmd_query_cable_type(adapter);

			ecmd->supported =
				convert_to_et_setting(adapter,
						      auto_speeds |
						      fixed_speeds);
			if (BE2_chip(adapter))
				ecmd->supported |= SUPPORTED_10000baseT_Full |
						SUPPORTED_1000baseT_Full;
			ecmd->advertising =
				convert_to_et_setting(adapter, auto_speeds);

			ecmd->port = be_get_port_type(adapter);

			if (adapter->phy.auto_speeds_supported) {
				ecmd->supported |= SUPPORTED_Autoneg;
				ecmd->autoneg = adapter->phy.autoneg;
				ecmd->advertising |= ADVERTISED_Autoneg;
			}

			ecmd->supported |= SUPPORTED_Pause;
			if (be_pause_autoneg_supported(adapter))
				ecmd->advertising |= ADVERTISED_Pause;

			switch (adapter->phy.interface_type) {
			case PHY_TYPE_KR_10GB:
			case PHY_TYPE_KX4_10GB:
			case PHY_TYPE_KR4_40GB:
				ecmd->transceiver = XCVR_INTERNAL;
				break;
			default:
				ecmd->transceiver = XCVR_EXTERNAL;
				break;
			}
		} else {
			ecmd->port = PORT_OTHER;
			ecmd->autoneg = AUTONEG_DISABLE;
			ecmd->transceiver = XCVR_DUMMY1;
		}

		/* Save for future use */
		adapter->phy.link_speed = link_speed;
		adapter->phy.port_type = ecmd->port;
		adapter->phy.transceiver = ecmd->transceiver;
		adapter->phy.advertising = ecmd->advertising;
		adapter->phy.supported = ecmd->supported;
	} else {
		link_speed = adapter->phy.link_speed;
		ecmd->port = adapter->phy.port_type;
		ecmd->transceiver = adapter->phy.transceiver;
		ecmd->autoneg = adapter->phy.autoneg;
		ecmd->advertising = adapter->phy.advertising;
		ecmd->supported = adapter->phy.supported;
	}

	if (netif_carrier_ok(netdev)) {
		ethtool_cmd_speed_set(ecmd, link_speed);
		ecmd->duplex = DUPLEX_FULL;
	} else {
		ethtool_cmd_speed_set(ecmd, -1);
		ecmd->duplex = -1;
	}

	ecmd->phy_address = adapter->hba_port_num;

	return 0;
}

static u16 ethtool_to_be_adv_speed(u32 advertising)
{
	u16 speed = 0;

	if (advertising & ADVERTISED_100baseT_Full &&
	    advertising & ADVERTISED_1000baseT_Full &&
	    advertising & ADVERTISED_10000baseT_Full)
		speed = SPEED_AUTONEG_10GB_1GB_100MB;
	else if	(advertising & ADVERTISED_10baseT_Full &&
		 advertising & ADVERTISED_100baseT_Full &&
		 advertising & ADVERTISED_1000baseT_Full)
		speed = SPEED_AUTONEG_1GB_100MB_10MB;
	else if (advertising & ADVERTISED_1000baseT_Full &&
		 advertising & ADVERTISED_100baseT_Full)
		speed = SPEED_AUTONEG_1GB_100MB;
	else if (advertising & ADVERTISED_10baseT_Full &&
		 advertising & ADVERTISED_100baseT_Full)
		speed = SPEED_AUTONEG_100MB_10MB;
	else if (advertising & ADVERTISED_20000baseKR2_Full &&
		 advertising & ADVERTISED_10000baseKR_Full &&
		 advertising & ADVERTISED_1000baseKX_Full)
		speed = SPEED_AUTONEG_20GB_10GB_1GB;
	else if (advertising & ADVERTISED_40000baseKR4_Full &&
		 advertising & ADVERTISED_10000baseKR_Full &&
		 advertising & ADVERTISED_1000baseKX_Full)
		speed = SPEED_AUTONEG_40GB_10GB_1GB;
	else if (advertising & ADVERTISED_20000baseKR2_Full &&
		 advertising & ADVERTISED_10000baseKR_Full)
		speed = SPEED_AUTONEG_20GB_10GB;
	else if (advertising & ADVERTISED_20000baseKR2_Full &&
		 advertising & ADVERTISED_1000baseKX_Full)
		speed = SPEED_AUTONEG_20GB_1GB;
	else if (advertising & ADVERTISED_1000baseT_Full &&
		 advertising & ADVERTISED_10000baseT_Full)
		speed = SPEED_AUTONEG_10GB_1GB;
	else if ((advertising & ADVERTISED_10000baseKX4_Full ||
		  advertising & ADVERTISED_10000baseKR_Full) &&
		  advertising & ADVERTISED_1000baseKX_Full)
		speed = SPEED_AUTONEG_10GB_1GB;
	else if (advertising & ADVERTISED_40000baseKR4_Full &&
		 advertising & ADVERTISED_10000baseKR_Full)
		speed = SPEED_AUTONEG_40GB_10GB;
	else if (advertising & ADVERTISED_40000baseKR4_Full &&
		 advertising & ADVERTISED_1000baseKX_Full)
		speed = SPEED_AUTONEG_40GB_1GB;
	else if (advertising & ADVERTISED_40000baseKR4_Full)
		speed = SPEED_AUTONEG_40GB;
	else if (advertising & ADVERTISED_20000baseKR2_Full)
		speed = SPEED_AUTONEG_20GB;
	else if (advertising & ADVERTISED_10000baseT_Full ||
		 advertising & ADVERTISED_10000baseKX4_Full ||
		advertising & ADVERTISED_10000baseKR_Full)
		speed = SPEED_AUTONEG_10GB;
	else if (advertising & ADVERTISED_1000baseT_Full ||
		 advertising & ADVERTISED_1000baseKX_Full)
		speed = SPEED_AUTONEG_1GB;
	else if (advertising & ADVERTISED_100baseT_Full)
		speed = SPEED_AUTONEG_100MB;
	else if (advertising & ADVERTISED_10baseT_Full)
		speed = SPEED_AUTONEG_10MB;

	return speed;
}

static int be_set_settings(struct net_device *netdev,
			   struct ethtool_cmd *ecmd)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	u16 speed = 0;
	u16 link_speed = 0;
	u8 link_status;
	int status = 0;

	status = be_cmd_get_phy_info(adapter);
	if (status) {
		dev_warn(&adapter->pdev->dev, "port speed set failed\n");
		return -EIO;
	}

	if (ecmd->autoneg == AUTONEG_ENABLE) {
		if (adapter->phy.interface_type == PHY_TYPE_SFP_PLUS_10GB ||
		    adapter->phy.interface_type == PHY_TYPE_QSFP) {
			dev_warn(&adapter->pdev->dev,
				 "Autoneg not supported on this module\n");
			return -EINVAL;
		}

		if (!ecmd->advertising ||
		    (adapter->phy.advertising == ecmd->advertising))
			goto done;

		if (ecmd->advertising & ~adapter->phy.supported)
			return -EINVAL;

		speed = ethtool_to_be_adv_speed(ecmd->advertising);
	} else if (ecmd->autoneg == AUTONEG_DISABLE) {
		be_cmd_query_cable_type(adapter);
		if ((adapter->phy.interface_type == PHY_TYPE_SFP_PLUS_10GB &&
		     adapter->phy.cable_type & SFP_PLUS_COPPER_CABLE) ||
		    (adapter->phy.interface_type == PHY_TYPE_QSFP &&
		     adapter->phy.cable_type & QSFP_PLUS_CR4_CABLE))
			return -EOPNOTSUPP;

		if (adapter->phy.autoneg == AUTONEG_DISABLE) {
			status = be_cmd_link_status_query(adapter, &link_speed,
							  &link_status, 0);
			if (!status && link_speed == ecmd->speed)
				goto done;
		}

		if (ecmd->speed == SPEED_10)
			speed = SPEED_FORCED_10MB;
		else if (ecmd->speed == SPEED_100)
			speed = SPEED_FORCED_100MB;
		else if (ecmd->speed == SPEED_1000)
			speed = SPEED_FORCED_1GB;
		else if (ecmd->speed == SPEED_10000)
			speed = SPEED_FORCED_10GB;
		else if (ecmd->speed == SPEED_40000)
			speed = SPEED_FORCED_40GB;
	}

	status = be_cmd_set_port_speed_v1(adapter,
					  adapter->hba_port_num,
					  speed);
	if (status) {
		dev_warn(&adapter->pdev->dev, "port speed set failed.\n");
		return -EINVAL;
	}

done:
	adapter->phy.autoneg = ecmd->autoneg;

	return 0;
}

static void be_get_ringparam(struct net_device *netdev,
			     struct ethtool_ringparam *ring)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	ring->rx_max_pending = adapter->rx_obj[0].q.len;
	ring->rx_pending = adapter->rx_obj[0].q.len;
	ring->tx_max_pending = adapter->tx_obj[0].q.len;
	ring->tx_pending = adapter->tx_obj[0].q.len;
}

static void be_get_pauseparam(struct net_device *netdev,
			      struct ethtool_pauseparam *ecmd)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	be_cmd_get_flow_control(adapter, &ecmd->tx_pause, &ecmd->rx_pause);
	ecmd->autoneg = adapter->phy.fc_autoneg;
}

static int be_set_pauseparam(struct net_device *netdev,
			     struct ethtool_pauseparam *ecmd)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	int status;

	if (ecmd->autoneg != adapter->phy.fc_autoneg)
		return -EINVAL;

	status = be_cmd_set_flow_control(adapter, ecmd->tx_pause,
					 ecmd->rx_pause);
	if (status) {
		dev_err(&adapter->pdev->dev,
			"Failed to set Ethernet flow control parameters\n");
		if (base_status(status) == MCC_STATUS_FEATURE_NOT_SUPPORTED)
			return -EOPNOTSUPP;
		return be_cmd_status(status);
	}

	adapter->tx_fc = ecmd->tx_pause;
	adapter->rx_fc = ecmd->rx_pause;
	return 0;
}

#ifndef PHYS_ID_STATE_defined
static int be_phys_id(struct net_device *netdev, u32 data)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	int status;
	u32 cur;

	status = be_cmd_get_beacon_state(adapter, adapter->hba_port_num, &cur);
	if (status)
		return be_cmd_status(status);

	if (cur == BEACON_STATE_ENABLED)
		return 0;

	if (data < 2)
		data = 2;

	status = be_cmd_set_beacon_state(adapter, adapter->hba_port_num, 0, 0,
					 BEACON_STATE_ENABLED);
	if (status)
		return be_cmd_status(status);

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(data*HZ);

	status = be_cmd_set_beacon_state(adapter, adapter->hba_port_num, 0, 0,
					 BEACON_STATE_DISABLED);

	return be_cmd_status(status);
}
#else
static int be_set_phys_id(struct net_device *netdev,
			  enum ethtool_phys_id_state state)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	int status = 0;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		status = be_cmd_get_beacon_state(adapter, adapter->hba_port_num,
						 &adapter->beacon_state);
		if (status)
			return be_cmd_status(status);
		return 1;       /* cycle on/off once per second */

	case ETHTOOL_ID_ON:
		status = be_cmd_set_beacon_state(adapter, adapter->hba_port_num,
						 0, 0, BEACON_STATE_ENABLED);
		break;

	case ETHTOOL_ID_OFF:
		status = be_cmd_set_beacon_state(adapter, adapter->hba_port_num,
						 0, 0, BEACON_STATE_DISABLED);
		break;

	case ETHTOOL_ID_INACTIVE:
		status = be_cmd_set_beacon_state(adapter, adapter->hba_port_num,
						 0, 0, adapter->beacon_state);
	}

	return be_cmd_status(status);
}
#endif

static void be_get_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	if (adapter->wol_cap & BE_WOL_CAP) {
		wol->supported |= WAKE_MAGIC;
		if (adapter->wol_en)
			wol->wolopts |= WAKE_MAGIC;
	} else
		wol->wolopts = 0;
	memset(&wol->sopass, 0, sizeof(wol->sopass));
}

static int be_set_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	struct device *dev = &adapter->pdev->dev;
	struct be_dma_mem cmd;
	u8 mac[ETH_ALEN];
	bool enable;
	int status;

	if (wol->wolopts & ~WAKE_MAGIC)
		return -EOPNOTSUPP;

	if (!(adapter->wol_cap & BE_WOL_CAP)) {
		dev_warn(&adapter->pdev->dev, "WOL not supported\n");
		return -EOPNOTSUPP;
	}

	cmd.size = sizeof(struct be_cmd_req_acpi_wol_magic_config);
	cmd.va = dma_zalloc_coherent(dev, cmd.size, &cmd.dma, GFP_KERNEL);
	if (!cmd.va)
		return -ENOMEM;

	eth_zero_addr(mac);

	enable = wol->wolopts & WAKE_MAGIC;
	if (enable)
		ether_addr_copy(mac, adapter->netdev->dev_addr);

	status = be_cmd_enable_magic_wol(adapter, mac, &cmd);
	if (status) {
		dev_err(dev, "Could not set Wake-on-lan mac address\n");
		status = be_cmd_status(status);
		goto err;
	}

	pci_enable_wake(adapter->pdev, PCI_D3hot, enable);
	pci_enable_wake(adapter->pdev, PCI_D3cold, enable);

	adapter->wol_en = enable ? true : false;

err:
	dma_free_coherent(dev, cmd.size, cmd.va, cmd.dma);
	return status;
}

static int be_test_ddr_dma(struct be_adapter *adapter)
{
	int ret, i;
	struct be_dma_mem ddrdma_cmd;
	u64 pattern[2] = {0x5a5a5a5a5a5a5a5aULL, 0xa5a5a5a5a5a5a5a5ULL};
	struct device *dev = &adapter->pdev->dev;

	ddrdma_cmd.size = sizeof(struct be_cmd_req_ddrdma_test);
	ddrdma_cmd.va = dma_zalloc_coherent(dev, ddrdma_cmd.size,
					   &ddrdma_cmd.dma, GFP_KERNEL);
	if (!ddrdma_cmd.va) {
		dev_err(dev, "%s: Memory allocation failure\n", __func__);
		return -ENOMEM;
	}

	for (i = 0; i < 2; i++) {
		ret = be_cmd_ddr_dma_test(adapter, pattern[i], 4096,
					  &ddrdma_cmd);
		if (ret != 0)
			goto err;
	}

err:
	dma_free_coherent(dev, ddrdma_cmd.size, ddrdma_cmd.va, ddrdma_cmd.dma);
	return be_cmd_status(ret);
}

static u64 be_loopback_test(struct be_adapter *adapter, u8 loopback_type,
			    u64 *status)
{
	int ret;

	ret = be_cmd_set_loopback(adapter, adapter->hba_port_num,
				  loopback_type, 1);
	if (ret)
		return ret;

	*status = be_cmd_loopback_test(adapter, adapter->hba_port_num,
				       loopback_type, 1500, 2, 0xabc);
	ret = be_cmd_set_loopback(adapter, adapter->hba_port_num,
				  BE_NO_LOOPBACK, 1);
	if (ret)
		return ret;

	return *status;
}

static void be_self_test(struct net_device *netdev, struct ethtool_test *test,
			 u64 *data)
{
#define LINK_READY_TIMEOUT 5
	struct be_adapter *adapter = netdev_priv(netdev);
	int status;
	u8 link_status = 0;
	int timeout = netif_carrier_ok(netdev) ? 0 : LINK_READY_TIMEOUT;

	if (adapter->function_caps & BE_FUNCTION_CAPS_SUPER_NIC &&
	    test->flags & ETH_TEST_FL_OFFLINE) {
		memset(data, -1, sizeof(u64) * ETHTOOL_TESTS_NUM);
		dev_err(&adapter->pdev->dev, "offline test not supported\n");
		test->flags |= ETH_TEST_FL_FAILED;
		return;
	}

	memset(data, 0, sizeof(u64) * ETHTOOL_TESTS_NUM);

	if (test->flags & ETH_TEST_FL_OFFLINE) {
		if (be_loopback_test(adapter, BE_MAC_LOOPBACK,
				     &data[0]) != 0) {
			test->flags |= ETH_TEST_FL_FAILED;
		}
		if (be_loopback_test(adapter, BE_PHY_LOOPBACK,
				     &data[1]) != 0) {
			test->flags |= ETH_TEST_FL_FAILED;
		}
	}

#ifdef ETHTOOL_EXTERNAL_LB_defined
	if (test->flags & ETH_TEST_FL_EXTERNAL_LB) {
		if (be_loopback_test(adapter, BE_ONE_PORT_EXT_LOOPBACK,
				     &data[2]) != 0) {
			test->flags |= ETH_TEST_FL_FAILED;
		}
		test->flags |= ETH_TEST_FL_EXTERNAL_LB_DONE;
	}
#endif /* ETHTOOL_EXTERNAL_LB_defined */

	if (!lancer_chip(adapter) && be_test_ddr_dma(adapter) != 0) {
		data[3] = 1;
		test->flags |= ETH_TEST_FL_FAILED;
	}

	/* After the loopback test is finished,
	 * it takes a few seconds for the link to comeback up.
	 * Poll for 5s before reporting a failure to the link test.
	 */
	do {
		status = be_cmd_link_status_query(adapter, NULL,
						  &link_status, 0);
		if (link_status || status || ++timeout >= LINK_READY_TIMEOUT)
			break;
		ssleep(1);
	} while (true);

	if (status) {
		test->flags |= ETH_TEST_FL_FAILED;
		data[4] = status;
	} else if (!link_status) {
		test->flags |= ETH_TEST_FL_FAILED;
		data[4] = 1;
	}
}

#ifdef ETHTOOL_FLASH_defined
static int be_do_flash(struct net_device *netdev, struct ethtool_flash *efl)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	char file_name[ETHTOOL_FLASH_MAX_FILENAME];

	file_name[ETHTOOL_FLASH_MAX_FILENAME - 1] = 0;
	strlcpy(file_name, efl->data, sizeof(file_name));

	return be_load_fw(adapter, file_name);
}
#endif /* ETHTOOL_FLASH_defined */

#ifdef ETHTOOL_SET_DUMP_defined
static int
be_get_dump_flag(struct net_device *netdev, struct ethtool_dump *dump)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	if (!check_privilege(adapter, MAX_PRIVILEGES))
		return -EOPNOTSUPP;

	dump->len = be_get_dump_len(adapter);
	dump->version = 1;
	dump->flag = 0x1;	/* FW dump is enabled */
	return 0;
}

static int
be_get_dump_data(struct net_device *netdev, struct ethtool_dump *dump,
		 void *buf)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	int status;

	if (!check_privilege(adapter, MAX_PRIVILEGES))
		return -EOPNOTSUPP;

	status = be_read_dump_data(adapter, dump->len, buf);
	return be_cmd_status(status);
}

static int be_set_dump(struct net_device *netdev, struct ethtool_dump *dump)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	struct device *dev = &adapter->pdev->dev;
	int status;

	if (!lancer_chip(adapter) ||
	    !check_privilege(adapter, MAX_PRIVILEGES))
		return -EOPNOTSUPP;

	switch (dump->flag) {
	case LANCER_INITIATE_FW_DUMP:
		status = lancer_initiate_dump(adapter);
		break;
	case LANCER_DELETE_FW_DUMP:
		status = lancer_delete_dump(adapter);
		break;
	default:
		dev_err(dev, "Invalid dump flag : 0x%x\n", dump->flag);
		return -EINVAL;
	}

	return status;
}
#endif /* ETHTOOL_SET_DUMP_defined */

static int be_get_eeprom_len(struct net_device *netdev)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	if (!check_privilege(adapter, MAX_PRIVILEGES))
		return 0;

	if (lancer_chip(adapter)) {
		if (be_physfn(adapter))
			return lancer_cmd_get_file_len(adapter,
						       LANCER_VPD_PF_FILE);
		else
			return lancer_cmd_get_file_len(adapter,
						       LANCER_VPD_VF_FILE);
	} else {
		return BE_READ_SEEPROM_LEN;
	}
}

static int be_read_eeprom(struct net_device *netdev,
			  struct ethtool_eeprom *eeprom, uint8_t *data)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	struct device *dev = &adapter->pdev->dev;
	struct be_dma_mem eeprom_cmd;
	struct be_cmd_resp_seeprom_read *resp;
	int status;

	if (!check_privilege(adapter, MAX_PRIVILEGES))
		return -EOPNOTSUPP;

	if (!eeprom->len)
		return -EINVAL;

	if (lancer_chip(adapter)) {
		if (be_physfn(adapter))
			return lancer_cmd_read_file(adapter, LANCER_VPD_PF_FILE,
						    eeprom->len, data);
		else
			return lancer_cmd_read_file(adapter, LANCER_VPD_VF_FILE,
						    eeprom->len, data);
	}

	eeprom->magic = BE_VENDOR_ID | (adapter->pdev->device<<16);

	memset(&eeprom_cmd, 0, sizeof(struct be_dma_mem));
	eeprom_cmd.size = sizeof(struct be_cmd_req_seeprom_read);
	eeprom_cmd.va = dma_zalloc_coherent(dev, eeprom_cmd.size,
					   &eeprom_cmd.dma, GFP_KERNEL);

	if (!eeprom_cmd.va)
		return -ENOMEM;

	status = be_cmd_get_seeprom_data(adapter, &eeprom_cmd);

	if (!status) {
		resp = (struct be_cmd_resp_seeprom_read *) eeprom_cmd.va;
		memcpy(data, resp->seeprom_data + eeprom->offset, eeprom->len);
	}
	dma_free_coherent(dev, eeprom_cmd.size, eeprom_cmd.va, eeprom_cmd.dma);

	return be_cmd_status(status);
}

static u32 be_get_msg_level(struct net_device *netdev)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	return adapter->msg_enable;
}

static void be_set_msg_level(struct net_device *netdev, u32 level)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	if (adapter->msg_enable == level)
		return;

	if ((level & NETIF_MSG_HW) != (adapter->msg_enable & NETIF_MSG_HW))
		if (BEx_chip(adapter))
			be_cmd_set_fw_log_level(adapter, level & NETIF_MSG_HW ?
						FW_LOG_LEVEL_DEFAULT :
						FW_LOG_LEVEL_FATAL);
	adapter->msg_enable = level;
}

#ifdef ETHTOOL_RXNFC_OPS_defined
static u64 be_get_rss_hash_opts(struct be_adapter *adapter, u64 flow_type)
{
	u64 data = 0;

	switch (flow_type) {
	case TCP_V4_FLOW:
		if (adapter->rss_info.rss_flags & RSS_ENABLE_IPV4)
			data |= RXH_IP_DST | RXH_IP_SRC;
		if (adapter->rss_info.rss_flags & RSS_ENABLE_TCP_IPV4)
			data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
		break;
	case UDP_V4_FLOW:
		if (adapter->rss_info.rss_flags & RSS_ENABLE_IPV4)
			data |= RXH_IP_DST | RXH_IP_SRC;
		if (adapter->rss_info.rss_flags & RSS_ENABLE_UDP_IPV4)
			data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
		break;
	case TCP_V6_FLOW:
		if (adapter->rss_info.rss_flags & RSS_ENABLE_IPV6)
			data |= RXH_IP_DST | RXH_IP_SRC;
		if (adapter->rss_info.rss_flags & RSS_ENABLE_TCP_IPV6)
			data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
		break;
	case UDP_V6_FLOW:
		if (adapter->rss_info.rss_flags & RSS_ENABLE_IPV6)
			data |= RXH_IP_DST | RXH_IP_SRC;
		if (adapter->rss_info.rss_flags & RSS_ENABLE_UDP_IPV6)
			data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
		break;
	}

	return data;
}

static int be_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd,
			eth_rxnfc_t *rule_locs)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	if (!be_multi_rxq(adapter)) {
		dev_info(&adapter->pdev->dev,
			 "ethtool::get_rxnfc: RX flow hashing is disabled\n");
		return -EINVAL;
	}

	switch (cmd->cmd) {
	case ETHTOOL_GRXFH:
		cmd->data = be_get_rss_hash_opts(adapter, cmd->flow_type);
		break;
	case ETHTOOL_GRXRINGS:
		cmd->data = adapter->num_rx_qs - 1;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int be_set_rss_hash_opts(struct be_adapter *adapter,
				struct ethtool_rxnfc *cmd)
{
	int status = 0;
	u32 rss_flags = adapter->rss_info.rss_flags;

	if (cmd->data != L3_RSS_FLAGS &&
	    cmd->data != (L3_RSS_FLAGS | L4_RSS_FLAGS))
		return -EINVAL;

	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
		if (cmd->data == L3_RSS_FLAGS)
			rss_flags &= ~RSS_ENABLE_TCP_IPV4;
		else if (cmd->data == (L3_RSS_FLAGS | L4_RSS_FLAGS))
			rss_flags |= RSS_ENABLE_IPV4 |
					RSS_ENABLE_TCP_IPV4;
		break;
	case TCP_V6_FLOW:
		if (cmd->data == L3_RSS_FLAGS)
			rss_flags &= ~RSS_ENABLE_TCP_IPV6;
		else if (cmd->data == (L3_RSS_FLAGS | L4_RSS_FLAGS))
			rss_flags |= RSS_ENABLE_IPV6 |
					RSS_ENABLE_TCP_IPV6;
		break;
	case UDP_V4_FLOW:
		if ((cmd->data == (L3_RSS_FLAGS | L4_RSS_FLAGS)) &&
		    BEx_chip(adapter))
			return -EINVAL;

		if (cmd->data == L3_RSS_FLAGS)
			rss_flags &= ~RSS_ENABLE_UDP_IPV4;
		else if (cmd->data == (L3_RSS_FLAGS | L4_RSS_FLAGS))
			rss_flags |= RSS_ENABLE_IPV4 |
					RSS_ENABLE_UDP_IPV4;
		break;
	case UDP_V6_FLOW:
		if ((cmd->data == (L3_RSS_FLAGS | L4_RSS_FLAGS)) &&
		    BEx_chip(adapter))
			return -EINVAL;

		if (cmd->data == L3_RSS_FLAGS)
			rss_flags &= ~RSS_ENABLE_UDP_IPV6;
		else if (cmd->data == (L3_RSS_FLAGS | L4_RSS_FLAGS))
			rss_flags |= RSS_ENABLE_IPV6 |
					RSS_ENABLE_UDP_IPV6;
		break;
	default:
		return -EINVAL;
	}

	if (rss_flags == adapter->rss_info.rss_flags)
		return status;

	status = be_cmd_rss_config(adapter, adapter->rss_info.rsstable,
				   rss_flags, RSS_INDIR_TABLE_LEN,
				   adapter->rss_info.rss_hkey);
	if (!status)
		adapter->rss_info.rss_flags = rss_flags;

	return be_cmd_status(status);
}

static int be_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	int status = 0;

	if (!be_multi_rxq(adapter)) {
		dev_err(&adapter->pdev->dev,
			"ethtool::set_rxnfc: RX flow hashing is disabled\n");
		return -EINVAL;
	}

	switch (cmd->cmd) {
	case ETHTOOL_SRXFH:
		status = be_set_rss_hash_opts(adapter, cmd);
		break;
	default:
		return -EINVAL;
	}

	return be_cmd_status(status);
}
#endif

#ifdef ETHTOOL_OPS_CHANNELS_defined
static void be_get_channels(struct net_device *netdev,
			    struct ethtool_channels *ch)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	u16 num_rx_qs = max_t(u16, adapter->num_rss_qs, 1);

	ch->combined_count = min(adapter->num_tx_qs, num_rx_qs);
	ch->rx_count = num_rx_qs - ch->combined_count;
	ch->tx_count = adapter->num_tx_qs - ch->combined_count;

	ch->max_combined = be_max_qp_irqs(adapter);
	/* The user must create atleast one combined channel */
	ch->max_rx = be_max_rx_irqs(adapter) - 1;
	ch->max_tx = be_max_tx_irqs(adapter) - 1;
}

static int be_set_channels(struct net_device  *netdev,
			   struct ethtool_channels *ch)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	int status;

	/* we support either only combined channels or a combination of
	 * combined and either RX-only or TX-only channels.
	 */
	if (ch->other_count || !ch->combined_count ||
	    (ch->rx_count && ch->tx_count))
		return -EINVAL;

	if (ch->combined_count > be_max_qp_irqs(adapter) ||
	    (ch->rx_count &&
	     (ch->rx_count + ch->combined_count) > be_max_rx_irqs(adapter)) ||
	    (ch->tx_count &&
	     (ch->tx_count + ch->combined_count) > be_max_tx_irqs(adapter)))
		return -EINVAL;

	adapter->cfg_num_rx_irqs = ch->combined_count + ch->rx_count;
	adapter->cfg_num_tx_irqs = ch->combined_count + ch->tx_count;

	status = be_update_queues(adapter);

	return be_cmd_status(status);
}
#endif

#ifdef ETHTOOL_OPS_RSSH_defined
static u32 be_get_rxfh_indir_size(struct net_device *netdev)
{
	return RSS_INDIR_TABLE_LEN;
}

static u32 be_get_rxfh_key_size(struct net_device *netdev)
{
	return RSS_HASH_KEY_LEN;
}

int __be_get_rxfh(struct net_device *netdev, u32 *indir, u8 *hkey, u8 *hfunc)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	int i;
	struct rss_info *rss = &adapter->rss_info;

	if (indir) {
		for (i = 0; i < RSS_INDIR_TABLE_LEN; i++)
			indir[i] = rss->rss_queue[i];
	}

	if (hkey)
		memcpy(hkey, rss->rss_hkey, RSS_HASH_KEY_LEN);

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

	return 0;
}

int __be_set_rxfh(struct net_device *netdev, const u32 *indir,
		     const u8 *hkey, u8 hfunc)
{
	int rc = 0, i, j;
	struct be_adapter *adapter = netdev_priv(netdev);
	u8 rsstable[RSS_INDIR_TABLE_LEN];

	/* We do not allow change in unsupported parameters */
	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	if (indir) {
		struct be_rx_obj *rxo;

		for (i = 0; i < RSS_INDIR_TABLE_LEN; i++) {
			j = indir[i];
			rxo = &adapter->rx_obj[j];
			rsstable[i] = rxo->rss_id;
			adapter->rss_info.rss_queue[i] = j;
		}
	} else {
		memcpy(rsstable, adapter->rss_info.rsstable,
		       RSS_INDIR_TABLE_LEN);
	}

	if (!hkey)
		hkey =  adapter->rss_info.rss_hkey;

	rc = be_cmd_rss_config(adapter, rsstable,
			       adapter->rss_info.rss_flags,
			       RSS_INDIR_TABLE_LEN, hkey);
	if (rc) {
		adapter->rss_info.rss_flags = RSS_ENABLE_NONE;
		return -EIO;
	}
	memcpy(adapter->rss_info.rss_hkey, hkey, RSS_HASH_KEY_LEN);
	memcpy(adapter->rss_info.rsstable, rsstable,
	       RSS_INDIR_TABLE_LEN);
	return 0;
}

#ifdef ETHTOOL_OPS_RSSH_HFUNC_defined
int be_get_rxfh(struct net_device *netdev, u32 *indir, u8 *hkey, u8 *hfunc)
{
	return __be_get_rxfh(netdev, indir, hkey, hfunc);
}

int be_set_rxfh(struct net_device *netdev, const u32 *indir,
		const u8 *hkey, u8 hfunc)
{
	return __be_set_rxfh(netdev, indir, hkey, hfunc);
}
#else
int be_get_rxfh(struct net_device *netdev, u32 *indir, u8 *hkey)
{
	return __be_get_rxfh(netdev, indir, hkey, NULL);
}
#ifdef ETHTOOL_OPS_RSSH_IS_NEW
int be_set_rxfh(struct net_device *netdev, const u32 *indir, const u8 *hkey)
{
	return __be_set_rxfh(netdev, indir, hkey, 0);
}
#else
int be_set_rxfh(struct net_device *netdev, u32 *indir, u8 *hkey)
{
	return __be_set_rxfh(netdev, indir, hkey, 0);
}
#endif
#endif
#endif

#ifdef ETHTOOL_GET_MODULE_defined
static int be_get_module_info(struct net_device *netdev,
			      struct ethtool_modinfo *modinfo)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	u8 page_data[TR_PAGE_DATA_LEN];
	int status;

	if (!check_privilege(adapter, MAX_PRIVILEGES))
		return -EOPNOTSUPP;

	status = be_cmd_read_port_transceiver_data(adapter, TR_PAGE_A0,
						   page_data);
	if (!status) {
		if (!page_data[SFP_PLUS_SFF_8472_COMP]) {
			modinfo->type = ETH_MODULE_SFF_8079;
			modinfo->eeprom_len = TR_PAGE_DATA_LEN;
		} else {
			modinfo->type = ETH_MODULE_SFF_8472;
			modinfo->eeprom_len = 2 * TR_PAGE_DATA_LEN;
		}
	}
	return be_cmd_status(status);
}

static int be_get_module_eeprom(struct net_device *netdev,
				struct ethtool_eeprom *eeprom, u8 *data)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	int status;

	if (!check_privilege(adapter, MAX_PRIVILEGES))
		return -EOPNOTSUPP;

	status = be_cmd_read_port_transceiver_data(adapter, TR_PAGE_A0, data);
	if (status)
		goto err;

	if (eeprom->offset + eeprom->len > TR_PAGE_DATA_LEN) {
		status = be_cmd_read_port_transceiver_data(adapter, TR_PAGE_A2,
							   data +
							   TR_PAGE_DATA_LEN);
		if (status)
			goto err;
	}
	if (eeprom->offset)
		memcpy(data, data + eeprom->offset, eeprom->len);
err:
	return be_cmd_status(status);
}
#endif

static u32 be_get_priv_flags(struct net_device *netdev)
{
	struct be_adapter *adapter = netdev_priv(netdev);

	return adapter->priv_flags;
}

static int be_set_priv_flags(struct net_device *netdev, u32 flags)
{
	struct be_adapter *adapter = netdev_priv(netdev);
	bool tpe_old = !!(adapter->priv_flags & BE_DISABLE_TPE_RECOVERY);
	bool tpe_new = !!(flags & BE_DISABLE_TPE_RECOVERY);

	if (tpe_old != tpe_new) {
		if (tpe_new) {
			adapter->priv_flags |= BE_DISABLE_TPE_RECOVERY;
			dev_info(&adapter->pdev->dev,
				 "HW error recovery is disabled\n");
		} else {
			adapter->priv_flags &= ~BE_DISABLE_TPE_RECOVERY;
			dev_info(&adapter->pdev->dev,
				 "HW error recovery is enabled\n");
		}
	}

	return 0;
}

struct ethtool_ops be_ethtool_ops = {
	.get_settings = be_get_settings,
	.set_settings = be_set_settings,
	.get_drvinfo = be_get_drvinfo,
	.get_wol = be_get_wol,
	.set_wol = be_set_wol,
	.get_link = ethtool_op_get_link,
	.get_eeprom_len = be_get_eeprom_len,
	.get_eeprom = be_read_eeprom,
	.get_coalesce = be_get_coalesce,
	.set_coalesce = be_set_coalesce,
	.get_ringparam = be_get_ringparam,
	.get_pauseparam = be_get_pauseparam,
	.set_pauseparam = be_set_pauseparam,
	.set_priv_flags = be_set_priv_flags,
	.get_priv_flags = be_get_priv_flags,
#ifndef NDO_SET_FEATURES_defined
	.get_rx_csum = be_get_rx_csum,
	.set_rx_csum = be_set_rx_csum,
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = be_set_tx_csum,
	.get_sg = ethtool_op_get_sg,
	.set_sg = ethtool_op_set_sg,
	.get_tso = ethtool_op_get_tso,
	.set_tso = be_set_tso,
#endif
	.get_strings = be_get_stat_strings,
	.get_msglevel = be_get_msg_level,
	.set_msglevel = be_set_msg_level,
#ifdef ETHTOOL_SSET_COUNT_defined
	.get_sset_count = be_get_sset_count,
#else
	.self_test_count = be_self_test_count,
	.get_stats_count = be_get_stats_count,
#endif
	.get_ethtool_stats = be_get_ethtool_stats,
#ifndef ETHTOOL_SET_DUMP_defined
	.get_regs_len = be_get_reg_len,
	.get_regs = be_get_regs,
#endif
#ifdef ETHTOOL_FLASH_defined
	.flash_device = be_do_flash,
#endif
	.self_test = be_self_test,
#ifdef ETHTOOL_RXNFC_OPS_defined
	.get_rxnfc = be_get_rxnfc,
	.set_rxnfc = be_set_rxnfc,
#endif
#if !defined(ETHTOOL_OPS_EXT_defined)
	.set_phys_id = be_set_phys_id,
#if defined(ETHTOOL_SET_DUMP_defined)
	.set_dump = be_set_dump,
	.get_dump_flag = be_get_dump_flag,
	.get_dump_data = be_get_dump_data,
#endif
#if defined(ETHTOOL_OPS_CHANNELS_defined)
	.get_channels = be_get_channels,
	.set_channels = be_set_channels,
#endif
#if defined(ETHTOOL_GET_MODULE_defined)
	.get_module_info = be_get_module_info,
	.get_module_eeprom = be_get_module_eeprom,
#endif
#ifdef ETHTOOL_OPS_RSSH_defined
	.get_rxfh_indir_size = be_get_rxfh_indir_size,
	.get_rxfh_key_size = be_get_rxfh_key_size,
	.get_rxfh = be_get_rxfh,
	.set_rxfh = be_set_rxfh
#endif
#endif /* !defined(ETHTOOL_OPS_EXT_defined) */
};

#ifdef ETHTOOL_OPS_EXT_defined
struct ethtool_ops_ext be_ethtool_ops_ext = {
	.size = sizeof(struct ethtool_ops_ext),

#ifdef ETHTOOL_OPS_RSSH_defined
	.get_rxfh_indir_size = be_get_rxfh_indir_size,
	.get_rxfh_key_size = be_get_rxfh_key_size,
	.get_rxfh = be_get_rxfh,
	.set_rxfh = be_set_rxfh,
#endif
	.set_phys_id = be_set_phys_id,
	.set_dump = be_set_dump,
	.get_dump_flag = be_get_dump_flag,
	.get_dump_data = be_get_dump_data,
	.get_channels = be_get_channels,
	.set_channels = be_set_channels,
	.get_module_info = be_get_module_info,
	.get_module_eeprom = be_get_module_eeprom
};
#endif
