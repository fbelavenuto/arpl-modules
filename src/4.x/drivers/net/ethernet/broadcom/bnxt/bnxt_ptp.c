/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2017 Broadcom Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#ifdef HAVE_IEEE1588_SUPPORT
#include <linux/ptp_clock_kernel.h>
#include <linux/net_tstamp.h>
#include <linux/timecounter.h>
#include <linux/timekeeping.h>
#endif
#include "bnxt_compat.h"
#include "bnxt_hsi.h"
#include "bnxt.h"
#include "bnxt_ptp.h"

#ifdef HAVE_IEEE1588_SUPPORT
static int bnxt_ptp_settime(struct ptp_clock_info *ptp_info,
			    const struct timespec64 *ts)
{
	struct bnxt_ptp_cfg *ptp = container_of(ptp_info, struct bnxt_ptp_cfg,
						ptp_info);
	u64 ns = timespec64_to_ns(ts);

	ns = timespec64_to_ns(ts);
	timecounter_init(&ptp->tc, &ptp->cc, ns);
	return 0;
}

static int bnxt_ptp_gettime(struct ptp_clock_info *ptp_info,
			    struct timespec64 *ts)
{
	struct bnxt_ptp_cfg *ptp = container_of(ptp_info, struct bnxt_ptp_cfg,
						ptp_info);
	u64 ns;

	ns = timecounter_read(&ptp->tc);
	*ts = ns_to_timespec64(ns);
	return 0;
}

static int bnxt_ptp_adjtime(struct ptp_clock_info *ptp_info, s64 delta)
{
	struct bnxt_ptp_cfg *ptp = container_of(ptp_info, struct bnxt_ptp_cfg,
						ptp_info);

	timecounter_adjtime(&ptp->tc, delta);
	return 0;
}

static int bnxt_ptp_adjfreq(struct ptp_clock_info *ptp_info, s32 ppb)
{
	struct bnxt_ptp_cfg *ptp = container_of(ptp_info, struct bnxt_ptp_cfg,
						ptp_info);
	s32 period, period1, period2, dif, dif1, dif2;
	s32 step, best_step = 0, best_period = 0;
	s32 best_dif = BNXT_MAX_PHC_DRIFT;
	u32 drift_sign = 1;

	/* Frequency adjustment requires programming 3 values:
	 * 1-bit direction
	 * 5-bit adjustment step in 1 ns unit
	 * 24-bit period in 1 us unit between adjustments
	 */
	if (ppb < 0) {
		ppb = -ppb;
		drift_sign = 0;
	}

	if (ppb == 0) {
		/* no adjustment */
		best_step = 0;
		best_period = 0xFFFFFF;
	} else if (ppb >= BNXT_MAX_PHC_DRIFT) {
		/* max possible adjustment */
		best_step = 31;
		best_period = 1;
	} else {
		/* Find the best possible adjustment step and period */
		for (step = 0; step <= 31; step++) {
			period1 = step * 1000000 / ppb;
			period2 = period1 + 1;
			if (period1 != 0)
				dif1 = ppb - (step * 1000000 / period1);
			else
				dif1 = BNXT_MAX_PHC_DRIFT;
			if (dif1 < 0)
				dif1 = -dif1;
			dif2 = ppb - (step * 1000000 / period2);
			if (dif2 < 0)
				dif2 = -dif2;
			dif = (dif1 < dif2) ? dif1 : dif2;
			period = (dif1 < dif2) ? period1 : period2;
			if (dif < best_dif) {
				best_dif = dif;
				best_step = step;
				best_period = period;
			}
		}
	}
	writel((drift_sign << BNXT_GRCPF_REG_SYNC_TIME_ADJ_SIGN_SFT) |
	       (best_step << BNXT_GRCPF_REG_SYNC_TIME_ADJ_VAL_SFT) |
	       (best_period & BNXT_GRCPF_REG_SYNC_TIME_ADJ_PER_MSK),
	       ptp->bp->bar0 + BNXT_GRCPF_REG_SYNC_TIME_ADJ);

	return 0;
}

static int bnxt_ptp_enable(struct ptp_clock_info *ptp,
			   struct ptp_clock_request *rq, int on)
{
        return -ENOTSUPP;
}

static void bnxt_clr_rx_ts(struct bnxt *bp)
{
	struct bnxt_ptp_cfg *ptp = bp->ptp_cfg;
	struct bnxt_pf_info *pf = &bp->pf;
	u16 port_id;
	int i = 0;
	u32 fifo;

	if (!ptp)
		return;

	port_id = pf->port_id;
	fifo = readl(bp->bar0 + ptp->rx_mapped_regs[BNXT_PTP_RX_FIFO]);
	while ((fifo & BNXT_PTP_RX_FIFO_PENDING) && (i < 10)) {
		writel(1 << port_id, bp->bar0 +
		       ptp->rx_mapped_regs[BNXT_PTP_RX_FIFO_ADV]);
		fifo = readl(bp->bar0 + ptp->rx_mapped_regs[BNXT_PTP_RX_FIFO]);
		i++;
	}
}

static int bnxt_hwrm_ptp_cfg(struct bnxt *bp)
{
	struct hwrm_port_mac_cfg_input req = {0};
	struct bnxt_ptp_cfg *ptp = bp->ptp_cfg;
	u32 flags = 0;

	if (!ptp)
		return 0;

	bnxt_hwrm_cmd_hdr_init(bp, &req, HWRM_PORT_MAC_CFG, -1, -1);

	if (ptp->rx_filter)
		flags |= PORT_MAC_CFG_REQ_FLAGS_PTP_RX_TS_CAPTURE_ENABLE;
	else
		flags |= PORT_MAC_CFG_REQ_FLAGS_PTP_RX_TS_CAPTURE_DISABLE;
	if (ptp->tx_tstamp_en)
		flags |= PORT_MAC_CFG_REQ_FLAGS_PTP_TX_TS_CAPTURE_ENABLE;
	else
		flags |= PORT_MAC_CFG_REQ_FLAGS_PTP_TX_TS_CAPTURE_DISABLE;
	req.flags = cpu_to_le32(flags);
	req.enables = cpu_to_le32(
		PORT_MAC_CFG_REQ_ENABLES_RX_TS_CAPTURE_PTP_MSG_TYPE);
	req.rx_ts_capture_ptp_msg_type = cpu_to_le16(ptp->rxctl);

	if (hwrm_send_message(bp, &req, sizeof(req), HWRM_CMD_TIMEOUT))
		return -EIO;

	return 0;
}

int bnxt_hwtstamp_set(struct net_device *dev, struct ifreq *ifr)
{
	struct bnxt *bp = netdev_priv(dev);
	struct hwtstamp_config stmpconf;
	struct bnxt_ptp_cfg *ptp;
	u16 old_rxctl, new_rxctl;
	int old_rx_filter, rc;
	u8 old_tx_tstamp_en;

	ptp = bp->ptp_cfg;
	if (!ptp)
		return -EOPNOTSUPP;

	if (copy_from_user(&stmpconf, ifr->ifr_data, sizeof(stmpconf)))
		return -EFAULT;

	if (stmpconf.flags)
		return -EINVAL;

	if (stmpconf.tx_type != HWTSTAMP_TX_ON &&
	    stmpconf.tx_type != HWTSTAMP_TX_OFF)
		return -ERANGE;

	old_rx_filter = ptp->rx_filter;
	old_rxctl = ptp->rxctl;
	old_tx_tstamp_en = ptp->tx_tstamp_en;
	switch (stmpconf.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		new_rxctl = 0;
		ptp->rx_filter = HWTSTAMP_FILTER_NONE;
		break;
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
		new_rxctl = BNXT_PTP_MSG_EVENTS;
		ptp->rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		break;
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
		new_rxctl = BNXT_PTP_MSG_SYNC;
		ptp->rx_filter = HWTSTAMP_FILTER_PTP_V2_SYNC;
		break;
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		new_rxctl = BNXT_PTP_MSG_DELAY_REQ;
		ptp->rx_filter = HWTSTAMP_FILTER_PTP_V2_DELAY_REQ;
		break;
	default:
		return -ERANGE;
	}

	if (stmpconf.tx_type == HWTSTAMP_TX_ON)
		ptp->tx_tstamp_en = 1;
	else
		ptp->tx_tstamp_en = 0;

	if (!old_rxctl && new_rxctl) {
		rc = bnxt_hwrm_ptp_cfg(bp);
		if (rc)
			goto ts_set_err;
		ptp->rxctl = new_rxctl;
		bnxt_clr_rx_ts(bp);
	}

	rc = bnxt_hwrm_ptp_cfg(bp);
	if (rc)
		goto ts_set_err;

	stmpconf.rx_filter = ptp->rx_filter;
	return copy_to_user(ifr->ifr_data, &stmpconf, sizeof(stmpconf)) ?
		-EFAULT : 0;

ts_set_err:
	ptp->rx_filter = old_rx_filter;
	ptp->rxctl = old_rxctl;
	ptp->tx_tstamp_en = old_tx_tstamp_en;
	return rc;
}

int bnxt_hwtstamp_get(struct net_device *dev, struct ifreq *ifr)
{
	struct bnxt *bp = netdev_priv(dev);
	struct hwtstamp_config stmpconf;
	struct bnxt_ptp_cfg *ptp;

	ptp = bp->ptp_cfg;
	if (!ptp)
		return -EOPNOTSUPP;

	stmpconf.flags = 0;
	stmpconf.tx_type = ptp->tx_tstamp_en ? HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;

	stmpconf.rx_filter = ptp->rx_filter;
	return copy_to_user(ifr->ifr_data, &stmpconf, sizeof(stmpconf)) ?
		-EFAULT : 0;
}

static int bnxt_map_regs(struct bnxt *bp, u32 *reg_arr, int count, int reg_win)
{
	u32 reg_base = *reg_arr & 0xfffff000;
	u32 win_off;
	int i;

	for (i = 0; i < count; i++) {
		if ((reg_arr[i] & 0xfffff000) != reg_base)
			return -ERANGE;
	}
	win_off = BNXT_GRCPF_REG_WINDOW_BASE_OUT + (reg_win - 1) * 4;
	writel(reg_base, bp->bar0 + win_off);
	return 0;
}

static int bnxt_map_ptp_regs(struct bnxt *bp)
{
	struct bnxt_ptp_cfg *ptp = bp->ptp_cfg;
	u32 *reg_arr, reg_base;
	int rc, i;

	reg_arr = ptp->rx_regs;
	rc = bnxt_map_regs(bp, reg_arr, BNXT_PTP_RX_REGS, 5);
	if (rc)
		return rc;

	reg_arr = ptp->tx_regs;
	rc = bnxt_map_regs(bp, reg_arr, BNXT_PTP_TX_REGS, 6);
	if (rc)
		return rc;

	reg_base = ptp->rx_regs[BNXT_PTP_RX_TS_L] & 0xfffff000;
	for (i = 0; i < BNXT_PTP_RX_REGS; i++)
		ptp->rx_mapped_regs[i] = 0x5000 + (ptp->rx_regs[i] & 0xfff);

	reg_base = ptp->tx_regs[BNXT_PTP_TX_TS_L] & 0xfffff000;
	for (i = 0; i < BNXT_PTP_TX_REGS; i++)
		ptp->tx_mapped_regs[i] = 0x6000 + (ptp->tx_regs[i] & 0xfff);

	return 0;
}

static void bnxt_unmap_ptp_regs(struct bnxt *bp)
{
	writel(0, bp->bar0 + BNXT_GRCPF_REG_WINDOW_BASE_OUT + 16);
	writel(0, bp->bar0 + BNXT_GRCPF_REG_WINDOW_BASE_OUT + 20);
}

static u64 bnxt_cc_read(const struct cyclecounter *cc)
{
	struct bnxt_ptp_cfg *ptp = container_of(cc, struct bnxt_ptp_cfg, cc);
	struct bnxt *bp = ptp->bp;
	u64 ns;

	ns = readl(bp->bar0 + BNXT_GRCPF_REG_SYNC_TIME);
	ns |= (u64)readl(bp->bar0 + BNXT_GRCPF_REG_SYNC_TIME + 4) << 32;
	return ns;
}

int bnxt_get_tx_ts(struct bnxt *bp, u64 *ts)
{
	struct bnxt_ptp_cfg *ptp = bp->ptp_cfg;
	u32 fifo;

	fifo = readl(bp->bar0 + ptp->tx_mapped_regs[BNXT_PTP_TX_FIFO]);
	if (fifo & BNXT_PTP_TX_FIFO_EMPTY)
		return -EAGAIN;

	fifo = readl(bp->bar0 + ptp->tx_mapped_regs[BNXT_PTP_TX_FIFO]);
	*ts = readl(bp->bar0 + ptp->tx_mapped_regs[BNXT_PTP_TX_TS_L]);
	*ts |= (u64)readl(bp->bar0 + ptp->tx_mapped_regs[BNXT_PTP_TX_TS_H]) <<
	       32;
	readl(bp->bar0 + ptp->tx_mapped_regs[BNXT_PTP_TX_SEQ]);
	return 0;
}

int bnxt_get_rx_ts(struct bnxt *bp, u64 *ts)
{
	struct bnxt_ptp_cfg *ptp = bp->ptp_cfg;
	struct bnxt_pf_info *pf = &bp->pf;
	u16 port_id;
	u32 fifo;

	if (!ptp)
		return -ENODEV;

	fifo = readl(bp->bar0 + ptp->rx_mapped_regs[BNXT_PTP_RX_FIFO]);
	if (!(fifo & BNXT_PTP_RX_FIFO_PENDING))
		return -EAGAIN;

	port_id = pf->port_id;
	writel(1 << port_id, bp->bar0 +
	       ptp->rx_mapped_regs[BNXT_PTP_RX_FIFO_ADV]);

	fifo = readl(bp->bar0 + ptp->rx_mapped_regs[BNXT_PTP_RX_FIFO]);
	if (fifo & BNXT_PTP_RX_FIFO_PENDING) {
		bnxt_clr_rx_ts(bp);
		return -EBUSY;
	}

	*ts = readl(bp->bar0 + ptp->rx_mapped_regs[BNXT_PTP_RX_TS_L]);
	*ts |= (u64)readl(bp->bar0 + ptp->rx_mapped_regs[BNXT_PTP_RX_TS_H]) <<
	       32;

	return 0;
}

static const struct ptp_clock_info bnxt_ptp_caps = {
        .owner          = THIS_MODULE,
        .name           = "bnxt clock",
        .max_adj        = BNXT_MAX_PHC_DRIFT,
        .n_alarm        = 0,
        .n_ext_ts       = 0,
        .n_per_out      = 1,
        .n_pins         = 0,
        .pps            = 0,
        .adjfreq        = bnxt_ptp_adjfreq,
        .adjtime        = bnxt_ptp_adjtime,
        .gettime64      = bnxt_ptp_gettime,
        .settime64      = bnxt_ptp_settime,
        .enable         = bnxt_ptp_enable,
};

int bnxt_ptp_init(struct bnxt *bp)
{
	struct bnxt_ptp_cfg *ptp = bp->ptp_cfg;
	int rc;

	if (!ptp)
		return 0;
	rc = bnxt_map_ptp_regs(bp);
	if (rc)
		return rc;

	atomic_set(&ptp->tx_avail, BNXT_MAX_TX_TS);

	memset(&ptp->cc, 0, sizeof(ptp->cc));
	ptp->cc.read = bnxt_cc_read;
	ptp->cc.mask = CYCLECOUNTER_MASK(64);
	ptp->cc.shift = 0;
	ptp->cc.mult = 1;

	timecounter_init(&ptp->tc, &ptp->cc, ktime_to_ns(ktime_get_real()));

	ptp->ptp_info = bnxt_ptp_caps;
	ptp->ptp_clock = ptp_clock_register(&ptp->ptp_info, &bp->pdev->dev);
	if (IS_ERR(ptp->ptp_clock))
		ptp->ptp_clock = NULL;

	return 0;
}

void bnxt_ptp_free(struct bnxt *bp)
{
	struct bnxt_ptp_cfg *ptp = bp->ptp_cfg;

	if (!ptp)
		return;

	if (ptp->ptp_clock)
		ptp_clock_unregister(ptp->ptp_clock);

	ptp->ptp_clock = NULL;
	bnxt_unmap_ptp_regs(bp);
}

#else

int bnxt_hwtstamp_set(struct net_device *dev, struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

int bnxt_hwtstamp_get(struct net_device *dev, struct ifreq *ifr)
{
	return -EOPNOTSUPP;
}

int bnxt_ptp_init(struct bnxt *bp)
{
	return 0;
}

void bnxt_ptp_free(struct bnxt *bp)
{
	return;
}

#endif
