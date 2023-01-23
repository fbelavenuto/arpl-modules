/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2014-2016 Broadcom Corporation
 * Copyright (c) 2016-2017 Broadcom Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/pci.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#if !defined(NEW_FLOW_KEYS) && defined(HAVE_FLOW_KEYS)
#include <net/flow_keys.h>
#endif
#include <linux/sched.h>

#ifdef HAVE_TC_CLS_FLOWER_OFFLOAD
#include <net/pkt_cls.h>
#endif

/* Reconcile all dependencies for VF reps:
 * SRIOV, Devlink, Switchdev and HW port info in metadata_dst
 */
#if defined(CONFIG_BNXT_SRIOV) && defined(HAVE_DEVLINK) && \
	defined(CONFIG_NET_SWITCHDEV) && defined(HAVE_METADATA_HW_PORT_MUX)
#define CONFIG_VF_REPS		1
#ifndef SWITCHDEV_SET_OPS
#define SWITCHDEV_SET_OPS(netdev, ops) ((netdev)->switchdev_ops = (ops))
#endif
#endif

/* Reconcile all dependencies for TC Flower offload
 * Need the following to be defined to build TC flower offload
 * HAVE_TC_CLS_FLOWER_OFFLOAD
 * HAVE_RHASHTABLE
 * HAVE_FLOW_DISSECTOR_KEY_ICMP
 * CONFIG_NET_SWITCHDEV
 * HAVE_TCF_EXTS_TO_LIST (its possible to do without this but
 * the code gets a bit complicated. So, for now depend on this.)
 * HAVE_TCF_TUNNEL
 * Instead of checking for all of the above defines, enable one
 * define when all are enabled.
 */
#if defined(HAVE_TC_CLS_FLOWER_OFFLOAD) && defined(HAVE_TCF_EXTS_TO_LIST) && \
	defined(HAVE_RHASHTABLE) && defined(HAVE_FLOW_DISSECTOR_KEY_ICMP) && \
	defined(HAVE_TCF_TUNNEL) && defined(CONFIG_NET_SWITCHDEV)
#define	CONFIG_BNXT_FLOWER_OFFLOAD	1
#endif

#ifndef SPEED_20000
#define SPEED_20000		20000
#endif

#ifndef SPEED_25000
#define SPEED_25000		25000
#endif

#ifndef SPEED_40000
#define SPEED_40000		40000
#endif

#ifndef SPEED_50000
#define SPEED_50000		50000
#endif

#ifndef SPEED_100000
#define SPEED_100000		100000
#endif

#ifndef SPEED_UNKNOWN
#define SPEED_UNKNOWN		-1
#endif

#ifndef DUPLEX_UNKNOWN
#define DUPLEX_UNKNOWN		0xff
#endif

#ifndef PORT_DA
#define PORT_DA			0x05
#endif

#ifndef PORT_NONE
#define PORT_NONE		0xef
#endif

#if !defined(SUPPORTED_40000baseCR4_Full)
#define SUPPORTED_40000baseCR4_Full	(1 << 24)

#define ADVERTISED_40000baseCR4_Full	(1 << 24)
#endif

#if !defined(IPV4_FLOW)
#define IPV4_FLOW	0x10
#endif

#if !defined(IPV6_FLOW)
#define IPV6_FLOW	0x11
#endif

#if defined(HAVE_ETH_GET_HEADLEN) || (LINUX_VERSION_CODE > 0x040900)
#define BNXT_RX_PAGE_MODE_SUPPORT	1
#endif

#if !defined(ETH_P_8021AD)
#define ETH_P_8021AD		0x88A8
#endif

#if !defined(ETH_P_ROCE)
#define ETH_P_ROCE		0x8915
#endif

#if !defined(ROCE_V2_UDP_PORT)
#define ROCE_V2_UDP_DPORT	4791
#endif

#ifndef NETIF_F_GSO_UDP_TUNNEL
#define NETIF_F_GSO_UDP_TUNNEL	0
#endif

#ifndef NETIF_F_GSO_UDP_TUNNEL_CSUM
#define NETIF_F_GSO_UDP_TUNNEL_CSUM	0
#endif

#ifndef NETIF_F_GSO_GRE
#define NETIF_F_GSO_GRE		0
#endif

#ifndef NETIF_F_GSO_GRE_CSUM
#define NETIF_F_GSO_GRE_CSUM	0
#endif

#ifndef NETIF_F_GSO_IPIP
#define NETIF_F_GSO_IPIP	0
#endif

#ifndef NETIF_F_GSO_SIT
#define NETIF_F_GSO_SIT		0
#endif

#ifndef NETIF_F_GSO_IPXIP4
#define NETIF_F_GSO_IPXIP4	(NETIF_F_GSO_IPIP | NETIF_F_GSO_SIT)
#endif

#ifndef NETIF_F_GSO_PARTIAL
#define NETIF_F_GSO_PARTIAL	0
#else
#define HAVE_GSO_PARTIAL_FEATURES	1
#endif

/* Tie rx checksum offload to tx checksum offload for older kernels. */
#ifndef NETIF_F_RXCSUM
#define NETIF_F_RXCSUM		NETIF_F_IP_CSUM
#endif

#ifndef NETIF_F_NTUPLE
#define NETIF_F_NTUPLE		0
#endif

#ifndef NETIF_F_RXHASH
#define NETIF_F_RXHASH		0
#else
#define HAVE_NETIF_F_RXHASH
#endif

#ifndef HAVE_SKB_GSO_UDP_TUNNEL_CSUM
#ifndef HAVE_SKB_GSO_UDP_TUNNEL
#define SKB_GSO_UDP_TUNNEL 0
#endif
#define SKB_GSO_UDP_TUNNEL_CSUM SKB_GSO_UDP_TUNNEL
#endif

#ifndef BRIDGE_MODE_VEB
#define BRIDGE_MODE_VEB		0
#endif

#ifndef BRIDGE_MODE_VEPA
#define BRIDGE_MODE_VEPA	1
#endif

#ifndef BRIDGE_MODE_UNDEF
#define BRIDGE_MODE_UNDEF	0xffff
#endif

#ifndef DEFINE_DMA_UNMAP_ADDR
#define DEFINE_DMA_UNMAP_ADDR(mapping) DECLARE_PCI_UNMAP_ADDR(mapping)
#endif

#ifndef DEFINE_DMA_UNMAP_LEN
#define DEFINE_DMA_UNMAP_LEN(len) DECLARE_PCI_UNMAP_LEN(len)
#endif

#ifndef dma_unmap_addr_set
#define dma_unmap_addr_set pci_unmap_addr_set
#endif

#ifndef dma_unmap_addr
#define dma_unmap_addr pci_unmap_addr
#endif

#ifndef dma_unmap_len
#define dma_unmap_len pci_unmap_len
#endif

#ifdef HAVE_DMA_ATTRS_H
#define dma_map_single_attrs(dev, cpu_addr, size, dir, attrs) \
	dma_map_single_attrs(dev, cpu_addr, size, dir, NULL)

#define dma_unmap_single_attrs(dev, dma_addr, size, dir, attrs) \
	dma_unmap_single_attrs(dev, dma_addr, size, dir, NULL)

#ifdef HAVE_DMA_MAP_PAGE_ATTRS
#define dma_map_page_attrs(dev, page, offset, size, dir, attrs) \
	dma_map_page_attrs(dev, page, offset, size, dir, NULL)

#define dma_unmap_page_attrs(dev, dma_addr, size, dir, attrs) \
	dma_unmap_page_attrs(dev, dma_addr, size, dir, NULL)
#endif
#endif

#ifndef HAVE_DMA_MAP_PAGE_ATTRS
#define dma_map_page_attrs(dev, page, offset, size, dir, attrs) \
	dma_map_page(dev, page, offset, size, dir)

#define dma_unmap_page_attrs(dev, dma_addr, size, dir, attrs) \
	dma_unmap_page(dev, dma_addr, size, dir)
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) 0
#endif

#if defined(RHEL_RELEASE_CODE) && (RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(6,3))
#if defined(CONFIG_X86_64) && !defined(CONFIG_NEED_DMA_MAP_STATE)
#undef DEFINE_DMA_UNMAP_ADDR
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)        dma_addr_t ADDR_NAME
#undef DEFINE_DMA_UNMAP_LEN
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)          __u32 LEN_NAME
#undef dma_unmap_addr
#define dma_unmap_addr(PTR, ADDR_NAME)           ((PTR)->ADDR_NAME)
#undef dma_unmap_addr_set
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  (((PTR)->ADDR_NAME) = (VAL))
#undef dma_unmap_len
#define dma_unmap_len(PTR, LEN_NAME)             ((PTR)->LEN_NAME)
#undef dma_unmap_len_set
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    (((PTR)->LEN_NAME) = (VAL))
#endif
#endif

#ifdef HAVE_NDO_SET_VF_VLAN_RH73
#define ndo_set_vf_vlan ndo_set_vf_vlan_rh73
#endif

#ifndef ETHTOOL_GEEE
struct ethtool_eee {
	__u32	cmd;
	__u32	supported;
	__u32	advertised;
	__u32	lp_advertised;
	__u32	eee_active;
	__u32	eee_enabled;
	__u32	tx_lpi_enabled;
	__u32	tx_lpi_timer;
	__u32	reserved[2];
};
#endif

#ifndef HAVE_SKB_FRAG_PAGE
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}

static inline void *skb_frag_address_safe(const skb_frag_t *frag)
{
	void *ptr = page_address(skb_frag_page(frag));
	if (unlikely(!ptr))
		return NULL;

	return ptr + frag->page_offset;
}

static inline void __skb_frag_set_page(skb_frag_t *frag, struct page *page)
{
	frag->page = page;
}

#define skb_frag_dma_map(x, frag, y, len, z) \
	pci_map_page(bp->pdev, (frag)->page, \
		     (frag)->page_offset, (len), PCI_DMA_TODEVICE)
#endif

#ifndef HAVE_PCI_VFS_ASSIGNED
static inline int pci_vfs_assigned(struct pci_dev *dev)
{
	return 0;
}
#endif

#ifndef HAVE_PCI_NUM_VF
#include <../drivers/pci/pci.h>

static inline int pci_num_vf(struct pci_dev *dev)
{
	if (!dev->is_physfn)
		return 0;

	return dev->sriov->nr_virtfn;
}
#endif

#ifndef SKB_ALLOC_NAPI
static inline struct sk_buff *napi_alloc_skb(struct napi_struct *napi,
					     unsigned int length)
{
	struct sk_buff *skb;

	length += NET_SKB_PAD + NET_IP_ALIGN;
	skb = netdev_alloc_skb(napi->dev, length);

	if (likely(skb))
		skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);

	return skb;
}
#endif

#ifndef HAVE_SKB_HASH_TYPE

enum pkt_hash_types {
	PKT_HASH_TYPE_NONE,	/* Undefined type */
	PKT_HASH_TYPE_L2,	/* Input: src_MAC, dest_MAC */
	PKT_HASH_TYPE_L3,	/* Input: src_IP, dst_IP */
	PKT_HASH_TYPE_L4,	/* Input: src_IP, dst_IP, src_port, dst_port */
};

static inline void
skb_set_hash(struct sk_buff *skb, __u32 hash, enum pkt_hash_types type)
{
#ifdef HAVE_NETIF_F_RXHASH
	skb->rxhash = hash;
#endif
}

#endif

#define GET_NET_STATS(x) (unsigned long)le64_to_cpu(x)

#if !defined(NETDEV_RX_FLOW_STEER) || !defined(HAVE_FLOW_KEYS) || (LINUX_VERSION_CODE < 0x030300) || defined(NO_NETDEV_CPU_RMAP)
#undef CONFIG_RFS_ACCEL
#endif

#if !defined(IEEE_8021QAZ_APP_SEL_DGRAM) || !defined(CONFIG_DCB) || !defined(HAVE_IEEE_DELAPP)
#undef CONFIG_BNXT_DCB
#endif

#ifdef NETDEV_UDP_TUNNEL_PUSH_INFO
#define HAVE_NDO_UDP_TUNNEL	1
#endif

#ifdef HAVE_NDO_XDP
#define CONFIG_BNXT_XDP	1
#endif

#ifndef NETDEV_HW_FEATURES
#define hw_features features
#endif

#ifndef HAVE_NETDEV_FEATURES_T
#ifdef HAVE_NDO_FIX_FEATURES
typedef u32 netdev_features_t;
#else
typedef unsigned long netdev_features_t;
#endif
#endif

#if !defined(IFF_UNICAST_FLT)
#define IFF_UNICAST_FLT 0
#endif

#ifndef HAVE_NEW_BUILD_SKB
#define build_skb(data, frag) build_skb(data)
#endif

#ifndef __rcu
#define __rcu
#endif

#ifndef rcu_dereference_protected
#define rcu_dereference_protected(p, c)	\
	rcu_dereference((p))
#endif

#ifndef rcu_access_pointer
#define rcu_access_pointer rcu_dereference
#endif

#ifndef rtnl_dereference
#define rtnl_dereference(p)		\
	rcu_dereference_protected(p, lockdep_rtnl_is_held())
#endif

#ifndef RCU_INIT_POINTER
#define RCU_INIT_POINTER(p, v)	\
	p = (typeof(*v) __force __rcu *)(v)
#endif

#ifdef HAVE_OLD_HLIST
#define __hlist_for_each_entry_rcu(f, n, h, m) \
	hlist_for_each_entry_rcu(f, n, h, m)
#define __hlist_for_each_entry_safe(f, n, t, h, m) \
	hlist_for_each_entry_safe(f, n, t, h, m)
#else
#define __hlist_for_each_entry_rcu(f, n, h, m) \
	hlist_for_each_entry_rcu(f, h, m)
#define __hlist_for_each_entry_safe(f, n, t, h, m) \
	hlist_for_each_entry_safe(f, t, h, m)
#endif

#ifndef skb_vlan_tag_present
#define skb_vlan_tag_present(skb) vlan_tx_tag_present(skb)
#define skb_vlan_tag_get(skb) vlan_tx_tag_get(skb)
#endif

#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT		13
#endif

#ifndef NETIF_F_HW_VLAN_CTAG_TX
#define NETIF_F_HW_VLAN_CTAG_TX NETIF_F_HW_VLAN_TX
#define NETIF_F_HW_VLAN_CTAG_RX NETIF_F_HW_VLAN_RX
/* 802.1AD not supported on older kernels */
#define NETIF_F_HW_VLAN_STAG_TX 0
#define NETIF_F_HW_VLAN_STAG_RX 0

#define __vlan_hwaccel_put_tag(skb, proto, tag) \
	if (proto == ntohs(ETH_P_8021Q))	\
		__vlan_hwaccel_put_tag(skb, tag)

#define vlan_proto protocol

#if defined(HAVE_VLAN_RX_REGISTER)
#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
#define OLD_VLAN	1
#define OLD_VLAN_VALID	(1 << 31)
#endif
#endif

#endif

#ifndef HAVE_NETDEV_UPDATE_FEATURES
static inline void netdev_update_features(struct net_device *dev)
{
	/* Do nothing, since we can't set default VLAN on these old kernels. */
}
#endif

#if !defined(netdev_printk) && (LINUX_VERSION_CODE < 0x020624)

#ifndef HAVE_NETDEV_NAME
static inline const char *netdev_name(const struct net_device *dev)
{
	if (dev->reg_state != NETREG_REGISTERED)
		return "(unregistered net_device)";
	return dev->name;
}
#endif

#define NET_PARENT_DEV(netdev)  ((netdev)->dev.parent)

#define netdev_printk(level, netdev, format, args...)		\
	dev_printk(level, NET_PARENT_DEV(netdev),		\
		   "%s: " format,				\
		   netdev_name(netdev), ##args)

#endif

#ifndef netdev_err
#define netdev_err(dev, format, args...)			\
	netdev_printk(KERN_ERR, dev, format, ##args)
#endif

#ifndef netdev_info
#define netdev_info(dev, format, args...)			\
	netdev_printk(KERN_INFO, dev, format, ##args)
#endif

#ifndef netdev_warn
#define netdev_warn(dev, format, args...)			\
	netdev_printk(KERN_WARNING, dev, format, ##args)
#endif

#ifndef netdev_uc_count
#define netdev_uc_count(dev)	((dev)->uc.count)
#endif

#ifndef netdev_for_each_uc_addr
#define netdev_for_each_uc_addr(ha, dev) \
	list_for_each_entry(ha, &dev->uc.list, list)
#endif

#ifndef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(mclist, dev) \
	for (mclist = dev->mc_list; mclist; mclist = mclist->next)
#endif

#ifndef smp_mb__before_atomic
#define smp_mb__before_atomic()	smp_mb()
#endif

#ifndef smp_mb__after_atomic
#define smp_mb__after_atomic()	smp_mb()
#endif

#ifndef dma_rmb
#define dma_rmb() rmb()
#endif

#ifdef CONFIG_NET_RX_BUSY_POLL
#include <net/busy_poll.h>
#if defined(HAVE_NAPI_HASH_ADD) && defined(NETDEV_BUSY_POLL)
#define BNXT_PRIV_RX_BUSY_POLL	1
#endif
#endif

#if !defined(CONFIG_PTP_1588_CLOCK) && !defined(CONFIG_PTP_1588_CLOCK_MODULE)
#undef HAVE_IEEE1588_SUPPORT
#endif

#if !defined(HAVE_NAPI_HASH_DEL)
static inline void napi_hash_del(struct napi_struct *napi)
{
}
#endif

#if !defined(LL_FLUSH_FAILED) || !defined(HAVE_NAPI_HASH_ADD)
static inline void napi_hash_add(struct napi_struct *napi)
{
}
#endif

#ifndef HAVE_SET_COHERENT_MASK
static inline int dma_set_coherent_mask(struct device *dev, u64 mask)
{
	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);

	return pci_set_consistent_dma_mask(pdev, mask);
}
#endif

#ifndef HAVE_SET_MASK_AND_COHERENT
static inline int dma_set_mask_and_coherent(struct device *dev, u64 mask)
{
	int rc = dma_set_mask(dev, mask);
	if (rc == 0)
		dma_set_coherent_mask(dev, mask);
	return rc;
}
#endif

#ifndef HAVE_DMA_ZALLOC_COHERENT
static inline void *dma_zalloc_coherent(struct device *dev, size_t size,
					dma_addr_t *dma_handle, gfp_t flag)
{
	void *ret = dma_alloc_coherent(dev, size, dma_handle,
				       flag | __GFP_ZERO);
	return ret;
}
#endif

#ifndef HAVE_IFLA_TX_RATE
#define ndo_set_vf_rate ndo_set_vf_tx_rate
#endif

#ifndef HAVE_PRANDOM_BYTES
#define prandom_bytes get_random_bytes
#endif

#ifndef rounddown
#define rounddown(x, y) (				\
{							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
}							\
)
#endif

#ifdef NO_SKB_FRAG_SIZE
static inline unsigned int skb_frag_size(const skb_frag_t *frag)
{
	return frag->size;
}
#endif

#ifndef HAVE_SKB_CHECKSUM_NONE_ASSERT
static inline void skb_checksum_none_assert(struct sk_buff *skb)
{
	skb->ip_summed = CHECKSUM_NONE;
}
#endif

#ifndef HAVE_NEW_FLOW_DISSECTOR_WITH_FLAGS
#define skb_flow_dissect_flow_keys(skb, fkeys, flags)	\
	skb_flow_dissect_flow_keys(skb, fkeys)
#endif

#ifndef HAVE_ETHER_ADDR_EQUAL
static inline bool ether_addr_equal(const u8 *addr1, const u8 *addr2)
{
	return !compare_ether_addr(addr1, addr2);
}
#endif

#ifndef HAVE_ETHER_ADDR_COPY
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
	memcpy(dst, src, ETH_ALEN);
}
#endif

#ifndef HAVE_ETH_BROADCAST_ADDR
static inline void eth_broadcast_addr(u8 *addr)
{
	memset(addr, 0xff, ETH_ALEN);
}
#endif

#ifndef HAVE_ETH_HW_ADDR_RANDOM
static inline void eth_hw_addr_random(struct net_device *dev)
{
#if defined(NET_ADDR_RANDOM)
	dev->addr_assign_type = NET_ADDR_RANDOM;
#endif
	random_ether_addr(dev->dev_addr);
}
#endif

#ifndef HAVE_NETDEV_TX_QUEUE_CTRL
static inline void netdev_tx_sent_queue(struct netdev_queue *dev_queue,
				unsigned int bytes)
{
}

static inline void netdev_tx_completed_queue(struct netdev_queue *dev_queue,
				unsigned int pkts, unsigned int bytes)
{
}

static inline void netdev_tx_reset_queue(struct netdev_queue *q)
{
}
#endif

#ifndef HAVE_NETIF_SET_REAL_NUM_RX
static inline int netif_set_real_num_rx_queues(struct net_device *dev,
				unsigned int rxq)
{
	return 0;
}
#endif

#ifndef HAVE_NETIF_SET_REAL_NUM_TX
static inline void netif_set_real_num_tx_queues(struct net_device *dev,
						unsigned int txq)
{
	dev->real_num_tx_queues = txq;
}
#endif

#ifndef HAVE_NETIF_GET_DEFAULT_RSS
static inline int netif_get_num_default_rss_queues(void)
{
	return min_t(int, 8, num_online_cpus());
}
#endif

#if !defined(HAVE_TCP_V6_CHECK)
static __inline__ __sum16 tcp_v6_check(int len,
				const struct in6_addr *saddr,
				const struct in6_addr *daddr,
				__wsum base)
{
	return csum_ipv6_magic(saddr, daddr, len, IPPROTO_TCP, base);
}
#endif

#ifndef HAVE_USLEEP_RANGE
static inline void usleep_range(unsigned long min, unsigned long max)
{
	if (min < 1000)
		udelay(min);
	else
		msleep(min / 1000);
}
#endif

#ifndef HAVE_GET_NUM_TC
static inline int netdev_get_num_tc(struct net_device *dev)
{
	return 0;
}

static inline void netdev_reset_tc(struct net_device *dev)
{
}

static inline int netdev_set_tc_queue(struct net_device *devi, u8 tc,
				      u16 count, u16 offset)
{
	return 0;
}
#endif

#ifndef HAVE_VZALLOC
static inline void *vzalloc(size_t size)
{
	void *ret = vmalloc(size);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif

#ifndef ETH_MODULE_SFF_8436
#define ETH_MODULE_SFF_8436             0x4
#endif

#ifndef ETH_MODULE_SFF_8436_LEN
#define ETH_MODULE_SFF_8436_LEN         256
#endif

#ifndef ETH_MODULE_SFF_8636
#define ETH_MODULE_SFF_8636             0x3
#endif

#ifndef ETH_MODULE_SFF_8636_LEN
#define ETH_MODULE_SFF_8636_LEN         256
#endif

#ifndef HAVE_PCIE_GET_MINIMUM_LINK
enum pcie_link_width {
	PCIE_LNK_WIDTH_UNKNOWN		= 0xFF,
};

#ifndef HAVE_PCIE_BUS_SPEED
enum pci_bus_speed {
	PCIE_SPEED_2_5GT		= 0x14,
	PCIE_SPEED_5_0GT		= 0x15,
	PCIE_SPEED_8_0GT		= 0x16,
	PCI_SPEED_UNKNOWN		= 0xFF,
};
#endif

static const unsigned char pcie_link_speed[] = {
	PCI_SPEED_UNKNOWN,		/* 0 */
	PCIE_SPEED_2_5GT,		/* 1 */
	PCIE_SPEED_5_0GT,		/* 2 */
	PCIE_SPEED_8_0GT,		/* 3 */
	PCI_SPEED_UNKNOWN,		/* 4 */
	PCI_SPEED_UNKNOWN,		/* 5 */
	PCI_SPEED_UNKNOWN,		/* 6 */
	PCI_SPEED_UNKNOWN,		/* 7 */
	PCI_SPEED_UNKNOWN,		/* 8 */
	PCI_SPEED_UNKNOWN,		/* 9 */
	PCI_SPEED_UNKNOWN,		/* A */
	PCI_SPEED_UNKNOWN,		/* B */
	PCI_SPEED_UNKNOWN,		/* C */
	PCI_SPEED_UNKNOWN,		/* D */
	PCI_SPEED_UNKNOWN,		/* E */
	PCI_SPEED_UNKNOWN		/* F */
};

#ifndef PCI_EXP_LNKSTA_NLW_SHIFT
#define PCI_EXP_LNKSTA_NLW_SHIFT	4
#endif

#ifdef HAVE_PCIE_CAPABILITY_READ_WORD
static inline int pcie_get_minimum_link(struct pci_dev *dev,
					enum pci_bus_speed *speed,
					enum pcie_link_width *width)
{
	int ret;

	*speed = PCI_SPEED_UNKNOWN;
	*width = PCIE_LNK_WIDTH_UNKNOWN;

	while (dev) {
		u16 lnksta;
		enum pci_bus_speed next_speed;
		enum pcie_link_width next_width;

		ret = pcie_capability_read_word(dev, PCI_EXP_LNKSTA, &lnksta);
		if (ret)
			return ret;

		next_speed = pcie_link_speed[lnksta & PCI_EXP_LNKSTA_CLS];
		next_width = (lnksta & PCI_EXP_LNKSTA_NLW) >>
			PCI_EXP_LNKSTA_NLW_SHIFT;

		if (next_speed < *speed)
			*speed = next_speed;

		if (next_width < *width)
			*width = next_width;

		dev = dev->bus->self;
	}

	return 0;
}
#else
static inline int pcie_get_minimum_link(struct pci_dev *dev,
					enum pci_bus_speed *speed,
					enum pcie_link_width *width)
{
#define BNXT_PCIE_CAP		0xAC
	u16 lnksta;
	int ret;

	ret = pci_read_config_word(dev, BNXT_PCIE_CAP + PCI_EXP_LNKSTA,
				   &lnksta);
	if (ret)
		return ret;

	*speed = pcie_link_speed[lnksta & PCI_EXP_LNKSTA_CLS];
	*width = (lnksta & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

	return 0;
}
#endif
#endif

#ifndef HAVE_PCI_IS_BRIDGE
static inline bool pci_is_bridge(struct pci_dev *dev)
{
	return dev->hdr_type == PCI_HEADER_TYPE_BRIDGE ||
		dev->hdr_type == PCI_HEADER_TYPE_CARDBUS;
}
#endif

#ifndef HAVE_PCI_PHYSFN
static inline struct pci_dev *pci_physfn(struct pci_dev *dev)
{
#ifdef CONFIG_PCI_IOV
	if (dev->is_virtfn)
		dev = dev->physfn;
#endif

	return dev;
}
#endif

#ifndef HAVE_NDO_XDP
struct netdev_xdp;
struct xdp_buff;
#endif

#ifndef XDP_PACKET_HEADROOM
#define XDP_PACKET_HEADROOM	0
#endif

#ifndef HAVE_NDO_XDP_XMIT
#define XDP_REDIRECT	4

#ifdef HAVE_NDO_XDP
static inline int xdp_do_redirect(struct net_device *dev, struct xdp_buff *xdp,
				  struct bpf_prog *prog)
{
	return 0;
}
#endif
#endif

#ifndef HAVE_BPF_TRACE
#define trace_xdp_exception(dev, xdp_prog, act)
#endif

#ifndef HAVE_XDP_SET_DATA_META_INVALID
#define xdp_set_data_meta_invalid(xdp)
#endif

#ifndef HAVE_TCF_EXTS_HAS_ACTIONS
#define tcf_exts_has_actions(x)			(!tc_no_actions(x))
#endif

#if defined(CONFIG_BNXT_FLOWER_OFFLOAD) && !defined(HAVE_TCF_STATS_UPDATE)
static inline void
tcf_exts_stats_update(const struct tcf_exts *exts,
		      u64 bytes, u64 packets, u64 lastuse)
{
#ifdef CONFIG_NET_CLS_ACT
	int i;

	preempt_disable();

	for (i = 0; i < exts->nr_actions; i++) {
		struct tc_action *a = exts->actions[i];

		tcf_action_stats_update(a, bytes, packets, lastuse);
	}

	preempt_enable();
#endif
}
#endif
