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

#ifndef BE_COMPAT_H
#define BE_COMPAT_H

#ifdef RHEL_RELEASE_CODE
#define RHEL
#endif

#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a,b)	(((a) << 8) + (b))
#endif

#ifndef NETIF_F_HW_VLAN_CTAG_DEFINED
#define NETIF_F_HW_VLAN_CTAG_TX         NETIF_F_HW_VLAN_TX
#define NETIF_F_HW_VLAN_CTAG_RX         NETIF_F_HW_VLAN_RX
#define NETIF_F_HW_VLAN_CTAG_FILTER     NETIF_F_HW_VLAN_FILTER
#endif

/****************************** RHEL5 backport ***************************/
/* Backport of request_irq */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
typedef irqreturn_t(*backport_irq_handler_t) (int, void *);
static inline int request_irq_compat(uint irq,
				     irqreturn_t(*handler) (int, void *),
				     ulong flags, const char *dev_name,
				     void *dev_id)
{
	return request_irq(irq,
		(irqreturn_t(*) (int, void *, struct pt_regs *))handler,
		flags, dev_name, dev_id);
}
#define request_irq			request_irq_compat
#define dma_mapping_error(dev, busaddr)	dma_mapping_error(busaddr)
#endif /************************ RHEL5 backport ***************************/

/*************************** NAPI backport ********************************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)

/* RHEL 5.4+ has a half baked napi_struct implementation.
 * Bypass it and use simulated NAPI using multiple netdev structs
 */
#ifdef RHEL
typedef struct napi_struct		rhel_napi;
#endif

#define netif_napi_add			netif_napi_add_compat
#define	netif_napi_del			netif_napi_del_compat
#define napi_gro_frags(napi) 		napi_gro_frags((rhel_napi*) napi)
#define napi_get_frags(napi)		napi_get_frags((rhel_napi*) napi)
#define vlan_gro_frags(napi, g, v)	vlan_gro_frags((rhel_napi*) napi, g, v);
#define napi_schedule(napi)		netif_rx_schedule((napi)->dev)
#define napi_enable(napi)		netif_poll_enable((napi)->dev)
#define napi_disable(napi)		netif_poll_disable((napi)->dev)
#define napi_complete(napi)		napi_gro_flush((rhel_napi *)napi); \
					netif_rx_complete(napi->dev)
#define napi_schedule_prep(napi)	netif_rx_schedule_prep((napi)->dev)
#define __napi_schedule(napi)		__netif_rx_schedule((napi)->dev)

#define napi_struct			napi_struct_compat

struct napi_struct_compat {
#ifdef RHEL
	rhel_napi napi;	/* must be the first member */
#endif
	struct net_device *dev;
	int (*poll) (struct napi_struct *napi, int budget);
};

extern void netif_napi_del_compat(struct napi_struct *napi);
extern void netif_napi_add_compat(struct net_device *, struct napi_struct *,
				int (*poll) (struct napi_struct *, int), int);
#endif /*********************** NAPI backport *****************************/


/*********************** Backport of netdev ops struct ********************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
struct net_device_ops {
	int	(*ndo_init)(struct net_device *dev);
	void	(*ndo_uninit)(struct net_device *dev);
	int	(*ndo_open)(struct net_device *dev);
	int	(*ndo_stop)(struct net_device *dev);
	int	(*ndo_start_xmit) (struct sk_buff *skb, struct net_device *dev);
	u16	(*ndo_select_queue)(struct net_device *dev,
				    struct sk_buff *skb);
	void	(*ndo_change_rx_flags)(struct net_device *dev, int flags);
	void	(*ndo_set_rx_mode)(struct net_device *dev);
	void	(*ndo_set_multicast_list)(struct net_device *dev);
	int	(*ndo_set_mac_address)(struct net_device *dev, void *addr);
	int	(*ndo_validate_addr)(struct net_device *dev);
	int	(*ndo_do_ioctl)(struct net_device *dev,
			struct ifreq *ifr, int cmd);
	int	(*ndo_set_config)(struct net_device *dev, struct ifmap *map);
	int	(*ndo_change_mtu)(struct net_device *dev, int new_mtu);
	int	(*ndo_neigh_setup)(struct net_device *dev,
				struct neigh_parms *);
	void	(*ndo_tx_timeout) (struct net_device *dev);

	struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);

	void	(*ndo_vlan_rx_register)(struct net_device *dev,
				struct vlan_group *grp);
	void	(*ndo_vlan_rx_add_vid)(struct net_device *dev,
				unsigned short vid);
	void	(*ndo_vlan_rx_kill_vid)(struct net_device *dev,
				unsigned short vid);
#ifdef CONFIG_NET_POLL_CONTROLLER
	void	(*ndo_poll_controller)(struct net_device *dev);
#endif
};

#define eth_validate_addr		NULL
extern void be_netdev_ops_init(struct net_device *n, struct net_device_ops *p);

#endif /******************** Backport of netdev ops struct ****************/

/*************** Backport of Delayed work queues **************************/
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 19)
/******** initialize all of a work-struct: ***************/
static inline void INIT_WORK_COMPAT(struct work_struct *work, void (*func))
{
	INIT_WORK(work, func, work);
}
#undef INIT_WORK
#define INIT_WORK INIT_WORK_COMPAT
#undef INIT_DELAYED_WORK
#define INIT_DELAYED_WORK(_work, _func)	INIT_WORK(&(_work)->work, _func)

static inline int backport_schedule_delayed_work(struct delayed_work *work,
		unsigned long delay)
{
	if (unlikely(!delay))
		return schedule_work(&work->work);
	else
		return schedule_delayed_work(&work->work, delay);
}
#define schedule_delayed_work backport_schedule_delayed_work

static inline int backport_queue_delayed_work(struct workqueue_struct *wq,
					      struct delayed_work *work,
					      unsigned long delay)
{
	if (unlikely(!delay))
		return queue_work(wq, &work->work);
	else
		return queue_delayed_work(wq, &work->work, delay);
}
#define queue_delayed_work backport_queue_delayed_work
#endif /*************** Backport of Delayed work queues ******************/

/************************* Multi TXQ Support *****************************/
/* Supported only in RHEL6 and SL11.1 (barring one execption) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#define MQ_TX
#define tx_mq_kernel				true
#else
#define tx_mq_kernel				false
#endif

#ifndef ALLOC_ETHDEV_MQS_defined 
#define alloc_etherdev_mqs(sz, tx_cnt, rx_cnt)  alloc_etherdev_mq(sz, \
							max(tx_cnt, rx_cnt))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#define alloc_etherdev_mq(sz, cnt) 		alloc_etherdev(sz)
#define skb_get_queue_mapping(skb)		0
#define skb_tx_hash(dev, skb)			0
#define netif_tx_start_all_queues(dev)		netif_start_queue(dev)
#define netif_wake_subqueue(dev, idx)		netif_wake_queue(dev)
#define netif_stop_subqueue(dev, idx)		netif_stop_queue(dev)
#define __netif_subqueue_stopped(dev, idx)	netif_queue_stopped(dev)
#endif /* < 2.6.27 */

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)) && \
		        (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)))
#define skb_tx_hash(dev, skb)			0
#endif

#ifndef CONFIG_NET_RX_BUSY_POLL
#define skb_mark_napi_id(skb, napi)		do {} while (0)
#define napi_hash_add(napi)			0
#define napi_hash_del(napi)			0
#endif /* CONFIG_NET_RX_BUSY_POLL */

#ifndef NETIF_SET_REAL_NUM_TX_QS_defined
static inline void netif_set_real_num_tx_queues(struct net_device *dev,
						unsigned int txq)
{
#ifdef REAL_NUM_TX_QS_defined
	dev->real_num_tx_queues = txq;
#endif
}
#endif /********************** Multi TXQ Support **************************/

#ifndef GET_NUM_DEF_RSS_defined
#define DEFAULT_MAX_NUM_RSS_QUEUES	(8)
int netif_get_num_default_rss_queues(void);
#endif

#ifndef NETDEV_RSS_KEY_FILL_defined
void netdev_rss_key_fill(void *buffer, size_t len);
#endif

#ifndef NETIF_SET_REAL_NUM_RX_QS_defined
static inline int netif_set_real_num_rx_queues(struct net_device *dev,
					       unsigned int rxq)
{
#ifdef REAL_NUM_RX_QS_defined
	dev->real_num_rx_queues = rxq;
#endif
	return 0;
}
#endif

#ifdef NETDEV_RPS_INFO_defined
/* Handling RHEL6.4 kernel bug related to netif_set_real_num_rx_queues.
 * Calling of netif_set_real_num_rx_queues before register_netdev results in
 * updating both num_rx_queues and real_num_rx_queues with given num_rx_qs.
 * Because of this unable to increase the num_rx_qs with set_channel
 */
static inline int netif_set_real_num_rx_queues_fixed(struct net_device *dev,
						      unsigned int rxq)
{
	unsigned int num_rx_queues;
	int status;

	num_rx_queues = netdev_extended(dev)->rps_data.num_rx_queues;

	status = netif_set_real_num_rx_queues(dev, rxq);

	/*Restoring num_rx_queues*/
	netdev_extended(dev)->rps_data.num_rx_queues = num_rx_queues;

	return status;
}

#define netif_set_real_num_rx_queues	netif_set_real_num_rx_queues_fixed

#endif

#ifndef SKB_RECORD_RX_QUEUE_defined
#define skb_record_rx_queue(skb, index) do {} while(0)
#endif

#ifndef PTR_ALIGN
#define PTR_ALIGN(p, a)			((typeof(p)) ALIGN((ulong)(p), (a)))
#endif

#ifndef	ETH_FCS_LEN 
#define ETH_FCS_LEN			4
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 31)
#define netdev_tx_t			int
#endif

#ifndef VLAN_PRIO_MASK
#define VLAN_PRIO_MASK          	0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT         	13
#endif

#if defined(USE_NEW_VLAN_MODEL) || LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
/* vlan_gro_frags() can be safely called when vlan_group is NULL
 * for kernels >= 3.0 or when kernels uses USE_NEW_VLAN_MODEL.
 */
#define NULL_VLAN_GRP_SAFE
#endif

#ifndef ETHTOOL_FLASH_MAX_FILENAME
#define ETHTOOL_FLASH_MAX_FILENAME	128
#endif

#ifndef ALLOC_SKB_IP_ALIGN_defined
static inline struct sk_buff *netdev_alloc_skb_ip_align(struct net_device *dev,
		unsigned int length)
{
	struct sk_buff *skb = netdev_alloc_skb(dev, length + NET_IP_ALIGN);

	if (NET_IP_ALIGN && skb)
		skb_reserve(skb, NET_IP_ALIGN);
	return skb;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#ifndef netif_set_gso_max_size
#define netif_set_gso_max_size(netdev, size) do {} while (0)
#endif
#endif

#ifndef NETIF_F_VLAN_SG
#define NETIF_F_VLAN_SG			NETIF_F_SG
#endif

#ifndef NETIF_F_VLAN_CSUM
#define NETIF_F_VLAN_CSUM		0
#endif

#ifndef NETIF_F_VLAN_TSO
#define NETIF_F_VLAN_TSO		NETIF_F_TSO
#endif

#ifndef NETIF_F_IPV6_CSUM
#define NETIF_F_IPV6_CSUM		NETIF_F_HW_CSUM
#endif

#ifndef NETIF_F_RXCSUM
#define NETIF_F_RXCSUM			0
#endif

#ifndef NETIF_F_RXHASH
#define NETIF_F_RXHASH			0
#endif

#ifndef NETIF_F_CSUM_MASK
#define	NETIF_F_CSUM_MASK		NETIF_F_ALL_CSUM
#endif

#ifndef NDO_SET_FEATURES_defined
#define hw_features			features
#endif

#ifndef NDO_SET_FEATURES_USES_FEATURES
#define netdev_features_t		u32
#endif

#ifndef VLAN_GROUP_ARRAY_LEN
#define VLAN_GROUP_ARRAY_LEN		VLAN_N_VID
#endif

#ifndef FOR_EACH_SET_BIT_defined
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
#define vlan_features			features
#endif

#ifndef DEFINE_DMA_UNMAP_ADDR
#define DEFINE_DMA_UNMAP_ADDR(bus)	dma_addr_t bus
#endif

#ifndef netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(h, n) 	for (h = (n)->mc_list; h; h = h->next)
#endif

#ifndef netdev_mc_count
#define netdev_mc_count(nd)		(nd->mc_count)
#endif

#ifdef netdev_uc_empty
#define NETDEV_UC_defined
#endif

#ifndef DEV_UC_MC_SYNC_defined

int __dev_uc_sync(struct net_device *dev,
		  int (*sync)(struct net_device *, const unsigned char *),
		  int (*unsync)(struct net_device *, const unsigned char *));
void __dev_uc_unsync(struct net_device *dev,
		     int (*unsync)(struct net_device *, const unsigned char *));
int __dev_mc_sync(struct net_device *dev,
		  int (*sync)(struct net_device *, const unsigned char *),
		  int (*unsync)(struct net_device *, const unsigned char *));
void __dev_mc_unsync(struct net_device *dev,
		     int (*unsync)(struct net_device *, const unsigned char *));

#endif

#ifndef PORT_DA
#define PORT_DA				PORT_FIBRE
#endif

#ifndef SUPPORTED_20000baseKR2_Full
#define SUPPORTED_20000baseKR2_Full	(1 << 22)
#endif

#ifndef SUPPORTED_40000baseKR4_Full
#define SUPPORTED_40000baseKR4_Full	(1 << 23)
#endif

#ifndef SUPPORTED_40000baseCR4_Full
#define SUPPORTED_40000baseCR4_Full	(1 << 24)
#endif

#ifndef SUPPORTED_40000baseSR4_Full
#define SUPPORTED_40000baseSR4_Full	(1 << 25)
#endif

#ifndef SUPPORTED_40000baseLR4_Full
#define SUPPORTED_40000baseLR4_Full	(1 << 26)
#endif

#ifndef ADVERTISED_20000baseKR2_Full
#define ADVERTISED_20000baseKR2_Full	(1 << 22)
#endif

#ifndef ADVERTISED_40000baseKR4_Full
#define ADVERTISED_40000baseKR4_Full	(1 << 23)
#endif

/* When new mc-list macros were used in 2.6.35, dev_mc_list was dropped */
#ifdef DEV_MC_LIST_defined
#define DMI_ADDR			dmi_addr
#else
#define DMI_ADDR			addr
#define dev_mc_list			netdev_hw_addr
#endif /* dev_mc_list */

#ifndef speed_hi
#define speed_hi			speed
#endif

#ifndef ETHTOOL_CMD_SPEED_SET_defined
static inline void ethtool_cmd_speed_set(struct ethtool_cmd *ep, __u32 speed)
{
	ep->speed = (__u16)speed;
}
#endif

#ifndef ETHTOOL_CMD_SPEED_defined
static inline __u32 ethtool_cmd_speed(struct ethtool_cmd *ep)
{
	return ep->speed;
}
#endif

#ifndef PHYS_ID_STATE_defined
enum ethtool_phys_id_state {
	ETHTOOL_ID_INACTIVE,
	ETHTOOL_ID_ACTIVE,
	ETHTOOL_ID_ON,
	ETHTOOL_ID_OFF
};
#define set_phys_id			phys_id
#define be_set_phys_id			be_phys_id
#endif /* PHYS_ID_STATE_defined */

#ifndef PCI_EXP_LNKCAP_SLS
#define  PCI_EXP_LNKCAP_SLS     0x0000000f /* Supported Link Speeds */
#endif

static inline void be_reset_skb_tx_vlan(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
	skb->vlan_tci = 0;
#else
	struct vlan_skb_tx_cookie *cookie;

	cookie = VLAN_TX_SKB_CB(skb);
	cookie->magic = 0;
#endif
}

#ifndef IS_ALIGNED
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
#endif

#ifndef ACCESS_ONCE
#define ACCESS_ONCE(x)			(*(volatile typeof(x) *)&(x))
#endif

static inline struct sk_buff *__vlan_put_tag_fixed(struct sk_buff *skb,
						__be16 vlan_proto,
						ushort vlan_tag)
{
#ifdef VLAN_PUT_TAG_defined
#ifdef VLAN_FUNCS_USES_PROTO
	struct sk_buff *new_skb = __vlan_put_tag(skb, vlan_proto, vlan_tag);
#else
	struct sk_buff *new_skb = __vlan_put_tag(skb, vlan_tag);
#endif /* VLAN_FUNCS_USES_PROTO */
#else
	struct sk_buff *new_skb = vlan_insert_tag_set_proto(skb, vlan_proto,
							    vlan_tag);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)
	/* On kernel versions < 2.6.27 the __vlan_put_tag() function
	 * distorts the network layer hdr pointer in the skb which
	 * affects the detection of UDP/TCP packets down the line in
	 * wrb_fill_hdr().This work-around sets it right.
	 */
	skb_set_network_header(new_skb, VLAN_ETH_HLEN);
#endif
	return new_skb;
}

#ifdef USE_NEW_VLAN_MODEL
#if !defined(VLAN_GRP_defined)
struct vlan_group {
	char dummy;
};
#endif

static inline int vlan_hwaccel_receive_skb_compat(struct sk_buff *skb,
						  struct vlan_group *grp,
						  u16 vlan_tci)
{
#ifdef VLAN_FUNCS_USES_PROTO
	__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vlan_tci);
#else
	__vlan_hwaccel_put_tag(skb, vlan_tci);
#endif
	return netif_receive_skb(skb);
}

static inline gro_result_t vlan_gro_frags_compat(struct napi_struct *napi,
						 struct vlan_group *grp,
						 unsigned int vlan_tci)
{
#ifdef VLAN_FUNCS_USES_PROTO
	__vlan_hwaccel_put_tag(napi->skb, htons(ETH_P_8021Q), vlan_tci);
#else
	__vlan_hwaccel_put_tag(napi->skb, vlan_tci);
#endif
	return napi_gro_frags(napi);
}

#define	vlan_hwaccel_receive_skb		vlan_hwaccel_receive_skb_compat
#define	vlan_gro_frags				vlan_gro_frags_compat
#endif /* USE_NEW_VLAN_MODEL */

#ifndef VLAN_FUNCS_USES_PROTO
#define be_vlan_add_vid(netdev, proto, vid)	be_vlan_add_vid(netdev, vid)
#define be_vlan_rem_vid(netdev, proto, vid)	be_vlan_rem_vid(netdev, vid)
#endif

#ifndef SKB_FRAG_API_defined
static inline dma_addr_t skb_frag_dma_map(struct device *dev,
					  const skb_frag_t *frag,
					  size_t offset, size_t size,
					  enum dma_data_direction dir)
{
	return dma_map_page(dev, frag->page, frag->page_offset + offset, size,
			    dir);
}

static inline void skb_frag_set_page(struct sk_buff *skb, int f,
				     struct page *page)
{
	skb_shinfo(skb)->frags[f].page = page;
}
#endif /* SKB_FRAG_API_define */

#ifndef SKB_FRAG_SIZE_defined
static inline void skb_frag_size_set(skb_frag_t *frag, unsigned int size)
{
        frag->size = size;
}

static inline void skb_frag_size_add(skb_frag_t *frag, int delta)
{
        frag->size += delta;
}

static inline unsigned int skb_frag_size(const skb_frag_t *frag)
{
        return frag->size;
}
#endif /* SKB_FRAG_SIZE_defined */

/* This API is broken in RHEL 6.3 due to half-baked back-porting. Additional
 * check needed to cover for Oracle UEK 6.3
 */
#if RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(6,3) || \
	LINUX_VERSION_CODE == KERNEL_VERSION(3, 0, 16) || \
	LINUX_VERSION_CODE == KERNEL_VERSION(3, 0, 36)
#define skb_frag_set_page(skb, f, p)	(skb_shinfo(skb)->frags[f].page = p)
#endif

#ifndef PCI_PHYSFN_defined
static inline struct pci_dev *pci_physfn(struct pci_dev *dev)
{
#ifdef CONFIG_PCI_IOV
	if (dev->is_virtfn)
		dev = dev->physfn;
#endif

	return dev;
}
#endif /* PCI_PHYSFN_defined */

/******************************** SRIOV ************************************/
#ifndef PCI_SRIOV_SET_TOTALVFS_defined
int pci_sriov_get_totalvfs(struct pci_dev *pdev);
int pci_sriov_set_totalvfs(struct pci_dev *pdev, u16 numvfs);
#endif

#ifdef NDO_SET_VF_VLAN_RH73_defined
#define ndo_set_vf_vlan ndo_set_vf_vlan_rh73
#endif
void be_wait_for_vfs_detach(struct pci_dev *pdev);

/* Half baked support for SRIOV in older kernels */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32) && defined(CONFIG_PCI_IOV)
#define sriov_kernel				true
#else
#define sriov_kernel				false
#endif

#ifndef PCI_FLAGS_ASSIGNED_defined
#define	PCI_DEV_FLAGS_ASSIGNED			0
#define dev_flags				class /* just for compiler */ 
#endif /* PCI_FLAGS_ASSIGNED_defined */

#ifdef CONFIG_PCI_IOV
int be_find_vfs(struct pci_dev *pdev, int vf_state);
#ifndef PCI_VFS_ASSIGNED_defined
int pci_vfs_assigned(struct pci_dev *pdev);
#endif

#ifndef PCI_NUM_VF_defined
int pci_num_vf(struct pci_dev *pdev);
#endif
#else
#define pci_vfs_assigned(x)			0
#define pci_num_vf(x)				0
#endif /* CONFIG_PCI_IOV */

#ifndef NDO_GET_STATS64_defined
struct u64_stats_sync {
	unsigned dummy;
};
#define rtnl_link_stats64			net_device_stats
/* Dummy implementation; also, avoid warnings */
#define u64_stats_update_begin(x)		do {} while(0)
#define u64_stats_update_end(x)			do {} while(0)
#define u64_stats_fetch_begin_bh(x)		((x)->dummy)
#define u64_stats_fetch_retry_bh(x, y)		((x)->dummy != y)
#endif /* NDO_GET_STATS64_defined */

#ifndef STATS_FETCH_IRQ_defined
#define u64_stats_fetch_begin_irq(syncp)	u64_stats_fetch_begin_bh(syncp)
#define u64_stats_fetch_retry_irq(syncp, start)	\
		u64_stats_fetch_retry_bh(syncp, start)
#endif /* STATS_FETCH_IRQ_defined */


#ifdef SKB_TRANSPORT_HDR_OLD
static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
	return ((skb)->h.raw);
}
#endif

#ifdef ICMP6_HDR_IS_OLD
static inline struct icmp6hdr *icmp6_hdr(const struct sk_buff *skb)
{
	return (struct icmp6hdr *)skb_transport_header(skb);
}
#endif

#ifdef UDP_HDR_IS_OLD
static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)skb_transport_header(skb);
}
#endif

void be_update_xmit_trans_start(struct net_device *netdev, int i);

#ifndef DMA_SET_COHERENT_MASK_defined
static inline int dma_set_coherent_mask(struct device *dev, u64 mask)
{
	if (!dma_supported(dev, mask))
		return -EIO;

	dev->coherent_dma_mask = mask;

	return 0;
}
#endif /* DMA_SET_COHERENT_MASK_defined */

#ifndef DMA_SET_MASK_AND_COHERENT_defined
static inline int dma_set_mask_and_coherent(struct device *dev, u64 mask)
{
	int status;

	status = dma_set_mask(dev, mask);
	if (!status)
		dma_set_coherent_mask(dev, mask);

	return status;
}
#endif /* DMA_SET_MASK_AND_COHERENT_defined */

#ifndef DMA_ZALLOC_COHERENT_defined
static inline void *dma_zalloc_coherent(struct device *dev, size_t size,
					dma_addr_t *dma_handle, gfp_t flag)
{
	void *ret = dma_alloc_coherent(dev, size, dma_handle,
				       flag | __GFP_ZERO);
	return ret;
}
#endif /* DMA_ZALLOC_COHERENT_defined */

#ifndef NDO_BRIDGE_SETLINK_USES_FLAGS
#define be_ndo_bridge_setlink(dev, nlh, flags)		\
	be_ndo_bridge_setlink(dev, nlh)
#endif

#ifndef NDO_BRIDGE_GETLINK_USES_NLFLAGS
#ifndef NDO_BRIDGE_GETLINK_USES_MASK
#define be_ndo_bridge_getlink(skb, pid, seq, dev, mask, nlflags)	\
	be_ndo_bridge_getlink(skb, pid, seq, dev)
#else
#define be_ndo_bridge_getlink(skb, pid, seq, dev, mask, nlflags)	\
	be_ndo_bridge_getlink(skb, pid, seq, dev, mask)
#endif
#endif

#ifndef NDO_DFLT_BRIDGE_GETLINK_USES_VLANFILL
#ifndef NDO_DFLT_BRIDGE_GETLINK_USES_NLFLAGS
#ifndef NDO_DFLT_BRIDGE_GETLINK_USES_MASK
#define ndo_dflt_bridge_getlink(skb, pid, seq, dev, mode, flags, mask, nlflags,\
				filter_mask, vlan_fill)	\
	ndo_dflt_bridge_getlink(skb, pid, seq, dev, mode)
#else
#define ndo_dflt_bridge_getlink(skb, pid, seq, dev, mode, flags, mask, nlflags,\
				filter_mask, vlan_fill)	\
	ndo_dflt_bridge_getlink(skb, pid, seq, dev, mode, flags, mask)
#endif	/* NDO_DFLT_BRIDGE_GETLINK_USES_MASK */
#else
#define ndo_dflt_bridge_getlink(skb, pid, seq, dev, mode, flags, mask, nlflags,\
				filter_mask, vlan_fill)	\
	ndo_dflt_bridge_getlink(skb, pid, seq, dev, mode, flags, mask, nlflags)
#endif	/* NDO_DFLT_BRIDGE_GETLINK_USES_NLFLAGS */
#endif	/* NDO_DFLT_BRIDGE_GETLINK_USES_VLANFILL */

#ifndef NDO_VF_RATE_defined
#define be_set_vf_tx_rate(netdev, vf, min_tx_rate, max_tx_rate)		\
	be_set_vf_tx_rate(netdev, vf, max_tx_rate)
#endif

#if !defined(NDO_SELECT_QUEUE_USES_QFALLBACK) &&			\
	defined(NDO_SELECT_QUEUE_USES_PRIV)
#define be_select_queue(netdev, skb, accel_priv, fallback)		\
	be_select_queue(netdev, skb, accel_priv)
#elif !defined(NDO_SELECT_QUEUE_USES_PRIV)
#define be_select_queue(netdev, skb, accel_priv, fallback)		\
	be_select_queue(netdev, skb)
#endif

#ifdef NDO_VLAN_RX_ADD_VID_VOID
#define vid_return_t			void
#define ndo_vlan_return(status)		return
#else
#define vid_return_t			int
#define ndo_vlan_return(status)		return(status)
#endif

#ifdef ETHTOOL_RXNFC_OLD
#define eth_rxnfc_t			void
#else
#define eth_rxnfc_t			u32
#endif

#ifdef CLASS_DEVICE_defined
#define CLASS_DEV		class_dev
#else
#define CLASS_DEV		dev
#endif /* CLASS_DEVICE_defined */

#ifndef ETHER_ADDR_EQUAL_defined
#define ether_addr_equal(addr1, addr2)	!compare_ether_addr(addr1, addr2)
#endif /* ETHER_ADDR_EQUAL_defined */

#ifndef CPUMASK_SET_CPU_LOCAL_FIRST_defined
extern int cpumask_set_cpu_local_first(int i, int numa_node, cpumask_t *dstp);
#endif /* CPUMASK_SET_LOCAL_CPU_FIRST_defined */

#ifndef DEV_TO_NODE_defined
static inline int dev_to_node(struct device *dev)
{
	return 0;
}
#endif /* DEV_TO_NODE_defined */

#ifndef IRQ_SET_AFFINITY_HINT_defined
static inline int irq_set_affinity_hint(unsigned int irq, cpumask_t *m)
{
	return -EINVAL;
}
#endif /* IRQ_SET_AFFINITY_HINT_defined */


#ifndef CPUMASK_VAR_T_defined
#define cpumask_var_t cpumask_t *
extern bool zalloc_cpumask_var(cpumask_t **mask, gfp_t flags);
extern void free_cpumask_var(cpumask_t *mask);
#endif /* CPUMASK_VAR_T_defined */

#ifndef HWMON_DEV_REGISTER_WITH_GROUPS
#define __ATTRIBUTE_GROUPS(_name)				\
static const struct attribute_group *_name##_groups[] = {	\
	&_name##_group,						\
	NULL,							\
}

#define ATTRIBUTE_GROUPS(_name)					\
static const struct attribute_group _name##_group = {		\
	.attrs = _name##_attrs,					\
};								\
__ATTRIBUTE_GROUPS(_name)

#ifdef HWMON_DEV_REGISTER_OLD
#define hwmon_dev_return_t struct class_device *
#else
#define hwmon_dev_return_t struct device *
#endif

hwmon_dev_return_t
devm_hwmon_device_register_groups_compat(struct device *dev,
					 const char *name,
					 void *drvdata,
					 const struct attribute_group **groups);

void devm_hwmon_device_unregister_compat(void *hwmon_dev);

#define devm_hwmon_device_register_with_groups			\
		devm_hwmon_device_register_groups_compat

#define devm_hwmon_device_unregister				\
		devm_hwmon_device_unregister_compat
#endif /* HWMON_DEV_REGISTER_WITH_GROUPS */

#if defined(VXLAN_NDO_defined) && !defined(VXLAN_GET_RX_PORT_defined)
#if !IS_ENABLED(CONFIG_VXLAN)
static inline void vxlan_get_rx_port(struct net_device *dev)
{
}
#endif
#endif

#ifndef skb_vlan_tag_get
#define skb_vlan_tag_get(skb)	vlan_tx_tag_get(skb)
#endif

#ifndef skb_vlan_tag_present
#define skb_vlan_tag_present(skb)	vlan_tx_tag_present(skb)
#endif

#ifdef VLAN_TX_TAG_GET_ID_OLD
static inline u32 vlan_tx_tag_get_id_compat(struct sk_buff *skb)
{
	u32 vlan_tag = skb_vlan_tag_get(skb);

	return vlan_tag & VLAN_VID_MASK;
}

#define	vlan_tx_tag_get_id	vlan_tx_tag_get_id_compat
#endif

#ifndef RCU_DEREFERENCE_BH_defined
#ifdef __CHECKER__
#define rcu_dereference_sparse(p, space) \
	((void)(((typeof(*p) space *)p) == p))
#else /* #ifdef __CHECKER__ */
#define rcu_dereference_sparse(p, space)
#endif /* #else #ifdef __CHECKER__ */

#define rcu_dereference_bh_check(p, c) \
	__rcu_dereference_check((p), rcu_read_lock_bh_held() || (c), __rcu)

#define rcu_dereference_bh(p) rcu_dereference_bh_check(p, 0)

#define __rcu_dereference_check(p, c, space) \
({ \
	typeof(*p) *_________p1 = (typeof(*p) *__force)ACCESS_ONCE(p); \
	rcu_dereference_sparse(p, space); \
	smp_read_barrier_depends(); /* Dependency order vs. p above. */ \
	((typeof(*p) __force __kernel *)(_________p1)); \
})
#endif /* RCU_DEREFERENCE_BH_defined */

#ifndef HLIST_FIRST_RCU_defined
#define hlist_first_rcu(head) (*((struct hlist_node **)(&(head)->first)))
#define hlist_next_rcu(node)   (*((struct hlist_node **)(&(node)->next)))
#endif /* HLIST_FIRST_RCU_defined */

#ifndef HLIST_ENTRY_SAFE_defined
#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
		____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})
#endif /* HLIST_ENTRY_SAFE_defined */

#if defined(HLIST_RCU_BH_TPOS_defined) || !defined(HLIST_RCU_BH_defined)
#undef hlist_for_each_entry_rcu_bh
#define hlist_for_each_entry_rcu_bh(pos, head, member)                  \
	for (pos = hlist_entry_safe(rcu_dereference_bh(hlist_first_rcu(head)),\
			typeof(*(pos)), member);                        \
		pos;                                                    \
		pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))
#endif /* HLIST_RCU_BH_TPOS_defined */

#ifndef ETHER_ADDR_EQUAL_64BITS_defined
static inline bool ether_addr_equal_64bits(const u8 addr1[6+2],
					   const u8 addr2[6+2])
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	u64 fold = (*(const u64 *)addr1) ^ (*(const u64 *)addr2);

#ifdef __BIG_ENDIAN
	return (fold >> 16) == 0;
#else
	return (fold << 16) == 0;
#endif
#else
	return ether_addr_equal(addr1, addr2);
#endif
}
#endif /* ETHER_ADDR_EQUAL_64BITS_defined */

#ifndef ETHER_ADDR_COPY_defined
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	*(u32 *)dst = *(const u32 *)src;
	*(u16 *)(dst + 4) = *(const u16 *)(src + 4);
#else
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
#endif
}
#endif /* ETHER_ADDR_COPY_defined */

#ifndef ETH_ZERO_ADDR_defined
static inline void eth_zero_addr(u8 *addr)
{
	memset(addr, 0x00, ETH_ALEN);
}
#endif /* ETH_ZERO_ADDR_defined */

#ifdef HLIST_ENTRY_IS_NEW
#undef hlist_for_each_entry_safe
#define hlist_for_each_entry_safe(node, unused, n, head, member)	\
	for (unused = NULL,\
	     node = hlist_entry_safe((head)->first, typeof(*node), member);\
	     node && ({ n = node->member.next; 1; });                     \
	     node = hlist_entry_safe(n, typeof(*node), member))
#endif /* HLIST_ENTRY_IS_NEW */

#ifndef NDO_VF_LINK_STATE_defined
enum {
	IFLA_VF_LINK_STATE_AUTO,	/* link state of the uplink */
	IFLA_VF_LINK_STATE_ENABLE,	/* link always up */
	IFLA_VF_LINK_STATE_DISABLE,	/* link always down */
	__IFLA_VF_LINK_STATE_MAX,
};
#endif /*NDO_VF_LINK_STATE_defined*/

#ifndef ETH_RSS_HASH_TOP
#define ETH_RSS_HASH_TOP	BIT(0)
#define ETH_RSS_HASH_NO_CHANGE	0
#endif

#ifndef dev_consume_skb_any
#define dev_consume_skb_any	dev_kfree_skb_any
#endif

#if defined NDO_GET_PHYS_PORT_ID_defined && !defined NDO_GET_PHYS_PORT_ID_NEW
#define MAX_PHYS_ITEM_ID_LEN MAX_PHYS_PORT_ID_LEN
#endif /* NDO_GET_PHYS_PORT_ID_NEW */

#ifndef PKT_HASH_TYPES_defined
enum pkt_hash_types {
	PKT_HASH_TYPE_NONE,     /* Undefined type */
	PKT_HASH_TYPE_L2,       /* Input: src_MAC, dest_MAC */
	PKT_HASH_TYPE_L3,       /* Input: src_IP, dst_IP */
	PKT_HASH_TYPE_L4,       /* Input: src_IP, dst_IP, src_port, dst_port */
};
#endif

#ifndef SKB_SET_HASH_defined
static inline void skb_set_hash(struct sk_buff *skb, __u32 hash,
				enum pkt_hash_types type)
{
#ifdef L4_HASH_defined
	skb->l4_rxhash = (type == PKT_HASH_TYPE_L4);
#endif
#ifdef RXHASH_defined
	skb->rxhash = hash;
#endif
}
#endif

#ifdef VXLAN_NDO_defined
#ifndef SKB_INNER_TRANSPORT_OFFSET_defined
static inline int skb_inner_transport_offset(const struct sk_buff *skb)
{
	return skb_inner_transport_header(skb) - skb->data;
}
#endif
#endif

#ifndef DEV_PRINTK_IS_NEW
#undef dev_printk
#define dev_printk dev_printk_compat
#define dev_printk_compat(level, dev, format, arg...)   \
			printk(KERN_INFO "%s %s: " "%s: " format,	\
			dev_driver_string(dev), dev_name(dev), level, ## arg)
#endif /* DEV_PRINTK_IS_NEW */

#ifndef NETIF_SET_XPS_QS_defined
static inline int netif_set_xps_queue(struct net_device *dev,
				      struct cpumask *mask,
				      u16 index)
{
	return 0;
}
#endif

#ifndef NETIF_ADDR_LOCK_BH_defined
#define netif_addr_lock_bh netif_tx_lock_bh
#define netif_addr_unlock_bh netif_tx_unlock_bh
#endif

#endif				/* BE_COMPAT_H */
