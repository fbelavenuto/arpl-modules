
obj-$(CONFIG_BE2NET) += be2net.o
be2net-y :=  be_main.o be_cmds.o be_ethtool.o be_compat.o be_sysfs.o be_roce.o
ccflags-y += -DBE2NET_DEFINED

# ************** Header checks ********************
ifneq (,$(shell grep -o CLASS_DEVICE_ATTR $(KSRC)/include/linux/device.h))
	ccflags-y += -DCLASS_DEVICE_defined
endif

ifneq (,$(shell grep -o alloc_etherdev_mqs $(KSRC)/include/linux/etherdevice.h))
	ccflags-y += -DALLOC_ETHDEV_MQS_defined
endif

ifneq (,$(shell grep -o ether_addr_equal $(KSRC)/include/linux/etherdevice.h))
      ccflags-y += -DETHER_ADDR_EQUAL_defined
endif

ifneq (,$(shell grep -o netif_set_real_num_rx_queues $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNETIF_SET_REAL_NUM_RX_QS_defined
endif

ifneq (,$(shell grep -o real_num_rx_queues $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DREAL_NUM_RX_QS_defined
endif

ifneq (,$(shell grep -o netif_set_real_num_tx_queues $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNETIF_SET_REAL_NUM_TX_QS_defined
endif

ifneq (,$(shell grep -o real_num_tx_queues $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DREAL_NUM_TX_QS_defined
endif

ifneq (,$(shell grep -o netif_get_num_default_rss_queues $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DGET_NUM_DEF_RSS_defined
endif

ifneq (,$(shell grep -o netdev_rss_key_fill $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNETDEV_RSS_KEY_FILL_defined
endif

ifneq (,$(shell grep -o ndo_add_vxlan_port $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DVXLAN_NDO_defined
ifneq (,$(shell grep -o "inline void vxlan_get_rx_port" $(KSRC)/include/net/vxlan.h))
	ccflags-y += -DVXLAN_GET_RX_PORT_defined
endif
ifneq (,$(shell grep -o ndo_features_check $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DVXLAN_NDO_FEATURES_CHK_defined
endif
endif

ifneq (,$(shell grep -o ndo_get_phys_port_id $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNDO_GET_PHYS_PORT_ID_defined
endif

ifneq (,$(shell grep -o netif_set_xps_queue $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNETIF_SET_XPS_QS_defined
endif

ifneq (,$(shell grep -A 2 ndo_get_phys_port_id $(KSRC)/include/linux/netdevice.h | grep netdev_phys_item_id))
	ccflags-y += -DNDO_GET_PHYS_PORT_ID_NEW
endif

ifneq (,$(shell grep -o PCI_DEV_FLAGS_ASSIGNED $(KSRC)/include/linux/pci.h))
	ccflags-y += -DPCI_FLAGS_ASSIGNED_defined
endif

ifneq (,$(shell grep -o sriov_configure $(KSRC)/include/linux/pci.h))
	ccflags-y += -DSRIOV_CONFIGURE_defined
endif

ifneq (,$(shell grep -A 2 pci_driver_rh $(KSRC)/include/linux/pci.h | grep sriov_configure))
	ccflags-y += -DPCI_DRIVER_RH_defined
endif

ifneq (,$(shell grep -o skb_frag_set_page $(KSRC)/include/linux/skbuff.h))
	ccflags-y += -DSKB_FRAG_API_defined
endif

ifneq (,$(shell grep -o skb_frag_size $(KSRC)/include/linux/skbuff.h))
	ccflags-y += -DSKB_FRAG_SIZE_defined
endif

ifneq (,$(shell grep -o netdev_alloc_skb_ip_align $(KSRC)/include/linux/skbuff.h))
	ccflags-y += -DALLOC_SKB_IP_ALIGN_defined
endif

ifneq (,$(shell grep -o skb_record_rx_queue $(KSRC)/include/linux/skbuff.h))
	ccflags-y += -DSKB_RECORD_RX_QUEUE_defined
endif

ifneq (,$(shell grep -o skb_set_hash $(KSRC)/include/linux/skbuff.h))
	ccflags-y += -DSKB_SET_HASH_defined
endif

ifneq (,$(shell grep -o pkt_hash_types $(KSRC)/include/linux/skbuff.h))
	ccflags-y += -DPKT_HASH_TYPES_defined
endif

ifneq (,$(shell grep -o l4_rxhash $(KSRC)/include/linux/skbuff.h))
	ccflags-y += -DL4_HASH_defined
endif

ifneq (,$(shell grep -o rxhash $(KSRC)/include/linux/skbuff.h))
	ccflags-y += -DRXHASH_defined
endif

ifneq (,$(shell grep -o dev_mc_list $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DDEV_MC_LIST_defined
endif

ifneq (,$(shell grep -o "struct vlan_group" $(KSRC)/include/linux/if_vlan.h))
	ccflags-y += -DVLAN_GRP_defined
endif

ifeq (,$(shell grep -o "vlan_hwaccel_receive_skb" $(KSRC)/include/linux/if_vlan.h))
	ccflags-y += -DUSE_NEW_VLAN_MODEL
endif

ifneq (,$(shell grep -o ndo_set_vf_mac $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNDO_VF_CFG_defined
endif

ifneq (,$(shell grep -o ndo_set_vf_rate $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNDO_VF_RATE_defined
endif

ifneq (,$(shell grep -o ndo_set_vf_link_state $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNDO_VF_LINK_STATE_defined
endif

ifneq (,$(shell grep -o ndo_set_vf_spoofchk $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNDO_VF_SPOOFCHK_defined
endif

ifneq (,$(shell grep -so "dma_set_coherent_mask" $(KSRC)/include/linux/dma-mapping.h))
	ccflags-y += -DDMA_SET_COHERENT_MASK_defined
endif

ifneq (,$(shell grep -so "dma_set_mask_and_coherent" $(KSRC)/include/linux/dma-mapping.h))
	ccflags-y += -DDMA_SET_MASK_AND_COHERENT_defined
endif

ifneq (,$(shell grep -o ndo_set_features $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNDO_SET_FEATURES_defined
endif

ifneq (,$(shell grep -A 2 ndo_set_features $(KSRC)/include/linux/netdevice.h | grep netdev_features_t))
	ccflags-y += -DNDO_SET_FEATURES_USES_FEATURES
endif

ifneq (,$(shell grep -so "ethtool_cmd_speed_set" $(KSRC)/include/linux/ethtool.h \
						$(KSRC)/include/uapi/linux/ethtool.h))
	ccflags-y += -DETHTOOL_CMD_SPEED_SET_defined
endif

ifneq (,$(shell grep -so "ethtool_cmd_speed" $(KSRC)/include/linux/ethtool.h \
					$(KSRC)/include/uapi/linux/ethtool.h))
	ccflags-y += -DETHTOOL_CMD_SPEED_defined
endif

ifneq (,$(shell grep -o "ethtool_phys_id_state" $(KSRC)/include/linux/ethtool.h))
	ccflags-y += -DPHYS_ID_STATE_defined
endif

ifneq (,$(shell grep -o "flash_device" $(KSRC)/include/linux/ethtool.h))
	ccflags-y += -DETHTOOL_FLASH_defined
endif

ifneq (,$(shell grep -o "get_sset_count" $(KSRC)/include/linux/ethtool.h))
	ccflags-y += -DETHTOOL_SSET_COUNT_defined
endif

ifneq (,$(shell grep -o "set_dump" $(KSRC)/include/linux/ethtool.h))
	ccflags-y += -DETHTOOL_SET_DUMP_defined
endif

ifneq (,$(shell grep -o "ethtool_ops_ext" $(KSRC)/include/linux/ethtool.h))
	ccflags-y += -DETHTOOL_OPS_EXT_defined
endif

ifneq (,$(shell grep -o "get_module_" $(KSRC)/include/linux/ethtool.h))
	ccflags-y += -DETHTOOL_GET_MODULE_defined
endif

ifneq (,$(shell grep -o -w "net_device_ops_ext" $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNETDEV_OPS_EXT_defined
endif

ifneq (,$(shell grep -o "pci_physfn" $(KSRC)/include/linux/pci.h))
	ccflags-y += -DPCI_PHYSFN_defined
endif

ifneq (,$(shell grep -o "set_rxnfc" $(KSRC)/include/linux/ethtool.h))
	ccflags-y += -DETHTOOL_RXNFC_OPS_defined
endif

ifneq (,$(shell grep -o "set_channels" $(KSRC)/include/linux/ethtool.h))
	ccflags-y += -DETHTOOL_OPS_CHANNELS_defined
endif

ifneq (,$(shell grep -so "ETH_TEST_FL_EXTERNAL_LB" $(KSRC)/include/linux/ethtool.h \
						$(KSRC)/include/uapi/linux/ethtool.h))
	ccflags-y += -DETHTOOL_EXTERNAL_LB_defined
endif

ifneq (,$(shell grep -so "IFF_UNICAST_FLT" $(KSRC)/include/uapi/linux/if.h \
					$(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DIFF_UNICAST_FLT_defined
endif

ifneq (,$(shell grep -o ndo_get_stats64 $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNDO_GET_STATS64_defined
ifneq (,$(shell grep -o "u64_stats_fetch_begin_irq" $(KSRC)/include/linux/u64_stats_sync.h))
	ccflags-y += -DSTATS_FETCH_IRQ_defined
endif
endif

ifneq (,$(shell grep -o txq_trans_update $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DTXQ_TRANS_UPDATE_defined
endif

ifeq (,$(shell grep hlist_for_each_entry_safe $(KSRC)/include/linux/list.h | grep tpos))
	ccflags-y += -DHLIST_ENTRY_IS_NEW
endif

ifneq (,$(shell grep -s hlist_for_each_entry_rcu_bh $(KSRC)/include/linux/rculist.h))
	ccflags-y += -DHLIST_RCU_BH_defined
endif

ifneq (,$(shell grep -s hlist_for_each_entry_rcu_bh $(KSRC)/include/linux/rculist.h | grep tpos))
	ccflags-y += -DHLIST_RCU_BH_TPOS_defined
endif

ifneq (,$(shell grep -o pci_vfs_assigned $(KSRC)/include/linux/pci.h))
	ccflags-y += -DPCI_VFS_ASSIGNED_defined
endif

ifneq (,$(shell grep -o pci_num_vf $(KSRC)/include/linux/pci.h))
	ccflags-y += -DPCI_NUM_VF_defined
endif

ifneq (,$(shell grep -o pci_sriov_set_totalvfs $(KSRC)/include/linux/pci.h))
	ccflags-y += -DPCI_SRIOV_SET_TOTALVFS_defined
endif

ifneq (,$(shell grep -A 2 __vlan_hwaccel_put_tag $(KSRC)/include/linux/if_vlan.h | grep vlan_proto))
	ccflags-y += -DVLAN_FUNCS_USES_PROTO
endif

ifeq (,$(shell grep vlan_tx_tag_get_id $(KSRC)/include/linux/if_vlan.h))
	ccflags-y += -DVLAN_TX_TAG_GET_ID_OLD
endif

ifeq (,$(shell grep icmp6_hdr $(KSRC)/include/linux/icmpv6.h))
	ccflags-y += -DICMP6_HDR_IS_OLD
endif

ifeq (,$(shell grep udp_hdr $(KSRC)/include/linux/udp.h))
	ccflags-y += -DUDP_HDR_IS_OLD
endif

ifeq (,$(shell grep skb_transport_header $(KSRC)/include/linux/skbuff.h))
	ccflags-y += -DSKB_TRANSPORT_HDR_OLD
endif

ifeq (,$(shell grep NETIF_F_HW_VLAN $(KSRC)/include/linux/netdevice.h ))
ifneq (,$(shell grep NETIF_F_HW_VLAN_CTAG $(KSRC)/include/linux/netdev_features.h ))
	ccflags-y += -DNETIF_F_HW_VLAN_CTAG_DEFINED
endif
endif

ifneq (,$(shell grep -o ndo_bridge_setlink $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNDO_BRIDGE_SETLINK_defined
endif

ifneq (,$(shell grep -A 3 ndo_bridge_setlink $(KSRC)/include/linux/netdevice.h | grep flags))
	ccflags-y += -DNDO_BRIDGE_SETLINK_USES_FLAGS
endif

ifneq (,$(shell grep -A 4 ndo_bridge_getlink $(KSRC)/include/linux/netdevice.h | grep filter_mask))
	ccflags-y += -DNDO_BRIDGE_GETLINK_USES_MASK
endif

ifneq (,$(shell grep -A 5 ndo_bridge_getlink $(KSRC)/include/linux/netdevice.h | grep nlflags))
	ccflags-y += -DNDO_BRIDGE_GETLINK_USES_NLFLAGS
endif

ifneq (,$(shell grep -A 4 ndo_dflt_bridge_getlink $(KSRC)/include/linux/rtnetlink.h | grep vlan_fill))
	ccflags-y += -DNDO_DFLT_BRIDGE_GETLINK_USES_VLANFILL
endif

ifneq (,$(shell grep -A 3 ndo_dflt_bridge_getlink $(KSRC)/include/linux/rtnetlink.h | grep nlflags))
	ccflags-y += -DNDO_DFLT_BRIDGE_GETLINK_USES_NLFLAGS
endif

ifneq (,$(shell grep -A 3 ndo_dflt_bridge_getlink $(KSRC)/include/linux/rtnetlink.h | grep mask))
	ccflags-y += -DNDO_DFLT_BRIDGE_GETLINK_USES_MASK
endif

ifneq (,$(shell grep -A 4 ndo_select_queue $(KSRC)/include/linux/netdevice.h | grep accel_priv))
	ccflags-y += -DNDO_SELECT_QUEUE_USES_PRIV
endif

ifneq (,$(shell grep -A 4 ndo_select_queue $(KSRC)/include/linux/netdevice.h | grep select_queue_fallback_t))
	ccflags-y += -DNDO_SELECT_QUEUE_USES_QFALLBACK
endif

ifneq (,$(shell grep -o "struct netdev_rps_info" $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNETDEV_RPS_INFO_defined
endif

ifneq (,$(shell grep -o "for_each_set_bit" $(KSRC)/include/linux/bitops.h))
	ccflags-y += -DFOR_EACH_SET_BIT_defined
endif

ifneq (,$(shell grep __vlan_put_tag $(KSRC)/include/linux/if_vlan.h))
	ccflags-y += -DVLAN_PUT_TAG_defined
endif

ifneq (,$(shell grep vlan_rx_add_vid $(KSRC)/include/linux/netdevice.h | grep void))
	ccflags-y += -DNDO_VLAN_RX_ADD_VID_VOID
endif

ifeq (,$(shell grep -o "*rule_locs" $(KSRC)/include/linux/ethtool.h))
	ccflags-y += -DETHTOOL_RXNFC_OLD
endif

ifneq (,$(shell grep -o  cpumask_set_cpu_local_first $(KSRC)/include/linux/cpumask.h))
	ccflags-y += -DCPUMASK_SET_CPU_LOCAL_FIRST_defined
endif

ifneq (,$(shell grep -o  cpumask_var_t $(KSRC)/include/linux/cpumask.h))
	ccflags-y += -DCPUMASK_VAR_T_defined
endif

ifneq (,$(shell grep -o  dev_to_node $(KSRC)/include/linux/device.h))
	ccflags-y += -DDEV_TO_NODE_defined
endif

ifneq (,$(shell grep -o  irq_set_affinity_hint $(KSRC)/include/linux/interrupt.h))
	ccflags-y += -DIRQ_SET_AFFINITY_HINT_defined
endif

ifneq (,$(shell grep -s hwmon_device_register_with_groups $(KSRC)/include/linux/hwmon.h))
	ccflags-y += -DHWMON_DEV_REGISTER_WITH_GROUPS
endif

ifneq (,$(shell grep -s hwmon_device_register $(KSRC)/include/linux/hwmon.h | grep -o class_device))
	ccflags-y += -DHWMON_DEV_REGISTER_OLD
endif

ifneq (,$(shell grep -s "(*get_rxfh)" $(KSRC)/include/linux/ethtool.h))
	ccflags-y += -DETHTOOL_OPS_RSSH_defined
endif

ifneq (,$(shell grep -A2 "(*set_rxfh)" $(KSRC)/include/linux/ethtool.h | grep hfunc))
	ccflags-y += -DETHTOOL_OPS_RSSH_HFUNC_defined
endif

ifneq (,$(shell grep -s "(*set_rxfh)" $(KSRC)/include/linux/ethtool.h | grep "const u32"))
	ccflags-y += -DETHTOOL_OPS_RSSH_IS_NEW
endif

ifneq (,$(shell grep -s ether_addr_equal_64bits $(KSRC)/include/linux/etherdevice.h))
	ccflags-y += -DETHER_ADDR_EQUAL_64BITS_defined
endif

ifneq (,$(shell grep -s ether_addr_copy $(KSRC)/include/linux/etherdevice.h))
	ccflags-y += -DETHER_ADDR_COPY_defined
endif

ifneq (,$(shell grep -s eth_zero_addr $(KSRC)/include/linux/etherdevice.h))
	ccflags-y += -DETH_ZERO_ADDR_defined
endif

ifneq (,$(shell grep -s rcu_dereference_bh $(KSRC)/include/linux/rcupdate.h))
	ccflags-y += -DRCU_DEREFERENCE_BH_defined
endif

ifneq (,$(shell grep -s hlist_first_rcu $(KSRC)/include/linux/rculist.h))
	ccflags-y += -DHLIST_FIRST_RCU_defined
endif

ifneq (,$(shell grep -s hlist_entry_safe $(KSRC)/include/linux/list.h))
	ccflags-y += -DHLIST_ENTRY_SAFE_defined
endif

ifneq (,$(shell grep -s dma_zalloc_coherent $(KSRC)/include/linux/dma-mapping.h))
	ccflags-y += -DDMA_ZALLOC_COHERENT_defined
endif

ifneq (,$(shell grep -s "dev_printk" $(KSRC)/include/linux/device.h | grep "const char"))
	ccflags-y += -DDEV_PRINTK_IS_NEW
endif

ifneq (,$(shell grep -o __dev_uc_sync $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DDEV_UC_MC_SYNC_defined
endif

ifneq (,$(shell grep skb_inner_transport_offset $(KSRC)/include/linux/skbuff.h))
	ccflags-y += -DSKB_INNER_TRANSPORT_OFFSET_defined
endif

ifneq (,$(shell grep -o netif_addr_lock_bh $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DNETIF_ADDR_LOCK_BH_defined
endif

ifneq (,$(shell grep -o  ndo_set_vf_vlan_rh73 $(KSRC)/include/linux/netdevice.h))
       ccflags-y += -DNDO_SET_VF_VLAN_RH73_defined
endif

ifneq (,$(shell grep -o max_mtu $(KSRC)/include/linux/netdevice.h))
	ccflags-y += -DMAX_MTU_defined
endif

# ************* End header checks *****************

#ifeq ($(DRV_NAME),lpnic)
#	ccflags-y += -DLPNIC_DEFINED
#endif

#RETPOLINE_GCC=$(shell gcc -Q --target-help | grep -q mindirect-branch-register && echo 1 || echo 0)
#INBOX_RETPOLINE_THUNK_SUP = 0

#ifdef CONFIG_RETPOLINE
#        INBOX_RETPOLINE_THUNK_SUP = 1
#endif

#ifeq ($(RETPOLINE_GCC),1)
#ifeq ($(INBOX_RETPOLINE_THUNK_SUP),0)
#	ccflags-y += -DENABLE_RETPOLINE
#        ccflags-y += -mindirect-branch=thunk-inline -mindirect-branch-register
#endif
#endif
