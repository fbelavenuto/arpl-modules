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

#ifndef GET_NUM_DEF_RSS_defined
/**
 * netif_get_num_default_rss_queues - default number of RSS queues
 *
 * This routine should set an upper limit on the number of RSS queues
 * used by default by multiqueue devices.
 */
int netif_get_num_default_rss_queues(void)
{
	return DEFAULT_MAX_NUM_RSS_QUEUES;
}
#endif /* GET_NUM_DEF_RSS_defined */

#ifndef NETDEV_RSS_KEY_FILL_defined
void netdev_rss_key_fill(void *buffer, size_t len)
{
	u8 rss_hkey[RSS_HASH_KEY_LEN] = {0x7B, 0x4C, 0x2A, 0x46, 0xC1, 0x97,
	    0x77, 0x89, 0x79, 0x02, 0xC9, 0x93, 0x6F, 0x5d, 0x40, 0x5c, 0x12,
	    0xca, 0x86, 0x59, 0xe8, 0x8d, 0xfa, 0xc3, 0x3e, 0xbd, 0x1d, 0xac,
	    0x99, 0x0d, 0x31, 0x2a, 0x82, 0x58, 0xa1, 0x21, 0xad, 0x23, 0x81,
	    0xff};

	memcpy(buffer, rss_hkey, len);
}
#endif /* NETDEV_RSS_KEY_FILL_defined */

#ifndef PCI_SRIOV_SET_TOTALVFS_defined
int pci_sriov_get_totalvfs(struct pci_dev *pdev)
{
	struct be_adapter *adapter = pci_get_drvdata(pdev);
	u16 num = 0;
	int pos;

	if (adapter->drv_max_vfs != -1)
		return adapter->drv_max_vfs;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (pos)
		pci_read_config_word(pdev, pos + PCI_SRIOV_TOTAL_VF, &num);
	return num;
}

int pci_sriov_set_totalvfs(struct pci_dev *pdev, u16 numvfs)
{
	struct be_adapter *adapter = pci_get_drvdata(pdev);

	adapter->drv_max_vfs = numvfs;
	return 0;
}
#endif /* PCI_SRIOV_SET_TOTALVFS_defined */

void be_wait_for_vfs_detach(struct pci_dev *pdev)
{
#ifndef PCI_SRIOV_SET_TOTALVFS_defined
	if (pci_vfs_assigned(pdev))
		 dev_warn(&pdev->dev,
			  "Waiting to unload, until VFs are detached\n");
	while (1) {
		if (pci_vfs_assigned(pdev) == 0)
			break;

		msleep(1000);
	}
#endif
}

void be_update_xmit_trans_start(struct net_device *netdev, int i)
{
#ifdef TXQ_TRANS_UPDATE_defined
	if (netdev->features & NETIF_F_LLTX)
		netdev_get_tx_queue(netdev, i)->trans_start = jiffies;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
	netdev->trans_start = jiffies;
#endif
}

#ifdef CONFIG_PCI_IOV
int be_find_vfs(struct pci_dev *pdev, int vf_state)
{
	struct pci_dev *dev = pdev;
	int vfs = 0, assigned_vfs = 0, pos;

	if (!sriov_kernel)
		return 0;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;

	dev = pci_get_device(pdev->vendor, PCI_ANY_ID, NULL);
	while (dev) {
		if (dev->is_virtfn && pci_physfn(dev) == pdev) {
			vfs++;
			if (dev->dev_flags & PCI_DEV_FLAGS_ASSIGNED)
				assigned_vfs++;
		}
		dev = pci_get_device(pdev->vendor, PCI_ANY_ID, dev);
	}
	return (vf_state == ASSIGNED) ? assigned_vfs : vfs;
}

#ifndef PCI_VFS_ASSIGNED_defined
/**
 * pci_vfs_assigned - returns number of VFs are assigned to a guest
 * @dev: the PCI device
 *
 * Returns number of VFs belonging to this device that are assigned to a guest.
 * If device is not a physical function returns -ENODEV.
 */
int pci_vfs_assigned(struct pci_dev *pdev)
{
	return be_find_vfs(pdev, ASSIGNED);
}
#endif /* PCI_VFS_ASSIGNED_defined */
#ifndef PCI_NUM_VF_defined
/**
 * pci_num_vf - return number of VFs associated with a PF device_release_driver
 * @dev: the PCI device
 *
 * Returns number of VFs, or 0 if SR-IOV is not enabled.
 */
int pci_num_vf(struct pci_dev *pdev)
{
	return be_find_vfs(pdev, ENABLED);
}
#endif /* PCI_NUM_VF_defined */
#endif /* CONFIG_PCI_IOV */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
void be_netdev_ops_init(struct net_device *netdev, struct net_device_ops *ops)
{
	netdev->open = ops->ndo_open;
	netdev->stop = ops->ndo_stop;
	netdev->hard_start_xmit = ops->ndo_start_xmit;
	netdev->set_mac_address = ops->ndo_set_mac_address;
	netdev->get_stats = ops->ndo_get_stats;
	netdev->set_multicast_list = ops->ndo_set_rx_mode;
	netdev->change_mtu = ops->ndo_change_mtu;
	netdev->vlan_rx_register = ops->ndo_vlan_rx_register;
	netdev->vlan_rx_add_vid = ops->ndo_vlan_rx_add_vid;
	netdev->vlan_rx_kill_vid = ops->ndo_vlan_rx_kill_vid;
	netdev->do_ioctl = ops->ndo_do_ioctl;
#ifdef CONFIG_NET_POLL_CONTROLLER
	netdev->poll_controller = ops->ndo_poll_controller;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
	netdev->select_queue = ops->ndo_select_queue;
#endif
}
#endif

/* New NAPI backport */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)

int be_poll_compat(struct net_device *netdev, int *budget)
{
	struct napi_struct *napi = netdev->priv;
	u32 work_done, can_do;

	can_do = min(*budget, netdev->quota);
	work_done = napi->poll(napi, can_do);

	*budget -= work_done;
	netdev->quota -= work_done;
	return (work_done >= can_do);
}

void netif_napi_add_compat(struct net_device *netdev,
		struct napi_struct *napi,
		int (*poll) (struct napi_struct *, int), int weight)
{
	struct net_device *nd;

	nd = alloc_netdev(0, "", ether_setup);
	if (!nd)
		return;
	nd->priv = napi;
	nd->weight = BE_NAPI_WEIGHT;
	nd->poll = be_poll_compat;
	set_bit(__LINK_STATE_START, &nd->state);
	napi->poll = poll;
	napi->dev = nd;
#ifdef RHEL
	napi->napi.dev = netdev;
#endif
}

void netif_napi_del_compat(struct napi_struct *napi)
{
	if (napi->dev) {
		free_netdev(napi->dev);
		napi->dev = NULL;
	}
}
#endif /* New NAPI backport */

#ifndef CPUMASK_SET_CPU_LOCAL_FIRST_defined
#ifdef CPUMASK_VAR_T_defined
int cpumask_set_cpu_local_first(int i, int numa_node, cpumask_t *dstp)
{
	cpumask_var_t mask;
	int cpu;
	int ret = 0;

	if (!zalloc_cpumask_var(&mask, GFP_KERNEL))
		return -ENOMEM;

	i %= num_online_cpus();

	if (!cpumask_of_node(numa_node)) {
		/* Use all online cpu's for non numa aware system */
		cpumask_copy(mask, cpu_online_mask);
	} else {
		int n;

		cpumask_and(mask,
			    cpumask_of_node(numa_node), cpu_online_mask);

		n = cpumask_weight(mask);
		if (i >= n) {
			i -= n;

			/* If index > number of local cpu's, mask out local
			 * cpu's
			 */
			cpumask_andnot(mask, cpu_online_mask, mask);
		}
	}

	for_each_cpu(cpu, mask) {
		if (--i < 0)
			goto out;
	}

	ret = -EAGAIN;

out:
	free_cpumask_var(mask);

	if (!ret)
		cpumask_set_cpu(cpu, dstp);

	return ret;
}
#else
int cpumask_set_cpu_local_first(int i, int numa_node, cpumask_t *dstp)
{
	i %= num_online_cpus();

	if (cpu_online(i))
		cpu_set(i, *dstp);
	return 0;
}
#endif /* CPUMASK_VAR_T_defined */
#endif /* CPUMASK_SET_CPU_LOCAL_FIRST_defined */

#ifndef CPUMASK_VAR_T_defined
bool zalloc_cpumask_var(cpumask_t **mask, gfp_t flags)
{
	*mask = kmalloc(sizeof(cpumask_t), flags | __GFP_ZERO);
	return *mask != NULL;
}

void free_cpumask_var(cpumask_t *mask)
{
	kfree(mask);
}
#endif

#ifndef HWMON_DEV_REGISTER_WITH_GROUPS
extern ssize_t be_hwmon_show_temp(struct device *dev,
				  struct device_attribute *dev_attr,
				  char *buf);

static ssize_t be_show_name(struct device *dev,
			    struct device_attribute *devattr,
			    char *buf)
{
	return sprintf(buf, "%s\n", DRV_NAME);
}

static SENSOR_DEVICE_ATTR(name, S_IRUGO, be_show_name, NULL, 0);

static SENSOR_DEVICE_ATTR(temp1_input, S_IRUGO,
			  be_hwmon_show_temp, NULL, 1);

static struct attribute *be_hwmon_attrs[] = {
	&sensor_dev_attr_name.dev_attr.attr,
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	NULL
};

ATTRIBUTE_GROUPS(be_hwmon);

hwmon_dev_return_t
devm_hwmon_device_register_groups_compat(struct device *dev,
					 const char *name,
					 void *drvdata,
					 const struct attribute_group **groups)
{
	struct be_adapter *adapter = (struct be_adapter *)drvdata;
	int err;

	err = sysfs_create_group(&dev->kobj, *be_hwmon_groups);
	if (err)
		return NULL;

	adapter->hwmon_info.hwmon_dev = hwmon_device_register(dev);
	if (IS_ERR(adapter->hwmon_info.hwmon_dev))
		sysfs_remove_group(&dev->kobj, *be_hwmon_groups);

	return adapter->hwmon_info.hwmon_dev;
}

void devm_hwmon_device_unregister_compat(void *hwmon_dev)
{
#ifdef HWMON_DEV_REGISTER_OLD
	struct class_device *hdev = (struct class_device *)hwmon_dev;
	struct device *dev = hdev->dev;
#else
	struct device *hdev = (struct device *)hwmon_dev;
	struct device *dev = hdev->parent;
#endif

	if (hdev) {
		hwmon_device_unregister(hdev);
		sysfs_remove_group(&dev->kobj, *be_hwmon_groups);
	}
}
#endif

#ifndef DEV_UC_MC_SYNC_defined

int __dev_uc_sync(struct net_device *dev,
		  int (*sync)(struct net_device *, const unsigned char *),
		  int (*unsync)(struct net_device *, const unsigned char *))
{
	struct be_adapter *adapter = netdev_priv(dev);

#ifdef	NETDEV_UC_defined
	u8 *uc_list = adapter->uc_list;
	struct netdev_hw_addr *ha;
	int i, j;

	if (netdev_uc_count(dev) != adapter->uc_macs) {
		adapter->update_uc_list = true;
		goto done;
	}

	adapter->update_uc_list = false;
	netdev_for_each_uc_addr(ha, dev) {
		for (i = 0, j = 0; j < adapter->uc_macs; i += ETH_ALEN, j++) {
			if (ether_addr_equal(uc_list + i, ha->addr))
				break;
		}
		if (j >= adapter->uc_macs) {
		/* Couldn't find this stack entry in our list; stop further
		 * search
		 */
			adapter->update_uc_list = true;
			break;
		}
	}

done:
#else
	adapter->update_uc_list = true;
#endif
	return 0;
}

void __dev_uc_unsync(struct net_device *dev,
		     int (*unsync)(struct net_device *, const unsigned char *))
{
}

int __dev_mc_sync(struct net_device *dev,
		  int (*sync)(struct net_device *, const unsigned char *),
		  int (*unsync)(struct net_device *, const unsigned char *))
{
	struct be_adapter *adapter = netdev_priv(dev);
	u8 *mc_list = adapter->mc_list;
	struct dev_mc_list *ha;
	int i, j;

	if (netdev_mc_count(dev) != adapter->mc_count) {
		adapter->update_mc_list = true;
		goto done;
	}

	adapter->update_mc_list = false;
	netdev_for_each_mc_addr(ha, dev) {
		for (i = 0, j = 0; j < adapter->mc_count; i += ETH_ALEN, j++) {
			if (ether_addr_equal(mc_list + i, ha->DMI_ADDR))
				break;
		}
		if ( j >= adapter->mc_count) {
		/* Couldn't find this stack entry in our list; stop further
		 * search
		 */
			adapter->update_mc_list = true;
			break;
		}
	}
done:
	return 0;
}

void __dev_mc_unsync(struct net_device *dev,
		     int (*unsync)(struct net_device *, const unsigned char *))
{
}

#endif
