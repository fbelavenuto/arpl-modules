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

#ifdef CLASS_DEVICE_defined
static ssize_t
flash_fw_store(struct class_device *dev, const char *buf, size_t len)
#else
static ssize_t
flash_fw_store(struct device *dev, struct device_attribute *attr,
	       const char *buf, size_t len)
#endif
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));
	char file_name[ETHTOOL_FLASH_MAX_FILENAME];
	int status;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	file_name[ETHTOOL_FLASH_MAX_FILENAME - 1] = 0;
	strncpy(file_name, buf, (ETHTOOL_FLASH_MAX_FILENAME - 1));

	/* Removing new-line char given by sysfs */
	file_name[strlen(file_name) - 1] = '\0';

	status = be_load_fw(adapter, file_name);
	if (!status)
		return len;
	else
		return status;
}

#ifndef ETHTOOL_OPS_CHANNELS_defined
#ifdef CLASS_DEVICE_defined
static ssize_t show_max_qs(struct class_device *dev, char *buf)
#else
static ssize_t show_max_qs(struct device *dev, struct device_attribute *attr,
			   char *buf)
#endif
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));

	return sprintf(buf, "%d\n", be_max_qp_irqs(adapter));
}

#ifdef CLASS_DEVICE_defined
static ssize_t show_num_qs(struct class_device *dev, char *buf)
#else
static ssize_t show_num_qs(struct device *dev, struct device_attribute *attr,
			   char *buf)
#endif
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));

	return sprintf(buf, "%d\n", min(adapter->num_tx_qs,
					adapter->num_rx_qs));
}

#ifdef CLASS_DEVICE_defined
static ssize_t set_num_qs(struct class_device *dev, const char *buf, size_t len)
#else
static ssize_t set_num_qs(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t len)
#endif
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));
	int num_qs, status;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	sscanf(buf, "%d", &num_qs);

	if (!num_qs || num_qs > be_max_qp_irqs(adapter))
		return -EINVAL;

	adapter->cfg_num_rx_irqs = num_qs;
	adapter->cfg_num_tx_irqs = num_qs;
	rtnl_lock();
	status = be_update_queues(adapter);
	rtnl_unlock();
	if (!status)
		return len;
	else
		return status;
}
#endif /* ETHTOOL_OPS_CHANNELS_defined */

#ifndef ETHTOOL_OPS_RSSH_defined
static int convert_string_to_hashkey(struct be_adapter *adapter, char *rss_hkey,
				     u32 key_size, const char *rss_hkey_string)
{
	u32 i = 0;
	int hex_byte, len;

	do {
		if (i > (key_size - 1)) {
			dev_err(&adapter->pdev->dev,
				"RSS hash key is longer than %u bytes\n",
				key_size);
			goto err;
		}

		if (sscanf(rss_hkey_string, "%2x%n", &hex_byte, &len) < 1 ||
		    len != 2) {
			dev_err(&adapter->pdev->dev,
				"Invalid RSS hash key format\n");
			goto err;
		}

		rss_hkey[i++] = hex_byte;
		rss_hkey_string += 2;

		if (*rss_hkey_string == ':') {
			rss_hkey_string++;
		} else if (*rss_hkey_string != '\0') {
			dev_err(&adapter->pdev->dev,
				"Invalid RSS hash key format\n");
			goto err;
		}

	} while (*rss_hkey_string);

	if (i != key_size) {
			dev_err(&adapter->pdev->dev,
				"RSS hash key is too short (%u < %u)\n",
				i, key_size);
		goto err;
	}

	return 0;
err:
	return -EINVAL;
}

static int parse_hkey(struct be_adapter *adapter,
		      char **rss_hkey, u32 key_size,
		      const char *rss_hkey_string)
{
	if (!key_size) {
		dev_err(&adapter->pdev->dev,
			"Cannot set RX flow hash configuration:\n"
			"Hash key setting not supported\n");
		return -ENOTSUPP;
	}

	*rss_hkey = kzalloc(key_size, GFP_KERNEL);
	if (!(*rss_hkey)) {
		dev_err(&adapter->pdev->dev,
			"Cannot allocate memory for RSS hash key");
		return -ENOMEM;
	}

	if (convert_string_to_hashkey(adapter, *rss_hkey, key_size,
				      rss_hkey_string)) {
		kfree(*rss_hkey);
		*rss_hkey = NULL;
		return -EINVAL;
	}
	return 0;
}

#ifdef CLASS_DEVICE_defined
static ssize_t be_set_hashkey(struct class_device *dev, const char *buf,
			      size_t len)
#else
static ssize_t be_set_hashkey(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t len)
#endif
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));
	char *hkey = NULL;
	int rc;

	rc = parse_hkey(adapter, &hkey, RSS_HASH_KEY_LEN, buf);
	if (rc)
		return rc;

	rc = be_cmd_rss_config(adapter, adapter->rss_info.rsstable,
			       adapter->rss_info.rss_flags,
			       RSS_INDIR_TABLE_LEN, hkey);
	if (rc) {
		adapter->rss_info.rss_flags = RSS_ENABLE_NONE;
		kfree(hkey);
		return -EIO;
	}
	memcpy(adapter->rss_info.rss_hkey, hkey, RSS_HASH_KEY_LEN);
	kfree(hkey);

	return len;
}

#define BE_RSS_HKEY_WITH_DELIMITER_LENGTH 120
#ifdef CLASS_DEVICE_defined
static ssize_t be_get_hashkey(struct class_device *dev, char *buf)
#else
static ssize_t be_get_hashkey(struct device *dev, struct device_attribute *attr,
			      char *buf)
#endif
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));
	u8 *rss_hkey = adapter->rss_info.rss_hkey;
	int i, j;

	if (!adapter->rss_info.rss_flags)
		return 0;

	for (i = 0, j = 0; i < RSS_HASH_KEY_LEN; i++, j += 3) {
		if (i == (RSS_HASH_KEY_LEN - 1))
			snprintf(buf + j, 4, "%02x\n", *(rss_hkey + i));
		else
			snprintf(buf + j, 4,  "%02x:", *(rss_hkey + i));
	}
	return BE_RSS_HKEY_WITH_DELIMITER_LENGTH;
}
#endif /* ETHTOOL_OPS_RSSH_defined */

#if !defined(ETHTOOL_SET_DUMP_defined)
#ifdef CLASS_DEVICE_defined
static ssize_t trigger_dump(struct class_device *dev, const char *buf,
			    size_t len)
#else
static ssize_t trigger_dump(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t len)
#endif
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));
	int flag, status;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (sscanf(buf, "%d", &flag) != 1 || flag != 1)
		return -EINVAL;

	if (!lancer_chip(adapter) ||
	    !check_privilege(adapter, MAX_PRIVILEGES))
		return -EOPNOTSUPP;

	status = lancer_initiate_dump(adapter);
	if (!status)
		return len;

	return be_cmd_status(status);
}

#ifdef CLASS_DEVICE_defined
static ssize_t delete_dump(struct class_device *dev, const char *buf,
			   size_t len)
#else
static ssize_t delete_dump(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t len)
#endif
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));
	int flag, status;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (sscanf(buf, "%d", &flag) != 1 || flag != 1)
		return -EINVAL;

	if (!lancer_chip(adapter) ||
	    !check_privilege(adapter, MAX_PRIVILEGES))
		return -EOPNOTSUPP;

	status = lancer_delete_dump(adapter);
	if (!status)
		return len;

	return be_cmd_status(status);
}
#endif /* ETHTOOL_SET_DUMP_defined */

#ifndef SRIOV_CONFIGURE_defined
static ssize_t sriov_totalvfs(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));

	return sprintf(buf, "%d\n", pci_sriov_get_totalvfs(adapter->pdev));
}

static ssize_t sriov_numvfs_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));

	return sprintf(buf, "%d\n", adapter->num_vfs);
}

static ssize_t sriov_numvfs_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct be_adapter *adapter =
		netdev_priv(container_of(dev, struct net_device, CLASS_DEV));
	int num_vfs, ret;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	sscanf(buf, "%d", &num_vfs);

	if (num_vfs > pci_sriov_get_totalvfs(adapter->pdev))
		return -ERANGE;

	if (num_vfs == adapter->num_vfs)
		return count;		/* no change */

	if (num_vfs == 0) {
		/* disable VFs */
		ret = be_pci_sriov_configure(adapter->pdev, 0);
		if (ret < 0)
			return ret;
		return count;
	}

	/* enable VFs */
	if (adapter->num_vfs) {
		dev_warn(&adapter->pdev->dev,
			 "%d VFs already enabled. Disable before enabling %d VFs",
			 adapter->num_vfs, num_vfs);
		return -EBUSY;
	}

	ret = be_pci_sriov_configure(adapter->pdev, num_vfs);
	if (ret < 0)
		return ret;

	if (ret != num_vfs)
		dev_warn(&adapter->pdev->dev,
			 "%d VFs requested; only %d enabled", num_vfs, ret);

	return count;
}
#endif /* SRIOV_CONFIGURE_defined */

#ifdef CLASS_DEVICE_defined
static CLASS_DEVICE_ATTR(flash_fw, S_IWUSR, NULL, flash_fw_store);
#ifndef ETHTOOL_OPS_CHANNELS_defined
static CLASS_DEVICE_ATTR(max_qs, S_IRUGO, show_max_qs, NULL);
static CLASS_DEVICE_ATTR(num_qs, S_IWUSR | S_IRUGO, show_num_qs, set_num_qs);
#endif /* ETHTOOL_OPS_CHANNELS_defined */
#if !defined(ETHTOOL_SET_DUMP_defined)
static CLASS_DEVICE_ATTR(trigger_dump, S_IWUSR, NULL, trigger_dump);
static CLASS_DEVICE_ATTR(delete_dump, S_IWUSR, NULL, delete_dump);
#endif /* ETHTOOL_SET_DUMP_defined */
#ifndef ETHTOOL_OPS_RSSH_defined
static CLASS_DEVICE_ATTR(rss_hashkey, S_IWUSR | S_IRUGO, be_get_hashkey,
			 be_set_hashkey);
#endif /* ETHTOOL_OPS_RSSH_defined */

static struct attribute *benet_attrs[] = {
	&class_device_attr_flash_fw.attr,
#ifndef ETHTOOL_OPS_CHANNELS_defined
	&class_device_attr_max_qs.attr,
	&class_device_attr_num_qs.attr,
#endif /* ETHTOOL_OPS_CHANNELS_defined */
#if !defined(ETHTOOL_SET_DUMP_defined)
	&class_device_attr_trigger_dump.attr,
	&class_device_attr_delete_dump.attr,
#endif /* ETHTOOL_SET_DUMP_defined */
#ifndef ETHTOOL_OPS_RSSH_defined
	&class_device_attr_rss_hashkey.attr,
#endif /* ETHTOOL_OPS_RSSH_defined */
	NULL,
};
#else /* !CLASS_DEVICE_defined */
static DEVICE_ATTR(flash_fw, S_IWUSR, NULL, flash_fw_store);
#ifndef ETHTOOL_OPS_CHANNELS_defined
static DEVICE_ATTR(max_qs, S_IRUGO, show_max_qs, NULL);
static DEVICE_ATTR(num_qs, S_IWUSR | S_IRUGO, show_num_qs, set_num_qs);
#endif /* ETHTOOL_OPS_CHANNELS_defined */
#if !defined(ETHTOOL_SET_DUMP_defined)
static DEVICE_ATTR(trigger_dump, S_IWUSR, NULL, trigger_dump);
static DEVICE_ATTR(delete_dump, S_IWUSR, NULL, delete_dump);
#endif /* ETHTOOL_SET_DUMP_defined */
#ifndef ETHTOOL_OPS_RSSH_defined
static DEVICE_ATTR(rss_hashkey, S_IWUSR | S_IRUGO, be_get_hashkey,
		   be_set_hashkey);
#endif /* ETHTOOL_OPS_RSSH_defined */

#ifndef SRIOV_CONFIGURE_defined
static DEVICE_ATTR(sriov_totalvfs, S_IRUGO, sriov_totalvfs, NULL);
static DEVICE_ATTR(sriov_numvfs, S_IWUSR | S_IRUGO, sriov_numvfs_show,
		   sriov_numvfs_store);
#endif /* SRIOV_CONFIGURE_defined */

static struct attribute *benet_attrs[] = {
	&dev_attr_flash_fw.attr,
#ifndef ETHTOOL_OPS_CHANNELS_defined
	&dev_attr_max_qs.attr,
	&dev_attr_num_qs.attr,
#endif /* ETHTOOL_OPS_CHANNELS_defined */
#if !defined(ETHTOOL_SET_DUMP_defined)
	&dev_attr_trigger_dump.attr,
	&dev_attr_delete_dump.attr,
#endif /* ETHTOOL_SET_DUMP_defined */
#ifndef ETHTOOL_OPS_RSSH_defined
	&dev_attr_rss_hashkey.attr,
#endif /* ETHTOOL_OPS_RSSH_defined */
#ifndef SRIOV_CONFIGURE_defined
	&dev_attr_sriov_totalvfs.attr,
	&dev_attr_sriov_numvfs.attr,
#endif /* SRIOV_CONFIGURE_defined */
	NULL,
};
#endif /* CLASS_DEVICE_defined */

static struct attribute_group benet_attr_group = {.attrs = benet_attrs };

void be_sysfs_create_group(struct be_adapter *adapter)
{
	int status;

	status = sysfs_create_group(&adapter->netdev->CLASS_DEV.kobj,
			&benet_attr_group);
	if (status)
		dev_err(&adapter->pdev->dev, "Could not create sysfs group\n");
}

void be_sysfs_remove_group(struct be_adapter *adapter)
{
	sysfs_remove_group(&adapter->netdev->CLASS_DEV.kobj, &benet_attr_group);
}
