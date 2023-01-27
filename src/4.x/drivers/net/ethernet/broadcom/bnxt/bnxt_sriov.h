/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2014-2016 Broadcom Corporation
 * Copyright (c) 2016-2017 Broadcom Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#ifndef BNXT_SRIOV_H
#define BNXT_SRIOV_H

#ifdef HAVE_NDO_GET_VF_CONFIG
int bnxt_get_vf_config(struct net_device *, int, struct ifla_vf_info *);
int bnxt_set_vf_mac(struct net_device *, int, u8 *);
#ifdef NEW_NDO_SET_VF_VLAN
int bnxt_set_vf_vlan(struct net_device *, int, u16, u8, __be16);
#else
int bnxt_set_vf_vlan(struct net_device *, int, u16, u8);
#endif
#ifdef HAVE_IFLA_TX_RATE
int bnxt_set_vf_bw(struct net_device *, int, int, int);
#else
int bnxt_set_vf_bw(struct net_device *, int, int);
#endif
#ifdef HAVE_NDO_SET_VF_LINK_STATE
int bnxt_set_vf_link_state(struct net_device *, int, int);
#endif
#ifdef HAVE_VF_SPOOFCHK
int bnxt_set_vf_spoofchk(struct net_device *, int, bool);
#endif
#ifdef HAVE_NDO_SET_VF_TRUST
int bnxt_set_vf_trust(struct net_device *dev, int vf_id, bool trust);
#endif
#endif
int bnxt_sriov_configure(struct pci_dev *pdev, int num_vfs);
#ifndef PCIE_SRIOV_CONFIGURE
void bnxt_start_sriov(struct bnxt *, int);
void bnxt_sriov_init(unsigned int);
void bnxt_sriov_exit(void);
#endif
void bnxt_sriov_disable(struct bnxt *);
void bnxt_hwrm_exec_fwd_req(struct bnxt *);
void bnxt_update_vf_mac(struct bnxt *);
int bnxt_approve_mac(struct bnxt *, u8 *);
#endif
