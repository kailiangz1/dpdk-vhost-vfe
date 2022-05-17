/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021, NVIDIA CORPORATION & AFFILIATES.
 */

#ifndef _RTE_RPC_H_
#define _RTE_RPC_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 *
 * Device specific rpc lib
 */

#include <stdint.h>
#include <rte_dev.h>
#include <rte_ether.h>

struct vdpa_pf_info {
	char pf_name[RTE_DEV_NAME_MAX_LEN];
};

struct vdpa_vf_info {
	uint32_t vfid;
	char vf_name[RTE_DEV_NAME_MAX_LEN];
	uint32_t modify_flags;
	uint32_t msix_num;
	uint32_t queue_num;
	uint32_t queue_size;
	uint64_t features;
	uint32_t mtu;
	struct rte_ether_addr mac;
};

enum vdpa_vf_modify_flags {
	VDPA_VF_MSIX_NUM,
	VDPA_VF_QUEUE_NUM,
	VDPA_VF_QUEUE_SZIE,
	VDPA_VF_FEATURES,
	VDPA_VF_MTU,
	VDPA_VF_MAC,
};

struct rte_rpc_vdpa_global_ops {
	/** Add pf to system */
	int (*pf_dev_add)(const char *pf_name);

	/** Remove pf from system */
	int (*pf_dev_remove)(const char *pf_name);

	/** Get info of pfs */
	int (*get_pf_list)(struct vdpa_pf_info *pf_info, int max_pf_num);

	/** Add vf to system and associate with pf */
	int (*pf_dev_vf_dev_add)(const char *pf_name,
			struct vdpa_vf_info *vf_info);

	/** Remove vf from system */
	int (*pf_dev_vf_dev_remove)(const char *pf_name, uint32_t vfid);

	/** Get info of vfs under pf */
	int (*get_vf_list)(const char *pf_name,
		struct vdpa_vf_info *vf_info, int max_vf_num);

	/** Get info of vfs */
	int (*get_vf_info)(const char *pf_name, uint32_t vfid,
		struct vdpa_vf_info *vf_info);
};

void
rte_rpc_vdpa_global_ops_init(struct rte_rpc_vdpa_global_ops *ops);

int
rte_vdpa_pf_dev_add(const char *pf_name);

int
rte_vdpa_pf_dev_remove(const char *pf_name);

int
rte_vdpa_get_pf_list(struct vdpa_pf_info *pf_info, int max_pf_num);

int
rte_vdpa_pf_dev_vf_dev_add(const char *pf_name,
		struct vdpa_vf_info *vf_info);

int
rte_vdpa_pf_dev_vf_dev_remove(const char *pf_name, uint32_t vfid);

int
rte_vdpa_get_vf_list(const char *pf_name, struct vdpa_vf_info *vf_info,
		int max_vf_num);

int
rte_vdpa_get_vf_info(const char *pf_name, uint32_t vfid,
		struct vdpa_vf_info *vf_info);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_RPC_H_ */
