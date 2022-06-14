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
#include <rte_compat.h>
#include <rte_dev.h>
#include <rte_ether.h>

struct vdpa_pf_info {
	char pf_name[RTE_DEV_NAME_MAX_LEN];
};

struct vdpa_vf_params {
	char vf_name[RTE_DEV_NAME_MAX_LEN];
	uint32_t prov_flags;
	uint32_t msix_num;
	uint32_t queue_num;
	uint32_t queue_size;
	uint64_t features;
	uint32_t mtu;
	struct rte_ether_addr mac;
};

struct vdpa_vf_info {
	uint32_t vfid;
	struct vdpa_vf_params vf_params;
};

enum vdpa_vf_prov_flags {
	VDPA_VF_MSIX_NUM,
	VDPA_VF_QUEUE_NUM,
	VDPA_VF_QUEUE_SIZE,
	VDPA_VF_FEATURES,
	VDPA_VF_MTU,
	VDPA_VF_MAC,
};

#ifdef RTE_LIBRTE_VDPA_DEBUG
struct vdpa_debug_vf_info {
	uint32_t vfid;
	uint32_t test_type;
	uint32_t test_mode;
	uint64_t mem_size;
};
enum vdpa_vf_debug_test_type {
	VDPA_DEBUG_CMD_INVALID,
	VDPA_DEBUG_CMD_RUNNING = 1,
	VDPA_DEBUG_CMD_QUIESCED,
	VDPA_DEBUG_CMD_FREEZED,
	VDPA_DEBUG_CMD_START_LOGGING,
	VDPA_DEBUG_CMD_STOP_LOGGING,
	VDPA_DEBUG_CMD_MAX_INVALID,
};
#endif

struct rte_rpc_vdpa_global_ops {
	/** Add pf to system */
	int (*pf_dev_add)(const char *pf_name);

	/** Remove pf from system */
	int (*pf_dev_remove)(const char *pf_name);

	/** Get info of pfs */
	int (*get_pf_list)(struct vdpa_pf_info *pf_info, int max_pf_num);

	/** Add vf provision to system and associate with pf */
	int (*pf_dev_vf_dev_prov)(const char *pf_name, uint32_t vfid,
			struct vdpa_vf_params *vf_params);

	/** Add vf to system and associate with pf, vf_params maybe NULL */
	int (*pf_dev_vf_dev_add)(const char *pf_name, uint32_t vfid,
			struct vdpa_vf_params *vf_params);

	/** Remove vf from system */
	int (*pf_dev_vf_dev_remove)(const char *pf_name, uint32_t vfid);

	/** Get info of vfs under pf */
	int (*get_vf_list)(const char *pf_name,
		struct vdpa_vf_info *vf_info, int max_vf_num);

	/** Get info of vfs */
	int (*get_vf_info)(const char *pf_name, uint32_t vfid,
		struct vdpa_vf_info *vf_info);
#ifdef RTE_LIBRTE_VDPA_DEBUG
	/** debug vf */
	int (*debug_vf_info)(const char *pf_name,
		struct vdpa_debug_vf_info *vf_debug_info);
#endif
};

__rte_internal
void
rte_rpc_vdpa_global_ops_init(struct rte_rpc_vdpa_global_ops *ops);

int
rte_vdpa_pf_dev_add(const char *pf_name);

int
rte_vdpa_pf_dev_remove(const char *pf_name);

int
rte_vdpa_get_pf_list(struct vdpa_pf_info *pf_info, int max_pf_num);

int
rte_vdpa_pf_dev_vf_dev_prov(const char *pf_name, uint32_t vfid,
			struct vdpa_vf_params *vf_params);

int
rte_vdpa_pf_dev_vf_dev_add(const char *pf_name, uint32_t vfid,
			struct vdpa_vf_params *vf_params);

int
rte_vdpa_pf_dev_vf_dev_remove(const char *pf_name, uint32_t vfid);

int
rte_vdpa_get_vf_list(const char *pf_name, struct vdpa_vf_info *vf_info,
		int max_vf_num);

int
rte_vdpa_get_vf_info(const char *pf_name, uint32_t vfid,
		struct vdpa_vf_info *vf_info);

#ifdef RTE_LIBRTE_VDPA_DEBUG
int
rte_vdpa_vf_dev_debug(const char *pf_name,
		struct vdpa_debug_vf_info *vf_debug_info);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_RPC_H_ */
