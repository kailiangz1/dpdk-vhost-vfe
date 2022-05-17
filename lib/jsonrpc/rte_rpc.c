/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021, NVIDIA CORPORATION & AFFILIATES.
 */

/**
 * @file
 *
 * Device specific rpc lib
 */
#include "rte_rpc.h"

static struct rte_rpc_vdpa_global_ops rte_rpc_vdpa_ops;

void
rte_rpc_vdpa_global_ops_init(struct rte_rpc_vdpa_global_ops *ops)
{
	rte_rpc_vdpa_ops = (*ops);
}

/* Macros to check for invalid function pointers */
#define RTE_GLOBAL_FUNC_PTR_ERR_RET(func, retval) do { \
	if (rte_rpc_vdpa_ops.func == NULL) \
		return retval; \
} while (0)

int
rte_vdpa_pf_dev_add(const char *pf_name)
{
	RTE_GLOBAL_FUNC_PTR_ERR_RET(pf_dev_add, -ENOTSUP);

	return rte_rpc_vdpa_ops.pf_dev_add(pf_name);
}

int
rte_vdpa_pf_dev_remove(const char *pf_name)
{
	RTE_GLOBAL_FUNC_PTR_ERR_RET(pf_dev_remove, -ENOTSUP);

	return rte_rpc_vdpa_ops.pf_dev_remove(pf_name);
}

int
rte_vdpa_get_pf_list(struct vdpa_pf_info *pf_info, int max_pf_num)
{
	RTE_GLOBAL_FUNC_PTR_ERR_RET(get_pf_list, -ENOTSUP);

	return rte_rpc_vdpa_ops.get_pf_list(pf_info, max_pf_num);
}

int
rte_vdpa_pf_dev_vf_dev_add(const char *pf_name,
		struct vdpa_vf_info *vf_info)
{
	RTE_GLOBAL_FUNC_PTR_ERR_RET(pf_dev_vf_dev_add, -ENOTSUP);

	return rte_rpc_vdpa_ops.pf_dev_vf_dev_add(pf_name, vf_info);
}

int
rte_vdpa_pf_dev_vf_dev_remove(const char *pf_name, uint32_t vfid)
{
	RTE_GLOBAL_FUNC_PTR_ERR_RET(pf_dev_vf_dev_remove, -ENOTSUP);

	return rte_rpc_vdpa_ops.pf_dev_vf_dev_remove(pf_name, vfid);
}

int
rte_vdpa_get_vf_list(const char *pf_name, struct vdpa_vf_info *vf_info,
		int max_vf_num)
{
	RTE_GLOBAL_FUNC_PTR_ERR_RET(get_vf_list, -ENOTSUP);

	return rte_rpc_vdpa_ops.get_vf_list(pf_name, vf_info, max_vf_num);
}

int
rte_vdpa_get_vf_info(const char *pf_name, uint32_t vfid,
		struct vdpa_vf_info *vf_info)
{
	RTE_GLOBAL_FUNC_PTR_ERR_RET(get_vf_info, -ENOTSUP);

	return rte_rpc_vdpa_ops.get_vf_info(pf_name, vfid, vf_info);
}
