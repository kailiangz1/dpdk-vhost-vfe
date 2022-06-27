/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021, NVIDIA CORPORATION & AFFILIATES.
 */

/**
 * @file
 *
 * Device specific rpc lib
 */
#include "rte_vf_rpc.h"

int
rte_vdpa_vf_dev_prov(const char *vf_name, struct vdpa_vf_params *vf_params)
{
	/*To be added*/
	return 0;
}

int
rte_vdpa_vf_dev_add(const char *vf_name, struct vdpa_vf_params *vf_params)
{
	/*To be added*/
	return 0;
}

int
rte_vdpa_vf_dev_remove(const char *vf_name)
{
	/*To be added*/
	return 0;
}

int
rte_vdpa_get_vf_list(const char *pf_name, struct vdpa_vf_params *vf_info,
		int max_vf_num)
{
	/*To be added*/
	return 0;
}

int
rte_vdpa_get_vf_info(const char *vf_name, struct vdpa_vf_params *vf_info)
{
	/*To be added*/
	return 0;
}

#ifdef RTE_LIBRTE_VDPA_DEBUG
int
rte_vdpa_vf_dev_debug(const char *vf_name,
		struct vdpa_debug_vf_params *vf_debug_info)
{
	/*To be added*/
	return 0;
}
#endif
