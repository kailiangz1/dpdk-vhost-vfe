/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#ifndef _VIRTIO_VDPA_LM_H_
#define _VIRTIO_VDPA_LM_H_
#include <virtio_lm.h>

struct virtio_vdpa_pf_priv *
virtio_vdpa_get_mi_by_bdf(const char *bdf);

void
virtio_vdpa_get_pf_info(struct virtio_vdpa_pf_priv *priv,
		struct vdpa_pf_info_priv *pf_info);

int
virtio_vdpa_mi_list_dump(void *buf, int max_count, void *filter,
		vdpa_dump_func_t dump_func);

#ifdef RTE_LIBRTE_VDPA_DEBUG
struct vdpa_debug_info {
	uint32_t vfid;
	uint32_t page_size;
	enum virtio_dirty_track_mode track_mode;
	uint64_t range_addr;
	uint64_t range_length;
	int num_sges;
	struct virtio_sge data[32];
};

int
virtio_vdpa_debug(struct virtio_vdpa_pf_priv *priv, uint32_t cmd,
		struct vdpa_debug_info* info);
#endif

#endif /* _VIRTIO_VDPA_LM_H_ */

