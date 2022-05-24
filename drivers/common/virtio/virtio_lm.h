/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#ifndef _VIRTIO_LM_H_
#define _VIRTIO_LM_H_

#define VIRTIO_ARG_VDPA_PF       "mipf"

struct virtio_vdpa_pf_priv;

struct virtio_vdpa_mi_ops {
	struct virtio_vdpa_pf_priv *(*get_mi_by_bdf)(const char *bdf);
};

__rte_internal void
virtio_vdpa_register_mi_ops(struct virtio_vdpa_mi_ops *ops);

__rte_internal struct virtio_vdpa_pf_priv *
virtio_vdpa_get_mi_by_bdf(const char *bdf);

#endif /* _VIRTIO_LM_H_ */
