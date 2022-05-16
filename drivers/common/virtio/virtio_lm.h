/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#ifndef _VIRTIO_LM_H_
#define _VIRTIO_LM_H_

#define VIRTIO_ARG_VDPA_PF       "mipf"

struct vdpa_pf_info_priv {
	struct rte_pci_addr pci_addr;
};

struct vdpa_vf_info_priv {
	struct rte_pci_addr pci_addr;
	uint32_t vfid;
	uint32_t msix_num;
	uint32_t queue_num;
	uint32_t queue_size;
	uint64_t features;
	uint32_t mtu;
	struct rte_ether_addr mac;
};

struct virtio_vdpa_pf_priv;
struct virtadmin_ctl;
struct virtio_admin_ctrl;
struct virtio_admin_data_ctrl;
struct virtio_vdpa_priv;

struct virtio_vdpa_mi_ops {
	struct virtio_vdpa_pf_priv *(*get_mi_by_bdf)(const char *bdf);

	int (*lm_cmd_resume)(struct virtio_vdpa_pf_priv *priv, int vdev_id,
			enum virtio_internal_status status);

	int (*lm_cmd_suspend)(struct virtio_vdpa_pf_priv *priv, int vdev_id,
			enum virtio_internal_status status);

	int (*lm_cmd_save_state)(struct virtio_vdpa_pf_priv *priv,
			uint16_t vdev_id, uint64_t offset, uint64_t length,
			rte_iova_t out_data, uint64_t out_data_len);

	int (*lm_cmd_restore_state)(struct virtio_vdpa_pf_priv *priv,
			uint16_t vdev_id, uint64_t offset, uint64_t length,
			rte_iova_t data);

	int (*lm_cmd_get_pending_bytes)(struct virtio_vdpa_pf_priv *priv,
			int vdev_id,
			rte_iova_t pending_bytes);
};

__rte_internal void
virtio_vdpa_register_mi_ops(struct virtio_vdpa_mi_ops *ops);

__rte_internal struct virtio_vdpa_pf_priv *
virtio_vdpa_get_mi_by_bdf(const char *bdf);

__rte_internal void
virtio_vdpa_get_pf_info(struct virtio_vdpa_pf_priv *priv,
		struct vdpa_pf_info_priv *pf_info);

__rte_internal void
virtio_vdpa_get_vf_info(struct virtio_vdpa_priv *priv,
		struct vdpa_vf_info_priv *vf_info);

__rte_internal bool
is_mi_pf(struct virtio_vdpa_priv *priv, struct virtio_vdpa_pf_priv *pf_priv);

/*
 * Dump a vdpa device
 * priv devic private data
 * buf buffer of information required by caller
 * return size of buffer consumed
 */
typedef int (*vdpa_dump_func_t)(void *priv, void *filter, void *buf);

__rte_internal int
virtio_vdpa_mi_list_dump(void *buf, int max_count, void *filter,
		vdpa_dump_func_t dump_func);
__rte_internal int
virtio_vdpa_dev_list_dump(void *buf, int max_count, void *filter,
		vdpa_dump_func_t dump_func);

#endif /* _VIRTIO_LM_H_ */
