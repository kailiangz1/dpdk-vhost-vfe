/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */
#ifdef RTE_EXEC_ENV_LINUX
 #include <dirent.h>
 #include <fcntl.h>
#endif

#include <rte_io.h>
#include <rte_bus.h>

#include "virtio_pci.h"
#include "virtio_logs.h"
#include "virtqueue.h"
#include "virtio_admin.h"
#include "virtio_pci_state.h"

struct virtio_net_dev_state {
	struct virtio_dev_common_state common_state;
	struct virtio_net_config net_dev_cfg;
	struct virtio_dev_queue_info q_info[];
} __rte_packed;

static uint16_t
modern_net_get_queue_num(struct virtio_hw *hw)
{
	uint16_t nr_vq;

	if (virtio_dev_with_feature(hw, VIRTIO_NET_F_MQ) ||
			virtio_dev_with_feature(hw, VIRTIO_NET_F_RSS)) {
		VIRTIO_OPS(hw)->read_dev_cfg(hw,
			offsetof(struct virtio_net_config, max_virtqueue_pairs),
			&hw->max_queue_pairs,
			sizeof(hw->max_queue_pairs));
	} else {
		PMD_INIT_LOG(DEBUG,
				 "Neither VIRTIO_NET_F_MQ nor VIRTIO_NET_F_RSS are supported");
		hw->max_queue_pairs = 1;
	}

	nr_vq = hw->max_queue_pairs * 2;
	if (virtio_dev_with_feature(hw, VIRTIO_NET_F_CTRL_VQ))
		nr_vq += 1;
	if (virtio_dev_with_feature(hw, VIRTIO_F_ADMIN_VQ))
		nr_vq += 1;

	PMD_INIT_LOG(DEBUG, "Virtio net nr_vq is %d", nr_vq);
	return nr_vq;

}

static uint16_t
modern_net_get_dev_cfg_size(void)
{
	return sizeof(struct virtio_net_config);
}

static void *
modern_net_get_queue_offset(void *state)
{
	struct virtio_net_dev_state *state_net = state;

	return state_net->q_info;
}

static uint32_t
modern_net_get_state_size(uint16_t num_queues)
{
	return sizeof(struct virtio_net_config) + sizeof(struct virtio_dev_common_state) +
			num_queues * sizeof(struct virtio_dev_queue_info);
}

const struct virtio_dev_specific_ops virtio_net_dev_pci_modern_ops = {
	.get_queue_num = modern_net_get_queue_num,
	.get_dev_cfg_size = modern_net_get_dev_cfg_size,
	.get_queue_offset = modern_net_get_queue_offset,
	.get_state_size = modern_net_get_state_size,
};
