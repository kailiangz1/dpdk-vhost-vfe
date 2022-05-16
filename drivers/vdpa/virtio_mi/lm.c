/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_bus_pci.h>
#include <rte_vfio.h>
#include <rte_kvargs.h>
#include <rte_eal_paging.h>

#include <virtio_api.h>
#include <virtqueue.h>
#include <virtio_admin.h>
#include <virtio_lm.h>

#define VIRTIO_VDPA_MI_SUPPORTED_FEATURE (1ULL << VIRTIO_F_ADMIN_VQ)

struct virtio_vdpa_pf_priv {
	TAILQ_ENTRY(virtio_vdpa_pf_priv) next;
	struct rte_pci_device *pdev;
	struct virtio_pci_dev *vpdev;
	uint64_t guest_features;
	int vfio_dev_fd;
	uint16_t hw_nr_virtqs; /* number of vq device supported*/
};

struct virtio_admin_data_ctrl{
	bool have_in_data;
	rte_iova_t in_data;
	uint64_t in_data_len;
	bool have_out_data;
	rte_iova_t out_data;
	uint64_t out_data_len;
};

RTE_LOG_REGISTER(virtio_vdpa_mi_logtype, pmd.vdpa.virtio, NOTICE);
#define DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, virtio_vdpa_mi_logtype, \
		"VIRTIO VDPA MI %s(): " fmt "\n", __func__, ##args)

RTE_LOG_REGISTER(virtio_vdpa_cmd_logtype, pmd.vdpa.virtio, NOTICE);
#define CMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, virtio_vdpa_cmd_logtype, \
		"VIRTIO VDPA CMD %s(): " fmt "\n", __func__, ##args)

TAILQ_HEAD(virtio_vdpa_mi_privs, virtio_vdpa_pf_priv) virtio_mi_priv_list =
						TAILQ_HEAD_INITIALIZER(virtio_mi_priv_list);
static pthread_mutex_t mi_priv_list_lock = PTHREAD_MUTEX_INITIALIZER;

struct virtio_vdpa_pf_priv *
virtio_vdpa_get_mi_by_bdf(const char *bdf)
{
	struct virtio_vdpa_pf_priv *priv;
	struct rte_pci_addr dev_addr;
	int found = 0;

	if (rte_pci_addr_parse(bdf, &dev_addr))
		return NULL;

	pthread_mutex_lock(&mi_priv_list_lock);
	TAILQ_FOREACH(priv, &virtio_mi_priv_list, next) {
		if (!rte_pci_addr_cmp(&priv->pdev->addr, &dev_addr)) {
			found = 1;
			break;
		}
	}
	pthread_mutex_unlock(&mi_priv_list_lock);

	if (found)
		return priv;
	return NULL;
}

void
virtio_vdpa_get_pf_info(struct virtio_vdpa_pf_priv *priv,
		struct vdpa_pf_info_priv *pf_info)
{
	pf_info->pci_addr = priv->pdev->addr;
}

static struct virtio_admin_ctrl *
virtio_vdpa_send_admin_command_split(struct virtadmin_ctl *avq,
		struct virtio_admin_ctrl *ctrl,
		struct virtio_admin_data_ctrl *dat_ctrl,
		int *dlen, int pkt_num)
{
	struct virtqueue *vq = virtnet_aq_to_vq(avq);
	struct virtio_admin_ctrl *result;
	uint32_t head, i;
	int k, sum = 0;

	head = vq->vq_desc_head_idx;

	/*
	 * Format is enforced in qemu code:
	 * One TX packet for header;
	 * At least one TX packet per argument;
	 * One RX packet for ACK.
	 */
	vq->vq_split.ring.desc[head].flags = VRING_DESC_F_NEXT;
	vq->vq_split.ring.desc[head].addr = avq->virtio_admin_hdr_mem;
	vq->vq_split.ring.desc[head].len = sizeof(struct virtio_admin_ctrl_hdr);
	vq->vq_free_cnt--;
	i = vq->vq_split.ring.desc[head].next;

	for (k = 0; k < pkt_num; k++) {
		vq->vq_split.ring.desc[i].flags = VRING_DESC_F_NEXT;
		vq->vq_split.ring.desc[i].addr = avq->virtio_admin_hdr_mem
			+ sizeof(struct virtio_admin_ctrl_hdr)
			+ sizeof(ctrl->status) + sizeof(uint8_t)*sum;
		vq->vq_split.ring.desc[i].len = dlen[k];
		sum += dlen[k];
		vq->vq_free_cnt--;
		i = vq->vq_split.ring.desc[i].next;
	}

	if (dat_ctrl->have_in_data) {
		vq->vq_split.ring.desc[i].flags = VRING_DESC_F_NEXT;
		vq->vq_split.ring.desc[i].addr = dat_ctrl->in_data;
		vq->vq_split.ring.desc[i].len = dat_ctrl->in_data_len;
		vq->vq_free_cnt--;
		i = vq->vq_split.ring.desc[i].next;
	}

	if (dat_ctrl->have_out_data) {
		vq->vq_split.ring.desc[i].flags = VRING_DESC_F_WRITE | VRING_DESC_F_NEXT;
		vq->vq_split.ring.desc[i].addr = dat_ctrl->out_data;
		vq->vq_split.ring.desc[i].len = dat_ctrl->out_data_len;
		vq->vq_free_cnt--;
		i = vq->vq_split.ring.desc[i].next;
	}

	vq->vq_split.ring.desc[i].flags = VRING_DESC_F_WRITE;
	vq->vq_split.ring.desc[i].addr = avq->virtio_admin_hdr_mem
			+ sizeof(struct virtio_admin_ctrl_hdr);
	vq->vq_split.ring.desc[i].len = sizeof(ctrl->status);
	vq->vq_free_cnt--;

	vq->vq_desc_head_idx = vq->vq_split.ring.desc[i].next;

	vq_update_avail_ring(vq, head);
	vq_update_avail_idx(vq);

	virtqueue_notify(vq);

	while (virtqueue_nused(vq) == 0) {
		usleep(100);
	}

	while (virtqueue_nused(vq)) {
		uint32_t idx, desc_idx, used_idx;
		struct vring_used_elem *uep;

		used_idx = (uint32_t)(vq->vq_used_cons_idx
				& (vq->vq_nentries - 1));
		uep = &vq->vq_split.ring.used->ring[used_idx];
		idx = (uint32_t) uep->id;
		desc_idx = idx;

		while (vq->vq_split.ring.desc[desc_idx].flags &
		       VRING_DESC_F_NEXT) {
			desc_idx = vq->vq_split.ring.desc[desc_idx].next;
			vq->vq_free_cnt++;
		}

		vq->vq_split.ring.desc[desc_idx].next = vq->vq_desc_head_idx;
		vq->vq_desc_head_idx = idx;

		vq->vq_used_cons_idx++;
		vq->vq_free_cnt++;
	}

	DRV_LOG(DEBUG, "vq->vq_free_cnt=%d\nvq->vq_desc_head_idx=%d",
			vq->vq_free_cnt, vq->vq_desc_head_idx);

	result = avq->virtio_admin_hdr_mz->addr;
	return result;
}

static int
virtio_vdpa_send_admin_command(struct virtadmin_ctl *avq,
		struct virtio_admin_ctrl *ctrl,
		struct virtio_admin_data_ctrl *dat_ctrl,
		int *dlen,
		int pkt_num)
{
	virtio_admin_ctrl_ack status = ~0;
	struct virtio_admin_ctrl *result;
	struct virtqueue *vq;

	ctrl->status = status;

	if (!avq) {
		DRV_LOG(ERR, "Admin queue is not supported");
		return -1;
	}

	rte_spinlock_lock(&avq->lock);
	vq = virtnet_aq_to_vq(avq);

	DRV_LOG(DEBUG, "vq->vq_desc_head_idx = %d, status = %d, "
		"vq->hw->avq = %p vq = %p",
		vq->vq_desc_head_idx, status, vq->hw->avq, vq);

	if (vq->vq_free_cnt < pkt_num + 2 || pkt_num < 1) {
		rte_spinlock_unlock(&avq->lock);
		return -1;
	}

	result = virtio_vdpa_send_admin_command_split(avq, ctrl, dat_ctrl,
			dlen, pkt_num);

	rte_spinlock_unlock(&avq->lock);
	return result->status;
}

static int
virtio_vdpa_cmd_set_status(struct virtio_hw *hw, int vdev_id,
		enum virtio_internal_status status)
{
	struct virtio_admin_migration_modify_internal_status_data *sd;
	struct virtio_admin_data_ctrl dat_ctrl;
	struct virtio_admin_ctrl *ctrl;
	int dlen[1];
	int ret;

	ctrl = virtnet_get_aq_hdr_addr(hw->avq);
	ctrl->hdr.class = VIRTIO_ADMIN_PCI_MIGRATION_CTRL;
	ctrl->hdr.cmd = VIRTIO_ADMIN_PCI_MIGRATION_MODIFY_INTERNAL_STATUS;
	sd = (struct virtio_admin_migration_modify_internal_status_data *)&ctrl->data[0];
	sd->vdev_id = rte_cpu_to_le_16(vdev_id);
	sd->internal_status = rte_cpu_to_le_16((uint16_t)status);
	dlen[0] = sizeof(*sd);
	dat_ctrl.have_in_data = false;
	dat_ctrl.have_out_data = false;

	ret = virtio_vdpa_send_admin_command(hw->avq, ctrl, &dat_ctrl, dlen, 1);
	if (ret) {
		CMD_LOG(ERR, "Failed to change device %u status to %d, cmd status %d",
				vdev_id, status, ret);
		return -EAGAIN;
	}

	return 0;
}

static int
virtio_vdpa_cmd_resume(struct virtio_vdpa_pf_priv *priv, int vdev_id,
		enum virtio_internal_status status)
{
	struct virtio_hw *hw = &priv->vpdev->hw;

	if (status != VIRTIO_S_QUIESCED && status != VIRTIO_S_RUNNING)
		return -EINVAL;

	if (!virtio_with_feature(hw, VIRTIO_F_ADMIN_VQ)) {
		CMD_LOG(INFO, "host does not support admin queue");
		return -ENOTSUP;
	}

	return virtio_vdpa_cmd_set_status(hw, vdev_id, status);
}

static int
virtio_vdpa_cmd_suspend(struct virtio_vdpa_pf_priv *priv, int vdev_id,
		enum virtio_internal_status status)
{
	struct virtio_hw *hw = &priv->vpdev->hw;

	if (status != VIRTIO_S_QUIESCED && status != VIRTIO_S_FREEZED)
		return -EINVAL;

	if (!virtio_with_feature(hw, VIRTIO_F_ADMIN_VQ)) {
		CMD_LOG(INFO, "host does not support admin queue");
		return -ENOTSUP;
	}

	return virtio_vdpa_cmd_set_status(hw, vdev_id, status);
}

static int
virtio_vdpa_cmd_save_state(struct virtio_vdpa_pf_priv *priv,
		uint16_t vdev_id, uint64_t offset, uint64_t length,
		rte_iova_t out_data, uint64_t out_data_len)
{
	struct virtio_admin_migration_save_internal_state_data *sd;
	struct virtio_hw *hw = &priv->vpdev->hw;
	struct virtio_admin_data_ctrl dat_ctrl;
	struct virtio_admin_ctrl *ctrl;
	int dlen[1];
	int ret;

	if (!virtio_with_feature(hw, VIRTIO_F_ADMIN_VQ)) {
		CMD_LOG(INFO, "host does not support admin queue");
		return -ENOTSUP;
	}

	ctrl = virtnet_get_aq_hdr_addr(hw->avq);
	ctrl->hdr.class = VIRTIO_ADMIN_PCI_MIGRATION_CTRL;
	ctrl->hdr.cmd = VIRTIO_ADMIN_PCI_MIGRATION_SAVE_INTERNAL_STATE;
	sd = (struct virtio_admin_migration_save_internal_state_data *)&ctrl->data[0];
	sd->vdev_id = rte_cpu_to_le_16(vdev_id);
	sd->offset = rte_cpu_to_le_64(offset);
	sd->length = rte_cpu_to_le_64(length);
	dlen[0] = sizeof(*sd);
	dat_ctrl.have_in_data = false;
	dat_ctrl.have_out_data = true;
	dat_ctrl.out_data = out_data;
	dat_ctrl.out_data_len = out_data_len;
	ret = virtio_vdpa_send_admin_command(hw->avq, ctrl, &dat_ctrl, dlen, 1);
	if (ret) {
		CMD_LOG(ERR, "Failed to save device %u state, cmd status %d",
				vdev_id, ret);
		return -EAGAIN;
	}

	return 0;
}

static int
virtio_vdpa_cmd_restore_state(struct virtio_vdpa_pf_priv *priv,
		uint16_t vdev_id, uint64_t offset, uint64_t length,
		rte_iova_t data)
{
	struct virtio_admin_migration_restore_internal_state_data *sd;
	struct virtio_hw *hw = &priv->vpdev->hw;
	struct virtio_admin_data_ctrl dat_ctrl;
	struct virtio_admin_ctrl *ctrl;
	int dlen[1];
	int ret;

	if (!virtio_with_feature(hw, VIRTIO_F_ADMIN_VQ)) {
		CMD_LOG(INFO, "host does not support admin queue");
		return -ENOTSUP;
	}

	ctrl = virtnet_get_aq_hdr_addr(hw->avq);
	ctrl->hdr.class = VIRTIO_ADMIN_PCI_MIGRATION_CTRL;
	ctrl->hdr.cmd = VIRTIO_ADMIN_PCI_MIGRATION_RESTORE_INTERNAL_STATE;
	sd = (struct virtio_admin_migration_restore_internal_state_data *)&ctrl->data[0];
	sd->vdev_id = rte_cpu_to_le_16(vdev_id);
	sd->offset = rte_cpu_to_le_64(offset);
	sd->length = rte_cpu_to_le_64(length);
	dlen[0] = sizeof(*sd);
	dat_ctrl.have_in_data = true;
	dat_ctrl.have_out_data = false;
	dat_ctrl.in_data = data;
	dat_ctrl.in_data_len = length;
	ret = virtio_vdpa_send_admin_command(hw->avq, ctrl, &dat_ctrl, dlen, 1);
	if (ret) {
		CMD_LOG(ERR, "Failed to save device %u state, cmd status %d",
				vdev_id, ret);
		return -EAGAIN;
	}

	return 0;
}

static int
virtio_vdpa_cmd_get_pending_bytes(struct virtio_vdpa_pf_priv *priv,
		int vdev_id,
		rte_iova_t pending_bytes)
{
	struct virtio_admin_migration_get_internal_state_pending_bytes_data *sd;
	struct virtio_hw *hw = &priv->vpdev->hw;
	struct virtio_admin_data_ctrl dat_ctrl;
	struct virtio_admin_ctrl *ctrl;
	int dlen[1];
	int ret;

	if (!virtio_with_feature(hw, VIRTIO_F_ADMIN_VQ)) {
		CMD_LOG(INFO, "host does not support admin queue");
		return -ENOTSUP;
	}

	ctrl = virtnet_get_aq_hdr_addr(hw->avq);
	ctrl->hdr.class = VIRTIO_ADMIN_PCI_MIGRATION_CTRL;
	ctrl->hdr.cmd = VIRTIO_ADMIN_PCI_MIGRATION_GET_INTERNAL_STATE_PENDING_BYTES;
	sd = (struct virtio_admin_migration_get_internal_state_pending_bytes_data *)&ctrl->data[0];
	sd->vdev_id = rte_cpu_to_le_16(vdev_id);
	dlen[0] = sizeof(*sd);

	dat_ctrl.have_in_data = false;
	dat_ctrl.have_out_data = true;
	dat_ctrl.out_data = pending_bytes;
	dat_ctrl.out_data_len = sizeof(uint64_t);
	ret = virtio_vdpa_send_admin_command(hw->avq, ctrl, &dat_ctrl, dlen, 1);
	if (ret) {
		CMD_LOG(ERR, "Failed to get pending bytes for vdev %u, cmd status %d",
				vdev_id, ret);
		return -EAGAIN;
	}

	return 0;
}

static void
virtio_vdpa_init_vring(struct virtqueue *vq)
{
	uint8_t *ring_mem = vq->vq_ring_virt_mem;
	int size = vq->vq_nentries;
	struct vring *vr;

	DRV_LOG(DEBUG, ">>");

	memset(ring_mem, 0, vq->vq_ring_size);

	vq->vq_used_cons_idx = 0;
	vq->vq_desc_head_idx = 0;
	vq->vq_avail_idx = 0;
	vq->vq_desc_tail_idx = (uint16_t)(vq->vq_nentries - 1);
	vq->vq_free_cnt = vq->vq_nentries;
	memset(vq->vq_descx, 0, sizeof(struct vq_desc_extra) * vq->vq_nentries);
	vr = &vq->vq_split.ring;

	vring_init_split(vr, ring_mem, VIRTIO_VRING_ALIGN, size);
	vring_desc_init_split(vr->desc, size);
	/*
	 * Disable device(host) interrupting guest
	 */
	virtqueue_disable_intr_split(vq);
}

static void
virtio_vdpa_destroy_aq_ctl(struct virtadmin_ctl *ctl)
{
	rte_memzone_free(ctl->mz);
	rte_memzone_free(ctl->virtio_admin_hdr_mz);
}

/* Todo: queue size */
#define VPDA_ADMIN_QUEUE_SIZE			64
static int
virtio_vdpa_init_admin_queue(struct virtio_vdpa_pf_priv *priv, uint16_t queue_idx)
{
	const struct rte_memzone *mz = NULL, *hdr_mz = NULL;
	int numa_node = priv->pdev->device.numa_node;
	unsigned int vq_size = VPDA_ADMIN_QUEUE_SIZE;
	struct virtio_pci_dev *vpdev = priv->vpdev;
	struct virtio_pci_dev_vring_info vr_info;
	char vq_hdr_name[VIRTQUEUE_MAX_NAME_SZ];
	char vq_name[VIRTQUEUE_MAX_NAME_SZ];
	struct virtio_hw *hw = &vpdev->hw;
	struct virtadmin_ctl *avq = NULL;
	struct virtqueue *vq;
	size_t sz_hdr_mz = 0;
	unsigned int size;
	int ret;

	DRV_LOG(INFO, "setting up admin queue on NUMA node %d", numa_node);

	snprintf(vq_name, sizeof(vq_name), "vdev%d_vq%u",
		 vpdev->vfio_dev_fd, queue_idx);

	size = RTE_ALIGN_CEIL(sizeof(*vq) +
				vq_size * sizeof(struct vq_desc_extra),
				RTE_CACHE_LINE_SIZE);
	vq = rte_zmalloc_socket(vq_name, size, RTE_CACHE_LINE_SIZE,
				numa_node);
	if (vq == NULL) {
		DRV_LOG(ERR, "can not allocate vq %u", queue_idx);
		return -ENOMEM;
	}
	hw->vqs[queue_idx] = vq;

	vq->hw = hw;
	vq->vq_queue_index = queue_idx;
	vq->vq_nentries = vq_size;

	/*
	 * Reserve a memzone for vring elements
	 */
	size = vring_size(hw, vq_size, VIRTIO_VRING_ALIGN);
	vq->vq_ring_size = RTE_ALIGN_CEIL(size, VIRTIO_VRING_ALIGN);

	mz = rte_memzone_reserve_aligned(vq_name, vq->vq_ring_size,
			numa_node, RTE_MEMZONE_IOVA_CONTIG,
			VIRTIO_VRING_ALIGN);
	if (mz == NULL) {
		if (rte_errno == EEXIST)
			mz = rte_memzone_lookup(vq_name);
		if (mz == NULL) {
			ret = -ENOMEM;
			goto err_ret;
		}
	}

	memset(mz->addr, 0, mz->len);

	vq->vq_ring_mem = mz->iova;
	vq->vq_ring_virt_mem = mz->addr;

	virtio_vdpa_init_vring(vq);


	if (queue_idx == (priv->vpdev->common_cfg->num_queues - 1)) {
		avq = &vq->aq;
		avq->mz = mz;

		/* Allocate a page for admin vq command, data and status */
		sz_hdr_mz = rte_mem_page_size();
		
		if (sz_hdr_mz) {
			snprintf(vq_hdr_name, sizeof(vq_hdr_name), "vdev%d_vq%u_hdr",
					vpdev->vfio_dev_fd, queue_idx);
			hdr_mz = rte_memzone_reserve_aligned(vq_hdr_name, sz_hdr_mz,
					numa_node, RTE_MEMZONE_IOVA_CONTIG,
					RTE_CACHE_LINE_SIZE);
			if (hdr_mz == NULL) {
				if (rte_errno == EEXIST)
					hdr_mz = rte_memzone_lookup(vq_hdr_name);
				if (hdr_mz == NULL) {
					ret = -ENOMEM;
					goto free_mz;
				}
			}
			avq->virtio_admin_hdr_mz = hdr_mz;
			avq->virtio_admin_hdr_mem = hdr_mz->iova;
			memset(avq->virtio_admin_hdr_mz->addr, 0, rte_mem_page_size());
		} else {
			DRV_LOG(ERR, "rte mem page size is zero");
		}

		hw->avq = avq;
	}

	vr_info.size  = vq_size;
	vr_info.desc  = (uint64_t)(uintptr_t)vq->vq_split.ring.desc;
	vr_info.avail = (uint64_t)(uintptr_t)vq->vq_split.ring.avail;
	vr_info.used  = (uint64_t)(uintptr_t)vq->vq_split.ring.used;
	ret = virtio_pci_dev_queue_set(vpdev, queue_idx, &vr_info);
	if (ret) {
		DRV_LOG(ERR, "setup_queue %u failed", queue_idx);
		ret = -EINVAL;
		goto clean_vq;
	}

	return 0;

clean_vq:
	hw->avq = NULL;
	rte_memzone_free(hdr_mz);
free_mz:
	rte_memzone_free(mz);
err_ret:
	return ret;
}

static void
virtio_vdpa_admin_queue_free(struct virtio_vdpa_pf_priv *priv)
{
	uint16_t nr_vq = priv->hw_nr_virtqs;
	struct virtio_hw *hw = &priv->vpdev->hw;
	struct virtqueue *vq;
	uint16_t i;

	if (hw->vqs == NULL)
		return;

	if (hw->avq) {
		virtio_vdpa_destroy_aq_ctl(hw->avq);
		hw->avq = NULL;
	}

	for (i = 0; i < nr_vq; i++) {
		vq = hw->vqs[i];
		if (vq) {
			rte_free(vq);
			hw->vqs[i] = NULL;
		}
	}
	rte_free(hw->vqs);
	hw->vqs = NULL;
}

static int
virtio_vdpa_admin_queue_alloc(struct virtio_vdpa_pf_priv *priv)
{
	struct virtio_hw *hw = &priv->vpdev->hw;
	uint16_t i, queue_idx;
	int ret;

	hw->max_queue_pairs = priv->vpdev->common_cfg->num_queues / 2;
	priv->hw_nr_virtqs = 1;
	hw->vqs = rte_zmalloc(NULL, sizeof(struct virtqueue *) * priv->hw_nr_virtqs, 0);
	if (!hw->vqs) {
		DRV_LOG(ERR, "failed to allocate vqs");
		return -ENOMEM;
	}

	queue_idx = priv->vpdev->common_cfg->num_queues - 1;
	for (i = 0; i < priv->hw_nr_virtqs; i++) {
		ret = virtio_vdpa_init_admin_queue(priv, queue_idx);
		if (ret < 0) {
			DRV_LOG(ERR, "Failed to init virtio device queue %u", queue_idx);
			virtio_vdpa_admin_queue_free(priv);
			return ret;
		}
		queue_idx--;
	}

	return 0;
}

int
virtio_vdpa_mi_list_dump(void *buf, int max_count, void *filter,
		vdpa_dump_func_t dump_func)
{
	struct virtio_vdpa_pf_priv *priv;
	char * tbuf = (char *)buf;
	int len, count = 0;

	if (!buf || !dump_func || !max_count)
		return -EINVAL;

	pthread_mutex_lock(&mi_priv_list_lock);
	TAILQ_FOREACH(priv, &virtio_mi_priv_list, next) {
		len = dump_func(priv, filter, tbuf);
		if (len > 0) {
			count++;
			if (count >= max_count)
				break;
			tbuf += len;
		}
	}
	pthread_mutex_unlock(&mi_priv_list_lock);

	return count;
}

static int vdpa_mi_check_handler(__rte_unused const char *key,
		const char *value, void *ret_val)
{
	if (strcmp(value, "2") == 0)
		*(int *)ret_val = 1;
	else
		*(int *)ret_val = 0;

	return 0;
}

#define VIRTIO_ARG_VDPA 	  "vdpa"

static int
virtio_pci_devargs_parse(struct rte_devargs *devargs, int *vdpa)
{
	struct rte_kvargs *kvlist;
	int ret = 0;

	if (devargs == NULL)
		return 0;

	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL) {
		DRV_LOG(ERR, "Error when parsing param");
		return 0;
	}

	if (rte_kvargs_count(kvlist, VIRTIO_ARG_VDPA) == 1) {
		/* vdpa mode selected when there's a key-value pair:
		 * vdpa=1
		 */
		ret = rte_kvargs_process(kvlist, VIRTIO_ARG_VDPA,
					 vdpa_mi_check_handler, vdpa);
		if (ret < 0)
			DRV_LOG(ERR, "Failed to parse %s", VIRTIO_ARG_VDPA);
	}

	rte_kvargs_free(kvlist);

	return ret;
}

static int
virtio_vdpa_mi_dev_probe(struct rte_pci_driver *pci_drv __rte_unused,
		struct rte_pci_device *pci_dev)
{
	char devname[RTE_DEV_NAME_MAX_LEN] = {0};
	struct virtio_vdpa_pf_priv *priv = NULL;
	int vdpa = 0, ret = 0;
	uint64_t features;

	ret = virtio_pci_devargs_parse(pci_dev->device.devargs, &vdpa);
	if (ret < 0) {
		DRV_LOG(ERR, "Devargs parsing is failed");
		return ret;
	}
	/* virtio vdpa pmd skips probe if device needs to work in none vdpa mode */
	if (vdpa != 1)
		return 1;

	priv = rte_zmalloc("virtio vdpa pf device private", sizeof(*priv), RTE_CACHE_LINE_SIZE);
	if (!priv) {
		DRV_LOG(ERR, "Failed to allocate private memory");
		rte_errno = ENOMEM;
		return -rte_errno;
	}

	rte_pci_device_name(&pci_dev->addr, devname, RTE_DEV_NAME_MAX_LEN);

	priv->pdev = pci_dev;

	priv->vpdev = virtio_pci_dev_alloc(pci_dev);
	if (priv->vpdev == NULL) {
		DRV_LOG(ERR, "%s failed to alloc virito pci dev", devname);
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	priv->vfio_dev_fd = rte_intr_dev_fd_get(pci_dev->intr_handle);
	if (priv->vfio_dev_fd < 0) {
		DRV_LOG(ERR, "%s failed to get vfio dev fd", devname);
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	virtio_pci_dev_features_get(priv->vpdev, &priv->guest_features);
	if (!(priv->guest_features & (VIRTIO_VDPA_MI_SUPPORTED_FEATURE))) {
		DRV_LOG(ERR, "Device does not support feature required: 0x%" PRIx64 \
				", required: 0x%llx", priv->guest_features,
				VIRTIO_VDPA_MI_SUPPORTED_FEATURE);
		rte_errno = rte_errno ? rte_errno : EOPNOTSUPP;
		goto error;
	}
	features = VIRTIO_VDPA_MI_SUPPORTED_FEATURE;
	features = virtio_pci_dev_features_set(priv->vpdev, features);
	priv->vpdev->hw.weak_barriers = !virtio_with_feature(&priv->vpdev->hw, VIRTIO_F_ORDER_PLATFORM);
	virtio_pci_dev_set_status(priv->vpdev, VIRTIO_CONFIG_STATUS_FEATURES_OK);

	ret = virtio_vdpa_admin_queue_alloc(priv);
	if (ret) {
		DRV_LOG(ERR, "Failed to alloc vDPA device admin queue");
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	/* Start the device */
	virtio_pci_dev_set_status(priv->vpdev, VIRTIO_CONFIG_STATUS_DRIVER_OK);

	pthread_mutex_lock(&mi_priv_list_lock);
	TAILQ_INSERT_TAIL(&virtio_mi_priv_list, priv, next);
	pthread_mutex_unlock(&mi_priv_list_lock);
	return 0;

error:
	rte_free(priv);
	return -rte_errno;
}

static int
virtio_vdpa_mi_dev_remove(struct rte_pci_device *pci_dev)
{
	struct virtio_vdpa_pf_priv *priv = NULL;
	int found = 0;

	pthread_mutex_lock(&mi_priv_list_lock);
	TAILQ_FOREACH(priv, &virtio_mi_priv_list, next) {
		if (priv->pdev == pci_dev) {
			found = 1;
			TAILQ_REMOVE(&virtio_mi_priv_list, priv, next);
			break;
		}
	}
	pthread_mutex_unlock(&mi_priv_list_lock);

	if (found) {
		virtio_vdpa_admin_queue_free(priv);
		virtio_pci_dev_reset(priv->vpdev);

		/* Tell the host we've noticed this device. */
		virtio_pci_dev_set_status(priv->vpdev, VIRTIO_CONFIG_STATUS_ACK);

		/* Tell the host we've known how to drive the device. */
		virtio_pci_dev_set_status(priv->vpdev, VIRTIO_CONFIG_STATUS_DRIVER);
		virtio_pci_dev_free(priv->vpdev);
		rte_free(priv);
	}
	return 0;
}

RTE_INIT(virtio_vdpa_mi_init)
{
	struct virtio_vdpa_mi_ops mi_ops = {
		.get_mi_by_bdf = virtio_vdpa_get_mi_by_bdf,
		.lm_cmd_resume = virtio_vdpa_cmd_resume,
		.lm_cmd_suspend = virtio_vdpa_cmd_suspend,
		.lm_cmd_save_state = virtio_vdpa_cmd_save_state,
		.lm_cmd_restore_state = virtio_vdpa_cmd_restore_state,
		.lm_cmd_get_pending_bytes = virtio_vdpa_cmd_get_pending_bytes,
	};
	virtio_vdpa_register_mi_ops(&mi_ops);
}

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_virtio_mi_map[] = {
	{ RTE_PCI_DEVICE(VIRTIO_PCI_VENDORID, VIRTIO_PCI_MODERN_DEVICEID_NET) },
	{ .vendor_id = 0, /* sentinel */ },
};

static struct rte_pci_driver virtio_vdpa_mi_driver = {
	.id_table = pci_id_virtio_mi_map,
	.drv_flags = 0,
	.probe = virtio_vdpa_mi_dev_probe,
	.remove = virtio_vdpa_mi_dev_remove,
};

#define VIRTIO_VDPA_MI_DRIVER_NAME vdpa_virtio_mi

RTE_PMD_REGISTER_PCI(VIRTIO_VDPA_MI_DRIVER_NAME, virtio_vdpa_mi_driver);
RTE_PMD_REGISTER_PCI_TABLE(VIRTIO_VDPA_MI_DRIVER_NAME, pci_id_virtio_mi_map);
RTE_PMD_REGISTER_KMOD_DEP(VIRTIO_VDPA_MI_DRIVER_NAME, "* vfio-pci");
