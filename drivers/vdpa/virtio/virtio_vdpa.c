/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */
#include <unistd.h>
#include <net/if.h>
#include <rte_malloc.h>
#include <rte_vfio.h>
#include <rte_vhost.h>
#include <rte_vdpa.h>
#include <vdpa_driver.h>
#include <rte_kvargs.h>

#include <virtio_api.h>
#include <virtio_lm.h>
#include "virtio_vdpa.h"

RTE_LOG_REGISTER(virtio_vdpa_logtype, pmd.vdpa.virtio, NOTICE);
#define DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, virtio_vdpa_logtype, \
		"VIRTIO VDPA %s(): " fmt "\n", __func__, ##args)

#define VIRTIO_VDPA_INTR_RETRIES_USEC 1000
#define VIRTIO_VDPA_INTR_RETRIES 256

extern struct virtio_vdpa_device_callback virtio_vdpa_blk_callback;
extern struct virtio_vdpa_device_callback virtio_vdpa_net_callback;

static TAILQ_HEAD(virtio_vdpa_privs, virtio_vdpa_priv) virtio_priv_list =
						  TAILQ_HEAD_INITIALIZER(virtio_priv_list);
static pthread_mutex_t priv_list_lock = PTHREAD_MUTEX_INITIALIZER;

static struct virtio_vdpa_mi_ops mi_ops = {
	.get_mi_by_bdf = NULL,
	.lm_cmd_identity = NULL,
	.lm_cmd_resume = NULL,
	.lm_cmd_suspend = NULL,
	.lm_cmd_save_state = NULL,
	.lm_cmd_restore_state = NULL,
	.lm_cmd_get_internal_pending_bytes = NULL,
	.lm_cmd_dirty_page_identity = NULL,
	.lm_cmd_dirty_page_start_track = NULL,
	.lm_cmd_dirty_page_stop_track = NULL,
	.lm_cmd_dirty_page_get_map_pending_bytes = NULL,
	.lm_cmd_dirty_page_report_map = NULL,
};

void
virtio_vdpa_register_mi_ops(struct virtio_vdpa_mi_ops *ops)
{
	mi_ops = (*ops);
}

static struct virtio_vdpa_priv *
virtio_vdpa_find_priv_resource_by_vdev(const struct rte_vdpa_device *vdev)
{
	struct virtio_vdpa_priv *priv;
	bool found = false;

	pthread_mutex_lock(&priv_list_lock);
	TAILQ_FOREACH(priv, &virtio_priv_list, next) {
		if (vdev == priv->vdev) {
			found = true;
			break;
		}
	}
	pthread_mutex_unlock(&priv_list_lock);
	if (!found) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		rte_errno = ENODEV;
		return NULL;
	}
	return priv;
}

static int
virtio_vdpa_vqs_max_get(struct rte_vdpa_device *vdev, uint32_t *queue_num)
{
	struct virtio_vdpa_priv *priv =
		virtio_vdpa_find_priv_resource_by_vdev(vdev);

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		return -ENODEV;
	}

	*queue_num = priv->hw_nr_virtqs;
	DRV_LOG(DEBUG, "Vid %d queue num is %d", priv->vid, *queue_num);
	return 0;
}

static int
virtio_vdpa_features_get(struct rte_vdpa_device *vdev, uint64_t *features)
{
	struct virtio_vdpa_priv *priv =
		virtio_vdpa_find_priv_resource_by_vdev(vdev);

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		return -ENODEV;
	}

	virtio_pci_dev_features_get(priv->vpdev, features);
	*features |= (1ULL << VHOST_USER_F_PROTOCOL_FEATURES);

	return 0;
}

static int
virtio_vdpa_protocol_features_get(struct rte_vdpa_device *vdev,
		uint64_t *features)
{
	struct virtio_vdpa_priv *priv =
		virtio_vdpa_find_priv_resource_by_vdev(vdev);

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		return -ENODEV;
	}

	priv->dev_ops->vhost_feature_get(features);
	return 0;
}

static uint64_t
virtio_vdpa_hva_to_gpa(int vid, uint64_t hva)
{
	struct rte_vhost_memory *mem = NULL;
	struct rte_vhost_mem_region *reg;
	uint32_t i;
	uint64_t gpa = 0;

	if (rte_vhost_get_mem_table(vid, &mem) < 0) {
		if (mem)
			free(mem);
		DRV_LOG(ERR, "Virtio dev %d get mem table fail", vid);
		return 0;
	}

	for (i = 0; i < mem->nregions; i++) {
		reg = &mem->regions[i];

		if (hva >= reg->host_user_addr &&
				hva < reg->host_user_addr + reg->size) {
			gpa = hva - reg->host_user_addr + reg->guest_phys_addr;
			break;
		}
	}

	free(mem);
	return gpa;
}

static void
virtio_vdpa_virtq_handler(void *cb_arg)
{
	struct virtio_vdpa_vring_info *virtq = cb_arg;
	struct virtio_vdpa_priv *priv = virtq->priv;
	uint64_t buf;
	int nbytes;

	if (!priv->configured || !virtq->enable)
		return;

	if (rte_intr_fd_get(virtq->intr_handle) < 0)
		return;

	do {
		nbytes = read(rte_intr_fd_get(virtq->intr_handle), &buf, 8);
		if (nbytes < 0) {
			if (errno == EINTR ||
				errno == EWOULDBLOCK ||
				errno == EAGAIN)
				continue;
			DRV_LOG(ERR,  "%s failed to read kickfd of virtq %d: %s",
				priv->vdev->device->name, virtq->index, strerror(errno));
		}
		break;
	} while (1);
	virtio_pci_dev_queue_notify(priv->vpdev, virtq->index);
	if (virtq->notifier_state == VIRTIO_VDPA_NOTIFIER_STATE_DISABLED) {
		if (rte_vhost_host_notifier_ctrl(priv->vid, virtq->index, true)) {
			DRV_LOG(ERR,  "%s failed to set notify ctrl virtq %d: %s",
					priv->vdev->device->name, virtq->index, strerror(errno));
			virtq->notifier_state = VIRTIO_VDPA_NOTIFIER_STATE_ERR;
		} else
			virtq->notifier_state = VIRTIO_VDPA_NOTIFIER_STATE_ENABLED;
		DRV_LOG(INFO, "%s virtq %u notifier state is %s",
						priv->vdev->device->name,
						virtq->index,
						virtq->notifier_state ==
						VIRTIO_VDPA_NOTIFIER_STATE_ENABLED ? "enabled" :
									"disabled");
	}
	DRV_LOG(DEBUG, "%s ring virtq %u doorbell",
					priv->vdev->device->name, virtq->index);
}

static int
virtio_vdpa_virtq_doorbell_relay_disable(struct virtio_vdpa_priv *priv,
														int vq_idx)
{
	int ret = -EAGAIN;
	struct rte_intr_handle *intr_handle;
	int retries = VIRTIO_VDPA_INTR_RETRIES;

	intr_handle = priv->vrings[vq_idx]->intr_handle;
	if (rte_intr_fd_get(intr_handle) != -1) {
		while (retries-- && ret == -EAGAIN) {
			ret = rte_intr_callback_unregister(intr_handle,
							virtio_vdpa_virtq_handler,
							priv->vrings[vq_idx]);
			if (ret == -EAGAIN) {
				DRV_LOG(DEBUG, "%s try again to unregister fd %d "
				"of virtq %d interrupt, retries = %d",
				priv->vdev->device->name,
				rte_intr_fd_get(intr_handle),
				(int)priv->vrings[vq_idx]->index, retries);
				usleep(VIRTIO_VDPA_INTR_RETRIES_USEC);
			}
		}
		rte_intr_fd_set(intr_handle, -1);
	}
	rte_intr_instance_free(intr_handle);
	return 0;
}

static int
virtio_vdpa_virtq_doorbell_relay_enable(struct virtio_vdpa_priv *priv, int vq_idx)
{
	int ret;
	struct rte_vhost_vring vq;
	struct rte_intr_handle *intr_handle;

	ret = rte_vhost_get_vhost_vring(priv->vid, vq_idx, &vq);
	if (ret)
		return ret;

	intr_handle = rte_intr_instance_alloc(RTE_INTR_INSTANCE_F_SHARED);
	if (intr_handle == NULL) {
		DRV_LOG(ERR, "%s fail to allocate intr_handle",
						priv->vdev->device->name);
		return -EINVAL;
	}

	priv->vrings[vq_idx]->intr_handle = intr_handle;
	if (rte_intr_fd_set(intr_handle, vq.kickfd)) {
		DRV_LOG(ERR, "%s fail to set kick fd", priv->vdev->device->name);
		goto error;
	}

	if (rte_intr_fd_get(intr_handle) == -1) {
		DRV_LOG(ERR, "%s virtq %d kickfd is invalid",
					priv->vdev->device->name, vq_idx);
		goto error;
	} else {
		if (rte_intr_type_set(intr_handle, RTE_INTR_HANDLE_EXT))
			goto error;

		if (rte_intr_callback_register(intr_handle,
						   virtio_vdpa_virtq_handler,
						   priv->vrings[vq_idx])) {
			rte_intr_fd_set(intr_handle, -1);
			DRV_LOG(ERR, "%s failed to register virtq %d interrupt",
						priv->vdev->device->name,
						vq_idx);
			goto error;
		} else {
			DRV_LOG(DEBUG, "%s register fd %d interrupt for virtq %d",
				priv->vdev->device->name,
				rte_intr_fd_get(intr_handle),
				vq_idx);
		}
	}

	return 0;

error:
	virtio_vdpa_virtq_doorbell_relay_disable(priv, vq_idx);
	return -EINVAL;
}

static int
virtio_vdpa_virtq_disable(struct virtio_vdpa_priv *priv, int vq_idx)
{
	int ret;

	ret = virtio_vdpa_virtq_doorbell_relay_disable(priv, vq_idx);
	if (ret) {
		DRV_LOG(ERR, "%s doorbell relay disable failed ret:%d",
						priv->vdev->device->name, ret);
		return ret;
	}

	virtio_pci_dev_queue_del(priv->vpdev, vq_idx);

	ret = virtio_pci_dev_interrupt_disable(priv->vpdev, vq_idx + 1);
	if (ret) {
		DRV_LOG(ERR, "%s virtq %d interrupt disabel failed",
						priv->vdev->device->name, vq_idx);
		return ret;
	}
	priv->vrings[vq_idx]->notifier_state = VIRTIO_VDPA_NOTIFIER_STATE_DISABLED;
	priv->vrings[vq_idx]->enable = false;
	return 0;
}

static int
virtio_vdpa_virtq_enable(struct virtio_vdpa_priv *priv, int vq_idx)
{
	int ret;
	int vid;
	struct rte_vhost_vring vq;
	struct virtio_pci_dev_vring_info vring_info;
	uint64_t gpa;

	vid = priv->vid;

	ret = rte_vhost_get_vhost_vring(vid, vq_idx, &vq);
	if (ret)
		return ret;

	ret = virtio_pci_dev_interrupt_enable(priv->vpdev, vq.callfd, vq_idx + 1);
	if (ret) {
		DRV_LOG(ERR, "%s virtq interrupt enable failed ret:%d",
						priv->vdev->device->name, ret);
		return ret;
	}

	gpa = virtio_vdpa_hva_to_gpa(vid, (uint64_t)(uintptr_t)vq.desc);
	if (gpa == 0) {
		DRV_LOG(ERR, "Dev %s fail to get GPA for descriptor ring %d",
						priv->vdev->device->name, vq_idx);
		return -EINVAL;
	}
	DRV_LOG(DEBUG, "%s virtq %d desc addr%"PRIx64,
					priv->vdev->device->name, vq_idx, gpa);
	priv->vrings[vq_idx]->desc = gpa;
	vring_info.desc = gpa;

	gpa = virtio_vdpa_hva_to_gpa(vid, (uint64_t)(uintptr_t)vq.avail);
	if (gpa == 0) {
		DRV_LOG(ERR, "%s fail to get GPA for available ring",
					priv->vdev->device->name);
		return -EINVAL;
	}
	DRV_LOG(DEBUG, "Virtq %d avail addr%"PRIx64, vq_idx, gpa);
	priv->vrings[vq_idx]->avail = gpa;
	vring_info.avail = gpa;

	gpa = virtio_vdpa_hva_to_gpa(vid, (uint64_t)(uintptr_t)vq.used);
	if (gpa == 0) {
		DRV_LOG(ERR, "%s fail to get GPA for used ring",
					priv->vdev->device->name);
		return -EINVAL;
	}
	DRV_LOG(DEBUG, "Virtq %d used addr%"PRIx64, vq_idx, gpa);
	priv->vrings[vq_idx]->used = gpa;
	vring_info.used = gpa;

	/* TO_DO: need to check vq_size not exceed hw limit */
	priv->vrings[vq_idx]->size = vq.size;
	vring_info.size = vq.size;

	DRV_LOG(DEBUG, "Virtq %d nr_entrys:%d", vq_idx, vq.size);
	if (virtio_pci_dev_queue_set(priv->vpdev, vq_idx, &vring_info)) {
		DRV_LOG(ERR, "%s setup_queue failed", priv->vdev->device->name);
		return -EINVAL;
	}

	ret = virtio_vdpa_virtq_doorbell_relay_enable(priv, vq_idx);
	if (ret) {
		DRV_LOG(ERR, "%s virtq doorbell relay failed ret:%d",
						priv->vdev->device->name, ret);
		return ret;
	}

	priv->vrings[vq_idx]->enable = true;
	virtio_pci_dev_queue_notify(priv->vpdev, vq_idx);
	return 0;
}

static int
virtio_vdpa_vring_state_set(int vid, int vq_idx, int state)
{
	struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
	struct virtio_vdpa_priv *priv =
		virtio_vdpa_find_priv_resource_by_vdev(vdev);
	int ret = 0;

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		return -ENODEV;
	}
	if (vq_idx >= (int)priv->hw_nr_virtqs) {
		DRV_LOG(ERR, "Too big vq_idx: %d", vq_idx);
		return -E2BIG;
	}

	/* TO_DO: check if vid set here is suitable */
	priv->vid = vid;

	if (virtio_pci_dev_get_status(priv->vpdev) &
		VIRTIO_CONFIG_STATUS_DRIVER_OK) {
		DRV_LOG(ERR, "Can not set vring state when driver ok vDPA device: %s",
						vdev->device->name);
		return -EINVAL;
	}

	/* If vq is already enabled, and enable again means parameter change, so,
	 * we disable vq first, then enable
	 */
	if (!state && priv->vrings[vq_idx]->enable)
		ret = virtio_vdpa_virtq_disable(priv, vq_idx);
	else if (state && !priv->vrings[vq_idx]->enable)
		ret = virtio_vdpa_virtq_enable(priv, vq_idx);
	else if (state && priv->vrings[vq_idx]->enable) {
		ret = virtio_vdpa_virtq_disable(priv, vq_idx);
		if (ret) {
			DRV_LOG(ERR, "%s fail to disable vring,ret:%d vring:%d state:%d",
						priv->vdev->device->name, ret, vq_idx, state);
			return ret;
		}
		ret = virtio_vdpa_virtq_enable(priv, vq_idx);
	}
	if (ret) {
		DRV_LOG(ERR, "%s fail to set vring state, ret:%d vq_idx:%d state:%d",
					priv->vdev->device->name, ret, vq_idx, state);
		return ret;
	}

	DRV_LOG(INFO, "VDPA device %s vid:%d  set vring %d state %d",
					priv->vdev->device->name, vid, vq_idx, state);
	return 0;
}

static int
virtio_vdpa_dma_unmap(struct virtio_vdpa_priv *priv)
{
	uint32_t i;
	int ret;
	struct rte_vhost_memory *mem = NULL;
	int vfio_container_fd;

	ret = rte_vhost_get_mem_table(priv->vid, &mem);
	if (ret < 0) {
		DRV_LOG(ERR, "%s failed to get VM memory layout ret:%d",
					priv->vdev->device->name, ret);
		goto exit;
	}

	vfio_container_fd = priv->vfio_container_fd;

	for (i = 0; i < mem->nregions; i++) {
		struct rte_vhost_mem_region *reg;

		reg = &mem->regions[i];
		DRV_LOG(INFO, "%s, region %u: HVA 0x%" PRIx64 ", "
			"GPA 0x%" PRIx64 ", size 0x%" PRIx64 ".",
			"DMA unmap", i,
			reg->host_user_addr, reg->guest_phys_addr, reg->size);

		ret = rte_vfio_container_dma_unmap(vfio_container_fd,
			reg->host_user_addr, reg->guest_phys_addr,
			reg->size);
		if (ret < 0) {
			DRV_LOG(ERR, "%s DMA unmap failed ret:%d",
						priv->vdev->device->name, ret);
			goto exit;
		}
	}

exit:
	free(mem);
	return ret;
}

static int
virtio_vdpa_dma_map(struct virtio_vdpa_priv *priv)
{
	uint32_t i = 0, j;
	int ret;
	struct rte_vhost_memory *mem = NULL;
	struct rte_vhost_mem_region *reg;
	int vfio_container_fd = priv->vfio_container_fd;

	ret = rte_vhost_get_mem_table(priv->vid, &mem);
	if (ret < 0) {
		DRV_LOG(ERR, "%s failed to get VM memory layout ret:%d",
					priv->vdev->device->name, ret);
		goto exit;
	}

	for (i = 0; i < mem->nregions; i++) {
		reg = &mem->regions[i];
		DRV_LOG(INFO, "%s, region %u: HVA 0x%" PRIx64 ", "
			"GPA 0x%" PRIx64 ", size 0x%" PRIx64 ".",
			"DMA map", i,
			reg->host_user_addr, reg->guest_phys_addr, reg->size);

		ret = rte_vfio_container_dma_map(vfio_container_fd,
			reg->host_user_addr, reg->guest_phys_addr,
			reg->size);
		if (ret < 0) {
			DRV_LOG(ERR, "%s DMA map failed ret:%d",
						priv->vdev->device->name, ret);
			goto exit;
		}
	}
	free(mem);
	return ret;

exit:
	for (j = 0; j < i; j++) {
		reg = &mem->regions[j];
		DRV_LOG(INFO, "%s, region %u: HVA 0x%" PRIx64 ", "
			"GPA 0x%" PRIx64 ", size 0x%" PRIx64 ".",
			"DMA unmap", j,
			reg->host_user_addr, reg->guest_phys_addr, reg->size);

		ret = rte_vfio_container_dma_unmap(vfio_container_fd,
			reg->host_user_addr, reg->guest_phys_addr,
			reg->size);
		if (ret < 0) {
			DRV_LOG(ERR, "%s DMA unmap failed ret:%d",
						priv->vdev->device->name, ret);
		}
	}

	free(mem);
	return ret;
}

static int
virtio_vdpa_features_set(int vid)
{
	struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
	struct virtio_vdpa_priv *priv =
		virtio_vdpa_find_priv_resource_by_vdev(vdev);
	uint64_t log_base, log_size;
	uint64_t features;
	int ret;

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		return -ENODEV;
	}
	priv->vid = vid;
	ret = rte_vhost_get_negotiated_features(vid, &features);
	if (ret) {
		DRV_LOG(ERR, "%s failed to get negotiated features",
					priv->vdev->device->name);
		return ret;
	}
	if (RTE_VHOST_NEED_LOG(features)) {
		ret = rte_vhost_get_log_base(vid, &log_base, &log_size);
		if (ret) {
			DRV_LOG(ERR, "%s failed to get log base",
						priv->vdev->device->name);
			return ret;
		}
		/* TO_DO: add log op */
	}

	/* TO_DO: check why --- */
	features |= (1ULL << VIRTIO_F_IOMMU_PLATFORM);
	priv->guest_features = virtio_pci_dev_features_set(priv->vpdev, features);
	DRV_LOG(INFO, "%s vid %d hw feature is %" PRIx64 "guest feature is %" PRIx64,
					priv->vdev->device->name, vid,
					priv->guest_features, features);

	return 0;
}

static int
virtio_vdpa_dev_close(int vid)
{
	struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
	struct virtio_vdpa_priv *priv =
		virtio_vdpa_find_priv_resource_by_vdev(vdev);
	int ret, i;

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		return -ENODEV;
	}

	/* Suspend */
	/* Set_vring_base */

	ret = virtio_pci_dev_interrupt_disable(priv->vpdev, 0);
	if (ret) {
		DRV_LOG(ERR, "%s error disabling virtio dev interrupts: %d (%s)",
				priv->vdev->device->name,
				ret, strerror(errno));
		return ret;
	}

	virtio_pci_dev_reset(priv->vpdev);

	ret = virtio_vdpa_dma_unmap(priv);
	if (ret) {
		DRV_LOG(ERR, "%s fail to do dma map: %d",
					priv->vdev->device->name, ret);
	}

	/* Disable all queues */
	for (i = 0; i < priv->nr_virtqs; i++) {
		if (priv->vrings[i]->enable)
			virtio_vdpa_vring_state_set(vid, i, 0);
	}

	/* Tell the host we've noticed this device. */
	virtio_pci_dev_set_status(priv->vpdev, VIRTIO_CONFIG_STATUS_ACK);

	/* Tell the host we've known how to drive the device. */
	virtio_pci_dev_set_status(priv->vpdev, VIRTIO_CONFIG_STATUS_DRIVER);

	priv->configured = 0;

	DRV_LOG(INFO, "%s vid %d was closed", priv->vdev->device->name, vid);
	return ret;
}

static int
virtio_vdpa_dev_config(int vid)
{
	struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
	struct virtio_vdpa_priv *priv =
		virtio_vdpa_find_priv_resource_by_vdev(vdev);
	int ret, fd;

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		return -ENODEV;
	}
	if (priv->configured) {
		DRV_LOG(ERR, "%s vid %d already configured",
					vdev->device->name, vid);
		return -EBUSY;
	}

	priv->nr_virtqs = rte_vhost_get_vring_num(vid);
	if (priv->nvec <= (priv->nr_virtqs + 1)) {
		DRV_LOG(ERR, "%s error dev interrupts %d less than queue: %d",
					vdev->device->name, priv->nvec, priv->nr_virtqs + 1);
		return -EINVAL;
	}

	priv->vid = vid;
	ret = virtio_vdpa_dma_map(priv);
	if (ret) {
		DRV_LOG(ERR, "%s fail to do dma map: %d",
					vdev->device->name, ret);
		return ret;
	}

	fd = rte_intr_fd_get(priv->pdev->intr_handle);
	ret = virtio_pci_dev_interrupt_enable(priv->vpdev, fd, 0);
	if (ret) {
		DRV_LOG(ERR, "%s error enabling virtio dev interrupts: %d(%s)",
				vdev->device->name, ret, strerror(errno));
		rte_errno = rte_errno ? rte_errno : EINVAL;
		virtio_vdpa_dma_unmap(priv);
		return -rte_errno;
	}

	virtio_pci_dev_set_status(priv->vpdev, VIRTIO_CONFIG_STATUS_FEATURES_OK);
	/* Start the device */
	virtio_pci_dev_set_status(priv->vpdev, VIRTIO_CONFIG_STATUS_DRIVER_OK);
	DRV_LOG(INFO, "%s vid %d move to driver ok", vdev->device->name, vid);

	priv->configured = 1;
	DRV_LOG(INFO, "%s vid %d was configured", vdev->device->name, vid);

	return 0;
}

static int
virtio_vdpa_group_fd_get(int vid)
{
	struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
	struct virtio_vdpa_priv *priv =
		virtio_vdpa_find_priv_resource_by_vdev(vdev);

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		return -ENODEV;
	}
	return priv->vfio_group_fd;
}

static int
virtio_vdpa_device_fd_get(int vid)
{
	struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
	struct virtio_vdpa_priv *priv =
		virtio_vdpa_find_priv_resource_by_vdev(vdev);

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		return -ENODEV;
	}
	return priv->vfio_dev_fd;
}

static int
virtio_vdpa_notify_area_get(int vid, int qid, uint64_t *offset, uint64_t *size)
{
	struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
	struct virtio_vdpa_priv *priv =
		virtio_vdpa_find_priv_resource_by_vdev(vdev);
	int ret;

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s", vdev->device->name);
		return -ENODEV;
	}

	ret = virtio_pci_dev_notify_area_get(priv->vpdev, qid, offset, size);
	if (ret) {
		DRV_LOG(ERR, "%s fail to get notify area", vdev->device->name);
		return ret;
	}

	DRV_LOG(DEBUG, "Vid %d qid:%d offset:0x%"PRIx64"size:0x%"PRIx64,
					vid, qid, *offset, *size);
	return 0;
}
static int
virtio_vdpa_dev_config_get(int vid ,uint8_t *payload, uint32_t len)
{
	struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
	struct virtio_vdpa_priv *priv = virtio_vdpa_find_priv_resource_by_vdev(vdev);

	if (priv == NULL) {
		DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
		return -EINVAL;
	}
	virtio_pci_dev_config_read(priv->vpdev, 0, payload, len);
	DRV_LOG(INFO, "vDPA device %d get config len %d", vid,len);

	return 0;
}

static struct rte_vdpa_dev_ops virtio_vdpa_ops = {
	.get_queue_num = virtio_vdpa_vqs_max_get,
	.get_features = virtio_vdpa_features_get,
	.get_protocol_features = virtio_vdpa_protocol_features_get,
	.dev_conf = virtio_vdpa_dev_config,
	.dev_close = virtio_vdpa_dev_close,
	.set_vring_state = virtio_vdpa_vring_state_set,
	.set_features = virtio_vdpa_features_set,
	.migration_done = NULL,
	.get_vfio_group_fd = virtio_vdpa_group_fd_get,
	.get_vfio_device_fd = virtio_vdpa_device_fd_get,
	.get_notify_area = virtio_vdpa_notify_area_get,
	.get_stats_names = NULL,
	.get_stats = NULL,
	.reset_stats = NULL,
	.get_dev_config = virtio_vdpa_dev_config_get,
};

static int vdpa_check_handler(__rte_unused const char *key,
		const char *value, void *ret_val)
{
	if (strcmp(value, VIRTIO_ARG_VDPA_VALUE_VF) == 0)
		*(int *)ret_val = 1;
	else
		*(int *)ret_val = 0;

	return 0;
}

static int vdpa_pf_check_handler(__rte_unused const char *key,
		const char *value, void *ret_val)
{
	if (mi_ops.get_mi_by_bdf)
		*(struct virtio_vdpa_pf_priv **)ret_val = mi_ops.get_mi_by_bdf(value);
	else
		*(struct virtio_vdpa_pf_priv **)ret_val = NULL;

	return 0;
}

static int
virtio_pci_devargs_parse(struct rte_devargs *devargs, int *vdpa, struct virtio_vdpa_pf_priv **pf)
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
		/* Vdpa mode selected when there's a key-value pair:
		 * vdpa=1
		 */
		ret = rte_kvargs_process(kvlist, VIRTIO_ARG_VDPA,
				vdpa_check_handler, vdpa);
		if (ret < 0)
			DRV_LOG(ERR, "Failed to parse %s", VIRTIO_ARG_VDPA);
	}

	if (rte_kvargs_count(kvlist, VIRTIO_ARG_VDPA_PF) == 1) {
		/* vdpa pf set when there's a key-value pair:
		 * mipf=0000:3b:0.0
		 */
		ret = rte_kvargs_process(kvlist, VIRTIO_ARG_VDPA_PF,
				vdpa_pf_check_handler, pf);
		if (ret < 0)
			DRV_LOG(ERR, "Failed to parse %s", VIRTIO_ARG_VDPA_PF);
	}

	rte_kvargs_free(kvlist);

	return ret;
}

static void
virtio_vdpa_queues_free(struct virtio_vdpa_priv *priv)
{
	uint16_t nr_vq = priv->hw_nr_virtqs;
	struct virtio_vdpa_vring_info *vr;
	uint16_t i;

	if (priv->vrings) {
		for (i = 0; i < nr_vq; i++) {
			vr = priv->vrings[i];
			if (!vr)
				continue;
			rte_free(vr);
			priv->vrings[i] = NULL;
		}
		rte_free(priv->vrings);
		priv->vrings = NULL;
	}

	virtio_pci_dev_queues_free(priv->vpdev, nr_vq);
}

static int
virtio_vdpa_queues_alloc(struct virtio_vdpa_priv *priv)
{
	uint16_t nr_vq = priv->hw_nr_virtqs;
	struct virtio_vdpa_vring_info *vr;
	uint16_t i;
	int ret;

	ret = virtio_pci_dev_queues_alloc(priv->vpdev, nr_vq);
	if (ret) {
		DRV_LOG(ERR, "%s failed to alloc virtio device queues",
					priv->vdev->device->name);
		return ret;
	}

	priv->vrings = rte_zmalloc(NULL,
							sizeof(struct virtio_vdpa_vring_info *) * nr_vq,
							0);
	if (!priv->vrings) {
		virtio_vdpa_queues_free(priv);
		return -ENOMEM;
	}

	for (i = 0; i < nr_vq; i++) {
		vr = rte_zmalloc_socket(NULL, sizeof(struct virtio_vdpa_vring_info),
								RTE_CACHE_LINE_SIZE,
								priv->pdev->device.numa_node);
		if (vr == NULL) {
			virtio_vdpa_queues_free(priv);
			return -ENOMEM;
		}
		priv->vrings[i] = vr;
		priv->vrings[i]->index = i;
		priv->vrings[i]->priv = priv;
	}
	return 0;
}

static int
virtio_vdpa_dev_probe(struct rte_pci_driver *pci_drv __rte_unused,
		struct rte_pci_device *pci_dev)
{
	int vdpa = 0;
	int ret;
	struct virtio_vdpa_priv *priv;
	struct virtio_vdpa_pf_priv *pf_priv = NULL;
	char devname[RTE_DEV_NAME_MAX_LEN] = {0};
	int iommu_group_num;

	rte_pci_device_name(&pci_dev->addr, devname, RTE_DEV_NAME_MAX_LEN);

	ret = virtio_pci_devargs_parse(pci_dev->device.devargs, &vdpa, &pf_priv);
	if (ret < 0) {
		DRV_LOG(ERR, "Devargs parsing is failed %d dev:%s", ret, devname);
		return ret;
	}
	/* Virtio vdpa pmd skips probe if device needs to work in none vdpa mode */
	if (vdpa != 1)
		return 1;

	/* check pf_priv before use it, might be null if not set */
	if (!pf_priv) {
		DRV_LOG(ERR, "PF was not set");
		return 1;
	}

	priv = rte_zmalloc("virtio vdpa device private", sizeof(*priv),
						RTE_CACHE_LINE_SIZE);
	if (!priv) {
		DRV_LOG(ERR, "Failed to allocate private memory %d dev:%s",
						ret, devname);
		rte_errno = ENOMEM;
		return -rte_errno;
	}

	priv->pf_priv = pf_priv;
	/* TO_DO: need to confirm following: */
	priv->vfio_dev_fd = -1;
	priv->vfio_group_fd = -1;
	priv->vfio_container_fd = -1;

	ret = rte_vfio_get_group_num(rte_pci_get_sysfs_path(), devname,
			&iommu_group_num);
	if (ret <= 0) {
		DRV_LOG(ERR, "%s failed to get IOMMU group ret:%d", devname, ret);
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	priv->vfio_container_fd = rte_vfio_container_create();
	if (priv->vfio_container_fd < 0) {
		DRV_LOG(ERR, "%s failed to get container fd", devname);
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	priv->vfio_group_fd = rte_vfio_container_group_bind(
			priv->vfio_container_fd, iommu_group_num);
	if (priv->vfio_group_fd < 0) {
		DRV_LOG(ERR, "%s failed to get group fd", devname);
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	priv->pdev = pci_dev;

	priv->vpdev = virtio_pci_dev_alloc(pci_dev);
	if (priv->vpdev == NULL) {
		DRV_LOG(ERR, "%s failed to alloc virito pci dev", devname);
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	if (priv->pdev->id.device_id == VIRTIO_PCI_MODERN_DEVICEID_NET)
		priv->dev_ops = &virtio_vdpa_net_callback;
	else if (priv->pdev->id.device_id == VIRTIO_PCI_MODERN_DEVICEID_BLK)
		priv->dev_ops = &virtio_vdpa_blk_callback;

	priv->vfio_dev_fd = rte_intr_dev_fd_get(pci_dev->intr_handle);
	if (priv->vfio_dev_fd < 0) {
		DRV_LOG(ERR, "%s failed to get vfio dev fd", devname);
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	priv->vdev = rte_vdpa_register_device(&pci_dev->device, &virtio_vdpa_ops);
	if (priv->vdev == NULL) {
		DRV_LOG(ERR, "%s failed to register vDPA device", devname);
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	priv->hw_nr_virtqs = virtio_pci_dev_nr_vq_get(priv->vpdev);
	ret = virtio_vdpa_queues_alloc(priv);
	if (ret) {
		DRV_LOG(ERR, "%s failed to alloc vDPA device queues ret:%d",
					devname, ret);
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	priv->nvec = virtio_pci_dev_interrupts_num_get(priv->vpdev);
	if (priv->nvec <= 0) {
		DRV_LOG(ERR, "%s error dev interrupts %d less than 0",
					devname, priv->nvec);
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	ret = virtio_pci_dev_interrupts_alloc(priv->vpdev, priv->nvec);
	if (ret) {
		DRV_LOG(ERR, "%s error alloc virtio dev interrupts ret:%d %s",
					devname, ret, strerror(errno));
		rte_errno = rte_errno ? rte_errno : EINVAL;
		goto error;
	}

	pthread_mutex_lock(&priv_list_lock);
	TAILQ_INSERT_TAIL(&virtio_priv_list, priv, next);
	pthread_mutex_unlock(&priv_list_lock);
	return 0;

error:
	if (priv)
		rte_free(priv);
	return -rte_errno;
}

static int
virtio_vdpa_dev_remove(struct rte_pci_device *pci_dev)
{
	struct virtio_vdpa_priv *priv = NULL;
	bool found = false, ret;

	pthread_mutex_lock(&priv_list_lock);
	TAILQ_FOREACH(priv, &virtio_priv_list, next) {
		if (priv->pdev == pci_dev) {
			found = true;
			TAILQ_REMOVE(&virtio_priv_list, priv, next);
			break;
		}
	}
	pthread_mutex_unlock(&priv_list_lock);
	if (found) {
		if (priv->configured)
			virtio_vdpa_dev_close(priv->vid);

		if (priv->vdev)
			rte_vdpa_unregister_device(priv->vdev);

		ret = virtio_pci_dev_interrupts_free(priv->vpdev);
		if (ret) {
			DRV_LOG(ERR, "Error free virtio dev interrupts: %s",
					strerror(errno));
		}

		virtio_vdpa_queues_free(priv);
		virtio_pci_dev_free(priv->vpdev);

		rte_free(priv);
	}

	return found ? 0 : -ENODEV;
}

void
virtio_vdpa_get_vf_info(struct virtio_vdpa_priv *priv,
		struct vdpa_vf_info_priv *vf_info)
{
	vf_info->vfid = priv->vid;
	vf_info->pci_addr = priv->pdev->addr;
	/* Todo */
	vf_info->msix_num = 0;
	vf_info->queue_num = priv->nr_virtqs;
	vf_info->queue_size = 0;
	vf_info->features = priv->guest_features;
	vf_info->mtu = 0;
	vf_info->mac;
}

bool
is_mi_pf(struct virtio_vdpa_priv *priv, struct virtio_vdpa_pf_priv *pf_priv)
{
	return (priv->pf_priv == pf_priv);
}

int
virtio_vdpa_dev_list_dump(void *buf, int max_count, void *filter,
		vdpa_dump_func_t dump_func)
{
	struct virtio_vdpa_priv *priv;
	char * tbuf = (char *)buf;
	int len, count = 0;

	if (!buf || !dump_func || !max_count)
		return -EINVAL;

	pthread_mutex_lock(&priv_list_lock);
	TAILQ_FOREACH(priv, &virtio_priv_list, next) {
		len = dump_func(priv, filter, tbuf);
		if (len > 0) {
			count++;
			if (count >= max_count)
				break;
			tbuf += len;
		}
	}
	pthread_mutex_unlock(&priv_list_lock);

	return count;
}

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_virtio_map[] = {
	{ RTE_PCI_DEVICE(VIRTIO_PCI_VENDORID, VIRTIO_PCI_MODERN_DEVICEID_NET) },
	{ RTE_PCI_DEVICE(VIRTIO_PCI_VENDORID, VIRTIO_PCI_MODERN_DEVICEID_BLK) },
	{ .vendor_id = 0, /* sentinel */ },
};

static struct rte_pci_driver virtio_vdpa_driver = {
	.id_table = pci_id_virtio_map,
	.drv_flags = 0,
	.probe = virtio_vdpa_dev_probe,
	.remove = virtio_vdpa_dev_remove,
};

RTE_PMD_REGISTER_PCI(VIRTIO_VDPA_DRIVER_NAME, virtio_vdpa_driver);
RTE_PMD_REGISTER_PCI_TABLE(VIRTIO_VDPA_DRIVER_NAME, pci_id_virtio_map);
RTE_PMD_REGISTER_KMOD_DEP(VIRTIO_VDPA_DRIVER_NAME, "* vfio-pci");
