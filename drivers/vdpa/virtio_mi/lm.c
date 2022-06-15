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
#include <rte_ether.h>

#include <virtqueue.h>
#include <virtio_admin.h>
#include <virtio_api.h>

#define VIRTIO_VDPA_MI_SUPPORTED_NET_FEATURES (1ULL << VIRTIO_F_ADMIN_VQ)

struct virtio_vdpa_pf_priv;
struct virtio_vdpa_dev_ops {
	uint64_t (*get_required_features)(void);
	uint16_t (*get_adminq_idx)(struct virtio_vdpa_pf_priv *priv);
};

struct virtio_vdpa_pf_priv {
	TAILQ_ENTRY(virtio_vdpa_pf_priv) next;
	struct rte_pci_device *pdev;
	struct virtio_pci_dev *vpdev;
	struct virtio_vdpa_dev_ops *dev_ops;
	uint64_t device_features;
	int vfio_dev_fd;
	uint16_t hw_nr_virtqs; /* number of vq device supported*/
};

RTE_LOG_REGISTER(virtio_vdpa_mi_logtype, pmd.vdpa.virtio, NOTICE);
#define DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, virtio_vdpa_mi_logtype, \
		"VIRTIO VDPA MI %s(): " fmt "\n", __func__, ##args)

TAILQ_HEAD(virtio_vdpa_mi_privs, virtio_vdpa_pf_priv) virtio_mi_priv_list =
						TAILQ_HEAD_INITIALIZER(virtio_mi_priv_list);
static pthread_mutex_t mi_priv_list_lock = PTHREAD_MUTEX_INITIALIZER;

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

static int
virtio_vdpa_init_admin_queue(struct virtio_vdpa_pf_priv *priv)
{
	const struct rte_memzone *mz = NULL, *hdr_mz = NULL;
	int numa_node = priv->pdev->device.numa_node;
	struct virtio_pci_dev *vpdev = priv->vpdev;
	struct virtio_pci_dev_vring_info vr_info;
	char vq_hdr_name[VIRTQUEUE_MAX_NAME_SZ];
	char vq_name[VIRTQUEUE_MAX_NAME_SZ];
	struct virtio_hw *hw = &vpdev->hw;
	struct virtadmin_ctl *avq = NULL;
	unsigned int vq_size, size;
	struct virtqueue *vq;
	size_t sz_hdr_mz = 0;
	uint16_t queue_idx;
	int ret;

	DRV_LOG(INFO, "setting up admin queue on NUMA node %d", numa_node);

	queue_idx = priv->dev_ops->get_adminq_idx(priv);
	vq_size = virtio_pci_dev_queue_size_get(vpdev, queue_idx);
	DRV_LOG(INFO, "admin queue idx %u, queue size %u", queue_idx, vq_size);

	snprintf(vq_name, sizeof(vq_name), "vdev%d_aq%u",
		 vpdev->vfio_dev_fd, queue_idx);

	size = RTE_ALIGN_CEIL(sizeof(*vq) +
				vq_size * sizeof(struct vq_desc_extra),
				RTE_CACHE_LINE_SIZE);
	vq = rte_zmalloc_socket(vq_name, size, RTE_CACHE_LINE_SIZE,
				numa_node);
	if (vq == NULL) {
		DRV_LOG(ERR, "can not allocate admin q %u", queue_idx);
		return -ENOMEM;
	}
	hw->vqs[priv->dev_ops->get_adminq_idx(priv)] = vq;

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

	avq = &vq->aq;
	avq->mz = mz;

	/* Allocate a page for admin vq command, data and status */
	sz_hdr_mz = rte_mem_page_size();

	if (sz_hdr_mz) {
		snprintf(vq_hdr_name, sizeof(vq_hdr_name), "vdev%d_aq%u_hdr",
				vpdev->vfio_dev_fd, queue_idx);
		hdr_mz = rte_memzone_reserve_aligned(vq_hdr_name, sz_hdr_mz,
				numa_node, RTE_MEMZONE_IOVA_CONTIG,
				RTE_CACHE_LINE_SIZE);
		if (hdr_mz == NULL) {
			if (rte_errno == EEXIST)
				hdr_mz = rte_memzone_lookup(vq_hdr_name);
			if (hdr_mz == NULL) {
				ret = -ENOMEM;
				goto err_free_mz;
			}
		}
		avq->virtio_admin_hdr_mz = hdr_mz;
		avq->virtio_admin_hdr_mem = hdr_mz->iova;
		memset(avq->virtio_admin_hdr_mz->addr, 0, rte_mem_page_size());
	} else {
		DRV_LOG(ERR, "rte mem page size is zero");
		ret = -EINVAL;
		goto err_free_mz;
	}

	hw->avq = avq;

	vr_info.size  = vq_size;
	vr_info.desc  = (uint64_t)(uintptr_t)vq->vq_split.ring.desc;
	vr_info.avail = (uint64_t)(uintptr_t)vq->vq_split.ring.avail;
	vr_info.used  = (uint64_t)(uintptr_t)vq->vq_split.ring.used;
	ret = virtio_pci_dev_queue_set(vpdev, queue_idx, &vr_info);
	if (ret) {
		DRV_LOG(ERR, "setup_queue %u failed", queue_idx);
		ret = -EINVAL;
		goto err_clean_avq;
	}

	return 0;

err_clean_avq:
	hw->avq = NULL;
	rte_memzone_free(hdr_mz);
err_free_mz:
	rte_memzone_free(mz);
err_ret:
	hw->vqs[0] = NULL;
	rte_free(vq);
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
	int ret;

	priv->hw_nr_virtqs = 1;
	hw->vqs = rte_zmalloc(NULL, sizeof(struct virtqueue *) * (priv->dev_ops->get_adminq_idx(priv) + 1), 0);
	if (!hw->vqs) {
		DRV_LOG(ERR, "failed to allocate vqs");
		return -ENOMEM;
	}

	ret = virtio_vdpa_init_admin_queue(priv);
	if (ret) {
		DRV_LOG(ERR, "Failed to init admin queue for virtio device");
		rte_free(hw->vqs);
		hw->vqs = NULL;
		return ret;
	}

	return 0;
}

static int vdpa_mi_check_handler(__rte_unused const char *key,
		const char *value, void *ret_val)
{
	if (strcmp(value, VIRTIO_ARG_VDPA_VALUE_PF) == 0)
		*(int *)ret_val = 1;
	else
		*(int *)ret_val = 0;

	return 0;
}

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

static uint64_t
virtio_vdpa_get_net_dev_required_features(void)
{
	return VIRTIO_VDPA_MI_SUPPORTED_NET_FEATURES;
}

static uint16_t
virtio_vdpa_net_dev_get_adminq_idx(struct virtio_vdpa_pf_priv *priv)
{
	return virtio_pci_dev_nr_vq_get(priv->vpdev) - 1;
}

static struct virtio_vdpa_dev_ops virtio_vdpa_net_dev_ops = {
	.get_required_features = virtio_vdpa_get_net_dev_required_features,
	.get_adminq_idx = virtio_vdpa_net_dev_get_adminq_idx,
};

static int
virtio_vdpa_mi_dev_probe(struct rte_pci_driver *pci_drv __rte_unused,
		struct rte_pci_device *pci_dev)
{
	char devname[RTE_DEV_NAME_MAX_LEN] = {0};
	struct virtio_vdpa_pf_priv *priv = NULL;
	int vdpa = 0, ret;
	uint64_t features;

	RTE_VERIFY(rte_eal_iova_mode() == RTE_IOVA_VA);

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
		rte_errno = rte_errno ? rte_errno : ENODEV;
		goto error;
	}

	priv->vfio_dev_fd = rte_intr_dev_fd_get(pci_dev->intr_handle);
	if (priv->vfio_dev_fd < 0) {
		DRV_LOG(ERR, "%s failed to get vfio dev fd", devname);
		rte_errno = rte_errno ? rte_errno : ENODEV;
		goto err_free_pci_dev;
	}

	priv->dev_ops = &virtio_vdpa_net_dev_ops;
	virtio_pci_dev_features_get(priv->vpdev, &priv->device_features);
	features = priv->dev_ops->get_required_features();
	if (!(priv->device_features & features)) {
		DRV_LOG(ERR, "Device does not support feature required: device 0x%" PRIx64 \
				", required: 0x%" PRIx64, priv->device_features,
				features);
		rte_errno = rte_errno ? rte_errno : EOPNOTSUPP;
		goto err_free_pci_dev;
	}
	features = virtio_pci_dev_features_set(priv->vpdev, features);
	priv->vpdev->hw.weak_barriers = !virtio_with_feature(&priv->vpdev->hw, VIRTIO_F_ORDER_PLATFORM);
	virtio_pci_dev_set_status(priv->vpdev, VIRTIO_CONFIG_STATUS_FEATURES_OK);

	ret = virtio_vdpa_admin_queue_alloc(priv);
	if (ret) {
		DRV_LOG(ERR, "Failed to alloc admin queue for vDPA device");
		rte_errno = rte_errno ? rte_errno : -ret;
		goto err_free_pci_dev;
	}

	/* Start the device */
	virtio_pci_dev_set_status(priv->vpdev, VIRTIO_CONFIG_STATUS_DRIVER_OK);

	pthread_mutex_lock(&mi_priv_list_lock);
	TAILQ_INSERT_TAIL(&virtio_mi_priv_list, priv, next);
	pthread_mutex_unlock(&mi_priv_list_lock);
	return 0;

err_free_pci_dev:
	virtio_pci_dev_free(priv->vpdev);
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
		virtio_pci_dev_free(priv->vpdev);
		rte_free(priv);
	}
	return 0;
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
