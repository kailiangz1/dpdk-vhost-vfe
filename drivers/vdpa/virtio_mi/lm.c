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
#include <rte_vdpa.h>
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

RTE_LOG_REGISTER(virtio_vdpa_mi_logtype, pmd.vdpa.virtio, NOTICE);
#define DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, virtio_vdpa_mi_logtype, \
		"VIRTIO VDPA MI %s(): " fmt "\n", __func__, ##args)

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
