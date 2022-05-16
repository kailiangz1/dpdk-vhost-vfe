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
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_bus_pci.h>
#include <rte_vfio.h>
#include <rte_rpc.h>
#include <rte_kvargs.h>

#include <virtio_api.h>
#include <virtio_lm.h>

RTE_LOG_REGISTER(virtio_vdpa_rpc_logtype, pmd.vdpa.virtio, NOTICE);
#define RPC_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, virtio_vdpa_rpc_logtype, \
		"VIRTIO VDPA RPC %s(): " fmt "\n", __func__, ##args)

#define VDPA_MAX_ARGS_LEN 1024

static int
virtio_vdpa_rpc_pf_dev_add(const char *pf_name)
{
	if (!pf_name)
		return -EINVAL;

	if (virtio_vdpa_get_mi_by_bdf(pf_name))
		return -EEXIST;

	return rte_eal_hotplug_add("pci", pf_name, "vdpa=2");
}

static int
virtio_vdpa_rpc_pf_dev_remove(const char *pf_name)
{
	struct virtio_vdpa_pf_priv *priv;
	if (!pf_name)
		return -EINVAL;

	priv = virtio_vdpa_get_mi_by_bdf(pf_name);
	if (!priv)
		return -ENODEV;

	/* Todo: vf count checking */
	return rte_eal_hotplug_remove("pci", pf_name);
}

static int
virtio_vdpa_dump_pf(void *priv, void *filter, void *buf)
{
	struct vdpa_pf_info *pf_info = (struct vdpa_pf_info *)buf;
	struct vdpa_pf_info_priv pf_info_priv;

	if (!filter || priv == filter) {
		virtio_vdpa_get_pf_info(priv, &pf_info_priv);
		rte_pci_device_name(&pf_info_priv.pci_addr, pf_info->pf_name,
				sizeof(pf_info->pf_name));
		return sizeof(*pf_info);
	}
	return 0;
}

static int
virtio_vdpa_rpc_get_pf_list(struct vdpa_pf_info *pf_info, int max_pf_num)
{
	if (!pf_info || max_pf_num <=0)
		return -EINVAL;

	return virtio_vdpa_mi_list_dump(pf_info, max_pf_num, NULL, virtio_vdpa_dump_pf);
}

static inline bool
test_bit(uint32_t nbits, uint32_t flags)
{
	return (nbits < 32) && (((((uint32_t)1) << nbits) & flags) != 0);
}

#define VDPA_VF_MAX (VDPA_VF_MAC+1)
#define MSIX_NUM_FMT ",msix_num=%u"
#define QUEUE_NUM_FMT ",queue_num=%u"
#define QUEUE_SIZE_FMT ",queue_szie=%u"
#define FEATURES_FMT ",features=0x%" PRIx64
#define MTU_FMT ",mtu=%u"
#define MAC_FMT  ",mac=" RTE_ETHER_ADDR_PRT_FMT

static inline bool
virtio_vdpa_rpc_is_buf_enough(size_t buf_len)
{
	return (buf_len >= (strlen(MSIX_NUM_FMT) + 8)
			+ (strlen(QUEUE_NUM_FMT) + 8)
			+ (strlen(QUEUE_SIZE_FMT) + 8)
			+ (strlen(FEATURES_FMT) + 16)
			+ (strlen(MTU_FMT) + 8)
			+ (strlen(MAC_FMT) + 8)
			+ strlen(" --vfio-vf-token=ac66f09e-00d8-4609-b372-dac24a9974a9"));
}

static int
virtio_vdpa_get_vf_name_by_vfid(const char *pf_name, uint32_t vfid, char *vf_name,
		size_t vf_name_len)
{
	char vfid_path[1024];
	char link[1024];
	int ret;

	if (!pf_name || !vf_name)
		return -EINVAL;

	snprintf(vfid_path, 1024, "%s/%s/virtfn%u", rte_pci_get_sysfs_path(), pf_name, vfid - 1);
	memset(link, 0, sizeof(link));
	ret = readlink(vfid_path, link, (sizeof(link)-1));
	if ((ret < 0) || ((unsigned int)ret > (sizeof(link)-1)))
		return -ENOENT;

	strncpy(vf_name, &link[3], vf_name_len);
	RPC_LOG(DEBUG, "vfid %d, link %s, vf name: %s", vfid, link, vf_name);

	return 0;
}

static int
virtio_vdpa_rpc_pf_dev_vf_dev_add(const char *pf_name,
		struct vdpa_vf_info *vf_info)
{
	char vf_dev_args[VDPA_MAX_ARGS_LEN], *buf;
	size_t avail_len = VDPA_MAX_ARGS_LEN, len;
	char vf_name[RTE_DEV_NAME_MAX_LEN] = {0};

	if (!pf_name || !vf_info)
		return -EINVAL;

	if (!virtio_vdpa_get_mi_by_bdf(pf_name))
		return -ENODEV;

	if (virtio_vdpa_get_vf_name_by_vfid(pf_name, vf_info->vfid, vf_name,
			RTE_DEV_NAME_MAX_LEN))
		return -EINVAL;

	buf = &vf_dev_args[0];
	len = snprintf(buf, VDPA_MAX_ARGS_LEN, "vdpa=1,vfid=%u," VIRTIO_ARG_VDPA_PF "=%s",
			vf_info->vfid, pf_name);
	avail_len -= len;
	buf += len;

	if (!virtio_vdpa_rpc_is_buf_enough(avail_len)) {
		RPC_LOG(ERR, "buffer overflow while preparing devargs");
		return -EINVAL;
	}

	if (test_bit(VDPA_VF_MSIX_NUM, vf_info->modify_flags)) {
		len = snprintf(buf, avail_len, MSIX_NUM_FMT, vf_info->msix_num);
		avail_len -= len;
		buf += len;
	}

	if (test_bit(VDPA_VF_QUEUE_NUM, vf_info->modify_flags)) {
		len = snprintf(buf, avail_len, QUEUE_NUM_FMT, vf_info->queue_num);
		avail_len -= len;
		buf += len;
	}

	if (test_bit(VDPA_VF_QUEUE_SZIE, vf_info->modify_flags)) {
		len = snprintf(buf, avail_len, QUEUE_SIZE_FMT, vf_info->queue_size);
		avail_len -= len;
		buf += len;
	}

	if (test_bit(VDPA_VF_FEATURES, vf_info->modify_flags)) {
		len = snprintf(buf, avail_len, FEATURES_FMT, vf_info->features);
		avail_len -= len;
		buf += len;
	}

	if (test_bit(VDPA_VF_MTU, vf_info->modify_flags)) {
		len = snprintf(buf, avail_len, MTU_FMT, vf_info->mtu);
		avail_len -= len;
		buf += len;
	}

	if (test_bit(VDPA_VF_MAC, vf_info->modify_flags)) {
		len = snprintf(buf, avail_len, MAC_FMT,
				RTE_ETHER_ADDR_BYTES(&vf_info->mac));
		avail_len -= len;
		buf += len;
	}

	return rte_eal_hotplug_add("pci", vf_name, vf_dev_args);
}

static int
virtio_vdpa_rpc_pf_dev_vf_dev_remove(const char *pf_name, uint32_t vfid)
{
	char vf_name[RTE_DEV_NAME_MAX_LEN] = {0};

	if (!pf_name)
		return -EINVAL;

	if (!virtio_vdpa_get_mi_by_bdf(pf_name))
		return -ENODEV;

	if (virtio_vdpa_get_vf_name_by_vfid(pf_name, vfid, vf_name,
			RTE_DEV_NAME_MAX_LEN))
		return -EINVAL;

	return rte_eal_hotplug_remove("pci", vf_name);
}

static int
virtio_vdpa_dump_vf_under_pf(void *priv, void *filter, void *buf)
{
	struct vdpa_vf_info *vf_info = (struct vdpa_vf_info *)buf;
	struct vdpa_vf_info_priv vf_info_priv;


	if (!filter || is_mi_pf(priv, filter)) {
		virtio_vdpa_get_vf_info(priv, &vf_info_priv);
		rte_pci_device_name(&vf_info_priv.pci_addr, vf_info->vf_name,
				sizeof(vf_info->vf_name));
		vf_info->queue_num = vf_info_priv.queue_num;
		vf_info->queue_size = vf_info_priv.queue_size;
		vf_info->features = vf_info_priv.features;

		return sizeof(*vf_info);
	}
	return 0;
}

static int
virtio_vdpa_rpc_get_vf_list(const char *pf_name, struct vdpa_vf_info *vf_info,
		int max_vf_num)
{
	if (!pf_name || !vf_info || max_vf_num <=0)
		return -EINVAL;

	struct virtio_vdpa_pf_priv *priv = virtio_vdpa_get_mi_by_bdf(pf_name);
	if (!priv)
		return -ENODEV;

	return virtio_vdpa_dev_list_dump(vf_info, max_vf_num, (void *)priv,
			virtio_vdpa_dump_vf_under_pf);
}

static int
virtio_vdpa_dump_vf_by_pci_addr(void *priv, void *filter, void *buf)
{
	struct vdpa_vf_info *vf_info = (struct vdpa_vf_info *)buf;
	struct rte_pci_addr *addr = (struct rte_pci_addr *)filter;
	struct vdpa_vf_info_priv vf_info_priv;

	virtio_vdpa_get_vf_info(priv, &vf_info_priv);
	if (rte_pci_addr_cmp(&vf_info_priv.pci_addr, addr) == 0) {
		rte_pci_device_name(&vf_info_priv.pci_addr, vf_info->vf_name,
				sizeof(vf_info->vf_name));
		vf_info->queue_num = vf_info_priv.queue_num;
		vf_info->queue_size = vf_info_priv.queue_size;
		vf_info->features = vf_info_priv.features;

		return sizeof(*vf_info);
	}
	return 0;
}

static int
virtio_vdpa_rpc_get_vf_info(const char *pf_name, uint32_t vfid, struct vdpa_vf_info *vf_info)
{
	char vf_name[RTE_DEV_NAME_MAX_LEN] = {0};
	struct rte_pci_addr addr;

	if (!pf_name || !vf_info)
		return -EINVAL;

	if (!virtio_vdpa_get_mi_by_bdf(pf_name))
		return -ENODEV;

	if (virtio_vdpa_get_vf_name_by_vfid(pf_name, vfid, vf_name,
			RTE_DEV_NAME_MAX_LEN))
		return -EINVAL;

	if (rte_pci_addr_parse(vf_name, &addr))
		return -EINVAL;

	return virtio_vdpa_dev_list_dump(vf_info, 1, (void *)&addr,
			virtio_vdpa_dump_vf_by_pci_addr);
}

RTE_INIT(virtio_vdpa_rpc_init)
{
	struct rte_rpc_vdpa_global_ops vdpa_rpc_ops = {
		.pf_dev_add	       = virtio_vdpa_rpc_pf_dev_add,
		.pf_dev_remove	       = virtio_vdpa_rpc_pf_dev_remove,
		.get_pf_list	       = virtio_vdpa_rpc_get_pf_list,
		.pf_dev_vf_dev_add     = virtio_vdpa_rpc_pf_dev_vf_dev_add,
		.pf_dev_vf_dev_remove  = virtio_vdpa_rpc_pf_dev_vf_dev_remove,
		.get_vf_list	       = virtio_vdpa_rpc_get_vf_list,
		.get_vf_info	       = virtio_vdpa_rpc_get_vf_info,
	};
	rte_rpc_vdpa_global_ops_init(&vdpa_rpc_ops);
}

