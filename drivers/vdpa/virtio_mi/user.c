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
#include "lm.h"

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

static int
virtio_vdpa_rpc_vf_dev_prov(const char *pf_name, uint32_t vfid,
			struct vdpa_vf_params *vf_params)
{
	if (!pf_name || !vf_params)
		return -EINVAL;

	if (!virtio_vdpa_get_mi_by_bdf(pf_name))
		return -ENODEV;

	if (test_bit(VDPA_VF_MSIX_NUM, vf_params->prov_flags)) {
		;
	}

	if (test_bit(VDPA_VF_QUEUE_NUM, vf_params->prov_flags)) {
		;
	}

	if (test_bit(VDPA_VF_QUEUE_SIZE, vf_params->prov_flags)) {
		;
	}

	if (test_bit(VDPA_VF_FEATURES, vf_params->prov_flags)) {
		;
	}

	if (test_bit(VDPA_VF_MTU, vf_params->prov_flags)) {
		;
	}

	if (test_bit(VDPA_VF_MAC, vf_params->prov_flags)) {
		;
	}

	return 0;
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
virtio_vdpa_rpc_pf_dev_vf_dev_add(const char *pf_name, uint32_t vfid,
		struct vdpa_vf_params *vf_params __rte_unused)
{
	char vf_dev_args[VDPA_MAX_ARGS_LEN], *buf;
	char vf_name[RTE_DEV_NAME_MAX_LEN] = {0};

	if (!pf_name)
		return -EINVAL;

	if (!virtio_vdpa_get_mi_by_bdf(pf_name))
		return -ENODEV;

	if (virtio_vdpa_get_vf_name_by_vfid(pf_name, vfid, vf_name,
			RTE_DEV_NAME_MAX_LEN))
		return -EINVAL;

	buf = &vf_dev_args[0];
	snprintf(buf, VDPA_MAX_ARGS_LEN, VIRTIO_ARG_VDPA "=1," \
			VIRTIO_ARG_VDPA_VFID "=%u," VIRTIO_ARG_VDPA_PF "=%s",
			vfid, pf_name);

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
		vf_info->vfid = vf_info_priv.vfid;
		rte_pci_device_name(&vf_info_priv.pci_addr, vf_info->vf_params.vf_name,
				sizeof(vf_info->vf_params.vf_name));
		vf_info->vf_params.queue_num = vf_info_priv.queue_num;
		vf_info->vf_params.queue_size = vf_info_priv.queue_size;
		vf_info->vf_params.features = vf_info_priv.features;

		return sizeof(*vf_info);
	}
	return 0;
}

static int
virtio_vdpa_rpc_get_vf_list(const char *pf_name, struct vdpa_vf_info *vf_info,
		int max_vf_num)
{
	struct virtio_vdpa_pf_priv *priv;

	if (!pf_name || !vf_info || max_vf_num <=0)
		return -EINVAL;

	priv = virtio_vdpa_get_mi_by_bdf(pf_name);
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
		vf_info->vfid = vf_info_priv.vfid;
		rte_pci_device_name(&vf_info_priv.pci_addr, vf_info->vf_params.vf_name,
				sizeof(vf_info->vf_params.vf_name));
		vf_info->vf_params.queue_num = vf_info_priv.queue_num;
		vf_info->vf_params.queue_size = vf_info_priv.queue_size;
		vf_info->vf_params.features = vf_info_priv.features;

		return sizeof(*vf_info);
	}
	return 0;
}

static int
virtio_vdpa_rpc_get_vf_info(const char *pf_name, uint32_t vfid,
		struct vdpa_vf_info *vf_info)
{
	char vf_name[RTE_DEV_NAME_MAX_LEN] = {0};
	struct rte_pci_addr addr;
	int ret;

	if (!pf_name || !vf_info)
		return -EINVAL;

	if (!virtio_vdpa_get_mi_by_bdf(pf_name))
		return -ENODEV;

	if (virtio_vdpa_get_vf_name_by_vfid(pf_name, vfid, vf_name,
			RTE_DEV_NAME_MAX_LEN))
		return -EINVAL;

	if (rte_pci_addr_parse(vf_name, &addr))
		return -EINVAL;

	ret = virtio_vdpa_dev_list_dump(vf_info, 1, (void *)&addr,
			virtio_vdpa_dump_vf_by_pci_addr);
	if (ret == 0)
		return -ENODEV;

	return (ret < 0 ? ret : 0);
}

#ifdef RTE_LIBRTE_VDPA_DEBUG
#define VIRTIO_VDPA_DEBUG_PAGE_SIZE (4096)
#define VIRTIO_VDPA_DEBUG_MZONE_LEN (4*1024*1024)

static inline unsigned int
log2above(unsigned int v)
{
	unsigned int l;
	unsigned int r;

	for (l = 0, r = 0; (v >> 1); ++l, v >>= 1)
		r |= (v & 1);
	return l + r;
}

#define ONES32(size) \
	((size) ? (0xffffffff >> (32 - (size))) : 0xffffffff)

#define ROUND_DOWN_BITS(source, num_bits) \
	((source >> num_bits) << num_bits)

#define ROUND_UP_BITS(source, num_bits) \
	(ROUND_DOWN_BITS((source + ((1 << num_bits) - 1)), num_bits))

#define DIV_ROUND_UP_BITS(source, num_bits) \
	(ROUND_UP_BITS(source, num_bits) >> num_bits)

static int
virtio_vdpa_rpc_check_dirty_logging(uint64_t dirty_addr, uint32_t dirty_len,
		uint8_t *log_base, uint32_t log_size, /* (iova, len) in start loging sge[0] */
		uint16_t mode, uint32_t guest_page_size) /*vm used page size*/
{
	uint32_t log_log_page_size = log2above(guest_page_size);
	uint32_t page_offset = dirty_addr & ONES32(log_log_page_size);
	uint64_t start_page = (dirty_addr >> log_log_page_size);
	uint32_t num_pages, num_of_bytes = 0;
	uint8_t  written_data = 0;
	uint32_t byte_offset =	0;
	uint64_t start_byte = 0, i;

	num_pages = DIV_ROUND_UP_BITS(dirty_len + page_offset,
						      log_log_page_size);

	switch (mode) {
	case VIRTIO_M_DIRTY_TRACK_PUSH_BITMAP:
	case VIRTIO_M_DIRTY_TRACK_PULL_BITMAP:
		byte_offset = start_page & ONES32(3);
		num_of_bytes = DIV_ROUND_UP_BITS(num_pages + byte_offset, 3);
		start_byte = start_page >> 3;
		written_data = 0xff;
		break;
	case VIRTIO_M_DIRTY_TRACK_PUSH_BYTEMAP:
	case VIRTIO_M_DIRTY_TRACK_PULL_BYTEMAP:
		num_of_bytes = num_pages;
		start_byte = start_page;
		written_data = 0x1;
		break;
	default:
		RPC_LOG(ERR, "check_dirty_logging failed<<<<Unsurpported map mode>>>>");
		return -EOPNOTSUPP;
	}

	if ((start_byte + num_of_bytes) > log_size) {
		RPC_LOG(ERR, "check_dirty_logging failed<<<<Too many pages>>>>");
		return -EINVAL;
	}
	/*check*/
	for (i = 0; i < num_of_bytes; i++)
		if (log_base[start_byte + i] != written_data) {
			RPC_LOG(ERR, "check_dirty_logging failed<<<<Byte[%" PRIu64 "] should be 0x%x, actual is [%u]>>>>",
					start_byte + i, written_data, log_base[start_byte + i]);
			return -EINVAL;
		}

	return 0;
}

static int
virtio_vdpa_rpc_debug(const char *pf_name,
		struct vdpa_debug_vf_info *vf_debug_info)
{
	static const struct rte_memzone *vdpa_dp_mz = NULL;
	char vf_name[RTE_DEV_NAME_MAX_LEN];
	struct virtio_vdpa_pf_priv *priv;
	struct virtio_vdpa_priv *vf_priv;
	struct vdpa_debug_info info;
	uint16_t queue_num;
	int ret, i;

	if (!pf_name || !vf_debug_info)
		return -EINVAL;

	RPC_LOG(ERR, "vdev_id: %u, cmd: %u", vf_debug_info->vfid, vf_debug_info->test_type);

	priv = virtio_vdpa_get_mi_by_bdf(pf_name);
	if (!priv)
		return -ENODEV;

	if (virtio_vdpa_get_vf_name_by_vfid(pf_name, vf_debug_info->vfid,
			vf_name,
			RTE_DEV_NAME_MAX_LEN))
			return -EINVAL;

	info.vfid = vf_debug_info->vfid;
	if (vf_debug_info->test_type == VDPA_DEBUG_CMD_START_LOGGING) {
		uint32_t unit = 1;

		RPC_LOG(ERR, "\ttrack_mode: %u", vf_debug_info->test_mode);
		if (!vdpa_dp_mz) {
			if (!vdpa_dp_mz) {
				vdpa_dp_mz = rte_memzone_reserve_aligned("VIRTIO_VDPA_DEBUG_DP_MZ",
						VIRTIO_VDPA_DEBUG_MZONE_LEN,
						rte_socket_id(), RTE_MEMZONE_IOVA_CONTIG,
						VIRTIO_VRING_ALIGN);
			}
			RTE_VERIFY(vdpa_dp_mz);
		}

		info.track_mode = vf_debug_info->test_mode;
		info.page_size = VIRTIO_VDPA_DEBUG_PAGE_SIZE;
		info.range_addr = 0;
		info.range_length = vf_debug_info->mem_size;
		if ((info.track_mode == VIRTIO_M_DIRTY_TRACK_PUSH_BITMAP ||
				info.track_mode == VIRTIO_M_DIRTY_TRACK_PULL_BITMAP))
			unit = 8;
		info.num_sges = 1;
		info.data[0].addr = vdpa_dp_mz->iova;
		info.data[0].len = info.range_length/(info.page_size * unit);
		RPC_LOG(DEBUG, "range_length[%" PRIu64 "]/(page_size[%u] * unit[%u]) = %u",
				info.range_length, info.page_size, unit, info.data[0].len);
		if(!info.data[0].len) {
			RPC_LOG(ERR, "<<<<Invalid map len>>>>");
			ret = -EINVAL;
			goto err_free_mz;
		}
	}

	ret = virtio_vdpa_debug(priv, vf_debug_info->test_type, &info);
	if (vf_debug_info->test_type != VDPA_DEBUG_CMD_STOP_LOGGING)
		return ret;

	vf_priv = virtio_vdpa_find_priv_resource_by_name(vf_name);
	RTE_VERIFY(vf_priv);
	queue_num = virtio_vdpa_dev_nr_vq_get(vf_priv);
	for (i = 0; i < queue_num; i++) {
		uint64_t dirty_addr;
		uint32_t dirty_len;
		ret = 0;

		if (!virtio_vdpa_dirty_desc_get(vf_priv, i, &dirty_addr, &dirty_len)) {
			ret = virtio_vdpa_rpc_check_dirty_logging(dirty_addr, dirty_len,
					vdpa_dp_mz->addr, info.data[0].len,
					info.track_mode, info.page_size);
			if (ret)
				break;
		}

		if (!virtio_vdpa_used_vring_addr_get(vf_priv, i, &dirty_addr, &dirty_len)) {
			ret = virtio_vdpa_rpc_check_dirty_logging(dirty_addr, dirty_len,
					vdpa_dp_mz->addr, info.data[0].len,
					info.track_mode, info.page_size);
			if (ret)
				break;
		}
	}

err_free_mz:
	if (vdpa_dp_mz) {
		rte_memzone_free(vdpa_dp_mz);
		vdpa_dp_mz = NULL;
	}
	return ret;
}
#endif

RTE_INIT(virtio_vdpa_rpc_init)
{
	struct rte_rpc_vdpa_global_ops vdpa_rpc_ops = {
		.pf_dev_add	       = virtio_vdpa_rpc_pf_dev_add,
		.pf_dev_remove	       = virtio_vdpa_rpc_pf_dev_remove,
		.get_pf_list	       = virtio_vdpa_rpc_get_pf_list,
		.pf_dev_vf_dev_prov    = virtio_vdpa_rpc_vf_dev_prov,
		.pf_dev_vf_dev_add     = virtio_vdpa_rpc_pf_dev_vf_dev_add,
		.pf_dev_vf_dev_remove  = virtio_vdpa_rpc_pf_dev_vf_dev_remove,
		.get_vf_list	       = virtio_vdpa_rpc_get_vf_list,
		.get_vf_info	       = virtio_vdpa_rpc_get_vf_info,
#ifdef RTE_LIBRTE_VDPA_DEBUG
		.debug_vf_info	       = virtio_vdpa_rpc_debug,
#endif
	};

	rte_rpc_vdpa_global_ops_init(&vdpa_rpc_ops);
}

