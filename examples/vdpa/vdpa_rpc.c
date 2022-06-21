/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022, NVIDIA CORPORATION & AFFILIATES.
 */

#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_vhost.h>
#include <rte_vdpa.h>
#include <rte_pci.h>
#include <rte_string_fns.h>
#include <rte_rpc.h>

#include <jsonrpc-c.h>
#include <jsonrpc-client.h>
#include "vdpa_rpc.h"

/* VDPA RPC */
/* For string conversion */
char string[MAX_JSON_STRING_LEN];

#define JSON_STR_NUM_TO_OBJ(obj, str, format, num) do { \
	memset(string, 0, MAX_JSON_STRING_LEN); \
	snprintf(string, MAX_JSON_STRING_LEN, format, num); \
	cJSON_AddStringToObject(obj, str, string); } while(0) \

#define JSON_NUM_STR_TO_OBJ(obj, num, format, str) do { \
	memset(string, 0, MAX_JSON_STRING_LEN); \
	snprintf(string, MAX_JSON_STRING_LEN, format, num); \
	cJSON_AddStringToObject(obj, string, str); } while(0) \

/* Size defined by VIRTNET_FEATURE_SZ */
const char *feature_names[] = {
	[VIRTIO_NET_F_CSUM]		= "VIRTIO_NET_F_CSUM",
	[VIRTIO_NET_F_GUEST_CSUM]	= "VIRTIO_NET_F_GUEST_CSUM",
	[VIRTIO_NET_F_MTU]		= "VIRTIO_NET_F_MTU",
	[VIRTIO_NET_F_GSO]		= "VIRTIO_NET_F_GSO",
	[VIRTIO_NET_F_MAC]		= "VIRTIO_NET_F_MAC",
	[VIRTIO_NET_F_GUEST_TSO4]	= "VIRTIO_NET_F_GUEST_TSO4",
	[VIRTIO_NET_F_GUEST_TSO6]	= "VIRTIO_NET_F_GUEST_TSO6",
	[VIRTIO_NET_F_GUEST_ECN]	= "VIRTIO_NET_F_GUEST_ECN",
	[VIRTIO_NET_F_GUEST_UFO]	= "VIRTIO_NET_F_GUEST_UFO",
	[VIRTIO_NET_F_HOST_TSO4]	= "VIRTIO_NET_F_HOST_TSO4",
	[VIRTIO_NET_F_HOST_TSO6]	= "VIRTIO_NET_F_HOST_TSO6",
	[VIRTIO_NET_F_HOST_ECN]		= "VIRTIO_NET_F_HOST_ECN",
	[VIRTIO_NET_F_HOST_UFO]		= "VIRTIO_NET_F_HOST_UFO",
	[VIRTIO_NET_F_MRG_RXBUF]	= "VIRTIO_NET_F_MRG_RXBUF",
	[VIRTIO_NET_F_STATUS]		= "VIRTIO_NET_F_STATUS",
	[VIRTIO_NET_F_CTRL_VQ]		= "VIRTIO_NET_F_CTRL_VQ",
	[VIRTIO_NET_F_CTRL_RX]		= "VIRTIO_NET_F_CTRL_RX",
	[VIRTIO_NET_F_CTRL_VLAN]	= "VIRTIO_NET_F_CTRL_VLAN",
	[VIRTIO_NET_F_CTRL_RX_EXTRA]	= "VIRTIO_NET_F_CTRL_RX_EXTRA",
	[VIRTIO_NET_F_GUEST_ANNOUNCE]	= "VIRTIO_NET_F_GUEST_ANNOUNCE",
	[VIRTIO_NET_F_MQ]		= "VIRTIO_NET_F_MQ",
	[VIRTIO_NET_F_CTRL_MAC_ADDR]	= "VIRTIO_NET_F_CTRL_MAC_ADDR",
	[VIRTIO_F_NOTIFY_ON_EMPTY]	= "VIRTIO_F_NOTIFY_ON_EMPTY",
	[VIRTIO_F_ANY_LAYOUT]		= "VIRTIO_F_ANY_LAYOUT",
	[VIRTIO_F_VERSION_1]		= "VIRTIO_F_VERSION_1",
	[VIRTIO_F_IOMMU_PLATFORM]	= "VIRTIO_F_IOMMU_PLATFORM",
};

static void vdpa_rpc_get_info(cJSON *obj, uint64_t val, const char **info,
			     uint16_t size)
{
	int i;

	JSON_STR_NUM_TO_OBJ(obj, "value", "0x%lx", val);
	for (i = 0; i < size; i++) {
		if (!(val & (1ULL << i)))
			continue;
		JSON_NUM_STR_TO_OBJ(obj, i, "%5d", info[i]);
	}
}

static cJSON *vdpa_pf_dev_add(const char *pf_name)
{
	cJSON *result = cJSON_CreateObject();

	if (rte_vdpa_pf_dev_add(pf_name))
		cJSON_AddStringToObject(result, "Error",
			"Fail to add PF device");
	else
		cJSON_AddStringToObject(result, "Success",
				pf_name);
	return result;
}

static cJSON *vdpa_pf_dev_remove(const char *pf_name)
{
	cJSON *result = cJSON_CreateObject();

	if (rte_vdpa_pf_dev_remove(pf_name))
		cJSON_AddStringToObject(result, "Error",
			"Fail to remove PF device");
	else
		cJSON_AddStringToObject(result, "Success",
				pf_name);
	return result;
}

static cJSON *vdpa_pf_dev_list(void)
{
	cJSON *result = cJSON_CreateObject();
	cJSON *devices = cJSON_CreateArray();
	struct vdpa_pf_info *pf_info = NULL;
	cJSON *device = NULL;
	int max_pf_num, i;

	pf_info = rte_zmalloc(NULL,
		sizeof(struct vdpa_pf_info) * MAX_VDPA_SAMPLE_PORTS, 0);
	max_pf_num = rte_vdpa_get_pf_list(pf_info, MAX_VDPA_SAMPLE_PORTS);
	if (max_pf_num <= 0) {
		cJSON_AddStringToObject(result, "Error",
			"Fail to dump all PF devices");
		rte_free(pf_info);
		return result;
	}
	if (max_pf_num > MAX_VDPA_SAMPLE_PORTS) {
		cJSON_AddStringToObject(result, "Warning",
			"PF devices number more than 1024");
		max_pf_num = MAX_VDPA_SAMPLE_PORTS;
	}
	for (i = 0; i < max_pf_num; i++) {
		device = cJSON_CreateObject();
		cJSON_AddStringToObject(device, "pf", pf_info[i].pf_name);
		cJSON_AddItemToArray(devices, device);
	}
	cJSON_AddItemToObject(result, "devices", devices);
	rte_free(pf_info);
	return result;
}

static cJSON *mgmtpf(jrpc_context *ctx, cJSON *params, cJSON *id)
{
	cJSON *pf_add = cJSON_GetObjectItem(params, "add");
	cJSON *pf_remove = cJSON_GetObjectItem(params, "remove");
	cJSON *pf_list = cJSON_GetObjectItem(params, "list");
	cJSON *pf_dev = cJSON_GetObjectItem(params, "dev");
	cJSON *result = NULL;
	struct vdpa_rpc_context *rpc_ctx;

	rpc_ctx = (struct vdpa_rpc_context *)ctx->data;
	pthread_mutex_lock(&rpc_ctx->rpc_lock);
	if (pf_add && pf_dev) {
		/* Parse PCI device name*/
		result = vdpa_pf_dev_add(pf_dev->valuestring);
	} else if (pf_remove && pf_dev) {
		/* Parse PCI device name*/
		result = vdpa_pf_dev_remove(pf_dev->valuestring);
	} else if (pf_list) {
		result = vdpa_pf_dev_list();
	}
	if (!result) {
		result = cJSON_CreateObject();
		cJSON_AddStringToObject(result, "Error",
			"Invalid pf parameters in RPC message");
		cJSON_AddItemToObject(result, "id", id);
	}
	pthread_mutex_unlock(&rpc_ctx->rpc_lock);
	return result;
}

static cJSON *vdpa_vf_dev_prov(const char *pf_name, uint32_t vfid,
			struct vdpa_vf_params *vf_params)
{
	struct vdpa_vf_info vf_info = {0};
	cJSON *result = cJSON_CreateObject();

	if (!rte_vdpa_get_vf_info(pf_name, vfid, &vf_info)) {
		cJSON_AddStringToObject(result, "Error",
		"VF device is already existed");
		return result;
	}
	if (rte_vdpa_pf_dev_vf_dev_prov(pf_name, vfid, vf_params)) {
		cJSON_AddStringToObject(result, "Error",
			"Fail to add VF device");
		return result;
	}
	cJSON_AddStringToObject(result, "Success",
				pf_name);
	return result;
}

static cJSON *vdpa_vf_dev_add(const char *pf_name, uint32_t vfid,
			struct vdpa_vf_params *vf_params)
{
	struct vdpa_vf_info vf_info = {0};
	cJSON *result = cJSON_CreateObject();

	if (rte_vdpa_pf_dev_vf_dev_add(pf_name, vfid, vf_params)) {
		cJSON_AddStringToObject(result, "Error",
			"Fail to add VF device");
		return result;
	}
	if (rte_vdpa_get_vf_info(pf_name, vfid, &vf_info)) {
		cJSON_AddStringToObject(result, "Error",
		"Fail to find VF device");
		return result;
	}
	if (vdpa_with_socket_path_start(vf_info.vf_params.vf_name)) {
		cJSON_AddStringToObject(result, "Error",
		"Fail to start socket for VF device");
		return result;
	}
	cJSON_AddStringToObject(result, "Success",
				vf_info.vf_params.vf_name);
	return result;
}

static cJSON *vdpa_vf_dev_remove(const char *pf_name, uint32_t vfid)
{
	cJSON *result = cJSON_CreateObject();

	if (rte_vdpa_pf_dev_vf_dev_remove(pf_name, vfid))
		cJSON_AddStringToObject(result, "Error",
			"Fail to remove VF device");
	else
		cJSON_AddStringToObject(result, "Success",
				pf_name);
	return result;
}

static void vdpa_vf_info_reformat(cJSON *device, struct vdpa_vf_info *vf_info)
{
	cJSON *device_feature = cJSON_CreateObject();
	char mac_string[MAX_PATH_LEN] = {0};
	uint8_t *addr_bytes = vf_info->vf_params.mac.addr_bytes;

	JSON_STR_NUM_TO_OBJ(device, "vfid", "%u", vf_info->vfid);
	cJSON_AddStringToObject(device, "vf", vf_info->vf_params.vf_name);
	JSON_STR_NUM_TO_OBJ(device, "msix_num", "%u",
				vf_info->vf_params.msix_num);
	JSON_STR_NUM_TO_OBJ(device, "queue_num", "%u",
				vf_info->vf_params.queue_num);
	JSON_STR_NUM_TO_OBJ(device, "queue_size", "%u",
				vf_info->vf_params.queue_size);
	vdpa_rpc_get_info(device_feature,  vf_info->vf_params.features,
			feature_names, VIRTNET_FEATURE_SZ);
	cJSON_AddItemToObject(device, "device_feature", device_feature);
	JSON_STR_NUM_TO_OBJ(device, "mtu", "%u", vf_info->vf_params.mtu);
	snprintf(mac_string, MAX_PATH_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
		addr_bytes[0], addr_bytes[1], addr_bytes[2],
		addr_bytes[3], addr_bytes[4], addr_bytes[5]);
	cJSON_AddStringToObject(device, "mac", mac_string);
}

static cJSON *vdpa_vf_dev_info(const char *pf_name, uint32_t vfid)
{
	cJSON *result = cJSON_CreateObject();
	struct vdpa_vf_info vf_info = {0};
	cJSON *device = NULL;

	if (rte_vdpa_get_vf_info(pf_name, vfid, &vf_info)) {
		cJSON_AddStringToObject(result, "Error",
			"Fail to dump all VF devices");
		return result;
	}
	device = cJSON_CreateObject();
	vdpa_vf_info_reformat(device, &vf_info);
	cJSON_AddItemToObject(result, "device", device);
	return result;
}

static cJSON *vdpa_vf_dev_list(const char *pf_name)
{
	cJSON *result = cJSON_CreateObject();
	cJSON *devices = cJSON_CreateArray();
	struct vdpa_vf_info *vf_info = NULL;
	cJSON *device = NULL;
	int max_vf_num, i;

	vf_info = rte_zmalloc(NULL,
		sizeof(struct vdpa_vf_info) * MAX_VDPA_SAMPLE_PORTS, 0);
	max_vf_num = rte_vdpa_get_vf_list(pf_name, vf_info,
			MAX_VDPA_SAMPLE_PORTS);
	if (max_vf_num <= 0) {
		cJSON_AddStringToObject(result, "Error",
			"Fail to dump all VF devices");
		rte_free(vf_info);
		return result;
	}
	if (max_vf_num > MAX_VDPA_SAMPLE_PORTS) {
		cJSON_AddStringToObject(result, "Warning",
			"VF devices number more than 1024");
		max_vf_num = MAX_VDPA_SAMPLE_PORTS;
	}
	for (i = 0; i < max_vf_num; i++) {
		device = cJSON_CreateObject();
		vdpa_vf_info_reformat(device, &vf_info[i]);
		cJSON_AddItemToArray(devices, device);
	}
	cJSON_AddItemToObject(result, "devices", devices);
	rte_free(vf_info);
	return result;
}

#ifdef RTE_LIBRTE_VDPA_DEBUG
static cJSON *vdpa_vf_dev_debug(const char *pf_name,
		struct vdpa_debug_vf_info *vf_debug_info)
{
	struct vdpa_vf_info vf_info = {0};
	cJSON *result = cJSON_CreateObject();

	if (rte_vdpa_get_vf_info(pf_name, vf_debug_info->vfid, &vf_info)) {
		cJSON_AddStringToObject(result, "Error",
		"Fail to find VF device");
		return result;
	}
	if (rte_vdpa_vf_dev_debug(pf_name, vf_debug_info)) {
		cJSON_AddStringToObject(result, "Error",
		"Fail to debug VF device");
		return result;
	}
	cJSON_AddStringToObject(result, "Success",
				vf_info.vf_params.vf_name);
	return result;
}
#endif

static cJSON *mgmtvf(jrpc_context *ctx, cJSON *params, cJSON *id)
{
	cJSON *vf_prov = cJSON_GetObjectItem(params, "provision");
	cJSON *vf_add = cJSON_GetObjectItem(params, "add");
	cJSON *vf_remove = cJSON_GetObjectItem(params, "remove");
	cJSON *vf_list = cJSON_GetObjectItem(params, "list");
	cJSON *vf_info_input = cJSON_GetObjectItem(params, "info");
	cJSON *vf_id = cJSON_GetObjectItem(params, "vfid");
	cJSON *pf_dev = cJSON_GetObjectItem(params, "mgmtpf");
#ifdef RTE_LIBRTE_VDPA_DEBUG
	cJSON *vf_debug = cJSON_GetObjectItem(params, "debug");
#endif
	cJSON *result = NULL;
	struct vdpa_rpc_context *rpc_ctx;

	rpc_ctx = (struct vdpa_rpc_context *)ctx->data;
	pthread_mutex_lock(&rpc_ctx->rpc_lock);
	if (vf_prov && vf_id && pf_dev) {
		struct vdpa_vf_params vf_params = {0};
		cJSON *msix_num = cJSON_GetObjectItem(params, "msix_num");
		cJSON *queue_num = cJSON_GetObjectItem(params, "queue_num");
		cJSON *queue_size = cJSON_GetObjectItem(params, "queue_size");
		cJSON *features = cJSON_GetObjectItem(params, "device_feature");
		cJSON *mtu = cJSON_GetObjectItem(params, "mtu");
		cJSON *mac = cJSON_GetObjectItem(params, "mac");
		uint8_t *addr_bytes = vf_params.mac.addr_bytes;

		/* Parse PCI device name*/
		vf_params.prov_flags = 0;
		if (msix_num) {
			vf_params.prov_flags |= (1 << VDPA_VF_MSIX_NUM);
			vf_params.msix_num = msix_num->valueint;
		}
		if (queue_num) {
			vf_params.prov_flags |= (1 << VDPA_VF_QUEUE_NUM);
			vf_params.queue_num = queue_num->valueint;
		}
		if (queue_size) {
			vf_params.prov_flags |= (1 << VDPA_VF_QUEUE_SIZE);
			vf_params.queue_size = queue_size->valueint;
		}
		if (features) {
			vf_params.prov_flags |= (1 << VDPA_VF_FEATURES);
			vf_params.features = features->valueint;
		}
		if (mtu) {
			vf_params.prov_flags |= (1 << VDPA_VF_MTU);
			vf_params.mtu = mtu->valueint;
		}
		if (mac) {
			vf_params.prov_flags |= (1 << VDPA_VF_MAC);
			sscanf(mac->valuestring,
			"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&addr_bytes[0], &addr_bytes[1], &addr_bytes[2],
			&addr_bytes[3], &addr_bytes[4], &addr_bytes[5]);
		}
		result = vdpa_vf_dev_prov(pf_dev->valuestring,
				vf_id->valueint, &vf_params);
	} else if (vf_add && vf_id && pf_dev) {
		result = vdpa_vf_dev_add(pf_dev->valuestring,
				vf_id->valueint, NULL);
	} else if (vf_remove && vf_id && pf_dev) {
		/* Parse PCI device name*/
		result = vdpa_vf_dev_remove(pf_dev->valuestring,
				vf_id->valueint);
	} else if (vf_list && pf_dev) {
		result = vdpa_vf_dev_list(pf_dev->valuestring);
	} else if (vf_info_input && vf_id && pf_dev) {
		/* Parse PCI device name*/
		result = vdpa_vf_dev_info(pf_dev->valuestring,
				vf_id->valueint);
#ifdef RTE_LIBRTE_VDPA_DEBUG
	} else if (vf_debug && vf_id && pf_dev) {
		struct vdpa_debug_vf_info vf_debug_info = {0};
		cJSON *test_operation = cJSON_GetObjectItem(params, "test_operation");

		vf_debug_info.vfid = vf_id->valueint;
		vf_debug_info.test_type = test_operation->valueint;
		if (vf_debug_info.test_type >= VDPA_DEBUG_CMD_MAX_INVALID ||
			vf_debug_info.test_type == VDPA_DEBUG_CMD_INVALID) {
				goto error_vf;
		}
		if (vf_debug_info.test_type == VDPA_DEBUG_CMD_START_LOGGING) {
			cJSON *size_mode = cJSON_GetObjectItem(params, "size_mode");
			cJSON *mem_size = cJSON_GetObjectItem(params, "mem_size");

			vf_debug_info.test_mode = size_mode->valueint;
			vf_debug_info.mem_size = mem_size->valueint;
		}
		result = vdpa_vf_dev_debug(pf_dev->valuestring,
				&vf_debug_info);
	}
error_vf:
#else
	}
#endif
	if (!result) {
		result = cJSON_CreateObject();
		cJSON_AddStringToObject(result, "Error",
			"Invalid vf parameters in RPC message");
		cJSON_AddItemToObject(result, "id", id);
	}
	pthread_mutex_unlock(&rpc_ctx->rpc_lock);
	return result;
}

static void *vdpa_rpc_handler(void *ctx)
{
	struct vdpa_rpc_context *rpc_ctx;

	rpc_ctx = (struct vdpa_rpc_context *)ctx;
	jrpc_server_init(&rpc_ctx->rpc_server, VDPA_RPC_PORT);
	jrpc_register_procedure(&rpc_ctx->rpc_server, mgmtpf, "mgmtpf", ctx);
	jrpc_register_procedure(&rpc_ctx->rpc_server, mgmtvf, "vf", ctx);
	jrpc_server_run(&rpc_ctx->rpc_server);
	pthread_exit(NULL);
}

int
vdpa_rpc_start(struct vdpa_rpc_context *rpc_ctx)
{
	const struct sched_param sp = {
		.sched_priority = sched_get_priority_max(SCHED_RR),
	};
	rte_cpuset_t cpuset;
	pthread_attr_t attr;
	char name[32];
	int ret;

	pthread_attr_init(&attr);
	ret = pthread_attr_setschedpolicy(&attr, SCHED_RR);
	if (ret) {
		RTE_LOG(ERR, RPC,
		"Failed to set thread sched policy = RR ret %d.\n", ret);
		return ret;
	}
	ret = pthread_attr_setschedparam(&attr, &sp);
	if (ret) {
		RTE_LOG(ERR, RPC,
		"Failed to set thread priority ret %d.\n", ret);
		return ret;
	}
	ret = pthread_create(&rpc_ctx->rpc_server_tid,
			&attr, vdpa_rpc_handler, (void *)rpc_ctx);
	if (ret) {
		RTE_LOG(ERR, RPC,
		"Failed to create vdpa rpc-thread ret %d.\n", ret);
		return ret;
	}
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(rpc_ctx->rpc_server_tid,
			sizeof(cpuset), &cpuset);
	if (ret) {
		RTE_LOG(ERR, RPC, "Failed to set thread affinity for "
		"vdpa rpc-thread ret %d.\n", ret);
		return ret;
	}
	snprintf(name, sizeof(name), "vDPA-RPC");
	ret = pthread_setname_np(rpc_ctx->rpc_server_tid, name);
	if (ret)
		RTE_LOG(ERR, RPC,
		"Failed to set vdpa rpc-thread name %s ret %d.\n",
		name, ret);
	else
		RTE_LOG(DEBUG, RPC, "Thread name: %s.\n", name);
	pthread_mutex_init(&rpc_ctx->rpc_lock, NULL);
	return 0;
}

void
vdpa_rpc_stop(struct vdpa_rpc_context *rpc_ctx)
{
	void *status;

	pthread_mutex_destroy(&rpc_ctx->rpc_lock);
	pthread_cancel(rpc_ctx->rpc_server_tid);
	pthread_join(rpc_ctx->rpc_server_tid, &status);
	jrpc_server_stop(&rpc_ctx->rpc_server);
}
