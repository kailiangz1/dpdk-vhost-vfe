/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Mellanox Technologies, Ltd
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
#include "rte_vhost.h"
#include <rte_vdpa.h>
#include <vdpa_driver.h>

#include <rte_kvargs.h>

#include "virtio_pci.h"
#include "virtqueue.h"

RTE_LOG_REGISTER(vfe_vdpa_logtype, pmd.vdpa.vfe, NOTICE);
#define DRV_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, vfe_vdpa_logtype, \
		"VFE %s(): " fmt "\n", __func__, ##args)

struct virtio_hw_internal vfe_virtio_hw_internal[VFE_MAX_PORT_NUM];

enum {
    VFE_VDPA_NOTIFIER_STATE_DISABLED,
    VFE_VDPA_NOTIFIER_STATE_ENABLED,
    VFE_VDPA_NOTIFIER_STATE_ERR
};

struct vfe_vring_info {
    uint64_t desc;
    uint64_t avail;
    uint64_t used;
    uint16_t size;
    uint16_t last_avail_idx;
    uint16_t last_used_idx; /*other is for future use, not use now*/
    bool enable;
    uint8_t notifier_state;
    uint16_t index;
    struct rte_intr_handle *intr_handle;
    struct vfe_vdpa_priv *priv;
};

#define VFE_VDPA_DRIVER_NAME vdpa_vfe
struct vfe_vdpa_priv {
    TAILQ_ENTRY(vfe_vdpa_priv) next;
    struct rte_pci_device *pdev;
    struct rte_vdpa_device *vdev;
    struct virtio_pci_dev vpdev;
    int vfio_container_fd;
    int vfio_group_fd;
    int vfio_dev_fd;
    int vid;
    uint64_t guest_features;
    pthread_mutex_t vq_config_lock;
//    virtio_admin_pf *manger_pf;  // for admin pf op
    int configured;
    uint16_t nr_virtqs;   //number of vq vhost enabled 
    uint16_t hw_nr_virtqs; // number of vq hardware supported
    struct vfe_vring_info **vrings;

};

//TO_DO: need to addd VHOST_USER_PROTOCOL_F_CONFIG later
#define VFE_VDPA_PROTOCOL_FEATURES \
                ((1ULL << VHOST_USER_PROTOCOL_F_SLAVE_REQ) | \
                 (1ULL << VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD) | \
                 (1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER) | \
                 (1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK))
/*                 (1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD) | \
                 (1ULL << VHOST_USER_PROTOCOL_F_MQ) | \
                 (1ULL << VHOST_USER_PROTOCOL_F_NET_MTU) | \
                 (1ULL << VHOST_USER_PROTOCOL_F_STATUS))
*/

TAILQ_HEAD(vfe_vdpa_privs, vfe_vdpa_priv) vfe_priv_list =
                          TAILQ_HEAD_INITIALIZER(vfe_priv_list);
static pthread_mutex_t priv_list_lock = PTHREAD_MUTEX_INITIALIZER;

static struct vfe_vdpa_priv *
vfe_vdpa_find_priv_resource_by_vdev(struct rte_vdpa_device *vdev)
{
    struct vfe_vdpa_priv *priv;
    int found = 0;

    pthread_mutex_lock(&priv_list_lock);
    TAILQ_FOREACH(priv, &vfe_priv_list, next) {
        if (vdev == priv->vdev) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&priv_list_lock);
    if (!found) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        rte_errno = EINVAL;
        return NULL;
    }
    return priv;
}

static uint16_t
vfe_get_nr_vq(struct virtio_hw *hw)
{
    uint16_t nr_vq = hw->max_queue_pairs * 2;

    if (virtio_with_feature(hw, VIRTIO_NET_F_MQ) ||
            virtio_with_feature(hw, VIRTIO_NET_F_RSS)) {
        vfe_virtio_read_dev_config(hw,
            offsetof(struct virtio_net_config, max_virtqueue_pairs),
            &hw->max_queue_pairs,
            sizeof(hw->max_queue_pairs));
    } else {
        DRV_LOG(DEBUG,
                 "Neither VIRTIO_NET_F_MQ nor VIRTIO_NET_F_RSS are supported");
        hw->max_queue_pairs = 1;
    }

    nr_vq = hw->max_queue_pairs * 2;
    if (virtio_with_feature(hw, VIRTIO_NET_F_CTRL_VQ))
        nr_vq += 1;

    DRV_LOG(DEBUG,"virtio nr_vq is %d",nr_vq);

    return nr_vq;
}

static int
vfe_vdpa_get_queue_num(struct rte_vdpa_device *vdev, uint32_t *queue_num)
{
    struct vfe_vdpa_priv *priv =
        vfe_vdpa_find_priv_resource_by_vdev(vdev);

    if (priv == NULL) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        return -1;
    }
    // TO_DO:for net, should use max_virtqueue_pairs? may be is same
    *queue_num = priv->hw_nr_virtqs;
    DRV_LOG(DEBUG, "vid %d queue num is %d", priv->vid, *queue_num);
    return 0;
}

static int
vfe_vdpa_get_vdpa_features(struct rte_vdpa_device *vdev, uint64_t *features)
{
    struct vfe_vdpa_priv *priv =
        vfe_vdpa_find_priv_resource_by_vdev(vdev);
    struct virtio_hw *hw = NULL;

    if (priv == NULL) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        return -1;
    }
    hw = &priv->vpdev.hw;
    *features = hw->guest_features;
    *features |= (1ULL << VHOST_USER_F_PROTOCOL_FEATURES);
   
    return 0;
}

static int
vfe_vdpa_get_protocol_features(struct rte_vdpa_device *vdev,
        uint64_t *features)
{
    struct vfe_vdpa_priv *priv =
        vfe_vdpa_find_priv_resource_by_vdev(vdev);

    if (priv == NULL) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        return -1;
    }
    *features = VFE_VDPA_PROTOCOL_FEATURES;
    return 0;
}

static uint64_t
hva_to_gpa(int vid, uint64_t hva)
{
	struct rte_vhost_memory *mem = NULL;
	struct rte_vhost_mem_region *reg;
	uint32_t i;
	uint64_t gpa = 0;

	if (rte_vhost_get_mem_table(vid, &mem) < 0)
		goto exit;

	for (i = 0; i < mem->nregions; i++) {
		reg = &mem->regions[i];

		if (hva >= reg->host_user_addr &&
				hva < reg->host_user_addr + reg->size) {
			gpa = hva - reg->host_user_addr + reg->guest_phys_addr;
			break;
		}
	}

exit:
	free(mem);
	return gpa;
}

static int
vfe_vdpa_enable_vfio_intr(struct vfe_vdpa_priv *priv)
{
    int ret;
    uint32_t i, nr_vring;
    struct vfio_irq_set *irq_set;
    int *fd_ptr;
    struct rte_vhost_vring vring;
    struct virtio_hw *hw = NULL;

    vring.callfd = -1;

    nr_vring = rte_vhost_get_vring_num(priv->vid);

    irq_set = rte_zmalloc(NULL, (sizeof(struct vfio_irq_set) + sizeof(int) * (nr_vring + 1)), 0);
    irq_set->argsz = sizeof(struct vfio_irq_set) + sizeof(int) * (nr_vring + 1);
    irq_set->count = nr_vring + 1;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD |
             VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;
    irq_set->start = 0;
    fd_ptr = (int *)&irq_set->data;
    fd_ptr[RTE_INTR_VEC_ZERO_OFFSET] =
        rte_intr_fd_get(priv->pdev->intr_handle);

    for (i = 0; i < nr_vring; i++) {
        ret = rte_vhost_get_vhost_vring(priv->vid, i, &vring);
        if (ret){
            rte_free(irq_set);
            DRV_LOG(ERR, "call fd get fail ret:0x%x",ret);
            return -1;
        }
        fd_ptr[RTE_INTR_VEC_RXTX_OFFSET + i] = vring.callfd;
        DRV_LOG(DEBUG, "queue %d call fd %d.", i,vring.callfd);
    }

    ret = ioctl(priv->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
    rte_free(irq_set);
    if (ret) {
        DRV_LOG(ERR, "Error enabling MSI-X interrupts: %s",
                strerror(errno));
        return -1;
    }


    hw = &priv->vpdev.hw;

    VIRTIO_OPS(hw)->intr_detect(hw);
    if(priv->vpdev.msix_status != VIRTIO_MSIX_ENABLED) {
        DRV_LOG(ERR, "Error MSI-X not enabled,status: %d",priv->vpdev.msix_status);
    }

    if (VIRTIO_OPS(hw)->set_config_irq(hw, 0) ==
            VIRTIO_MSI_NO_VECTOR) {
        DRV_LOG(ERR, "failed to set config vector");
        return -1;
    }

    for (i = 0; i < nr_vring; i++) {
        if (VIRTIO_OPS(hw)->set_queue_irq(hw, hw->vqs[i], i + RTE_INTR_VEC_RXTX_OFFSET) ==
                         VIRTIO_MSI_NO_VECTOR) {
            DRV_LOG(ERR, "failed to set queue vector");
            return -1;
        }
    }
    return 0;
}

static int
vfe_vdpa_disable_vfio_intr(struct vfe_vdpa_priv *priv)
{
    int ret;
    uint32_t i;
    struct vfio_irq_set irq_set;
    struct virtio_hw *hw = NULL;

    irq_set.argsz = sizeof(struct vfio_irq_set);
    irq_set.count = 0;
    irq_set.flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set.index = VFIO_PCI_MSIX_IRQ_INDEX;
    irq_set.start = 0;

    ret = ioctl(priv->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, &irq_set);
    if (ret) {
        DRV_LOG(ERR, "Error disabling MSI-X interrupts: %s",
                strerror(errno));
        return -1;
    }

    hw = &priv->vpdev.hw;
    if (VIRTIO_OPS(hw)->set_config_irq(hw, VIRTIO_MSI_NO_VECTOR) !=
            VIRTIO_MSI_NO_VECTOR) {
        DRV_LOG(ERR, "failed to disable config vector");
        return -1;
    }

    for (i = 0; i < priv->nr_virtqs; i++) {
        if (VIRTIO_OPS(hw)->set_queue_irq(hw, hw->vqs[i], VIRTIO_MSI_NO_VECTOR) !=
                         VIRTIO_MSI_NO_VECTOR) {
            DRV_LOG(ERR, "failed to disable queue vector");
            return -1;
        }
    }

    return 0;
}

static void
vfe_vdpa_virtq_handler(void *cb_arg)
{
	struct vfe_vring_info *virtq = cb_arg;
	struct vfe_vdpa_priv *priv = virtq->priv;
	uint64_t buf;
	int nbytes;

    if(!(priv->configured))return;
    if(!virtq->enable) return;
	if (rte_intr_fd_get(virtq->intr_handle) < 0)
		return;

	do {
		nbytes = read(rte_intr_fd_get(virtq->intr_handle), &buf,
			      8);
		if (nbytes < 0) {
			if (errno == EINTR ||
			    errno == EWOULDBLOCK ||
			    errno == EAGAIN)
				continue;
			DRV_LOG(ERR,  "Failed to read kickfd of virtq %d: %s",
				virtq->index, strerror(errno));
		}
		break;
	} while (1);
    virtqueue_notify(priv->vpdev.hw.vqs[virtq->index]);
    if(virtq->notifier_state == VFE_VDPA_NOTIFIER_STATE_DISABLED) {
        if (rte_vhost_host_notifier_ctrl(priv->vid, virtq->index, true)) {
            DRV_LOG(ERR,  "Failed to set nofity ctrl virtq %d: %s",
                            virtq->index, strerror(errno));
            virtq->notifier_state = VFE_VDPA_NOTIFIER_STATE_ERR;
        }
        else
            virtq->notifier_state = VFE_VDPA_NOTIFIER_STATE_ENABLED;
        DRV_LOG(INFO, "Virtq %u notifier state is %s.", virtq->index,
            virtq->notifier_state ==
                VFE_VDPA_NOTIFIER_STATE_ENABLED ? "enabled" :
                                    "disabled");
    }
	DRV_LOG(DEBUG, "Ring virtq %u doorbell.", virtq->index);
}
#define VFE_VDPA_INTR_RETRIES_USEC 1000
#define VFE_VDPA_INTR_RETRIES 256

static int
vfe_vdpa_virtq_doorbell_relay_disable(struct vfe_vdpa_priv *priv, int index)
{
    int ret = -EAGAIN;
    struct rte_intr_handle *intr_handle;
	int retries = VFE_VDPA_INTR_RETRIES;


    intr_handle = priv->vrings[index]->intr_handle;
    if (rte_intr_fd_get(intr_handle) != -1) {
        while (retries-- && ret == -EAGAIN) {
            ret = rte_intr_callback_unregister(intr_handle,
                            vfe_vdpa_virtq_handler,
                            priv->vrings[index]);
            if (ret == -EAGAIN) {
                DRV_LOG(DEBUG, "Try again to unregister fd %d "
                "of virtq %d interrupt, retries = %d.",
                rte_intr_fd_get(intr_handle),
                (int)priv->vrings[index]->index, retries);
    
                usleep(VFE_VDPA_INTR_RETRIES_USEC);
            }
        }
        rte_intr_fd_set(intr_handle, -1);
    }
    rte_intr_instance_free(intr_handle);
    return 0;
}

static int
vfe_vdpa_virtq_doorbell_relay_enable(struct vfe_vdpa_priv *priv, int index)
{
    int ret;
    struct rte_vhost_vring vq;
    struct rte_intr_handle *intr_handle;

    ret = rte_vhost_get_vhost_vring(priv->vid, index, &vq);
    if (ret)
        return -1;

    intr_handle = rte_intr_instance_alloc(RTE_INTR_INSTANCE_F_SHARED);
	if (intr_handle == NULL) {
		DRV_LOG(ERR, "Fail to allocate intr_handle");
        return -EINVAL;
	}
    
    priv->vrings[index]->intr_handle = intr_handle;

	if (rte_intr_fd_set(intr_handle, vq.kickfd)) {
        DRV_LOG(ERR, "Fail to set kick fd");
		goto error;
    }

	if (rte_intr_fd_get(intr_handle) == -1) {
		DRV_LOG(ERR, "Virtq %d kickfd is invalid.", index);
		goto error;
	} else {
		if (rte_intr_type_set(intr_handle, RTE_INTR_HANDLE_EXT))
			goto error;

		if (rte_intr_callback_register(intr_handle,
					       vfe_vdpa_virtq_handler,
					       priv->vrings[index])) {
			rte_intr_fd_set(intr_handle, -1);
			DRV_LOG(ERR, "Failed to register virtq %d interrupt.",
				index);
			goto error;
		} else {
			DRV_LOG(DEBUG, "Register fd %d interrupt for virtq %d.",
				rte_intr_fd_get(intr_handle),
				index);
		}
	}

    return 0;
error:
	vfe_vdpa_virtq_doorbell_relay_disable(priv, index);
	return -1; 
}

static int
vfe_vdpa_virtq_enable(struct vfe_vdpa_priv *priv, int index, int enable)
{
    int ret;
    int vid;
    struct rte_vhost_vring vq;
    uint64_t gpa;
    struct virtio_hw *hw = NULL;
    struct virtqueue *hw_vq;
    unsigned int size;

    hw = &priv->vpdev.hw;
    hw_vq = hw->vqs[index];


    if(enable==0) {
        VIRTIO_OPS(hw)->del_queue(hw, hw_vq);
        ret = vfe_vdpa_virtq_doorbell_relay_disable(priv, index);
        if (ret) {
             DRV_LOG(ERR, "virtq doorbell relay failed");            
             return ret;
        }
        return 0;
    }

    ret = rte_vhost_get_vhost_vring(priv->vid, index, &vq);
    if (ret)
        return -1;
    vid = priv->vid;
    

    gpa = hva_to_gpa(vid, (uint64_t)(uintptr_t)vq.desc);
    if (gpa == 0) {
        DRV_LOG(ERR, "Fail to get GPA for descriptor ring.");
        return -1;
    }
    DRV_LOG(DEBUG, "virtq %d desc addr%"PRIx64, index, gpa);
    priv->vrings[index]->desc = gpa;
    hw_vq->vq_ring_mem = gpa;
    
    gpa = hva_to_gpa(vid, (uint64_t)(uintptr_t)vq.avail);
    if (gpa == 0) {
        DRV_LOG(ERR, "Fail to get GPA for available ring.");
        return -1;
    }
    DRV_LOG(DEBUG, "virtq %d avail addr%"PRIx64, index, gpa);
    priv->vrings[index]->avail = gpa;
    
    gpa = hva_to_gpa(vid, (uint64_t)(uintptr_t)vq.used);
    if (gpa == 0) {
        DRV_LOG(ERR, "Fail to get GPA for used ring.");
        return -1;
    }
    DRV_LOG(DEBUG, "virtq %d used addr%"PRIx64, index, gpa);
    priv->vrings[index]->used = gpa;
        
    //TO_DO: need to check vq_size not exceed hw limit
    priv->vrings[index]->size = vq.size;
    hw_vq->vq_nentries = vq.size;

    size = vring_size(hw, vq.size, VIRTIO_VRING_ALIGN);
    hw_vq->vq_ring_size = RTE_ALIGN_CEIL(size, VIRTIO_VRING_ALIGN);

    DRV_LOG(DEBUG, "virtq %d nr_entrys:%d ring_size:%d",index, vq.size,hw_vq->vq_ring_size);
    if (VIRTIO_OPS(hw)->setup_queue(hw, hw_vq,priv->vrings[index]->avail,priv->vrings[index]->used) < 0) {
            DRV_LOG(ERR, "setup_queue failed");            
            return -EINVAL;
    }

    ret = vfe_vdpa_virtq_doorbell_relay_enable(priv, index);
    if (ret) {
         DRV_LOG(ERR, "virtq doorbell relay failed");            
         return ret;
    }

    return 0;
}

static int
vfe_vdpa_set_vring_state(int vid, int vring, int state)
{
    struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
    struct vfe_vdpa_priv *priv =
        vfe_vdpa_find_priv_resource_by_vdev(vdev);
    struct virtio_hw *hw = NULL;
    int ret = 0,i;

    if (priv == NULL) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        return -EINVAL;
    }
    if (vring >= (int)priv->hw_nr_virtqs) {
        DRV_LOG(ERR, "Too big vring id: %d.", vring);
        return -E2BIG;
    }

    //TO_DO: check if vid set here is sutiable
    priv->vid = vid;
    hw = &priv->vpdev.hw;

    if(vfe_virtio_get_status(hw)&VIRTIO_CONFIG_STATUS_DRIVER_OK) {
        DRV_LOG(ERR, "can not set vring stat when driver ok vDPA device: %s.", vdev->device->name);
        return -EINVAL;
    }

    pthread_mutex_lock(&priv->vq_config_lock);
    if (!state && priv->vrings[vring]->enable) {
        ret = vfe_vdpa_virtq_enable(priv, vring, state);
    }
    if (state && !priv->vrings[vring]->enable) {
        ret = vfe_vdpa_virtq_enable(priv, vring, state);
    }
    if (state && priv->vrings[vring]->enable) {
        ret = vfe_vdpa_virtq_enable(priv, vring, 0);
        if(ret) {
            DRV_LOG(ERR, "fail to set vring state to 0, ret:%d vring:%d state:%d.", ret, vring, state);
            pthread_mutex_unlock(&priv->vq_config_lock);
            return ret;
        }
        ret = vfe_vdpa_virtq_enable(priv, vring, state);
    }
    pthread_mutex_unlock(&priv->vq_config_lock);
    if(ret) {
        DRV_LOG(ERR, "fail to set vring state, ret:%d vring:%d state:%d.", ret, vring, state);
        return ret;
    }
    
    DRV_LOG(INFO, "vDPA device %d  set vring %d state %d.", vid, vring, state);
    priv->vrings[vring]->enable = !!state;
    if((priv->configured)&&(state)&&(vring== (rte_vhost_get_vring_num(vid)-1))) {
        for(i=0;i<(rte_vhost_get_vring_num(vid)-1);i++) {
            if (priv->vrings[i]->notifier_state == VFE_VDPA_NOTIFIER_STATE_DISABLED) {
                if (rte_vhost_host_notifier_ctrl(vid, i, true)) {
                    priv->vrings[i]->notifier_state = VFE_VDPA_NOTIFIER_STATE_ERR;
                    DRV_LOG(NOTICE, "vDPA (%s): enable notify fail", vdev->device->name);
                } else {
                    priv->vrings[i]->notifier_state = VFE_VDPA_NOTIFIER_STATE_ENABLED;
                    DRV_LOG(INFO, "vDPA (%s): virtq %d notify enabled", vdev->device->name,i);
                }
            }
        }

        ret = vfe_vdpa_enable_vfio_intr(priv);
        if (ret) {
             DRV_LOG(ERR, "fail to enable vfio interupt");            
             return ret;
        }
        vfe_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_FEATURES_OK);

        /* Start the device */
        vfe_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER_OK);
        DRV_LOG(INFO, "vDPA device %d  move to driver ok", vid);
    }

    return 0;
}

static int
vfe_dma_map(struct vfe_vdpa_priv *priv, bool do_map)
{
    uint32_t i;
    int ret;
    struct rte_vhost_memory *mem = NULL;
    int vfio_container_fd;

    ret = rte_vhost_get_mem_table(priv->vid, &mem);
    if (ret < 0) {
        DRV_LOG(ERR, "failed to get VM memory layout.");
        goto exit;
    }

    vfio_container_fd = priv->vfio_container_fd;

    for (i = 0; i < mem->nregions; i++) {
        struct rte_vhost_mem_region *reg;

        reg = &mem->regions[i];
        DRV_LOG(INFO, "%s, region %u: HVA 0x%" PRIx64 ", "
            "GPA 0x%" PRIx64 ", size 0x%" PRIx64 ".",
            do_map ? "DMA map" : "DMA unmap", i,
            reg->host_user_addr, reg->guest_phys_addr, reg->size);

        if (do_map) {
            ret = rte_vfio_container_dma_map(vfio_container_fd,
                reg->host_user_addr, reg->guest_phys_addr,
                reg->size);
            if (ret < 0) {
                DRV_LOG(ERR, "DMA map failed.");
                goto exit;
            }
        } else {
            ret = rte_vfio_container_dma_unmap(vfio_container_fd,
                reg->host_user_addr, reg->guest_phys_addr,
                reg->size);
            if (ret < 0) {
                DRV_LOG(ERR, "DMA unmap failed.");
                goto exit;
            }
        }
    }

exit:
    free(mem);
    return ret;
}

static int
vfe_vdpa_features_set(int vid)
{
    struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
    struct vfe_vdpa_priv *priv =
        vfe_vdpa_find_priv_resource_by_vdev(vdev);
    uint64_t log_base, log_size;
    uint64_t features;
    int ret;
    struct virtio_hw *hw = NULL;

    if (priv == NULL) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        return -EINVAL;
    }
    priv->vid = vid;
    ret = rte_vhost_get_negotiated_features(vid, &features);
    if (ret) {
        DRV_LOG(ERR, "Failed to get negotiated features.");
        return ret;
    }
    if (RTE_VHOST_NEED_LOG(features)) {
        ret = rte_vhost_get_log_base(vid, &log_base, &log_size);
        if (ret) {
            DRV_LOG(ERR, "Failed to get log base.");
            return ret;
        }
        //TO_DO: add log op
    }

    hw = &priv->vpdev.hw;

    //TO_DO: check why ---
    features |=(1ULL << VIRTIO_F_IOMMU_PLATFORM);
    priv->guest_features = vfe_virtio_negotiate_features(hw, features);
    DRV_LOG(INFO, "vDPA device %d hw feature is %" PRIx64 "guest feature is %" PRIx64, vid,priv->guest_features,features);

    return 0;
}

static int
vfe_vdpa_dev_close(int vid)
{
    struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
    struct vfe_vdpa_priv *priv =
        vfe_vdpa_find_priv_resource_by_vdev(vdev);
    struct virtio_hw *hw = &priv->vpdev.hw;
    int ret = 0, i;

    if (priv == NULL) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        return -1;
    }

    ret = vfe_vdpa_disable_vfio_intr(priv);
    if(ret) {
        DRV_LOG(ERR, "Fail to enable vfio intr ret: %d",ret);
    }




    for (i = 0; i < priv->nr_virtqs; i++) {
        if (priv->vrings[i]->enable)
            vfe_vdpa_virtq_enable(priv,i,0);
        
        if (priv->vrings[i]->notifier_state == VFE_VDPA_NOTIFIER_STATE_ENABLED) {
            if (rte_vhost_host_notifier_ctrl(vid, i, false) != 0)
                DRV_LOG(NOTICE, "vDPA (%s): disable notify fail", vdev->device->name);
        }
        priv->vrings[i]->notifier_state = VFE_VDPA_NOTIFIER_STATE_DISABLED;
        priv->vrings[i]->enable = 0;
    }

    ret = vfe_dma_map(priv,false);
    if(ret) {
        DRV_LOG(ERR, "Fail to do dma map: %d",ret);
    }
    //TO_DO: need to set rte_vhost_set_vring_base after LM supported
    vfe_virtio_reset(hw);
    /* Tell the host we've noticed this device. */
    vfe_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_ACK);

    /* Tell the host we've known how to drive the device. */
    vfe_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER);

    priv->configured = 0;
    priv->vid = 0;
    /* The mutex may stay locked after event thread cancel - initiate it. */
    pthread_mutex_init(&priv->vq_config_lock, NULL);
    DRV_LOG(INFO, "vDPA device %d was closed.", vid);
    return ret;
}

static int
vfe_vdpa_dev_config(int vid)
{
    struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
    struct vfe_vdpa_priv *priv =
        vfe_vdpa_find_priv_resource_by_vdev(vdev);
    int ret,i;

    if (priv == NULL) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        return -EINVAL;
    }
    if (priv->configured) {
        DRV_LOG(ERR, "Failed to reconfigure vid %d.", vid);
        return -1;
    }

    //ret = vfe_vdpa_enable_vfio_intr(priv);
    ret =0;
    if(ret) {
        DRV_LOG(ERR, "Fail to enable vfio intr ret: %d",ret);
        return ret;
    }

    priv->nr_virtqs = rte_vhost_get_vring_num(vid);
    for (i = 0; i < priv->nr_virtqs; i++) {
        if (!(priv->vrings[i]->enable))
            vfe_vdpa_virtq_enable(priv,i,1);
        priv->vrings[i]->enable = 1;
    }

    priv->vid = vid;
    ret = vfe_dma_map(priv,true);
    if(ret) {
        DRV_LOG(ERR, "Fail to do dma map: %d",ret);
        return ret;
    }
    priv->configured = 1;
    DRV_LOG(INFO, "vDPA device %d was configured.", vid);
    return 0;
}

static int
vfe_vdpa_get_group_fd(int vid)
{
    struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
    struct vfe_vdpa_priv *priv =
        vfe_vdpa_find_priv_resource_by_vdev(vdev);

    if (priv == NULL) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        return -EINVAL;
    }
    return priv->vfio_group_fd;
}

static int
vfe_vdpa_get_device_fd(int vid)
{
    struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
    struct vfe_vdpa_priv *priv =
        vfe_vdpa_find_priv_resource_by_vdev(vdev);

    if (priv == NULL) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        return -EINVAL;
    }
    return priv->vfio_dev_fd;
}

static int
vfe_vdpa_get_notify_area(int vid, int qid, uint64_t *offset, uint64_t *size)
{
    struct rte_vdpa_device *vdev = rte_vhost_get_vdpa_device(vid);
    struct vfe_vdpa_priv *priv =
        vfe_vdpa_find_priv_resource_by_vdev(vdev);
    struct vfio_region_info reg = { .argsz = sizeof(reg) };
    int ret;

    if (priv == NULL) {
        DRV_LOG(ERR, "Invalid vDPA device: %s.", vdev->device->name);
        return -EINVAL;
    }

    reg.index = priv->vpdev.notify_bar;
    ret = ioctl(priv->vfio_dev_fd, VFIO_DEVICE_GET_REGION_INFO, &reg);
    if (ret) {
        DRV_LOG(ERR, "Get not get device region info: %s",
                strerror(errno));
        return -1;
    }


    //TO_DO: check whether notify_addr is 4k aligned
    *offset = (uint8_t*)priv->vpdev.hw.vqs[qid]->notify_addr - (uint8_t*)priv->pdev->mem_resource[priv->vpdev.notify_bar].addr + reg.offset;
    //nofiy area should 4k aligned, so should not just one doorbell size
    *size = 0x1000;
    DRV_LOG(DEBUG, "vid %d qid:%d notify:%p bar %d base:%p reg.offset:0x%"PRIx64,
            vid, qid,(priv->vpdev.hw.vqs[qid]->notify_addr),priv->vpdev.notify_bar,priv->pdev->mem_resource[priv->vpdev.notify_bar].addr,*offset);
    return 0;
}

static struct rte_vdpa_dev_ops vfe_vdpa_ops = {
    .get_queue_num = vfe_vdpa_get_queue_num,
    .get_features = vfe_vdpa_get_vdpa_features,
    .get_protocol_features = vfe_vdpa_get_protocol_features,
    .dev_conf = vfe_vdpa_dev_config,
    .dev_close = vfe_vdpa_dev_close,
    .set_vring_state = vfe_vdpa_set_vring_state,
    .set_features = vfe_vdpa_features_set,
    .migration_done = NULL,
    .get_vfio_group_fd = vfe_vdpa_get_group_fd,
    .get_vfio_device_fd = vfe_vdpa_get_device_fd,
    .get_notify_area = vfe_vdpa_get_notify_area,
    .get_stats_names = NULL,
    .get_stats = NULL,
    .reset_stats = NULL,
};

static int vdpa_check_handler(__rte_unused const char *key,
        const char *value, void *ret_val)
{
    if (strcmp(value, "1") == 0)
        *(int *)ret_val = 1;
    else
        *(int *)ret_val = 0;

    return 0;
}

#define VIRTIO_ARG_VDPA       "vdpa"

static int
virtio_pci_devargs_parse(struct rte_devargs *devargs, int *vdpa)
{
    struct rte_kvargs *kvlist;
    int ret = 0;

    if (devargs == NULL)
        return 0;

    kvlist = rte_kvargs_parse(devargs->args, NULL);
    if (kvlist == NULL) {
        DRV_LOG(ERR, "error when parsing param");
        return 0;
    }

    if (rte_kvargs_count(kvlist, VIRTIO_ARG_VDPA) == 1) {
        /* vdpa mode selected when there's a key-value pair:
         * vdpa=1
         */
        ret = rte_kvargs_process(kvlist, VIRTIO_ARG_VDPA,
                vdpa_check_handler, vdpa);
        if (ret < 0)
            DRV_LOG(ERR, "Failed to parse %s", VIRTIO_ARG_VDPA);
    }

    rte_kvargs_free(kvlist);

    return ret;
}

static void
vfe_vdpa_free_queues(struct vfe_vdpa_priv *priv)
{
    uint16_t nr_vq = priv->hw_nr_virtqs;
    struct virtio_hw *hw = &priv->vpdev.hw;
    struct virtqueue *vq;
    struct vfe_vring_info *vr;
    uint16_t i;

    if(priv->vrings) {
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

    if (hw->vqs == NULL)
        return;

    for (i = 0; i < nr_vq; i++) {
        vq = hw->vqs[i];
        if (!vq)
            continue;
        rte_free(vq);
        hw->vqs[i] = NULL;
    }

    rte_free(hw->vqs);
    hw->vqs = NULL;
}

static int
vfe_vdpa_alloc_queues(struct vfe_vdpa_priv *priv)
{
    struct virtio_hw *hw = &priv->vpdev.hw;
    uint16_t nr_vq = priv->hw_nr_virtqs;
    struct virtqueue *vq;
    struct vfe_vring_info *vr;
    uint16_t i;

    hw->vqs = rte_zmalloc(NULL, sizeof(struct virtqueue *) * nr_vq, 0);
    if (!hw->vqs) {
        DRV_LOG(ERR, "Failed to alloc vDPA device queues.");
        return -ENOMEM;
    }


    for (i = 0; i < nr_vq; i++) {
        vq = rte_zmalloc_socket(NULL, sizeof(struct virtqueue), RTE_CACHE_LINE_SIZE,
                    priv->pdev->device.numa_node);
        if (vq == NULL) {
            vfe_vdpa_free_queues(priv);
            return -ENOMEM;
        }
        hw->vqs[i] = vq;
        vq->hw = hw;
        vq->vq_queue_index = i;
    }

    priv->vrings = rte_zmalloc(NULL, sizeof(struct vfe_vring_info *) * nr_vq, 0);
    if (!priv->vrings) {
        vfe_vdpa_free_queues(priv);
        return -ENOMEM;
    }

    for (i = 0; i < nr_vq; i++) {
        vr = rte_zmalloc_socket(NULL, sizeof(struct vfe_vring_info), RTE_CACHE_LINE_SIZE,
                    priv->pdev->device.numa_node);
        if (vr == NULL) {
            vfe_vdpa_free_queues(priv);
            return -ENOMEM;
        }
        priv->vrings[i] = vr;
        priv->vrings[i]->index = i;
        priv->vrings[i]->priv = priv;
    }
    return 0;
}
static uint16_t
vfe_vdpa_alloc_port_id(void)
{
    int i;
    for(i=0; i<VFE_MAX_PORT_NUM; i++)
        if(vfe_virtio_hw_internal[i].virtio_ops == NULL) return i;

    DRV_LOG(ERR, "Failed to get port id!!");
    return VFE_MAX_PORT_NUM;
}
static void
vfe_vdpa_free_port_id(uint16_t port_id)
{
    if (port_id >=VFE_MAX_PORT_NUM) return;
    vfe_virtio_hw_internal[port_id].virtio_ops=NULL;
}

static int
vfe_vdpa_dev_probe(struct rte_pci_driver *pci_drv __rte_unused,
        struct rte_pci_device *pci_dev)
{
    int vdpa = 0;
    int ret = 0;
    struct vfe_vdpa_priv *priv = NULL;
    struct virtio_hw *hw = NULL;
    char devname[RTE_DEV_NAME_MAX_LEN] = {0};
    int iommu_group_num;

    ret = virtio_pci_devargs_parse(pci_dev->device.devargs, &vdpa);
    if (ret < 0) {
        DRV_LOG(ERR, "devargs parsing is failed");
        return ret;
    }
    /* vfe vdpa pmd skips probe if device needs to work in none vdpa mode */
    if (vdpa != 1)
        return 1;


    priv = rte_zmalloc("vfe vdpa device private", sizeof(*priv), RTE_CACHE_LINE_SIZE);
    if (!priv) {
        DRV_LOG(ERR, "Failed to allocate private memory.");
        rte_errno = ENOMEM;
        return -rte_errno;
    }

    //TO_DO: need to confirm following:
    priv->vfio_dev_fd = -1;
    priv->vfio_group_fd = -1;
    priv->vfio_container_fd = -1;

    rte_pci_device_name(&pci_dev->addr, devname, RTE_DEV_NAME_MAX_LEN);
    ret = rte_vfio_get_group_num(rte_pci_get_sysfs_path(), devname,
            &iommu_group_num);
    if (ret <= 0) {
        DRV_LOG(ERR, "%s failed to get IOMMU group", devname);
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

    hw = &priv->vpdev.hw;
    priv->pdev = pci_dev;
    hw->port_id = vfe_vdpa_alloc_port_id();
    if (hw->port_id ==VFE_MAX_PORT_NUM) {
        DRV_LOG(ERR, "%s failed to get vfe port id", devname);
        goto error;
    }
    VTPCI_DEV(hw) = pci_dev;
    ret = vfe_vtpci_init(pci_dev, &priv->vpdev);
    if (ret) {
        DRV_LOG(ERR, "Failed to init virtio PCI device");
        rte_errno = rte_errno ? rte_errno : EINVAL;
        goto error;
    }

    priv->vfio_dev_fd = rte_intr_dev_fd_get(pci_dev->intr_handle);
    if (priv->vfio_dev_fd < 0) {
        DRV_LOG(ERR, "%s failed to get vfio dev fd", devname);
        rte_errno = rte_errno ? rte_errno : EINVAL;
        goto error;
    }

    priv->vdev = rte_vdpa_register_device(&pci_dev->device, &vfe_vdpa_ops);
    if (priv->vdev == NULL) {
        DRV_LOG(ERR, "Failed to register vDPA device.");
        rte_errno = rte_errno ? rte_errno : EINVAL;
        goto error;
    }


    //TO_DO: need to confirm following:
    /* Reset the device although not necessary at startup */
    vfe_virtio_reset(hw);

    /* Tell the host we've noticed this device. */
    vfe_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_ACK);

    /* Tell the host we've known how to drive the device. */
    vfe_virtio_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER);

    hw->guest_features = VIRTIO_OPS(hw)->get_features(hw);
    DRV_LOG(DEBUG,"guest_features is 0x%"PRIx64,hw->guest_features);

    priv->hw_nr_virtqs = vfe_get_nr_vq(hw);
    ret = vfe_vdpa_alloc_queues(priv);
    if (ret) {
        DRV_LOG(ERR, "Failed to alloc vDPA device queues.");
        rte_errno = rte_errno ? rte_errno : EINVAL;
        goto error;
    }

    pthread_mutex_init(&priv->vq_config_lock, NULL);
    pthread_mutex_lock(&priv_list_lock);
    TAILQ_INSERT_TAIL(&vfe_priv_list, priv, next);
    pthread_mutex_unlock(&priv_list_lock);
    return 0;

error:
    if (priv) {
        rte_free(priv);
    }
    return -rte_errno;
}

static int
vfe_vdpa_dev_remove(struct rte_pci_device *pci_dev)
{
    struct vfe_vdpa_priv *priv = NULL;
    int found = 0;
    struct virtio_hw *hw = NULL;

    pthread_mutex_lock(&priv_list_lock);
    TAILQ_FOREACH(priv, &vfe_priv_list, next) {
        if (priv->pdev == pci_dev) {
            found = 1;
            break;
        }
    }
    if (found)
        TAILQ_REMOVE(&vfe_priv_list, priv, next);
    pthread_mutex_unlock(&priv_list_lock);
    if (found) {
		if (priv->configured)
			vfe_vdpa_dev_close(priv->vid);

        if (priv->vdev)
            rte_vdpa_unregister_device(priv->vdev);

        vfe_vdpa_free_queues(priv);
        hw = &priv->vpdev.hw;
        if (VIRTIO_OPS(hw)->dev_close(hw))
            DRV_LOG(ERR, "Failed to close vDPA device.");
        vfe_vdpa_free_port_id(hw->port_id);
        pthread_mutex_destroy(&priv->vq_config_lock);
        rte_free(priv);
    }
    return 0;
}


/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_virtio_map[] = {
    { RTE_PCI_DEVICE(VIRTIO_PCI_VENDORID, VIRTIO_PCI_LEGACY_DEVICEID_NET) },
    { RTE_PCI_DEVICE(VIRTIO_PCI_VENDORID, VIRTIO_PCI_MODERN_DEVICEID_NET) },
    { .vendor_id = 0, /* sentinel */ },
};

static struct rte_pci_driver vfe_vdpa_driver = {
    .id_table = pci_id_virtio_map,
    .drv_flags = 0,
    .probe = vfe_vdpa_dev_probe,
    .remove = vfe_vdpa_dev_remove,
};


/**
 * Driver initialization routine.
 */
RTE_INIT(rte_vfe_vdpa_init)
{
    int i;
    for(i=0; i<VFE_MAX_PORT_NUM; i++)
        vfe_virtio_hw_internal[i].virtio_ops = NULL;
}

RTE_PMD_REGISTER_PCI(VFE_VDPA_DRIVER_NAME, vfe_vdpa_driver);
RTE_PMD_REGISTER_PCI_TABLE(VFE_VDPA_DRIVER_NAME, pci_id_virtio_map);
RTE_PMD_REGISTER_KMOD_DEP(VFE_VDPA_DRIVER_NAME, "* vfio-pci");

RTE_LOG_REGISTER_SUFFIX(vfe_virtio_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(vfe_virtio_logtype_driver, driver, NOTICE);

