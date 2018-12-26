#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>

MODULE_LICENSE("Dual BSD/GPL");

static int major_num = 0;
module_param(major_num, int, 0);
static int logical_block_size = 512;
module_param(logical_block_size, int, 0);
static int nsectors = 1024 * 100; /* How big the drive is */
module_param(nsectors, int, 0);

/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */
#define KERNEL_SECTOR_SIZE 512

#define SECTOR_SIZE 512
#define MBR_SIZE SECTOR_SIZE
#define MBR_DISK_SIGNATURE_OFFSET 440
#define MBR_DISK_SIGNATURE_SIZE 4
#define PARTITION_TABLE_OFFSET 446
#define PARTITION_ENTRY_SIZE 16 // sizeof(PartEntry)
#define PARTITION_TABLE_SIZE 64 // sizeof(PartTable)
#define MBR_SIGNATURE_OFFSET 510
#define MBR_SIGNATURE_SIZE 2
#define MBR_SIGNATURE 0xAA55
#define BR_SIZE SECTOR_SIZE
#define BR_SIGNATURE_OFFSET 510
#define BR_SIGNATURE_SIZE 2
#define BR_SIGNATURE 0xAA55

typedef struct {
    unsigned char boot;
    unsigned char start_head;
    unsigned char start_sec;
    unsigned char start_cyl;
    unsigned char part_type;
    unsigned char end_head;
    unsigned char end_sec;
    unsigned char end_cyl;
    unsigned char abs_start_sec_0;
    unsigned char abs_start_sec_1;
    unsigned char abs_start_sec_2;
    unsigned char abs_start_sec_3;
    unsigned char sec_in_part_0;
    unsigned char sec_in_part_1;
    unsigned char sec_in_part_2;
    unsigned char sec_in_part_3;
} PartEntry;
 
typedef struct {
    unsigned char boot_code[MBR_DISK_SIGNATURE_OFFSET];
    unsigned char disk_signature[5];
    unsigned char pad;
    PartEntry pt[4];
    unsigned short signature;
} MBR;

/*
 * Our request queue.
 */
static struct request_queue *Queue;

/*
 * The internal representation of our device.
 */
static struct sbd_device {
    unsigned long size;
    spinlock_t lock;
    u8 *data;
    struct gendisk *gd;
} Device;

/*
 * Handle an I/O request.
 */
static void sbd_transfer(struct sbd_device *dev, sector_t sector,
        unsigned long nsect, char *buffer, int write) {
    unsigned long offset = sector * logical_block_size;
    unsigned long nbytes = nsect * logical_block_size;

    if ((offset + nbytes) > dev->size) {
        printk (KERN_NOTICE "sbd: Beyond-end write (%ld %ld)\n", offset, nbytes);
        return;
    }
    if (write)
        memcpy(dev->data + offset, buffer, nbytes);
    else
        memcpy(buffer, dev->data + offset, nbytes);
}

static void sbd_request(struct request_queue *q) {
    struct request *req;

    req = blk_fetch_request(q);
    while (req != NULL) {
        // blk_fs_request() was removed in 2.6.36 - many thanks to
        // Christian Paro for the heads up and fix...
        //if (!blk_fs_request(req)) {
        sbd_transfer(&Device, blk_rq_pos(req), blk_rq_cur_sectors(req),
                bio_data(req->bio), rq_data_dir(req));
        if ( ! __blk_end_request_cur(req, 0) ) {
            req = blk_fetch_request(q);
        }
    }
}

/*
 * The HDIO_GETGEO ioctl is handled in blkdev_ioctl(), which
 * calls this. We need to implement getgeo, since we can't
 * use tools such as fdisk to partition the drive otherwise.
 */
int sbd_getgeo(struct block_device * block_device, struct hd_geometry * geo) {
    long size;

    /* We have no real geometry, of course, so make something up. */
    size = Device.size * (logical_block_size / KERNEL_SECTOR_SIZE);
    geo->cylinders = (size & ~0x3f) >> 6;
    geo->heads = 4;
    geo->sectors = 16;
    geo->start = 0;
    return 0;
}

/*
 * The device operations structure.
 */
static struct block_device_operations sbd_ops = {
        .owner  = THIS_MODULE,
        .getgeo = sbd_getgeo
};

static int __init sbd_init(void) {
    /*
     * Set up our internal device.
     */
    Device.size = nsectors * logical_block_size;
    spin_lock_init(&Device.lock);
    Device.data = vmalloc(Device.size);
    if (Device.data == NULL)
        return -ENOMEM;
    /*
     * Get a request queue.
     */
    Queue = blk_init_queue(sbd_request, &Device.lock);
    if (Queue == NULL)
        goto out;
    blk_queue_logical_block_size(Queue, logical_block_size);
    /*
     * Get registered.
     */
    major_num = register_blkdev(major_num, "sbd");
    if (major_num < 0) {
        printk(KERN_WARNING "sbd: unable to get major number\n");
        goto out;
    }
    /*
     * And the gendisk structure.
     */
    Device.gd = alloc_disk(16);
    if (!Device.gd)
        goto out_unregister;
    Device.gd->major = major_num;
    Device.gd->first_minor = 0;
    Device.gd->fops = &sbd_ops;
    Device.gd->private_data = &Device;
    strcpy(Device.gd->disk_name, "sbd0");
    set_capacity(Device.gd, nsectors);
    Device.gd->queue = Queue;
    memset(Device.data, 0x00, Device.size);
    MBR *mbr = kcalloc(1, sizeof(MBR), GFP_KERNEL);
    mbr->disk_signature[0] = 0x4a;
    mbr->disk_signature[1] = 0xad;
    mbr->disk_signature[2] = 0x36;
    mbr->disk_signature[3] = 0xd5;
    mbr->signature = 0xAA55;
    
    PartEntry ptr = {
        .boot = 0x00,
        .start_head = 0x00,
        .start_sec = 0x00,
        .start_cyl = 0x00,
        .part_type = 0x83,
        .end_head = 0x00,
        .end_sec = 0x00,
        .end_cyl = 0x00,
        .abs_start_sec_0 = 0x01,
        .abs_start_sec_1 = 0x00,
        .abs_start_sec_2 = 0x00,
        .abs_start_sec_3 = 0x00,
        .sec_in_part_0 = 0x00,
        .sec_in_part_1 = 0x50,
        .sec_in_part_2 = 0x00,
        .sec_in_part_3 = 0x00
    };
    PartEntry ptr2 = {
        .boot = 0x00,
        .start_head = 0x00,
        .start_sec = 0x00,
        .start_cyl = 0x00,
        .part_type = 0x05,
        .end_head = 0x00,
        .end_sec = 0x00,
        .end_cyl = 0x00,
        .abs_start_sec_0 = 0x01,
        .abs_start_sec_1 = 0x50,
        .abs_start_sec_2 = 0x00,
        .abs_start_sec_3 = 0x00,
        .sec_in_part_0 = 0x00,
        .sec_in_part_1 = 0x40,
        .sec_in_part_2 = 0x01,
        .sec_in_part_3 = 0x00
    };
    PartEntry lptr1 = {
        .boot = 0x00,
        .start_head = 0x00,
        .start_sec = 0x00,
        .start_cyl = 0x00,
        .part_type = 0x83,
        .end_head = 0x00,
        .end_sec = 0x00,
        .end_cyl = 0x00,
        .abs_start_sec_0 = 0x01,
        .abs_start_sec_1 = 0x00,
        .abs_start_sec_2 = 0x00,
        .abs_start_sec_3 = 0x00,
        .sec_in_part_0 = 0x00,
        .sec_in_part_1 = 0xA0,
        .sec_in_part_2 = 0x00,
        .sec_in_part_3 = 0x00
    };
    PartEntry lptr1link = {
        .boot = 0x00,
        .start_head = 0x00,
        .start_sec = 0x00,
        .start_cyl = 0x00,
        .part_type = 0x05,
        .end_head = 0x00,
        .end_sec = 0x00,
        .end_cyl = 0x00,
        .abs_start_sec_0 = 0x00,
        .abs_start_sec_1 = 0xA0,
        .abs_start_sec_2 = 0x00,
        .abs_start_sec_3 = 0x00,
        .sec_in_part_0 = 0x00,
        .sec_in_part_1 = 0xA0,
        .sec_in_part_2 = 0x00,
        .sec_in_part_3 = 0x00
    };
    PartEntry lptr2 = {
        .boot = 0x00,
        .start_head = 0x00,
        .start_sec = 0x00,
        .start_cyl = 0x00,
        .part_type = 0x83,
        .end_head = 0x00,
        .end_sec = 0x00,
        .end_cyl = 0x00,
        .abs_start_sec_0 = 0x01,
        .abs_start_sec_1 = 0x00,
        .abs_start_sec_2 = 0x00,
        .abs_start_sec_3 = 0x00,
        .sec_in_part_0 = 0x00,
        .sec_in_part_1 = 0xA0,
        .sec_in_part_2 = 0x00,
        .sec_in_part_3 = 0x00
    };
    unsigned long l1offset = 0x0a003c0;
    unsigned long l2offset = 0x1e003c0;
    memcpy(Device.data, mbr, sizeof(MBR));
    memcpy(Device.data + PARTITION_TABLE_OFFSET, &ptr, sizeof(PartEntry));
    memcpy(Device.data + PARTITION_TABLE_OFFSET + PARTITION_ENTRY_SIZE, &ptr2, sizeof(PartEntry));
    memcpy(Device.data + l1offset - 2, &lptr1, sizeof(PartEntry));
    memcpy(Device.data + l1offset - 2 + sizeof(PartEntry), &lptr1link, sizeof(PartEntry));
    memcpy(Device.data + l1offset + 0x40 - 0x02, &(mbr->signature), 2);
    memcpy(Device.data + l2offset - 2, &lptr2, sizeof(PartEntry));
    memcpy(Device.data + l2offset + 0x40 - 0x02, &(mbr->signature), 2); 
    add_disk(Device.gd);
    kfree(mbr);
    return 0;

out_unregister:
    unregister_blkdev(major_num, "sbd");
out:
    vfree(Device.data);
    return -ENOMEM;
}

static void __exit sbd_exit(void)
{
    del_gendisk(Device.gd);
    put_disk(Device.gd);
    unregister_blkdev(major_num, "sbd");
    blk_cleanup_queue(Queue);
    vfree(Device.data);
}

module_init(sbd_init);
module_exit(sbd_exit);