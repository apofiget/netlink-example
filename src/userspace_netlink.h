/* userspace_netlink.h ---
 *
 * Filename: userspace_netlink.h
 * Description:
 * Author: Andrey Andruschenko
 * Maintainer:
 * Created: Пт фев 10 16:11:41 2017 (+0300)
 * Version:
 * Package-Requires: ()
 * Last-Updated:
 *           By:
 *     Update #: 12
 * URL:
 * Doc URL:
 * Keywords:
 * Compatibility:
 *
 */

#ifndef __USERSPACE_NETLINK_H_
#define __USERSPACE_NETLINK_H_

#define MAX_PAYLOAD 1024
#define NETLINK_UNICAST_SEND 0
#define DST_KERNEL 0
#define MMAP_SZ 131072

typedef struct __ring_t_ {
    int fd;
    void *rx_ring;
    void *tx_ring;
    unsigned int blk_sz;
    unsigned int ring_sz;
    unsigned int tx_offset;
    unsigned int rx_offset;
    pid_t own_pid;
} ring_t;

#endif
/* userspace_netlink.h ends here */
