/* userspace_netlink_mmaped.c ---
 *
 * Filename: userspace_netlink_mmaped.c
 * Description:
 * Author: Andrey Andruschenko
 * Maintainer:
 * Created: Пт фев 10 15:47:47 2017 (+0300)
 * Version:
 * Package-Requires: ()
 * Last-Updated:
 *           By:
 *     Update #: 41
 * URL:
 * Doc URL:
 * Keywords:
 * Compatibility:
 *
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>

#include "userspace_netlink.h"

int main() {
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;
    unsigned int blk_sz, ring_sz = MMAP_SZ / 2;
    struct nl_mmap_req req;
    unsigned char *rx_ring = NULL, *tx_ring = NULL;

    if ((sock_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_USERSOCK)) < 0)
        err(EXIT_FAILURE, "socket() ");

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0)
        err(EXIT_FAILURE, "bind() ");

    blk_sz = 16 * getpagesize();

    /* Memory mapped Netlink operation request */
    req.nm_block_size = blk_sz;
    req.nm_block_nr = (unsigned int)ring_sz / blk_sz;
    req.nm_frame_size = NL_FR_SZ;
    req.nm_frame_nr = ring_sz / NL_FR_SZ;

    if (setsockopt(sock_fd, SOL_NETLINK, NETLINK_RX_RING, &req, sizeof(req)) < 0)
        err(EXIT_FAILURE, "cannot setup netlink rx ring ");
    if (setsockopt(sock_fd, SOL_NETLINK, NETLINK_TX_RING, &req, sizeof(req)) < 0)
        err(EXIT_FAILURE, "cannot setup netlink tx ring ");

    rx_ring = (char *)mmap(NULL, MMAP_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, sock_fd, 0);

    if (-1L == (long)rx_ring) err(EXIT_FAILURE, "mapping failed ");

    tx_ring = rx_ring + ring_sz;

    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = DST_KERNEL;
    dest_addr.nl_groups = NETLINK_UNICAST_SEND;

    if ((nlh = (struct nlmsghdr *)calloc(1, NLMSG_SPACE(MAX_PAYLOAD))) == NULL)
        err(EXIT_FAILURE, "calloc() ");

    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strcpy(NLMSG_DATA(nlh), "Hello from userspace");

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset((void *)&msg, 0, sizeof(msg));

    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("Sending message to kernel\n");

    if (sendmsg(sock_fd, &msg, 0) < 0) err(EXIT_FAILURE, "Sending error ", strerror(errno));

    printf("Waiting for message from kernel\n");

    if (recvmsg(sock_fd, &msg, 0) < 0) err(EXIT_FAILURE, "Receive error ", strerror(errno));

    printf("Received message payload: %s\n", (char *)NLMSG_DATA(nlh));

    munmap(rx_ring, ring_sz * 2);

    close(sock_fd);
}

/* userspace_netlink_mmaped.c ends here */
