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
 *     Update #: 91
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
#include "nl_msg.h"

inline void advoffset(unsigned *offset, unsigned int adv_to, unsigned int ring_sz) {
    *offset = (*offset + adv_to) % ring_sz;
}

int msg_send(ring_t *r, char *data, size_t len) {
    struct nl_mmap_hdr *fr_hdr;
    struct nlmsghdr *nlh;
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
    };
    us_nl_msg_t *message = NULL;
    void *user_data = NULL;

    fr_hdr = r->tx_ring + r->tx_offset;

    if (fr_hdr->nm_status != NL_MMAP_STATUS_UNUSED) /* No frame available. Use poll() to avoid. */
        exit(1);

    nlh = (void *)fr_hdr + NL_MMAP_HDRLEN;

    nlh->nlmsg_len = NLMSG_SPACE(sizeof(ring_t) + len);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    message = (us_nl_msg_t *)nlh + sizeof(struct nlmsghdr);
    message->type = MSG_OK | MSG_PING;
    message->len = len;

    user_data = (void *)message + sizeof(us_nl_msg_t);

    memcpy(user_data, data, len);

    /* Fill frame header: length and status need to be set */
    fr_hdr->nm_len = nlh->nlmsg_len;
    fr_hdr->nm_status = NL_MMAP_STATUS_VALID;

    if (sendto(r->fd, NULL, 0, 0, (const struct sockaddr *)&addr, sizeof(addr)) < 0) return 0;

    advoffset(&r->tx_offset, NL_MMAP_HDRLEN + sizeof(struct nlmsghdr) + sizeof(us_nl_msg_t) + len, r->ring_sz);

    return 1;
}

int main(int argc, char **argv) {
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    struct nl_mmap_req req;
    char *message = "Message to kernel from userspace application";
    ring_t r;

    memset((void *)&r, 0, sizeof(r));
    r.ring_sz = MMAP_SZ / 2;
    r.blk_sz = 16 * getpagesize();

    if ((r.fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_USERSOCK)) < 0)
        err(EXIT_FAILURE, "socket() ");

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    if (bind(r.fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0)
        err(EXIT_FAILURE, "bind() ");

    /* Memory mapped Netlink operation request */
    req.nm_block_size = r.blk_sz;
    req.nm_block_nr = (unsigned int)r.ring_sz / r.blk_sz;
    req.nm_frame_size = NL_FR_SZ;
    req.nm_frame_nr = r.ring_sz / NL_FR_SZ;

    if (setsockopt(r.fd, SOL_NETLINK, NETLINK_RX_RING, &req, sizeof(req)) < 0)
        err(EXIT_FAILURE, "cannot setup netlink rx ring ");
    if (setsockopt(r.fd, SOL_NETLINK, NETLINK_TX_RING, &req, sizeof(req)) < 0)
        err(EXIT_FAILURE, "cannot setup netlink tx ring ");

    r.rx_ring = (char *)mmap(NULL, MMAP_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, r.fd, 0);

    if (-1L == (long)r.rx_ring) err(EXIT_FAILURE, "memory mapping failed ");

    r.tx_ring = r.rx_ring + r.ring_sz;

    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = DST_KERNEL;
    dest_addr.nl_groups = NETLINK_UNICAST_SEND;

    printf("Sending message to kernel\n");

    if (msg_send(&r, message, strlen(message) + 1) == 0) err(EXIT_FAILURE, "Sending error ", strerror(errno));

    printf("Waiting for message from kernel\n");

    if (recvmsg(r.fd, &msg, 0) < 0) err(EXIT_FAILURE, "Receive error ", strerror(errno));

    printf("Received message payload: %s\n", (char *)NLMSG_DATA(nlh));

    munmap(r.rx_ring, r.ring_sz * 2);

    close(r.fd);
}

/* userspace_netlink_mmaped.c ends here */
