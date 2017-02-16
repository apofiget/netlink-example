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
 *     Update #: 268
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
#include <poll.h>

#include "userspace_netlink.h"
#include "nl_msg.h"

char *print_out_m_type(m_type_t message) {
    static char out[64];
    char *ptr = NULL;
    size_t i = 0;
    int len = 0;
    struct mtypes {
        m_type_t type;
        char *name;
    } m_array[] = {{MSG_OK, "MSG_OK"},
                   {MSG_PING, "MSG_PING"},
                   {MSG_PONG, "MSG_PONG"},
                   {MSG_DATA, "MSG_DATA"}};

    ptr = out;

    for (i = 0; i < sizeof(m_array) / sizeof(m_array[0]); i++) {
        if (message & m_array[i].type) {
            len = sprintf(ptr, " %s |", m_array[i].name);
            ptr = (char *)((size_t)ptr + (size_t)len);
        }
    }

    sprintf(((char *)(void *) ptr - 1), "(%d)", message);

    return out;
}

inline void adv_offset(unsigned *offset, unsigned int adv_to, unsigned int ring_sz) {
    *offset = (*offset + adv_to) % ring_sz;
}

void *prepare_nlh(struct nlmsghdr *nlh, unsigned int size, pid_t sender_pid) {
    nlh->nlmsg_len = NLMSG_SPACE(size);
    nlh->nlmsg_pid = sender_pid;
    nlh->nlmsg_flags |= NLM_F_REQUEST;
    nlh->nlmsg_type = NLMSG_MIN_TYPE + 1;

    return NLMSG_DATA(nlh);
}

void prepare_frame_hdr(struct nl_mmap_hdr *fr_hdr, struct nlmsghdr *nlh) {
    fr_hdr->nm_len = nlh->nlmsg_len;
    fr_hdr->nm_status = NL_MMAP_STATUS_VALID;
    fr_hdr->nm_group = 0;
    fr_hdr->nm_pid = 0;

    return;
}

void process_msg(struct nlmsghdr *nlh) {
    us_nl_msg_t *msg = NULL;
    void *data = NULL;

    if (nlh->nlmsg_len < sizeof(us_nl_msg_t)) {
        printf("Message len %d too short Should be at least %d.\n", nlh->nlmsg_len,
               sizeof(us_nl_msg_t));
        return;
    }

    msg = (us_nl_msg_t *)((void *)nlh + sizeof(struct nlmsghdr));
    data = (void *)((void *)msg + sizeof(us_nl_msg_t));

    printf("Message from kernel. Type: %s , data len: %d , data: %.*s\n",
           print_out_m_type(msg->type), msg->len, (msg->len == 0 ? strlen("NONE") : msg->len),
           (msg->len == 0 ? "NONE" : (char *)data));

    return;
}

int rcv_msg(ring_t *r) {
    struct nl_mmap_hdr *fr_hdr;
    struct nlmsghdr *nlh;
    unsigned char buf[NL_FR_SZ];
    ssize_t len;
    struct pollfd pfds[1];
    int exit_loop;

    while (1) {
        pfds[0].fd = r->fd;
        pfds[0].events = POLLIN | POLLERR;
        pfds[0].revents = 0;

        if (poll(pfds, 1, -1) < 0 && errno != -EINTR) return 0;

        if (pfds[0].revents & POLLERR) return 0;
        if (!(pfds[0].revents & POLLIN)) continue;

        exit_loop = 0;

        while (1) {
            fr_hdr = (struct nl_mmap_hdr *)(r->rx_ring + r->rx_offset);

            switch (fr_hdr->nm_status) {
            case NL_MMAP_STATUS_VALID:
                nlh = (struct nlmsghdr *)((void *)fr_hdr + NL_MMAP_HDRLEN);
                len = fr_hdr->nm_len;
                if (len != 0) process_msg(nlh);
                break;

            case NL_MMAP_STATUS_COPY:
                printf("Frame could not mapped. Back to regular recv()\n");
                if ((len = recv(r->fd, buf, sizeof(buf), MSG_DONTWAIT)) <= 0) break;
                nlh = (struct nlmsghdr *)buf;
                process_msg(nlh);
                break;
            default:
                exit_loop++;
                break;
            }

            if (exit_loop) break;

            fr_hdr->nm_status = NL_MMAP_STATUS_UNUSED;

            adv_offset(&r->rx_offset, NL_FR_SZ, r->ring_sz);
        }
    }

    return 1;
}

int msg_send(ring_t *r, void *data, size_t data_len) {
    struct nl_mmap_hdr *fr_hdr;
    struct nlmsghdr *nlh;
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK, .nl_pid = DST_KERNEL, .nl_groups = NETLINK_UNICAST_SEND,
    };
    us_nl_msg_t *message = NULL;
    void *user_data = NULL;
    int bytes_sent = 0;

    fr_hdr = r->tx_ring + r->tx_offset;

    if (fr_hdr->nm_status != NL_MMAP_STATUS_UNUSED) return 0;

    if (data == NULL || data_len == 0) data_len = 0;

    nlh = (void *)fr_hdr + NL_MMAP_HDRLEN;

    message =
        (us_nl_msg_t *)prepare_nlh(nlh, (unsigned int)(sizeof(us_nl_msg_t) + data_len), r->own_pid);

    memset(message, 0, sizeof(us_nl_msg_t) + data_len);

    if (data_len != 0) {
        message->type = MSG_OK | MSG_DATA;
        message->len = data_len;
        user_data = (char *)((void *)message + sizeof(us_nl_msg_t));
    } else
        message->type = MSG_OK | MSG_PING;

    if (data_len) memcpy(user_data, data, data_len);

    prepare_frame_hdr(fr_hdr, nlh);

    if ((bytes_sent = sendto(r->fd, NULL, 0, 0, (const struct sockaddr *)&addr, sizeof(addr))) < 0)
        return 0;

    adv_offset(&r->tx_offset, NL_FR_SZ, r->ring_sz);

    return bytes_sent;
}

int main(int argc, char **argv) {
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    struct nl_mmap_req req;
    char *message =
        "So logn-long-long message to kernel from userspace application. Bla-bla-bla! Hello!";
    char *another_message =
        "Another long-long-long message to kernel from userspace application. Hello one more time!";
    ring_t r;
    int bytes_sent = 0;

    memset((void *)&r, 0, sizeof(r));
    r.ring_sz = MMAP_SZ / 2;
    r.blk_sz = 16 * getpagesize();
    r.own_pid = getpid();

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

    if ((bytes_sent = msg_send(&r, (void *)message, strlen(message) + 1)) == 0)
        err(EXIT_FAILURE, "Sending error ", strerror(errno));

    if ((bytes_sent = msg_send(&r, NULL, 0)) == 0)
        err(EXIT_FAILURE, "Sending error ", strerror(errno));

    if ((bytes_sent = msg_send(&r, (void*)another_message, strlen(another_message) + 1)) == 0)
        err(EXIT_FAILURE, "Sending error ", strerror(errno));

    printf("Message size: %d, %d bytes sent to kernel.\n", strlen(message), bytes_sent);
    printf("Waiting for message from kernel\n");

    rcv_msg(&r);

    munmap(r.rx_ring, r.ring_sz * 2);

    close(r.fd);
}

/* userspace_netlink_mmaped.c ends here */
