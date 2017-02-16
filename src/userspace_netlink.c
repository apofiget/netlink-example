/* userspace_netlink.c ---
 *
 * Filename: userspace_netlink.c
 * Description:
 * Author: Andrey Andruschenko
 * Maintainer:
 * Created: Чт фев  9 15:37:35 2017 (+0300)
 * Version:
 * Package-Requires: ()
 * Last-Updated:
 *           By:
 *     Update #: 74
 * URL:
 * Doc URL: https://fpbrain.blogspot.ru/2017/02/mmaped-netlink-in-linux-kernel-zero.html
 * Keywords: linux, netlink, mmap
 * Compatibility:
 *
 */

#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>

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

int main() {
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;
    us_nl_msg_t u_msg_hdr, *resp;
    char *hello_msg = "Hello from userspace", *resp_hello = NULL;

    if ((sock_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_USERSOCK)) < 0)
        err(EXIT_FAILURE, "socket() ");

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0)
        err(EXIT_FAILURE, "bind() ");

    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = DST_KERNEL;
    dest_addr.nl_groups = NETLINK_UNICAST_SEND;

    if ((nlh = (struct nlmsghdr *)calloc(1, NLMSG_SPACE(MAX_PAYLOAD))) == NULL)
        err(EXIT_FAILURE, "calloc() ");

    nlh->nlmsg_len = NLMSG_SPACE(sizeof(us_nl_msg_t) + strlen(hello_msg) + 1);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags |= NLM_F_REQUEST;
    nlh->nlmsg_type = NLMSG_MIN_TYPE + 1;

    u_msg_hdr.type = MSG_OK | MSG_PING | MSG_DATA;
    u_msg_hdr.len = strlen(hello_msg) + 1;

    memcpy((void *)NLMSG_DATA(nlh), &u_msg_hdr, sizeof(us_nl_msg_t));
    memcpy((void *)(NLMSG_DATA(nlh) + sizeof(us_nl_msg_t)), hello_msg, u_msg_hdr.len - 1);

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

    resp = (us_nl_msg_t *)NLMSG_DATA(nlh);
    resp_hello = (char *)((void *)resp + sizeof(us_nl_msg_t));

    printf("Received message payload: %s %d bytes %.*s\n", print_out_m_type(resp->type), resp->len,
           resp->len, resp_hello);

    close(sock_fd);
}

/* userspace_netlink.c ends here */
