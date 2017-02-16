/* kernel_netlink.c ---
 *
 * Filename: kernel_netlink.c
 * Description:
 * Author: Andrey Andruschenko
 * Maintainer:
 * Created: Чт фев  9 15:42:17 2017 (+0300)
 * Version:
 * Package-Requires: ()
 * Last-Updated:
 *           By:
 *     Update #: 189
 * URL:
 * Doc URL:
 * Keywords:
 * Compatibility:
 *
 */

#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "nl_msg.h"

struct sock *nl_sk = NULL;

static char *print_out_m_type(m_type_t message) {
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

static int hello_nl_send_msg(struct sk_buff *skb, struct netlink_callback *cb) {
    struct nlmsghdr *nlh;
    us_nl_msg_t *resp, *req = cb->data;
    int msg_len = 0;
    char *resp_msg = NULL;

    if (cb->data != NULL) msg_len = req->len;

    if (!(nlh = nlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq, cb->nlh->nlmsg_type,
                          sizeof(us_nl_msg_t) + msg_len, 0)))
        return -EMSGSIZE;

    resp = (us_nl_msg_t *)nlmsg_data(nlh);

    if (req->type & MSG_DATA) {
        resp_msg = (char *)((void *)req + sizeof(us_nl_msg_t));
        resp->type = MSG_OK | MSG_DATA;
        resp->len = msg_len;
        memcpy((void *)((void *)resp + sizeof(us_nl_msg_t)), resp_msg, msg_len);
    }

    if (req->type & MSG_PING) resp->type |= (MSG_OK | MSG_PONG);

    printk(KERN_INFO "Sending %lu/%lu bytes to userspace.\n", resp->len,
           sizeof(us_nl_msg_t) + resp->len);

    return 0;
}

static int hello_nl_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh) {
    us_nl_msg_t *msg;
    char *usr_message;

    if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(us_nl_msg_t)) {
        printk(KERN_ALERT "Message to short %d", nlh->nlmsg_len);
        return -EINVAL;
    }

    msg = nlmsg_data(nlh);
    usr_message = (char *)((void *)msg + sizeof(us_nl_msg_t));

    printk(KERN_INFO "From [%u] msg type %s , payload len: %d, message %.*s\n", nlh->nlmsg_pid,
           print_out_m_type(msg->type), (int)msg->len, (int)msg->len, usr_message);

    struct netlink_dump_control c = {
        .dump = hello_nl_send_msg, .data = msg, .min_dump_alloc = NL_FR_SZ / 2,
    };

    return netlink_dump_start(nl_sk, skb, nlh, &c);

}

static void if_rcv(struct sk_buff *skb) {
    struct nlmsghdr *nlh;

    nlh = nlmsg_hdr(skb);

    netlink_rcv_skb(skb, &hello_nl_recv_msg);
}

static int __init kern_netlink_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = if_rcv,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);

    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    } else
        printk(KERN_INFO "Netlink socket created.\n");

    return 0;
}

static void __exit kern_netlink_exit(void) {
    netlink_kernel_release(nl_sk);
}

module_init(kern_netlink_init);
module_exit(kern_netlink_exit);

MODULE_LICENSE("GPL");

/* kernel_netlink.c ends here */
