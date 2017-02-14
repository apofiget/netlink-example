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
 *     Update #: 110
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

static int hello_nl_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh) {
    us_nl_msg_t *msg;
    char *usr_message;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    if (nlh->nlmsg_len < sizeof(*nlh) + sizeof(us_nl_msg_t)) {
        printk(KERN_ALERT "Message to short %d", nlh->nlmsg_len);
        return -EINVAL;
    }

    msg = nlmsg_data(nlh);
    usr_message = (char *)((void*)msg + sizeof(us_nl_msg_t));

    printk(KERN_INFO "[%u] User msg type (%d) , payload len: %d, message %s\n", nlh->nlmsg_pid, msg->type,
           (int)msg->len, usr_message);
    print_hex_dump(KERN_INFO, "mem:", DUMP_PREFIX_ADDRESS, 16, 1, (const void*)usr_message, msg->len, 1);

    return 1;
}

static void if_rcv(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    int ret;

    nlh = nlmsg_hdr(skb);

    printk("Entering: %s, nlh_len %d sk len %d data len %d\n", __FUNCTION__, nlh->nlmsg_len,
           skb->len, skb->data_len);

    ret = netlink_rcv_skb(skb, &hello_nl_recv_msg);

    printk("netlink_rcv_skb return %d\n", ret);
}

static int __init kern_netlink_init(void) {
    printk("Entering: %s\n", __FUNCTION__);

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
    printk(KERN_INFO "exiting kernel_netink module\n");
    netlink_kernel_release(nl_sk);
}

module_init(kern_netlink_init);
module_exit(kern_netlink_exit);

MODULE_LICENSE("GPL");

/* kernel_netlink.c ends here */
