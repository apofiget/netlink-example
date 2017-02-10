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
 *     Update #: 25
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

struct sock *nl_sk = NULL;

static void hello_nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "Hello from kernel";
    int res;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    msg_size = strlen(msg);

    nlh = (struct nlmsghdr *)skb->data;

    printk(KERN_INFO "Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
    pid = nlh->nlmsg_pid;

    skb_out = nlmsg_new(msg_size, 0);

    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

    strncpy(nlmsg_data(nlh), msg, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, pid);

    if (res < 0) printk(KERN_INFO "Error while sending bak to user\n");
}

static int __init kern_netlink_init(void) {
    printk("Entering: %s\n", __FUNCTION__);

    struct netlink_kernel_cfg cfg = {
        .groups = 0, .input = hello_nl_recv_msg,
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
