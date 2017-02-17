/* nl_msg.h ---
 *
 * Filename: nl_msg.h
 * Description:
 * Author: Andrey Andruschenko
 * Maintainer:
 * Created: Пн фев 13 16:08:07 2017 (+0300)
 * Version:
 * Package-Requires: ()
 * Last-Updated:
 *           By:
 *     Update #: 11
 * URL:
 * Doc URL: https://fpbrain.blogspot.ru/2017/02/mmaped-netlink-in-linux-kernel-zero.html
 * Keywords:
 * Compatibility:
 *
 */

#ifndef __NL_MSG_H_
#define __NL_MSG_H_

#define MAX_PAYLOAD 1024
#define NL_FR_SZ 16384

typedef enum { MSG_OK = 1, MSG_PING = 2, MSG_PONG = 4, MSG_DATA = 8  } m_type_t;

typedef struct __nl_msg_ {
    m_type_t type; /* Message type */
    size_t len; /* Payload length */
} __attribute__((packed)) us_nl_msg_t;

#endif
/* nl_msg.h ends here */
