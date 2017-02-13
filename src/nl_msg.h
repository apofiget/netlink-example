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
 *     Update #: 7
 * URL:
 * Doc URL:
 * Keywords:
 * Compatibility:
 *
 */

#ifndef __NL_MSG_H_
#define __NL_MSG_H_

typedef enum { MSG_PING = 2, MSG_PONG = 4, MSG_OK = 1 } m_type_t;

typedef struct __nl_msg_ {
    m_type_t type; /* Message type */
    size_t len; /* Payload length */
} us_nl_msg_t;

#endif
/* nl_msg.h ends here */
