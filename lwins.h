/*
    LWINS - Lightweight WINS Server http://www.lwins.org/

    Copyright (c) 2008 - 2010 by Thomas Bluemel <thomasb@lwins.org>

    This file is part of LWINS.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <execinfo.h>
#include <ucontext.h>

#define DBG_MEM_LEAK /* Define to enable debugging memory leaks */
#define DBG_PACKETS /* Define to be able to debug packets */

#define ARRAY_CNT(arr) (sizeof (arr) / sizeof (arr[0]))

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define __attr_format__(format_idx, arg_idx) \
    __attribute__((format (printf, format_idx, arg_idx)))
#define __attr_noreturn__ __attribute__((noreturn))
#else
#define __attr_format__(format_idx, arg_idx)
#define __attr_noreturn__
#endif

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

/* config.c */

struct lwins_config_option
{
    char *name;
    char **params;
    unsigned int params_cnt;
};

struct lwins_config
{
    struct lwins_config_option *options;
    unsigned int options_cnt;
};

int lwins_convert_to_integer (const char *param, unsigned int *ret);
int lwins_convert_to_bool (const char *param, int *ret);
int lwins_convert_to_ip (const char *param, struct in_addr *ret);
void lwins_free_config (struct lwins_config *cfg);
int lwins_read_config_args (int argc, const char *argv[], struct lwins_config *cfg);
int lwins_get_config_param (struct lwins_config *cfg, const char *option, unsigned int idx, const char **value);
int lwins_get_config_param_long (struct lwins_config *cfg, const char *option, unsigned int idx, unsigned long *value);
int lwins_config_get_option_param_cnt (struct lwins_config *cfg, const char *option);
int lwins_config_option_has_param (struct lwins_config *cfg, const char *option, const char *param);

/* discover.c */

#define DISCOVER_OP_UP 0
#define DISCOVER_OP_DOWN 1
struct nbns_discover_packet
{
    u32 op_code;
    struct in_addr *addresses;
    u16 addresses_cnt;
};

size_t calculate_nbns_discover_packet_size (struct nbns_discover_packet *packet);
void free_nbns_discover_packet (struct nbns_discover_packet *packet);
int parse_raw_nbns_discover_packet (unsigned char *raw_packet, size_t len, struct nbns_discover_packet *packet);
int build_raw_nbns_discover_packet (unsigned char *raw_packet, size_t len, struct nbns_discover_packet *packet);

/* netbios.c */
#define NETBT_MAX_LABELS 64

#define NETBT_COMPRESSED_MAX 255
#define NETBT_NAME_LENGTH 16

#define NETBT_HEADER_SIZE 12

#define NETBT_OP_QUERY 0
#define NETBT_OP_REGISTRATION 5
#define NETBT_OP_RELEASE 6
#define NETBT_OP_WACK 7
#define NETBT_OP_REFRESH 8
#define NETBT_OP_REFRESH_ALTERNATIVE 9
#define NETBT_OP_MULTIHOMED_REGISTRATION 15

struct netbt_header
{
    u16 tran_id;
    union
    {
        u16 u;
        struct
        {
            u8 is_response : 1;
            u8 op_code : 4;
            u8 authoritive_answer : 1;
            u8 truncation : 1;
            u8 recursion_desired : 1;
            u8 recursion_available : 1;
            u8 broadcast : 1;
        };
    };
    u16 qscnt;
    u16 ancnt;
    u16 nscnt;
    u16 arcnt;
    u8 response_code;
};

struct netbt_question
{
    char *qname;
    u16 qtype;
    u16 qclass;
};

struct netbt_resource
{
    char *rname;
    unsigned char *rdata;
    u32 rttl;
    u16 rtype;
    u16 rclass;
    u16 rdlen;
};

struct netbt_packet
{
    struct sockaddr_in addr;
    struct netbt_header header;
    struct netbt_question *questions;
    struct netbt_resource *answers;
    struct netbt_resource *authority;
    struct netbt_resource *additional;
};

int netbt_is_name_reserved (const char *name);
int netbt_is_valid_netbios_name (const char *name);
int netbt_is_valid_domain_name (const char *name);
int netbt_encode_netbios_name (const char *name, char *encoded, size_t encoded_size);
int netbt_decode_netbios_name (const char *encoded_name, char *decoded_name, size_t decoded_size);
struct netbt_packet* netbt_alloc_packet (void);
void netbt_free_packet_mem (struct netbt_packet *packet);
void netbt_free_packet (struct netbt_packet *packet);
struct netbt_packet* netbt_duplicate_packet (struct netbt_packet *packet);
int netbt_parse_raw_packet (unsigned char *raw_packet, size_t len, struct sockaddr_in *addr, struct netbt_packet *packet);
int netbt_build_raw_packet (struct netbt_packet *packet, unsigned char *raw_packet, size_t len);
const char* netbt_packet_question (struct netbt_packet *packet, unsigned int idx);

size_t netbt_name_to_str (const char *decoded_name, char *buffer, size_t buffer_size);
size_t netbt_str_to_name (const char *str, char *buffer, size_t buffer_size);
char* netbt_dup_name (const char *decoded_name);

/* replicate.c */

struct lwins_version
{
    u32 high;
    u32 low;
};

static __inline int lwins_is_version_higher (const struct lwins_version *version, const struct lwins_version *cmp)
{
    return version->high > cmp->high || (version->high == cmp->high && version->low > cmp->low);
}

static __inline int lwins_is_version_higher_equal (const struct lwins_version *version, const struct lwins_version *cmp)
{
    return version->high > cmp->high || (version->high == cmp->high && version->low >= cmp->low);
}

static __inline int lwins_is_version_lower (const struct lwins_version *version, const struct lwins_version *cmp)
{
    return version->high < cmp->high || (version->high == cmp->high && version->low < cmp->low);
}

static __inline int lwins_is_version_lower_equal (const struct lwins_version *version, const struct lwins_version *cmp)
{
    return version->high < cmp->high || (version->high == cmp->high && version->low <= cmp->low);
}

static __inline int lwins_is_version_equal (const struct lwins_version *version, const struct lwins_version *cmp)
{
    return version->high == cmp->high && version->low == cmp->low;
}

#define REPL_MSG_ASSOC_START_REQ 0x0
#define REPL_MSG_ASSOC_START_RESP 0x1
#define REPL_MSG_ASSOC_STOP_REQ 0x2
#define REPL_MSG_PUSHPULL 0x3
#define REPL_MSG_MAX REPL_MSG_PUSHPULL
struct replication_packet_header
{
    u32 assoc_handle;
    u32 msg_type;
};

struct replication_assoc_start
{
    u32 sdr_assoc_handle;
    u16 nbns_version_major;
    u16 nbns_version_minor;
};

#define REPL_ASSOC_STOP_NORMAL 0x0
#define REPL_ASSOC_STOP_ERROR 0x4
struct replication_assoc_stop
{
    u32 reason;
};

struct replication_owner_record
{
    struct in_addr addr;
    struct lwins_version max_version;
    struct lwins_version min_version;
};

struct replication_pushpull_ovmap
{
    u32 owners_cnt;
    struct replication_owner_record *owners;
};

struct replication_pushpull_updatenotify
{
    u32 owners_cnt;
    struct replication_owner_record *owners;
    struct in_addr initiator_addr;
};

struct replication_name_record_addr
{
    struct in_addr owner;
    struct in_addr member;
};

#define NREC_NODE_B 0x0
#define NREC_NODE_P 0x1
#define NREC_NODE_M 0x2

#define NREC_STATE_ACTIVE 0x0
#define NREC_STATE_RELEASED 0x1
#define NREC_STATE_TOMBSTONE 0x2

#define NREC_TYPE_UNIQUE 0x0
#define NREC_TYPE_GROUP 0x1
#define NREC_TYPE_GROUP_SPECIAL 0x2
#define NREC_TYPE_MULTIHOMED 0x3

struct replication_name_record
{
    char *name;
    u8 is_static;
    u8 node_type;
    u8 is_replica;
    u8 state;
    u8 type;
    struct lwins_version version;
    u32 version_high;
    u32 version_low;
    u8 addrs_cnt;
    struct replication_name_record_addr *addrs;
};

struct replication_pushpull_namerec_req
{
    struct replication_owner_record rec;
};

struct replication_pushpull_namerec_resp
{
    u32 namerecs_cnt;
    struct replication_name_record **namerecs;
};

#define REPL_PUSHPULL_OP_OVMAP_REQ 0x0
#define REPL_PUSHPULL_OP_OVMAP_RESP 0x1
#define REPL_PUSHPULL_OP_NREC_REQ 0x2
#define REPL_PUSHPULL_OP_NREC_RESP 0x3
#define REPL_PUSHPULL_OP_UN_NO_PROPAGATE 0x4
#define REPL_PUSHPULL_OP_UN_PROPAGATE 0x5
#define REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE 0x8
#define REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE 0x9
struct replication_pushpull
{
    u8 op_code;
    
    union
    {
        struct replication_pushpull_ovmap ovmap_resp;
        struct replication_pushpull_updatenotify updatenotify;
        struct replication_pushpull_namerec_req namerec_req;
        struct replication_pushpull_namerec_resp namerec_resp;
    };
};

struct replication_packet
{
    struct replication_packet_header header;
    union
    {
        struct replication_assoc_start assoc_start;
        struct replication_assoc_stop assoc_stop;
        struct replication_pushpull pushpull;
    };
};

struct replication_owner_request
{
    struct in_addr owner;
    struct lwins_version max_version;
    struct lwins_version min_version;
};

struct reg_entry;
struct merge_data
{
    struct reg_entry *existing_entry;
    struct reg_entry *new_entry;
    struct replication_service *service;
};

struct association
{
    u32 handle;
    int sd;
    struct sockaddr_in client;
    struct sockaddr_in server;
    
    unsigned char *buffer;
    size_t buffer_size;
    size_t buffer_length;

    int req_owners_cnt;
    struct replication_owner_request *req_owners;
    
    int un_requests_cnt;
    struct replication_packet **un_requests;
    struct replication_packet *un_req_propagate;
    
    struct lwins_event *timeout_event;
    
    u32 sender_handle;
    u8 step;
    u8 incoming : 1; /* Indicates that this is an incoming connection */
    u8 shutdown_conn : 1; /* Indicates that we should stop the association */
    u8 completed : 1;
    u8 started : 1; /* Indicates that we received or sent a start request */
    u8 stopped : 1; /* We received a stop request */
    u8 stop_requested : 1; /* We sent a stop request */
    u8 closed_conn : 1; /* Indicates that the connection was closed */
    u8 error : 1;
    u8 timeout : 1; /* Indicates that a timeout occured */
    u8 propagate : 1;
    u8 persistent : 1;
    u8 reprocess_packet : 1;
};

struct replication_service
{
    struct netbios_server *server;

    /* association handles */
    struct association **associations;
    unsigned short associations_size;
    unsigned short associations_cnt;
    
    /* merge requests */
    //unsigned int merge_data_cnt;
    //struct merge_data *merge_data;
    
    unsigned int max_packet_size;
    unsigned int max_pull_verify_records;
};

int replication_build_raw_packet (unsigned char *raw_packet, size_t packet_size, struct replication_packet *packet);
int replication_parse_raw_packet (unsigned char *raw_packet, size_t packet_size, struct replication_packet *packet);
void replication_free_packet (struct replication_packet *packet);
void lwins_free_replication_packet (struct replication_packet *packet);
struct replication_packet* lwins_duplicate_replication_packet (struct replication_packet *packet);
struct association *alloc_association (struct replication_service *service, int sd, struct sockaddr_in *client);
void free_association (struct replication_service *service, struct association *assoc);
void shutdown_association (struct replication_service *service, struct association *assoc);
struct association *find_association (struct replication_service *service, int sd);
struct replication_service *init_replication_service (struct lwins_config *cfg);
int is_replication_service_terminated (struct replication_service *service);
void terminate_replication_service (struct replication_service *service);
void free_replication_service (struct replication_service *service);
int association_buffer_receive(struct replication_service *service, struct association *assoc, unsigned char *buffer, size_t buffer_size);

/* control.c */

struct lwins_control_client
{
	int sd;

};

struct lwins_control
{
	struct netbios_server *server;

	int control_sd;
	int client_cnt;
	struct lwins_control_client *clients;
};

/* server.c */
struct registry;

struct wins_svc
{
    int sd;
    struct in_addr addr;
};

struct lwins_event;

typedef void (*lwins_event_handler)(struct netbios_server *server, struct lwins_event *event);

#define LWINS_EVENT_INSERTED 0x1
#define LWINS_EVENT_TIMEDOUT 0x2
#define LWINS_EVENT_DELETING 0x4

struct lwins_event
{
    struct timeval due;
    void *context;
    lwins_event_handler handler;
    lwins_event_handler deletion_handler;
    struct lwins_event *next;
    unsigned int flags;
};

struct nbns_req
{
    u16 tran_id;
    u16 req_cnt;

    struct sockaddr_in client;
    struct lwins_event *event;

    struct netbt_packet *reply_packet;

    struct nbns_req *next;
};

typedef unsigned long int lwins_fd_bits;
#define LWINS_FD_BITS (sizeof (lwins_fd_bits) * 8)
#define LWINS_FD_ROUND_SIZE(maxfd) ((((maxfd) / 8) + sizeof (lwins_fd_bits) - 1) / sizeof (lwins_fd_bits))
#define LWINS_FD_INDEX(fd) ((fd) / LWINS_FD_BITS)
#define LWINS_FD_MASK(fd) ((lwins_fd_bits)1 << ((fd) % LWINS_FD_BITS))

struct lwins_fd_set
{
    int cnt;
    int max_fd;
    lwins_fd_bits *fd_set;
};

typedef void (*send_buffer_flushed)(struct netbios_server *server, void *ctx);

struct send_buffer
{
    struct send_buffer *next;
    int sd;
    unsigned char *buffer;
    size_t sent;
    size_t size;
    send_buffer_flushed flushed;
    void *ctx;
};

#define SERVER_INITIALIZING 0
#define SERVER_RUNNING 1
#define SERVER_TERMINATING 2
#define SERVER_STOPPED 3

struct netbios_server
{
    volatile unsigned int *terminate;
    int status;
    
    struct lwins_fd_set master_fds;
    struct lwins_fd_set sending_fds;
    struct send_buffer *send;
    
    int nbns_cnt;
    int nbns_tran_cnt;
    struct wins_svc *nbns_svc;
    struct nbns_req *nbns_req;

    int replication_cnt;
    struct wins_svc *replication_svc;
    
    int discovery_sd;
    unsigned long discovery_interval;

	struct lwins_control *control;
    
    struct timeval current_time;
    
    struct lwins_event *events;
    
    const char *database_file;
    unsigned int database_save_interval;
    
    struct lwins_config *config;
    struct replication_service *replication;

    struct registry *registry;
};

int lwins_make_socket_nonblocking (int sd);
int lwins_send_socket (struct netbios_server *server, int sd, unsigned char *buffer, size_t len);
int lwins_register_socket_flushed (struct netbios_server *server, int sd, send_buffer_flushed flushed, void *ctx);
int lwins_is_socket_sending (struct netbios_server *server, int sd);
int lwins_set_socket_broadcast (int sd, int enable);
int lwins_broadcast_discover_msg (struct netbios_server *server, u32 op_code);
struct netbios_server* lwins_setup_server (struct lwins_config *cfg, volatile unsigned int *terminate);
void lwins_run_server (struct netbios_server *server);
void lwins_free_server (struct netbios_server *server);
int is_own_replication_address (struct netbios_server *server, struct in_addr *addr);
void lwins_close_socket (struct netbios_server *server, int sd);
void lwins_calculate_due_time (struct netbios_server *server, struct timeval *due, int seconds);
void lwins_set_event_due (struct netbios_server *server, struct lwins_event *event, const struct timeval *new_due);
void lwins_delete_event (struct netbios_server *server, struct lwins_event *event);
int lwins_delete_event_by_context (struct netbios_server *server, void *context);
struct lwins_event* lwins_add_event (struct netbios_server *server, lwins_event_handler handler, lwins_event_handler deletion_handler, void *context, const struct timeval *due);

int lwins_write_line (int fd, const char *line);
typedef int (*plwins_enum_section_line) (char *line, size_t line_size, void *ctx);
int lwins_enum_section_lines (int fd, const char *section, size_t max_line_size, plwins_enum_section_line enum_proc, void *ctx);

#ifdef DBG_MEM_LEAK
#define lwins_alloc(size) lwins_dbg_alloc(size, __FILE__, __LINE__)
#define lwins_free(ptr) lwins_dbg_free(ptr, __FILE__, __LINE__)
#else
void *lwins_alloc (size_t size);
void lwins_free (void *ptr);
#endif

/* registry.c */

struct reg_entry
{
    struct reg_entry *next;
    struct reg_entry *next_event;
    time_t event_time;
    time_t last_update;
    struct in_addr owner;
    
    struct replication_name_record rec;
    
    u8 locked : 1;
    
    /* The delete_tmp flag is set to 1 for all matching entries when a name record
       response is received.  This flag is set to 0 for all entries that are
       added or updated.  If there are any entries after merging that have not
       been updated, they are deleted */
    u8 delete_tmp : 1;
};

struct reg_owner_version
{
    struct in_addr owner;
    struct lwins_version max_version;
    struct lwins_version min_version;
    u32 entries_cnt;
};

struct registry
{
    unsigned int entries_cnt;
    struct reg_entry *entries;
    struct reg_entry *event_entries;
    
    /* owner/version map */
    unsigned int owner_version_cnt;
    struct reg_owner_version *owner_version;
    
    struct lwins_event *scavenge_event;
    
    struct netbios_server *server;
    
    time_t renewal_interval;
    time_t extinction_interval;
    time_t extinction_timeout;
    
    u8 in_scavenge_event : 1;
};

struct registry* lwins_create_registry (struct netbios_server *server);
void lwins_destroy_registry (struct registry *reg);
void lwins_free_reg_entry (struct registry *reg, struct reg_entry *entry);
typedef int (*plwins_enum_proc)(struct registry *reg, const struct reg_entry *entry, void *ctx);
int lwins_find_registry_entries (struct registry *reg, const char *match, plwins_enum_proc enum_proc, void *ctx);
struct reg_entry* lwins_find_registry_entry (struct registry *reg, const char *match);
struct replication_name_record* lwins_get_namerec_from_registry_entry (struct registry *reg, struct reg_entry *reg_entry);
struct reg_entry* lwins_create_registry_entry_from_namerec (struct registry *reg, struct replication_name_record *namerec, struct in_addr *owner);
void lwins_add_registry_entry (struct registry *reg, struct reg_entry *reg_entry);
void lwins_del_registry_entry (struct registry *reg, struct reg_entry *reg_entry);
int lwins_registry_load (struct registry *reg, int fd);
int lwins_registry_save (struct registry *reg, int fd);
struct reg_owner_version *lwins_registry_find_owner_version (struct registry *reg, struct in_addr *owner);
int lwins_update_registry_entry (struct registry *reg, struct reg_entry *entry, struct replication_name_record *namerec);
void lwins_registry_scavenge (struct registry *reg, struct reg_entry *event_entry);
void lwins_registry_merge_begin (struct registry *reg, struct replication_owner_request *req);
u32 lwins_nrec_get_registry_entries (struct registry *reg, struct replication_owner_record *req, struct replication_name_record **namerecs, u32 namerecs_cnt);
unsigned int lwins_registry_merge_end (struct registry *reg);
void lwins_registry_merge_skip_entry (struct registry *reg, struct reg_entry *entry);
void lwins_log_regentry (struct reg_entry *entry, const char *description);

/* debug.c */
void lwins_setup_stack_traces (void);

#ifdef DBG_MEM_LEAK
#define lwins_dbg_mem_check() lwins_dbg_mem_dump_leaks (__FILE__, __LINE__)
void lwins_dbg_mem_dump_leaks (const char *file, int line);
void *lwins_dbg_alloc (size_t size, const char *file, int line);
void lwins_dbg_free (void *ptr, const char *file, int line);
void lwins_init_memstat (struct netbios_server *server);
#endif

#define LWINS_ERR \
    LOG (LOG_ERR, "LWINS_ERR in %s at %s:%d\n", __FUNCTION__, __FILE__, __LINE__), 0

void lwins_assert (const char *msg, const char *file, int line) __attr_noreturn__;

#define ASSERT(cnd) \
    if (!(cnd)) { \
        assert (cnd); \
        lwins_assert (#cnd, __FILE__, __LINE__); \
    }
#define LOG(level,fmt,...) \
    lwins_log (level, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGSYSERR(func) \
    lwins_log (LOG_ERR, __FILE__, __LINE__, func " failed: %d (%s)\n", errno, strerror (errno))

#define LOG_ALL 0
#define LOG_WARN 1
#define LOG_ERR 2
#define LOG_PACKET 31
void lwins_log (int level, const char *file, int line, const char *fmt, ...) __attr_format__ (4, 5);
void lwins_dbg_start_assoc (u32 handle);
void lwins_dbg_start_nbns (u16 tran_id);
void lwins_dbg_start_discover (void);
void lwins_dbg_start (void);
int lwins_check_loglevel (int level);

#ifdef DBG_PACKETS
#define LOGPACKET(packet,len,client,dumpfunc) \
    if (lwins_check_loglevel (LOG_PACKET)) \
        dumpfunc (packet, len, client)
void lwins_dump_nbns_raw_packet (unsigned char *raw_packet, size_t len, struct sockaddr_in *client);
void lwins_dump_discovery_raw_packet (unsigned char *raw_packet, size_t len, struct sockaddr_in *client);
void lwins_dump_replication_raw_packet_from (unsigned char *raw_packet, size_t len, struct sockaddr_in *client);
void lwins_dump_replication_raw_packet_to (unsigned char *raw_packet, size_t len, struct sockaddr_in *client);
#else
#define LOGPACKET(packet,len,client,dumpfunc) do { } while (0)
#endif
