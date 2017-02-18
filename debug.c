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
#include <lwins.h>

static const unsigned int g_loglevel = 0xffffffff;
static char g_szReqId[6] = {0};

void lwins_dbg_start_nbns (u16 tran_id)
{
    sprintf (g_szReqId, "N%04x", tran_id & 0xFFFF);
}

static void lwins_dbg_start_memstat (void)
{
    strcpy (g_szReqId, "*MEM*");
}

void lwins_dbg_start_discover (void)
{
    static unsigned int req = 0;
    
    sprintf (g_szReqId, "D%04x", req);
    if (++req > 0xFFFF)
        req = 0;
}

void lwins_dbg_start_assoc (u32 handle)
{
    if (handle > 0xFFFF)
        strcpy (g_szReqId, "A????");
    else
        sprintf (g_szReqId, "A%04x", handle);
}

void lwins_dbg_start (void)
{
    memset (g_szReqId, 0, sizeof (g_szReqId));
}

#ifdef DBG_MEM_LEAK
#define LWINS_DBG_MEM_REDZONE_SIZE 32
#define LWINS_DBG_MEM_REDZONE_LEFT_PATTERN 0xAA
#define LWINS_DBG_MEM_REDZONE_RIGHT_PATTERN 0xDA
#define LWINS_DBG_MEM_FREED_PATTERN 0x55

struct lwins_mem_block
{
    struct lwins_mem_block *next;
    const char *file;
    size_t size;
    int line;
    void *data;
};

static const int dbg_memstat_interval = 60; /* Print memory statistics every 60 seconds */
static size_t dbg_alloc_cnt = 0;
static size_t dbg_alloc_size = 0;
static struct lwins_mem_block *dbg_mem_blocks = NULL;

#define LWINS_DBG_MEM_BLOCK_HEADER_SIZE \
    (size_t)(&((struct lwins_mem_block *)0)->data)
#define LWINS_DBG_MEM_BLOCK_SIZE(size) \
    (LWINS_DBG_MEM_BLOCK_HEADER_SIZE + (size_t)(size) + (2 * LWINS_DBG_MEM_REDZONE_SIZE))
#define LWINS_DBG_MEM_BLOCK_DATA(block) \
    (void *)((unsigned char *)(&(block)->data) + LWINS_DBG_MEM_REDZONE_SIZE)
#define LWINS_DBG_MEM_BLOCK_HEADER(data) \
    (struct lwins_mem_block *)((const unsigned char *)(data) - LWINS_DBG_MEM_BLOCK_HEADER_SIZE - LWINS_DBG_MEM_REDZONE_SIZE)
#define LWINS_DBG_MEM_BLOCK_REDZONE_LEFT(block) \
    (unsigned char *)(&(block)->data)
#define LWINS_DBG_MEM_BLOCK_REDZONE_RIGHT(block) \
    ((unsigned char *)LWINS_DBG_MEM_BLOCK_DATA(block) + (block)->size)

static int lwins_dbg_verify_redzone_left (struct lwins_mem_block *block)
{
    unsigned char *p;
    int i;
    
    for (p = LWINS_DBG_MEM_BLOCK_REDZONE_LEFT (block), i = 0; i < LWINS_DBG_MEM_REDZONE_SIZE; i++)
    {
        if (*p != LWINS_DBG_MEM_REDZONE_LEFT_PATTERN)
            return 0;
    }
    
    return 1;
}

static int lwins_dbg_verify_redzone_right (struct lwins_mem_block *block)
{
    unsigned char *p;
    int i;
    
    for (p = LWINS_DBG_MEM_BLOCK_REDZONE_RIGHT (block), i = 0; i < LWINS_DBG_MEM_REDZONE_SIZE; i++)
    {
        if (*p != LWINS_DBG_MEM_REDZONE_RIGHT_PATTERN)
            return 0;
    }
    
    return 1;
}

static int lwins_dbg_verify_redzone (struct lwins_mem_block *block, const char *file, int line)
{
    void *ptr = LWINS_DBG_MEM_BLOCK_DATA (block);
    
    if (!lwins_dbg_verify_redzone_left (block))
    {
        fprintf (stderr, "Buffer underflow detected on pointer %p size %zu allocated at %s:%d, detected at %s:%d\n", 
            ptr, block->size, block->file, block->line, file, line);
        return 0;
    }
    
    if (!lwins_dbg_verify_redzone_right (block))
    {
        fprintf (stderr, "Buffer overflow detected on pointer %p size %zu allocated at %s:%d, detected at %s:%d\n", 
            ptr, block->size, block->file, block->line, file, line);
        return 0;
    }
    
    return 1;
}

static int lwins_dbg_verify_all_redzones (const char *file, int line)
{
    struct lwins_mem_block *block;
    
    for (block = dbg_mem_blocks; block != NULL; block = block->next)
    {
        if (!lwins_dbg_verify_redzone (block, file, line))
            return 0;
    }
    
    return 1;
}

void *lwins_dbg_alloc (size_t size, const char *file, int line)
{
    struct lwins_mem_block *block;
    
    ASSERT (lwins_dbg_verify_all_redzones (file, line));
    
    block = malloc (LWINS_DBG_MEM_BLOCK_SIZE(size));
    if (!block)
        return NULL;
    
    block->file = file;
    block->line = line;
    block->size = size;
    memset (LWINS_DBG_MEM_BLOCK_REDZONE_LEFT (block), LWINS_DBG_MEM_REDZONE_LEFT_PATTERN, LWINS_DBG_MEM_REDZONE_SIZE);
    memset (LWINS_DBG_MEM_BLOCK_DATA (block), 0, size);
    memset (LWINS_DBG_MEM_BLOCK_REDZONE_RIGHT (block), LWINS_DBG_MEM_REDZONE_RIGHT_PATTERN, LWINS_DBG_MEM_REDZONE_SIZE);
    
    block->next = dbg_mem_blocks;
    dbg_mem_blocks = block;
    
    dbg_alloc_cnt++;
    dbg_alloc_size += size;
    
    return LWINS_DBG_MEM_BLOCK_DATA (block);
}

void lwins_dbg_free (void *ptr, const char *file, int line)
{
    struct lwins_mem_block *block, *cur, **prev;
    
    ASSERT (ptr);
    
    block = LWINS_DBG_MEM_BLOCK_HEADER(ptr);
    
    prev = &dbg_mem_blocks;
    cur = dbg_mem_blocks;
    while (cur)
    {
        if (cur == block)
        {
            *prev = cur->next;
            break;
        }
        
        prev = &cur->next;
        cur = cur->next;
    }
    
    if (cur == block)
    {
        ASSERT (lwins_dbg_verify_redzone (block, file, line));
        
        dbg_alloc_size -= block->size;
        dbg_alloc_cnt--;
        
        memset (LWINS_DBG_MEM_BLOCK_DATA (block), LWINS_DBG_MEM_FREED_PATTERN, block->size);
        
        free (block);
        
        ASSERT (lwins_dbg_verify_all_redzones (file, line));
    }
    else
    {
        fprintf (stderr, "Freeing invalid pointer %p at %s:%d\n", ptr, file, line);
        ASSERT (lwins_dbg_verify_all_redzones (file, line));
        ASSERT (0);
    }
}

void lwins_dbg_mem_dump_leaks (const char *file, int line)
{
    struct lwins_mem_block *block;
    size_t i;
    
    if (dbg_alloc_cnt != 0)
    {
        fprintf (stderr, "Memory leak detected: %zu blocks\n", dbg_alloc_cnt);
        
        for (block = dbg_mem_blocks, i = 0; block != NULL; block = block->next, i++)
        {
            fprintf (stderr, "    Block %p size %zu allocated at %s:%d\n", 
                LWINS_DBG_MEM_BLOCK_DATA (block), block->size, block->file, block->line);
            
            ASSERT (lwins_dbg_verify_redzone (block, file, line));
        }
        
        if (i != dbg_alloc_cnt)
            fprintf (stderr, "Memory corruption detected\n");
    }
}

static void lwins_dbg_memstat (void)
{
    lwins_dbg_start_memstat ();
    
    LOG (LOG_ALL, "%zu blocks allocated with a total size of %zu bytes\n", dbg_alloc_cnt, dbg_alloc_size);
    
    lwins_dbg_start ();
}

static void lwins_dbg_memstat_timer_handler (struct netbios_server *server, struct lwins_event *event)
{
    struct timeval due;
    
    lwins_dbg_memstat ();
    
    /* Update due date of timer */
    lwins_calculate_due_time (server, &due, dbg_memstat_interval);
    lwins_set_event_due (server, event, &due);
}

void lwins_init_memstat (struct netbios_server *server)
{
    struct timeval due;
    
    lwins_dbg_memstat ();
    
    lwins_calculate_due_time (server, &due, dbg_memstat_interval);
    if (!lwins_add_event (server, lwins_dbg_memstat_timer_handler, NULL, NULL, &due))
        LOG (LOG_ERR, "Could not install memory statistics timer\n");
}

#undef LWINS_DBG_MEM_BLOCK_REDZONE_RIGHT
#undef LWINS_DBG_MEM_BLOCK_REDZONE_LEFT
#undef LWINS_DBG_MEM_BLOCK_HEADER_SIZE
#undef LWINS_DBG_MEM_BLOCK_HEADER
#undef LWINS_DBG_MEM_BLOCK_DATA
#undef LWINS_DBG_MEM_BLOCK_SIZE

#endif

void lwins_assert (const char *msg, const char *file, int line)
{
    fprintf (stderr, "ASSERTION FAILED: %s at %s:%d\n", msg, file, line);
    exit (1);
}

void lwins_log (int level, const char *file, int line, const char *fmt, ...)
{
    va_list args;
    struct tm *ptm;
    struct timeval tv;
    
    (void)file;
    (void)line;
    
    if (gettimeofday (&tv, NULL) == 0)
    {
        ptm = localtime (&tv.tv_sec);
        fprintf (stderr, "%02d:%02d:%02d.%03ld ", ptm->tm_hour, ptm->tm_min, ptm->tm_sec, tv.tv_usec / 1000);
    }
    
    fprintf (stderr, "%-5.5s ", g_szReqId);
    va_start (args, fmt);
    if (!level || (g_loglevel & (1 << level)))
        vfprintf (stderr, fmt, args);
    va_end (args);
}

int lwins_check_loglevel (int level)
{
    if (!level || (g_loglevel & (1 << level)))
        return 1;
    return 0;
}

static void lwins_stack_trace (int signum, siginfo_t *info, void *ptr)
{
    static const size_t addrs_max = 128;
    size_t addr_cnt;
    void *addrs[addrs_max];
    
    (void)signum;
    (void)info;
    (void)ptr;
    
    addr_cnt = backtrace (addrs, addrs_max);
    if (addr_cnt != 0)
        backtrace_symbols_fd (addrs, addr_cnt, fileno (stderr));
    abort ();
}

void lwins_setup_stack_traces (void)
{
    struct sigaction action;
    
    memset (&action, 0, sizeof (action));
    action.sa_sigaction = lwins_stack_trace;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction (SIGSEGV, &action, NULL);
}

#ifdef DBG_PACKETS
static void lwins_dump_buffer_hex (const unsigned char *buffer, size_t len)
{
    char line[(16 * 3) + 2 + 16 + 2];
    size_t i, j, n;
    char hex[3];
    
    line[sizeof (line) - 2] = '\n';
    line[sizeof (line) - 1] = '\0';
    
    i = 0;
    while (i < len)
    {
        memset (line, ' ', sizeof (line) - 2);
        n = len - i;
        if (n > 16)
            n = 16;
        
        for (j = 0; j < n; j++)
        {
            sprintf (hex, "%02X", buffer[i + j]);
            line[j * 3] = hex[0];
            line[(j * 3) + 1] = hex[1];
            line[(16 * 3) + 2 + j] = (isprint ((char)buffer[i + j]) ? buffer[i + j] : '.');
        }
        
        LOG (LOG_PACKET, "%s", line);
        i += n;
    }
}

static void lwins_dump_resource_record (const char *name, struct netbt_resource *resource, unsigned int idx)
{
    LOG (LOG_PACKET, "--- %s[%u].rname: %s\n", name, idx, resource[idx].rname);
    LOG (LOG_PACKET, "--- %s[%u].rtype: %u\n", name, idx, resource[idx].rtype);
    LOG (LOG_PACKET, "--- %s[%u].rclass: %u\n", name, idx, resource[idx].rclass);
    LOG (LOG_PACKET, "--- %s[%u].rttl: %u\n", name, idx, resource[idx].rttl);
    LOG (LOG_PACKET, "--- %s[%u].rdlen: %u\n", name, idx, resource[idx].rdlen);
    lwins_dump_buffer_hex (resource[idx].rdata, resource[idx].rdlen);
}

void lwins_dump_nbns_raw_packet (unsigned char *raw_packet, size_t len, struct sockaddr_in *client)
{
    u16 tmpu16;
    struct netbt_packet packet;
    
    LOG (LOG_PACKET, "=== PACKET FROM %s:%u SIZE: %zd ===\n", inet_ntoa (client->sin_addr), ntohs(client->sin_port), len);
    
    if (netbt_parse_raw_packet (raw_packet, len, client, &packet))
    {
        LOG (LOG_PACKET, "- HEADER\n");
        LOG (LOG_PACKET, "--- tran_id: %u\n", packet.header.tran_id);
        LOG (LOG_PACKET, "--- is_response: %u\n", packet.header.is_response);
        LOG (LOG_PACKET, "--- op_code: %u\n", packet.header.op_code);
        LOG (LOG_PACKET, "--- authoritive_answer: %u\n", packet.header.authoritive_answer);
        LOG (LOG_PACKET, "--- truncation: %u\n", packet.header.truncation);
        LOG (LOG_PACKET, "--- recursion_desired: %u\n", packet.header.recursion_desired);
        LOG (LOG_PACKET, "--- recursion_available: %u\n", packet.header.recursion_available);
        LOG (LOG_PACKET, "--- broadcast: %u\n", packet.header.broadcast);
        LOG (LOG_PACKET, "--- response_code: %u\n", packet.header.response_code);
        LOG (LOG_PACKET, "--- qscnt: %u\n", packet.header.qscnt);
        LOG (LOG_PACKET, "--- ancnt: %u\n", packet.header.ancnt);
        LOG (LOG_PACKET, "--- nscnt: %u\n", packet.header.nscnt);
        LOG (LOG_PACKET, "--- arcnt: %u\n", packet.header.arcnt);
        if (packet.header.qscnt > 0)
            LOG (LOG_PACKET, "- QUESTIONS\n");
        for (tmpu16 = 0; tmpu16 < packet.header.qscnt; tmpu16++)
        {
            LOG (LOG_PACKET, "--- questions[%u].qname: %s\n", tmpu16, packet.questions[tmpu16].qname);
            LOG (LOG_PACKET, "--- questions[%u].qtype: %u\n", tmpu16, packet.questions[tmpu16].qtype);
            LOG (LOG_PACKET, "--- questions[%u].qclass: %u\n", tmpu16, packet.questions[tmpu16].qclass);
        }
        if (packet.header.ancnt > 0)
            LOG (LOG_PACKET, "- ANSWERS\n");
        for (tmpu16 = 0; tmpu16 < packet.header.ancnt; tmpu16++)
            lwins_dump_resource_record ("answers", packet.answers, tmpu16);
        if (packet.header.nscnt > 0)
            LOG (LOG_PACKET, "- AUTHORITIES\n");
        for (tmpu16 = 0; tmpu16 < packet.header.nscnt; tmpu16++)
            lwins_dump_resource_record ("authority", packet.authority, tmpu16);
        if (packet.header.arcnt > 0)
            LOG (LOG_PACKET, "- ADDITIONAL\n");
        for (tmpu16 = 0; tmpu16 < packet.header.arcnt; tmpu16++)
            lwins_dump_resource_record ("additional", packet.additional, tmpu16);
        netbt_free_packet (&packet);
    }
    else
        LOG (LOG_PACKET, "Could not parse packet\n");
    
    lwins_dump_buffer_hex (raw_packet, len);
    
    LOG (LOG_PACKET, "=== END PACKET ===\n");
}

void lwins_dump_discovery_raw_packet (unsigned char *raw_packet, size_t len, struct sockaddr_in *client)
{
    u16 tmpu16;
    struct nbns_discover_packet packet;
    
    LOG (LOG_PACKET, "=== DISCOVERY PACKET FROM %s:%u SIZE: %zd ===\n", inet_ntoa (client->sin_addr), ntohs(client->sin_port), len);
    
    memset (&packet, 0, sizeof (packet));
    if (parse_raw_nbns_discover_packet (raw_packet, len, &packet))
    {
        LOG (LOG_PACKET, "- HEADER\n");
        LOG (LOG_PACKET, "--- op_code: %u\n", packet.op_code);
        LOG (LOG_PACKET, "- ADDRESSES: %u\n", packet.addresses_cnt);
        for (tmpu16 = 0; tmpu16 < packet.addresses_cnt; tmpu16++)
            LOG (LOG_PACKET, "-- addresses[%u]: %s\n", tmpu16, inet_ntoa (packet.addresses[tmpu16]));
    }
    else
        LOG (LOG_PACKET, "Could not parse packet\n");
    
    free_nbns_discover_packet (&packet);
    
    lwins_dump_buffer_hex (raw_packet, len);
    
    LOG (LOG_PACKET, "=== END PACKET ===\n");
}

static const char *replication_msg_type (u32 msg_type)
{
    switch (msg_type)
    {
        case REPL_MSG_ASSOC_START_REQ:
            return "REPL_MSG_ASSOC_START_REQ";
        case REPL_MSG_ASSOC_START_RESP:
            return "REPL_MSG_ASSOC_START_RESP";
        case REPL_MSG_ASSOC_STOP_REQ:
            return "REPL_MSG_ASSOC_STOP_REQ";
        case REPL_MSG_PUSHPULL:
            return "REPL_MSG_PUSHPULL";
    }
    
    return "unknown";
}

static const char *replication_pushpull_opcode (u8 op_code)
{
    switch (op_code)
    {
        case REPL_PUSHPULL_OP_OVMAP_REQ:
            return "REPL_PUSHPULL_OP_OVMAP_REQ";
        case REPL_PUSHPULL_OP_OVMAP_RESP:
            return "REPL_PUSHPULL_OP_OVMAP_RESP";
        case REPL_PUSHPULL_OP_NREC_REQ:
            return "REPL_PUSHPULL_OP_NREC_REQ";
        case REPL_PUSHPULL_OP_NREC_RESP:
            return "REPL_PUSHPULL_OP_NREC_RESP";
        case REPL_PUSHPULL_OP_UN_NO_PROPAGATE:
            return "REPL_PUSHPULL_OP_UN_NO_PROPAGATE";
        case REPL_PUSHPULL_OP_UN_PROPAGATE:
            return "REPL_PUSHPULL_OP_UN_PROPAGATE";
        case REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE:
            return "REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE";
        case REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE:
            return "REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE";
    }
    
    return "unknown";
}

static void lwins_dump_replication_raw_packet (unsigned char *raw_packet, size_t len, struct sockaddr_in *client, const char *direction)
{
    struct replication_packet packet;
    u32 tmpu32;
    
    LOG (LOG_PACKET, "=== REPLICATION PACKET %s %s:%u SIZE: %zd ===\n", direction, inet_ntoa (client->sin_addr), ntohs(client->sin_port), len);
    
    memset (&packet, 0, sizeof (packet));
    
    if (replication_parse_raw_packet (raw_packet, len, &packet))
    {
        LOG (LOG_PACKET, "- HEADER\n");
        LOG (LOG_PACKET, "--- assoc_handle: %u\n", packet.header.assoc_handle);
        LOG (LOG_PACKET, "--- msg_type: %u (%s)\n", packet.header.msg_type, replication_msg_type (packet.header.msg_type));
        LOG (LOG_PACKET, "- BODY\n");
        switch (packet.header.msg_type)
        {
            case REPL_MSG_ASSOC_START_REQ:
            case REPL_MSG_ASSOC_START_RESP:
                LOG (LOG_PACKET, "--- sdr_assoc_handle: %u\n", packet.assoc_start.sdr_assoc_handle);
                LOG (LOG_PACKET, "--- nbns_version_major: %u\n", packet.assoc_start.nbns_version_major);
                LOG (LOG_PACKET, "--- nbns_version_minor: %u\n", packet.assoc_start.nbns_version_minor);
                break;
            case REPL_MSG_ASSOC_STOP_REQ:
                LOG (LOG_PACKET, "--- reason: %u\n", packet.assoc_stop.reason);
                break;
            case REPL_MSG_PUSHPULL:
                LOG (LOG_PACKET, "--- op_code: %u (%s)\n", packet.pushpull.op_code, replication_pushpull_opcode (packet.pushpull.op_code));
                switch (packet.pushpull.op_code)
                {
                    case REPL_PUSHPULL_OP_OVMAP_REQ:
                        break;
                    case REPL_PUSHPULL_OP_OVMAP_RESP:
                        LOG (LOG_PACKET, "-OWNER-VERSION MAP: %u entries\n", packet.pushpull.ovmap_resp.owners_cnt);
                        for (tmpu32 = 0; tmpu32 < packet.pushpull.ovmap_resp.owners_cnt; tmpu32++)
                        {
                            LOG (LOG_PACKET, "--- [%u] ip: %s\n", tmpu32, inet_ntoa (packet.pushpull.ovmap_resp.owners[tmpu32].addr));
                            LOG (LOG_PACKET, "--- [%u] max_version.high: %x\n", tmpu32, packet.pushpull.ovmap_resp.owners[tmpu32].max_version.high);
                            LOG (LOG_PACKET, "--- [%u] max_version.low: %x\n", tmpu32, packet.pushpull.ovmap_resp.owners[tmpu32].max_version.low);
                            LOG (LOG_PACKET, "--- [%u] min_version.high: %x\n", tmpu32, packet.pushpull.ovmap_resp.owners[tmpu32].min_version.high);
                            LOG (LOG_PACKET, "--- [%u] min_version.low: %x\n", tmpu32, packet.pushpull.ovmap_resp.owners[tmpu32].min_version.low);
                        }
                        break;
                    case REPL_PUSHPULL_OP_NREC_REQ:
                        LOG (LOG_PACKET, "--- ip: %s\n", inet_ntoa (packet.pushpull.namerec_req.rec.addr));
                        LOG (LOG_PACKET, "--- max_version.high: %x\n", packet.pushpull.namerec_req.rec.max_version.high);
                        LOG (LOG_PACKET, "--- max_version.low: %x\n", packet.pushpull.namerec_req.rec.max_version.low);
                        LOG (LOG_PACKET, "--- min_version.high: %x\n", packet.pushpull.namerec_req.rec.min_version.high);
                        LOG (LOG_PACKET, "--- min_version.low: %x\n", packet.pushpull.namerec_req.rec.min_version.low);
                        break;
                    case REPL_PUSHPULL_OP_NREC_RESP:
                        break;
                    case REPL_PUSHPULL_OP_UN_NO_PROPAGATE:
                    case REPL_PUSHPULL_OP_UN_PROPAGATE:
                    case REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE:
                    case REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE:
                        LOG (LOG_PACKET, "--- initiator_addr: %s\n", inet_ntoa (packet.pushpull.updatenotify.initiator_addr));
                        LOG (LOG_PACKET, "-UPDATE-NOTIFICATION: %u entries\n", packet.pushpull.updatenotify.owners_cnt);
                        for (tmpu32 = 0; tmpu32 < packet.pushpull.updatenotify.owners_cnt; tmpu32++)
                        {
                            LOG (LOG_PACKET, "--- [%u] ip: %s\n", tmpu32, inet_ntoa (packet.pushpull.updatenotify.owners[tmpu32].addr));
                            LOG (LOG_PACKET, "--- [%u] max_version.high: %x\n", tmpu32, packet.pushpull.updatenotify.owners[tmpu32].max_version.high);
                            LOG (LOG_PACKET, "--- [%u] max_version.low: %x\n", tmpu32, packet.pushpull.updatenotify.owners[tmpu32].max_version.low);
                            LOG (LOG_PACKET, "--- [%u] min_version.high: %x\n", tmpu32, packet.pushpull.updatenotify.owners[tmpu32].min_version.high);
                            LOG (LOG_PACKET, "--- [%u] min_version.low: %x\n", tmpu32, packet.pushpull.updatenotify.owners[tmpu32].min_version.low);
                        }
                        break;
                    default:
                        LOG (LOG_PACKET, "--- Unknown op_code!\n");
                        break;
                }
                break;
        }
    }
    replication_free_packet (&packet);
    
    lwins_dump_buffer_hex (raw_packet, len);
    
    LOG (LOG_PACKET, "=== END PACKET ===\n");
}

void lwins_dump_replication_raw_packet_from (unsigned char *raw_packet, size_t len, struct sockaddr_in *client)
{
    lwins_dump_replication_raw_packet (raw_packet, len, client, "FROM");
}

void lwins_dump_replication_raw_packet_to (unsigned char *raw_packet, size_t len, struct sockaddr_in *client)
{
    lwins_dump_replication_raw_packet (raw_packet, len, client, "TO");
}
#endif
