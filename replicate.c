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

static int replication_build_raw_packet_header (unsigned char *raw_packet, size_t packet_size, struct replication_packet_header *header)
{
    u32 tmpu32;
    
    if (packet_size < 4 * sizeof (u32))
        return LWINS_ERR;
    
    ASSERT (header->msg_type <= REPL_MSG_MAX);
    
    tmpu32 = htonl (packet_size - sizeof (u32));
    memcpy (raw_packet, &tmpu32, sizeof (u32));
    memset (&raw_packet[sizeof (u32)], sizeof (u32), sizeof (u32));
    tmpu32 = htonl (header->assoc_handle);
    memcpy (&raw_packet[2 * sizeof (u32)], &tmpu32, sizeof (u32));
    tmpu32 = htonl (header->msg_type);
    memcpy (&raw_packet[3 * sizeof (u32)], &tmpu32, sizeof (u32));
    return 1;
}

static int replication_parse_raw_packet_header (unsigned char *raw_packet, size_t packet_size, struct replication_packet_header *header)
{
    u32 tmpu32;
    
    if (packet_size < 4 * sizeof (u32))
        return LWINS_ERR;
    
    memcpy (&tmpu32, &raw_packet[2 * sizeof (u32)], sizeof (u32));
    header->assoc_handle = ntohl (tmpu32);
    memcpy (&tmpu32, &raw_packet[3 * sizeof (u32)], sizeof (u32));
    header->msg_type = ntohl (tmpu32);
    if (header->msg_type > REPL_MSG_MAX)
        return LWINS_ERR;
    return 1;
}

static int replication_build_raw_assoc_start (unsigned char *raw_packet, size_t packet_size, struct replication_assoc_start *start)
{
    u32 tmpu32;
    u16 tmpu16;
    
    if (packet_size != sizeof (u32) + 2 * sizeof (u16) + 21)
        return LWINS_ERR;
    
    tmpu32 = htonl (start->sdr_assoc_handle);
    memcpy (raw_packet, &tmpu32, sizeof (u32));
    tmpu16 = htons (start->nbns_version_major);
    memcpy (&raw_packet[sizeof (u32)], &tmpu16, sizeof (u16));
    tmpu16 = htons (start->nbns_version_minor);
    memcpy (&raw_packet[sizeof (u32) + sizeof (u16)], &tmpu16, sizeof (u16));
    memset (&raw_packet[2 * sizeof (u32)], 0, 21);
    return 1;
}

static int replication_parse_raw_assoc_start (unsigned char *raw_packet, size_t packet_size, struct replication_assoc_start *start)
{
    u32 tmpu32;
    u16 tmpu16;
    
    if (packet_size != sizeof (u32) + 2 * sizeof (u16) + 21)
        return LWINS_ERR;
    
    memcpy (&tmpu32, raw_packet, sizeof (u32));
    start->sdr_assoc_handle = ntohl (tmpu32);
    memcpy (&tmpu16, &raw_packet[sizeof (u32)], sizeof (u16));
    start->nbns_version_major = ntohs (tmpu16);
    memcpy (&tmpu16, &raw_packet[sizeof (u32) + sizeof (u16)], sizeof (u16));
    start->nbns_version_minor = ntohs (tmpu16);
    return 1;
}

static int replication_build_raw_assoc_stop (unsigned char *raw_packet, size_t packet_size, struct replication_assoc_stop *stop)
{
    u32 tmpu32;
    
    if (packet_size != sizeof (u32) + 24)
        return LWINS_ERR;
    
    tmpu32 = htonl (stop->reason);
    memcpy (raw_packet, &tmpu32, sizeof (u32));
    memset (&raw_packet[sizeof (u32)], 0, 24);
    return 1;
}

static int replication_parse_raw_assoc_stop (unsigned char *raw_packet, size_t packet_size, struct replication_assoc_stop *stop)
{
    u32 tmpu32;
    
    if (packet_size != sizeof (u32) + 24)
        return LWINS_ERR;
    
    memcpy (&tmpu32, raw_packet, sizeof (u32));
    stop->reason = ntohl (tmpu32);
    return 1;
}

static void replication_build_owner_record (unsigned char *raw_packet, struct replication_owner_record *rec)
{
    u32 tmpu32;
    
    tmpu32 = (u32)rec->addr.s_addr;
    memcpy (raw_packet, &tmpu32, sizeof (u32));
    tmpu32 = htonl (rec->max_version.high);
    memcpy (&raw_packet[sizeof (u32)], &tmpu32, sizeof (u32));
    tmpu32 = htonl (rec->max_version.low);
    memcpy (&raw_packet[2 * sizeof (u32)], &tmpu32, sizeof (u32));
    tmpu32 = htonl (rec->min_version.high);
    memcpy (&raw_packet[3 * sizeof (u32)], &tmpu32, sizeof (u32));
    tmpu32 = htonl (rec->min_version.low);
    memcpy (&raw_packet[4 * sizeof (u32)], &tmpu32, sizeof (u32));
    tmpu32 = htonl (1);
    memcpy (&raw_packet[5 * sizeof (u32)], &tmpu32, sizeof (u32));
}

static void replication_parse_owner_record (unsigned char *raw_packet, struct replication_owner_record *rec)
{
    u32 tmpu32;
    
    memcpy (&tmpu32, raw_packet, sizeof (u32));
    rec->addr.s_addr = tmpu32;
    
    memcpy (&tmpu32, &raw_packet[sizeof (u32)], sizeof (u32));
    rec->max_version.high = ntohl (tmpu32);
    memcpy (&tmpu32, &raw_packet[2 * sizeof (u32)], sizeof (u32));
    rec->max_version.low = ntohl (tmpu32);
    memcpy (&tmpu32, &raw_packet[3 * sizeof (u32)], sizeof (u32));
    rec->min_version.high = ntohl (tmpu32);
    memcpy (&tmpu32, &raw_packet[4 * sizeof (u32)], sizeof (u32));
    rec->min_version.low = ntohl (tmpu32);
}

static size_t replication_build_owner_records (unsigned char *raw_packet, size_t packet_size, u32 owners_cnt, struct replication_owner_record *owners)
{
    u32 cnt, i;
    size_t size;
    
    if (packet_size < sizeof (u32))
        return LWINS_ERR;
    
    size = sizeof (u32);
    cnt = htonl (owners_cnt);
    memcpy (raw_packet, &cnt, sizeof (u32));
    
    if (owners_cnt > 0)
    {
        if (packet_size < sizeof (u32) + ((size_t)owners_cnt * 6 * sizeof (u32)))
            return LWINS_ERR;
        
        for (i = 0; i < owners_cnt; i++)
        {
            replication_build_owner_record (&raw_packet[size], &owners[i]);
            size += 6 * sizeof (u32);
        }
    }
    
    return size;
}

static size_t replication_parse_owner_records (unsigned char *raw_packet, size_t packet_size, u32 *owners_cnt, struct replication_owner_record **owners_list)
{
    u32 cnt, i;
    size_t size;
    struct replication_owner_record *owners = NULL;
    
    if (packet_size < sizeof (u32))
        return LWINS_ERR;
    
    size = sizeof (u32);
    memcpy (&cnt, raw_packet, sizeof (u32));
    cnt = ntohl (cnt);
    
    if (cnt > 0)
    {
        if (packet_size < sizeof (u32) + ((size_t)cnt * 6 * sizeof (u32)))
            return LWINS_ERR;
        
        owners = lwins_alloc ((size_t)cnt * sizeof (*owners));
        if (!owners)
            return LWINS_ERR;
        
        for (i = 0; i < cnt; i++)
        {
            replication_parse_owner_record (&raw_packet[size], &owners[i]);
            size += 6 * sizeof (u32);
        }
    }
    
    *owners_cnt = cnt;
    *owners_list = owners;
    return size;
}

static int replication_build_raw_pushpull_ovmap (unsigned char *raw_packet, size_t packet_size, struct replication_pushpull_ovmap *ovmap)
{
    size_t size;
    
    if (packet_size < 2 * sizeof (u32))
        return LWINS_ERR;
    
    size = replication_build_owner_records (raw_packet, packet_size, ovmap->owners_cnt, ovmap->owners);
    if (!size || packet_size - size != sizeof (u32))
        return LWINS_ERR;
    
    return 1;
}

static int replication_parse_raw_pushpull_ovmap (unsigned char *raw_packet, size_t packet_size, struct replication_pushpull_ovmap *ovmap)
{
    size_t size;
    
    if (packet_size < 2 * sizeof (u32))
        return LWINS_ERR;
    
    size = replication_parse_owner_records (raw_packet, packet_size, &ovmap->owners_cnt, &ovmap->owners);
    if (!size || packet_size - size != sizeof (u32))
        return LWINS_ERR;
    
    return 1;
}

static int replication_build_raw_update_notification (unsigned char *raw_packet, size_t packet_size, struct replication_pushpull_updatenotify *updatenotify)
{
    u32 tmpu32;
    size_t size;
    
    if (packet_size < 2 * sizeof (u32))
        return LWINS_ERR;
    
    size = replication_build_owner_records (raw_packet, packet_size, updatenotify->owners_cnt, updatenotify->owners);
    if (!size || packet_size - size != sizeof (u32))
        return LWINS_ERR;
    
    tmpu32 = (u32)updatenotify->initiator_addr.s_addr;
    memcpy (&raw_packet[size], &tmpu32, sizeof (u32));
    return 1;
}

static int replication_parse_raw_update_notification (unsigned char *raw_packet, size_t packet_size, struct replication_pushpull_updatenotify *updatenotify)
{
    u32 tmpu32;
    size_t size;
    
    if (packet_size < 2 * sizeof (u32))
        return LWINS_ERR;
    
    size = replication_parse_owner_records (raw_packet, packet_size, &updatenotify->owners_cnt, &updatenotify->owners);
    if (!size || packet_size - size != sizeof (u32))
        return LWINS_ERR;
    
    memcpy (&tmpu32, &raw_packet[size], sizeof (u32));
    updatenotify->initiator_addr.s_addr = tmpu32;
    return 1;
}

static int replication_build_raw_pushpull_namerec_req (unsigned char *raw_packet, size_t packet_size, struct replication_pushpull_namerec_req *req)
{
    if (packet_size != 6 * sizeof (u32))
        return LWINS_ERR;
    
    replication_build_owner_record (raw_packet, &req->rec);
    return 1;
}

static int replication_parse_raw_pushpull_namerec_req (unsigned char *raw_packet, size_t packet_size, struct replication_pushpull_namerec_req *req)
{
    if (packet_size != 6 * sizeof (u32))
        return LWINS_ERR;
    
    replication_parse_owner_record (raw_packet, &req->rec);
    return 1;
}

static size_t replication_build_raw_name_record (unsigned char *raw_packet, size_t packet_size, struct replication_name_record *rec)
{
    u32 tmpu32;
    u8 flags, j;
    size_t size;
    
    if (packet_size < 6 * sizeof (u32))
        return LWINS_ERR;
    
    /* netbios name */
    ASSERT (rec->name);
    tmpu32 = strlen (rec->name);
    ASSERT (tmpu32 > 0 && tmpu32 <= 0xFF);
    tmpu32 = htonl (tmpu32) + 1;
    
    if (packet_size < sizeof (u32) + tmpu32)
        return LWINS_ERR;
    
    memcpy (raw_packet, &tmpu32, sizeof (u32));
    tmpu32 = (tmpu32 + 3) & ~3;
    if (packet_size < sizeof (u32) + tmpu32 + 5 * sizeof (u32))
        return LWINS_ERR;
    
    memset (&raw_packet[sizeof (u32)], 0, tmpu32 + sizeof (u32));
    strcpy ((char *)&raw_packet[sizeof (u32)], rec->name);
    
    size = tmpu32 + sizeof (u32);
    raw_packet += size;
    packet_size -= size;
    
    /* flags */
    ASSERT (rec->is_static <= 1);
    ASSERT (rec->node_type <= 3);
    ASSERT (rec->is_replica <= 1);
    ASSERT (rec->state <= 3);
    ASSERT (rec->type <= 3);
    flags = rec->type;
    flags |= rec->state << 2;
    flags |= rec->is_replica << 4;
    flags |= rec->node_type << 5;
    flags |= rec->is_static << 7;
    raw_packet[sizeof (u32) - 1] = flags;
    
    /* group */
    raw_packet[sizeof (u32)] = (rec->type == NREC_TYPE_GROUP || rec->type == NREC_TYPE_GROUP_SPECIAL);
    
    /* version */
    tmpu32 = htonl (rec->version.high);
    memcpy (&raw_packet[2 * sizeof (u32)], &tmpu32, sizeof (u32));
    tmpu32 = htonl (rec->version.low);
    memcpy (&raw_packet[3 * sizeof (u32)], &tmpu32, sizeof (u32));
    
    size += 4 * sizeof (u32);
    raw_packet += 4 * sizeof (u32);
    packet_size -= 4 * sizeof (u32);
    
    /* Don't just take the type to determine how the data is formatted */
    if (rec->type == NREC_TYPE_UNIQUE || rec->type == NREC_TYPE_GROUP || rec->addrs_cnt == 1)
    {
        /* IP address */
        if (packet_size < sizeof (u32))
            return LWINS_ERR;

        tmpu32 = (u32)rec->addrs[0].owner.s_addr;
        memcpy (raw_packet, &tmpu32, sizeof (u32));
        size += sizeof (u32);
    }
    else
    {
        /* address record */
        raw_packet[0] = rec->addrs_cnt;
        memset (&raw_packet[1], 0, sizeof (u32) - 1);
        if (packet_size < sizeof (u32) + ((size_t)rec->addrs_cnt * 2 * sizeof (u32)) + sizeof (u32))
            return LWINS_ERR;
        
        size += sizeof (u32) + ((size_t)rec->addrs_cnt * 2 * sizeof (u32));
        raw_packet += sizeof (u32);
        for (j = 0; j < rec->addrs_cnt; j++)
        {
            tmpu32 = (u32)rec->addrs[j].owner.s_addr;
            memcpy (raw_packet, &tmpu32, sizeof (u32));
            tmpu32 = (u32)rec->addrs[j].member.s_addr;
            memcpy (&raw_packet[sizeof (u32)], &tmpu32, sizeof (u32));
            
            raw_packet += 2 * sizeof (u32);
        }
    }
    
    /* reserved */
    memset (raw_packet, 0xFF, sizeof (u32));
    return size + sizeof (u32);
}

static size_t replication_parse_raw_name_record (unsigned char *raw_packet, size_t packet_size, struct replication_name_record *rec)
{
    u32 tmpu32;
    u8 flags, group, j;
    size_t size;
    
    if (packet_size < 6 * sizeof (u32))
        return LWINS_ERR;
    
    /* netbios name */
    memcpy (&tmpu32, raw_packet, sizeof (u32));
    tmpu32 = ntohl (tmpu32);
    if (tmpu32 < NETBT_NAME_LENGTH + 1 || tmpu32 > 0xFF)
        return LWINS_ERR;
    if (packet_size < sizeof (u32) + tmpu32)
        return LWINS_ERR;
    rec->name = lwins_alloc (tmpu32);
    if (!rec->name)
        return LWINS_ERR;
    memcpy (rec->name, &raw_packet[sizeof (u32)], tmpu32);
    if (rec->name[tmpu32 - 1] != '\0')
        return LWINS_ERR;
    
    /* 4 byte alignment */
    tmpu32 = (tmpu32 + 3) & ~3;
    if (packet_size < sizeof (u32) + tmpu32 + 5 * sizeof (u32))
        return LWINS_ERR;
    
    size = tmpu32 + sizeof (u32);
    raw_packet += size;
    packet_size -= size;
    
    /* flags */
    flags = raw_packet[sizeof (u32) - 1];
    rec->type = flags & 0x3;
    rec->state = (flags >> 2) & 0x3;
    if (flags & (1 << 4))
        rec->is_replica = 1;
    rec->node_type = (flags >> 5) & 0x3;
    if (flags & (1 << 7))
        rec->is_static = 1;
    
    /* group */
    group = raw_packet[sizeof (u32)];
    if ((rec->type == NREC_TYPE_UNIQUE || rec->type == NREC_TYPE_MULTIHOMED) && group != 0)
        return LWINS_ERR;
    if ((rec->type == NREC_TYPE_GROUP || rec->type == NREC_TYPE_GROUP_SPECIAL) && group != 1)
        return LWINS_ERR;
    
    /* version */
    memcpy (&tmpu32, &raw_packet[2 * sizeof (u32)], sizeof (u32));
    rec->version.high = ntohl (tmpu32);
    memcpy (&tmpu32, &raw_packet[3 * sizeof (u32)], sizeof (u32));
    rec->version.low = ntohl (tmpu32);
    
    size += 4 * sizeof (u32);
    raw_packet += 4 * sizeof (u32);
    packet_size -= 4 * sizeof (u32);
    
    if (rec->type == NREC_TYPE_UNIQUE || rec->type == NREC_TYPE_GROUP)
    {
        /* IP address */
        if (packet_size < sizeof (u32))
            return LWINS_ERR;

        rec->addrs = lwins_alloc (sizeof (*rec->addrs));
        if (!rec->addrs)
            return LWINS_ERR;
        
        rec->addrs_cnt = 1;
        rec->addrs[0].owner.s_addr = htonl (INADDR_ANY);
        memcpy (&tmpu32, raw_packet, sizeof (u32));
        rec->addrs[0].member.s_addr = tmpu32;
        size += sizeof (u32);
    }
    else
    {
        /* address record */
        rec->addrs_cnt = raw_packet[0];
        if (packet_size < sizeof (u32) + ((size_t)rec->addrs_cnt * 2 * sizeof (u32)) + sizeof (u32))
            return LWINS_ERR;
        rec->addrs = lwins_alloc ((size_t)rec->addrs_cnt * sizeof (*rec->addrs));
        if (!rec->addrs)
            return LWINS_ERR;
        
        size += sizeof (u32) + ((size_t)rec->addrs_cnt * 2 * sizeof (u32));
        raw_packet += sizeof (u32);
        for (j = 0; j < rec->addrs_cnt; j++)
        {
            memcpy (&tmpu32, raw_packet, sizeof (u32));
            rec->addrs[j].owner.s_addr = tmpu32;
            memcpy (&tmpu32, &raw_packet[sizeof (u32)], sizeof (u32));
            rec->addrs[j].member.s_addr = tmpu32;
            
            raw_packet += 2 * sizeof (u32);
        }
    }
    
    /* reserved field */
    return size + sizeof (u32);
}

static int replication_build_raw_pushpull_namerec_resp (unsigned char *raw_packet, size_t packet_size, struct replication_pushpull_namerec_resp *resp)
{
    u32 tmpu32, i;
    size_t size;
    
    if (packet_size < sizeof (u32))
        return LWINS_ERR;
    
    tmpu32 = htonl (resp->namerecs_cnt);
    memcpy (raw_packet, &tmpu32, sizeof (u32));
    raw_packet += sizeof (u32);
    packet_size -= sizeof (u32);
    
    if (resp->namerecs_cnt > 0)
    {
        for (i = 0; i < resp->namerecs_cnt; i++)
        {
            ASSERT (resp->namerecs[i]);
            size = replication_build_raw_name_record (raw_packet, packet_size, resp->namerecs[i]);
            ASSERT (size <= packet_size);
            packet_size -= size;
            raw_packet += size;
        }

        if (packet_size != 0)
            return LWINS_ERR;
    }
    else
    {
        /* Documentation does not cover this. WINS sends an empty name record */
        if (packet_size < 0x20)
            return LWINS_ERR;
        
        memset (raw_packet, 0x0, 0x20 - sizeof (u32));
        memset (&raw_packet[0x1C], 0xFF, sizeof (u32));
    }
    
    return 1;
}

static int replication_parse_raw_pushpull_namerec_resp (unsigned char *raw_packet, size_t packet_size, struct replication_pushpull_namerec_resp *resp)
{
    u32 tmpu32, i;
    size_t size;
    
    if (packet_size < sizeof (u32))
        return LWINS_ERR;
    
    memcpy (&tmpu32, raw_packet, sizeof (u32));
    resp->namerecs_cnt = ntohl (tmpu32);
    raw_packet += sizeof (u32);
    packet_size -= sizeof (u32);
    
    if (resp->namerecs_cnt > 0)
    {
        if (resp->namerecs_cnt * sizeof (*resp->namerecs) <= resp->namerecs_cnt)
            return LWINS_ERR;

        resp->namerecs = lwins_alloc (resp->namerecs_cnt * sizeof (*resp->namerecs));
        if (!resp->namerecs)
            return LWINS_ERR;
        memset (resp->namerecs, 0, resp->namerecs_cnt * sizeof (*resp->namerecs));
        
        for (i = 0; i < resp->namerecs_cnt; i++)
        {
            resp->namerecs[i] = lwins_alloc (sizeof (struct replication_name_record));
            if (!resp->namerecs[i])
                return LWINS_ERR;
            memset (resp->namerecs[i], 0, sizeof (struct replication_name_record));
            
            size = replication_parse_raw_name_record (raw_packet, packet_size, resp->namerecs[i]);
            packet_size -= size;
            raw_packet += size;
        }

        if (packet_size != 0)
            return LWINS_ERR;
    }
    else
    {
        /* Documentation does not cover this. WINS sends a zero name record */
        if (packet_size != 0x20)
            return LWINS_ERR;
    }
    
    return 1;
}

static int replication_build_raw_pushpull (unsigned char *raw_packet, size_t packet_size, struct replication_pushpull *pushpull)
{
    if (packet_size < sizeof (u32))
        return LWINS_ERR;
    
    memset (raw_packet, 0, 3);
    raw_packet[3] = pushpull->op_code;
    raw_packet += sizeof (u32);
    packet_size -= sizeof (u32);
    
    switch (pushpull->op_code)
    {
        case REPL_PUSHPULL_OP_OVMAP_REQ:
            if (packet_size != 0)
                return LWINS_ERR;
            return 1;
        
        case REPL_PUSHPULL_OP_OVMAP_RESP:
            return replication_build_raw_pushpull_ovmap (raw_packet, packet_size, &pushpull->ovmap_resp);
        
        case REPL_PUSHPULL_OP_NREC_REQ:
            return replication_build_raw_pushpull_namerec_req (raw_packet, packet_size, &pushpull->namerec_req);
        
        case REPL_PUSHPULL_OP_NREC_RESP:
            return replication_build_raw_pushpull_namerec_resp (raw_packet, packet_size, &pushpull->namerec_resp);
        
        case REPL_PUSHPULL_OP_UN_NO_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE:
            return replication_build_raw_update_notification (raw_packet, packet_size, &pushpull->updatenotify);
    }
    
    return LWINS_ERR;
}

static int replication_parse_raw_pushpull (unsigned char *raw_packet, size_t packet_size, struct replication_pushpull *pushpull)
{
    if (packet_size < sizeof (u32))
        return LWINS_ERR;
    
    pushpull->op_code = raw_packet[3];
    raw_packet += sizeof (u32);
    packet_size -= sizeof (u32);
    switch (pushpull->op_code)
    {
        case REPL_PUSHPULL_OP_OVMAP_REQ:
            if (packet_size != 0)
                return LWINS_ERR;
            return 1;
        
        case REPL_PUSHPULL_OP_OVMAP_RESP:
            return replication_parse_raw_pushpull_ovmap (raw_packet, packet_size, &pushpull->ovmap_resp);
        
        case REPL_PUSHPULL_OP_NREC_REQ:
            return replication_parse_raw_pushpull_namerec_req (raw_packet, packet_size, &pushpull->namerec_req);
        
        case REPL_PUSHPULL_OP_NREC_RESP:
            return replication_parse_raw_pushpull_namerec_resp (raw_packet, packet_size, &pushpull->namerec_resp);
        
        case REPL_PUSHPULL_OP_UN_NO_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE:
            return replication_parse_raw_update_notification (raw_packet, packet_size, &pushpull->updatenotify);
    }
    
    return LWINS_ERR;
}

int replication_build_raw_packet (unsigned char *raw_packet, size_t packet_size, struct replication_packet *packet)
{
    if (!replication_build_raw_packet_header (raw_packet, packet_size, &packet->header))
        return LWINS_ERR;
    
    raw_packet += 4 * sizeof (u32);
    packet_size -= 4 * sizeof (u32);
    switch (packet->header.msg_type)
    {
        case REPL_MSG_ASSOC_START_REQ:
        case REPL_MSG_ASSOC_START_RESP:
            return replication_build_raw_assoc_start (raw_packet, packet_size, &packet->assoc_start);
        
        case REPL_MSG_ASSOC_STOP_REQ:
            return replication_build_raw_assoc_stop (raw_packet, packet_size, &packet->assoc_stop);
        
        case REPL_MSG_PUSHPULL:
            return replication_build_raw_pushpull (raw_packet, packet_size, &packet->pushpull);
    }
    
    return LWINS_ERR;
}

int replication_parse_raw_packet (unsigned char *raw_packet, size_t packet_size, struct replication_packet *packet)
{
    if (!replication_parse_raw_packet_header (raw_packet, packet_size, &packet->header))
        return LWINS_ERR;
    
    raw_packet += 4 * sizeof (u32);
    packet_size -= 4 * sizeof (u32);
    switch (packet->header.msg_type)
    {
        case REPL_MSG_ASSOC_START_REQ:
        case REPL_MSG_ASSOC_START_RESP:
            return replication_parse_raw_assoc_start (raw_packet, packet_size, &packet->assoc_start);
        
        case REPL_MSG_ASSOC_STOP_REQ:
            return replication_parse_raw_assoc_stop (raw_packet, packet_size, &packet->assoc_stop);
        
        case REPL_MSG_PUSHPULL:
            return replication_parse_raw_pushpull (raw_packet, packet_size, &packet->pushpull);
    }
    
    return LWINS_ERR;
}

static size_t replication_calc_raw_push_pull_size (struct replication_packet *packet)
{
    size_t size = 0;
    switch (packet->pushpull.op_code)
    {
        case REPL_PUSHPULL_OP_OVMAP_REQ:
            break;

        case REPL_PUSHPULL_OP_OVMAP_RESP:
            size += 2 * sizeof (u32);
            size += packet->pushpull.ovmap_resp.owners_cnt * 6 * sizeof (u32);
            break;

        case REPL_PUSHPULL_OP_NREC_REQ:
            size += 6 * sizeof (u32);
            break;

        case REPL_PUSHPULL_OP_NREC_RESP:
            ASSERT (0); /* FIXME: Implement */
            break;

        case REPL_PUSHPULL_OP_UN_NO_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE:
            ASSERT (0); /* FIXME: Implement */
            break;

        default:
            ASSERT (0);
            break;
    }

    return size;
}

static size_t replication_calc_raw_packet_size (struct replication_packet *packet)
{
    size_t size;
    
    /* header */
    size = 3 * sizeof (u32);
    
    switch (packet->header.msg_type)
    {
        case REPL_MSG_ASSOC_START_REQ:
        case REPL_MSG_ASSOC_START_RESP:
            size += 2 * sizeof (u32) + 21;
            break;
        
        case REPL_MSG_ASSOC_STOP_REQ:
            size += sizeof (u32) + 24;
            break;
        
        case REPL_MSG_PUSHPULL:
            size += sizeof (u32) + replication_calc_raw_push_pull_size (packet);
            break;
        
        default:
            return LWINS_ERR;
    }
    
    return size;
}

static void replication_free_namerec (struct replication_name_record *rec)
{
    if (rec->name)
        lwins_free (rec->name);
    
    if (rec->addrs)
        lwins_free (rec->addrs);
    lwins_free (rec);
}

static int replication_duplicate_update_notification (struct replication_pushpull_updatenotify *src, struct replication_pushpull_updatenotify *dest)
{
    if (src->owners_cnt > 0)
    {
        dest->owners = lwins_alloc (src->owners_cnt * sizeof (dest->owners[0]));
        if (!dest->owners)
            return LWINS_ERR;
        
        memcpy (dest->owners, src->owners, src->owners_cnt * sizeof (dest->owners[0]));
        dest->owners_cnt = src->owners_cnt;
    }
    
    dest->initiator_addr = src->initiator_addr;
    return 1;
}

static int replication_duplicate_pushpull (struct replication_pushpull *src, struct replication_pushpull *dest)
{
    dest->op_code = src->op_code;
    switch (src->op_code)
    {
        case REPL_PUSHPULL_OP_OVMAP_RESP:
            ASSERT (0); /* FIXME */
            break;
        
        case REPL_PUSHPULL_OP_NREC_REQ:
            ASSERT (0); /* FIXME */
            break;
        
        case REPL_PUSHPULL_OP_NREC_RESP:
            ASSERT (0); /* FIXME */
            break;
        
        case REPL_PUSHPULL_OP_UN_NO_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE:
        case REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE:
            if (!replication_duplicate_update_notification (&src->updatenotify, &dest->updatenotify))
                return LWINS_ERR;
            break;
    }
    
    return 1;
}

static int replication_duplicate_packet (struct replication_packet *src, struct replication_packet *dest)
{
    memset (dest, 0, sizeof (*dest));
    
    dest->header = src->header;
    switch (src->header.msg_type)
    {
        case REPL_MSG_PUSHPULL:
        {
            if (!replication_duplicate_pushpull (&src->pushpull, &dest->pushpull))
            {
                replication_free_packet (dest);
                return LWINS_ERR;
            }
            break;
        }
        
        case REPL_MSG_ASSOC_START_REQ:
            dest->assoc_start = src->assoc_start;
            break;
        
        case REPL_MSG_ASSOC_STOP_REQ:
            dest->assoc_stop = src->assoc_stop;
            break;
    }
    
    return 1;
}

void replication_free_packet (struct replication_packet *packet)
{
    if (packet->header.msg_type == REPL_MSG_PUSHPULL)
    {
        switch (packet->pushpull.op_code)
        {
            case REPL_PUSHPULL_OP_OVMAP_RESP:
                if (packet->pushpull.ovmap_resp.owners)
                    lwins_free (packet->pushpull.ovmap_resp.owners);
                break;
            case REPL_PUSHPULL_OP_NREC_RESP:
                if (packet->pushpull.namerec_resp.namerecs)
                {
                    u32 i;
                    
                    for (i = 0; i < packet->pushpull.namerec_resp.namerecs_cnt; i++)
                    {
                        if (packet->pushpull.namerec_resp.namerecs)
                            replication_free_namerec (packet->pushpull.namerec_resp.namerecs[i]);
                    }
                    
                    lwins_free (packet->pushpull.namerec_resp.namerecs);
                }
                break;
            case REPL_PUSHPULL_OP_UN_NO_PROPAGATE:
            case REPL_PUSHPULL_OP_UN_PROPAGATE:
            case REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE:
            case REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE:
                if (packet->pushpull.updatenotify.owners)
                    lwins_free (packet->pushpull.updatenotify.owners);
                break;
        }
    }
    
    memset (packet, 0, sizeof (*packet));
}

void lwins_free_replication_packet (struct replication_packet *packet)
{
    replication_free_packet (packet);
    lwins_free (packet);
}

struct replication_packet* lwins_duplicate_replication_packet (struct replication_packet *packet)
{
    struct replication_packet *packet_dup;
    
    packet_dup = lwins_alloc (sizeof (*packet_dup));
    if (!packet_dup)
        return NULL;
    
    if (!replication_duplicate_packet (packet, packet_dup))
    {
        lwins_free (packet_dup);
        return NULL;
    }
    
    return packet_dup;
}

static void association_timeout_event_handler (struct netbios_server *server, struct lwins_event *event)
{
    struct association *assoc = (struct association *)event->context;
    
    lwins_dbg_start_assoc (assoc->handle);
    
    if (assoc->shutdown_conn)
        return;
    
    assoc->timeout = 1;
    assoc->error = 1;
    shutdown_association (server->replication, assoc);
}

static void association_timeout_event_deletion_handler (struct netbios_server *server, struct lwins_event *event)
{
    struct association *assoc = (struct association *)event->context;
    
    (void)server;
    
    assoc->timeout_event = NULL;
}

static void association_delete_timeout_event (struct replication_service *service, struct association *assoc)
{
    if (assoc->timeout_event)
    {
        lwins_delete_event (service->server, assoc->timeout_event);
        assoc->timeout_event = NULL;
    }
}

static int association_reset_timeout_event (struct replication_service *service, struct association *assoc)
{
    struct timeval due;
    
    lwins_calculate_due_time (service->server, &due, 30); /* TODO: Make configurable */
    if (assoc->timeout_event)
        lwins_set_event_due (service->server, assoc->timeout_event, &due);
    else
    {
        assoc->timeout_event = lwins_add_event (service->server, association_timeout_event_handler, association_timeout_event_deletion_handler, assoc, &due);
        if (!assoc->timeout_event)
            return 0;
    }
    
    return 1;
}

struct association *alloc_association (struct replication_service *service, int sd, struct sockaddr_in *client)
{
    struct association *assoc, **association_list;
    unsigned short i;
    static const unsigned int association_table_block = 16;
    socklen_t namelen;
    
    if ((unsigned int)service->associations_cnt + association_table_block >= 0xFFFF)
    {
        LOG (LOG_WARN, "Maximum number of associations reached!\n");
        return NULL;
    }
    
    assoc = lwins_alloc (sizeof (*assoc));
    if (!assoc)
        return NULL;
    
    /* Setup the timeout event, the first push/pull replication must have started before this event is triggered */
    if (!association_reset_timeout_event (service, assoc))
    {
        lwins_free (assoc);
        return NULL;
    }
    
    if (!service->associations)
    {
        service->associations = lwins_alloc (sizeof (service->associations[0]) * association_table_block);
        if (!service->associations)
        {
            lwins_delete_event (service->server, assoc->timeout_event);
            lwins_free (assoc);
            return NULL;
        }
        
        service->associations_size = association_table_block;
        service->associations[0] = assoc;
        assoc->handle = 1;
    }
    else if (service->associations_cnt == service->associations_size)
    {        
        association_list = lwins_alloc (sizeof (service->associations[0]) * (service->associations_size + association_table_block));
        if (!association_list)
        {
            lwins_delete_event (service->server, assoc->timeout_event);
            lwins_free (assoc);
            return NULL;
        }
        
        memcpy (association_list, service->associations, sizeof (service->associations[0]) * service->associations_size);
        lwins_free (service->associations);
        service->associations = association_list;
        service->associations[service->associations_size] = assoc;
        assoc->handle = (u32)service->associations_size + 1;
        service->associations_size += association_table_block;
    }
    else
    {
        for (i = 0; i < service->associations_size; i++)
        {
            if (!service->associations[i])
                break;
        }
        
        ASSERT (i < service->associations_size);
        
        service->associations[i] = assoc;
        assoc->handle = (u32)i + 1;
    }
    
    service->associations_cnt++;
    assoc->sd = sd;
    assoc->client = *client;

    namelen = sizeof (assoc->server);
    if (getsockname (assoc->sd, (struct sockaddr *)&assoc->server, &namelen) != 0)
        memset (&assoc->server, 0x0, sizeof (assoc->server));
    
    lwins_dbg_start_assoc (assoc->handle);
    
    LOG (LOG_ALL, "Established association handle %x with %s\n", assoc->handle, inet_ntoa (assoc->client.sin_addr));
    LOG (LOG_ALL, "The owner IP is %s\n", inet_ntoa (assoc->server.sin_addr));
    
    return assoc;
}

static const char *association_get_exit_reason (struct association *assoc)
{
    if (assoc->timeout)
        return "timeout";
    else if (assoc->error)
        return "error";
    else
        return "normal";
}

void free_association (struct replication_service *service, struct association *assoc)
{
    unsigned short i;
    
    (void)service;
    
    LOG (LOG_ALL, "Free association handle %x with %s (%s)\n", assoc->handle, inet_ntoa (assoc->client.sin_addr), association_get_exit_reason (assoc));
    
    lwins_register_socket_flushed (service->server, assoc->sd, NULL, NULL);
    
    for (i = 0; i < service->associations_size; i++)
    {
        if (service->associations[i] == assoc)
        {
            service->associations[i] = NULL;
            service->associations_cnt--;
            break;
        }
    }
    
    if (assoc->sd >= 0)
        lwins_close_socket (service->server, assoc->sd);
    
    if (assoc->buffer)
        lwins_free (assoc->buffer);

    if (assoc->req_owners)
        lwins_free (assoc->req_owners);
    
    if (assoc->un_requests)
    {
        for (i = 0; i < assoc->un_requests_cnt; i++)
            lwins_free_replication_packet (assoc->un_requests[i]);
        lwins_free (assoc->un_requests);
    }
    
    if (assoc->un_req_propagate)
        lwins_free_replication_packet (assoc->un_req_propagate);
    
    /* Delete all events associated with this association */
    lwins_delete_event_by_context (service->server, assoc);
    
    lwins_free (assoc);
}

struct association *find_association (struct replication_service *service, int sd)
{
    unsigned short i, cnt;
    
    cnt = service->associations_cnt;
    for (i = 0; i < service->associations_size; i++)
    {
        if (service->associations[i])
        {
            if (service->associations[i]->sd == sd)
                return service->associations[i];
            if (--cnt == 0)
                break;
        }
    }
    
    return NULL;
}

struct replication_service *init_replication_service (struct lwins_config *cfg)
{
    struct replication_service *service;
    const char *value;
    unsigned int val;
    
    service = lwins_alloc (sizeof (*service));
    if (!service)
        return NULL;
    
    if (lwins_get_config_param (cfg, "replication-packet-size-max", 0, &value) &&
        lwins_convert_to_integer (value, &val) && val > 0 && val * 1024 > val)
    {
        service->max_packet_size = val * 1024;
    }
    else
        service->max_packet_size = 0;
    
    if (lwins_get_config_param (cfg, "replication-pull-verify-max", 0, &value) &&
        lwins_convert_to_integer (value, &val))
    {
        service->max_pull_verify_records = (val > 0) ? val : 0;
    }
    else
        service->max_pull_verify_records = 30000; /* TODO: Make configurable */

    return service;
}

int is_replication_service_terminated (struct replication_service *service)
{
    if (!service->associations || service->associations_cnt == 0)
        return 1;
    
    return 0;
}

void terminate_replication_service (struct replication_service *service)
{
    unsigned short i;
    
    if (service->associations)
    {
        if (service->associations_cnt > 0)
        {
            for (i = 0; i < service->associations_size; i++)
            {
                if (service->associations[i])
                    shutdown_association (service, service->associations[i]);
            }
        }
    }
}

void free_replication_service (struct replication_service *service)
{
    unsigned short i;
    
    if (service->associations)
    {
        if (service->associations_cnt > 0)
        {
            for (i = 0; i < service->associations_size; i++)
            {
                if (service->associations[i])
                    free_association (service, service->associations[i]);
            }
        }
        
        lwins_free (service->associations);
    }
    
    lwins_free (service);
}

static int replication_send_packet (struct replication_service *service, struct association *assoc, struct replication_packet *packet)
{
    size_t size;
    unsigned char *raw_packet;
    
    size = replication_calc_raw_packet_size (packet);
    if (!size)
        return LWINS_ERR;
    
    if (service->max_packet_size != 0 && size + sizeof (u32) > service->max_packet_size)
    {
        LOG (LOG_WARN, "Maximum packet size %u exceeded sending replication packet\n", service->max_packet_size);
        return LWINS_ERR;
    }
    
    raw_packet = lwins_alloc (size + sizeof (u32));
    if (!raw_packet)
        return LWINS_ERR;
    
    if (!replication_build_raw_packet (raw_packet, size + sizeof (u32), packet))
    {
        lwins_free (raw_packet);
        return LWINS_ERR;
    }

    LOGPACKET (raw_packet, (size_t)size + sizeof (u32), &assoc->client, lwins_dump_replication_raw_packet_to);
    
    return lwins_send_socket (service->server, assoc->sd, raw_packet, size + sizeof (u32));
}

static int replication_send_start_response (struct replication_service *service, struct association *assoc)
{
    struct replication_packet reply;
    
    reply.header.assoc_handle = assoc->sender_handle;
    reply.header.msg_type = REPL_MSG_ASSOC_START_RESP;
    reply.assoc_start.sdr_assoc_handle = assoc->handle;
    reply.assoc_start.nbns_version_major = 2;
    reply.assoc_start.nbns_version_minor = 5;
    
    return replication_send_packet (service, assoc, &reply);
}

static int lwins_send_name_records_request (struct replication_service *service, struct association *assoc, int req)
{
    struct replication_packet request;
    struct reg_owner_version *ov_entry;

    ASSERT (req < assoc->req_owners_cnt);
    ASSERT (assoc->req_owners);
    
    ov_entry = lwins_registry_find_owner_version (service->server->registry, &assoc->req_owners[req].owner);
    if (ov_entry)
    {
        /* We must have a new entries with higher versions if we ever get here */
        ASSERT (lwins_is_version_higher (&assoc->req_owners[req].max_version, &ov_entry->max_version));
    }

    LOG (LOG_ALL, "Request name record for owner %s\n", inet_ntoa (assoc->req_owners[req].owner));

    /* Send the request */
    request.header.assoc_handle = assoc->sender_handle;
    request.header.msg_type = REPL_MSG_PUSHPULL;
    request.pushpull.op_code = REPL_PUSHPULL_OP_NREC_REQ;
    request.pushpull.namerec_req.rec.addr = assoc->req_owners[req].owner;
    request.pushpull.namerec_req.rec.max_version = assoc->req_owners[req].max_version;
    request.pushpull.namerec_req.rec.min_version = assoc->req_owners[req].min_version;
    
    return replication_send_packet (service, assoc, &request);
}

static int lwins_send_stop_assoc_request (struct replication_service *service, struct association *assoc, int error)
{
    struct replication_packet request;

    request.header.assoc_handle = assoc->sender_handle;
    request.header.msg_type = REPL_MSG_ASSOC_STOP_REQ;
    request.assoc_stop.reason = error ? REPL_ASSOC_STOP_ERROR : REPL_ASSOC_STOP_NORMAL;

    LOG (LOG_ALL, "Send association stop request (%s)\n", association_get_exit_reason (assoc));
    return replication_send_packet (service, assoc, &request);
}

static int lwins_queue_owner_request (struct association *assoc, struct replication_owner_record *owner)
{
    struct replication_owner_request *tmp;

    if (assoc->req_owners_cnt > 0)
    {
        ASSERT (assoc->req_owners);

        tmp = lwins_alloc ((assoc->req_owners_cnt + 1) * sizeof (assoc->req_owners[0]));
        if (!tmp)
            return LWINS_ERR;

        memcpy (tmp, assoc->req_owners, assoc->req_owners_cnt * sizeof (assoc->req_owners[0]));
        lwins_free (assoc->req_owners);
        assoc->req_owners = tmp;
    }
    else
    {
        assoc->req_owners = lwins_alloc (sizeof (assoc->req_owners[0]));
        if (!assoc->req_owners)
            return LWINS_ERR;
    }

    assoc->req_owners[assoc->req_owners_cnt].owner.s_addr = owner->addr.s_addr;
    assoc->req_owners[assoc->req_owners_cnt].max_version = owner->max_version;
    assoc->req_owners[assoc->req_owners_cnt].min_version = owner->min_version;
    assoc->req_owners_cnt++;
    return 1;
}

static int lwins_send_owner_version_map_reply (struct replication_service *service, struct association *assoc)
{
    struct registry *reg;
    struct replication_packet reply;
    u32 n;
    int ret;
    
    reg = service->server->registry;

    reply.header.assoc_handle = assoc->sender_handle;
    reply.header.msg_type = REPL_MSG_PUSHPULL;
    reply.pushpull.op_code = REPL_PUSHPULL_OP_OVMAP_RESP;
    reply.pushpull.ovmap_resp.owners_cnt = reg->owner_version_cnt;
    reply.pushpull.ovmap_resp.owners = lwins_alloc (reg->owner_version_cnt * sizeof (*reply.pushpull.ovmap_resp.owners));
    if (!reply.pushpull.ovmap_resp.owners)
        return LWINS_ERR;

    LOG (LOG_ALL, "Send owner/version map\n");

    for (n = 0; n < reg->owner_version_cnt; n++)
    {
        if (n == 0)
            reply.pushpull.ovmap_resp.owners[n].addr.s_addr = assoc->server.sin_addr.s_addr;
        else
            reply.pushpull.ovmap_resp.owners[n].addr.s_addr = reg->owner_version[n].owner.s_addr;
        reply.pushpull.ovmap_resp.owners[n].max_version = reg->owner_version[n].max_version;
        reply.pushpull.ovmap_resp.owners[n].min_version = reg->owner_version[n].min_version;
    }

    ret = replication_send_packet (service, assoc, &reply);

    replication_free_packet (&reply);
    return ret;
}

static int lwins_send_namerec_reply (struct replication_service *service, struct association *assoc, struct replication_packet *req)
{
    struct registry *reg;
    struct replication_packet reply;
    int ret;
    
    (void)assoc;
    
    reg = service->server->registry;
    
    ASSERT (req->header.msg_type == REPL_MSG_PUSHPULL);
    ASSERT (req->pushpull.op_code == REPL_PUSHPULL_OP_NREC_REQ);
    
    if (is_own_replication_address (service->server, &req->pushpull.namerec_req.rec.addr))
        req->pushpull.namerec_req.rec.addr.s_addr = htonl (INADDR_ANY);
    
    reply.header.assoc_handle = assoc->sender_handle;
    reply.header.msg_type = REPL_MSG_PUSHPULL;
    reply.pushpull.op_code = REPL_PUSHPULL_OP_NREC_RESP;
    
    reply.pushpull.namerec_resp.namerecs_cnt = lwins_nrec_get_registry_entries (reg, &req->pushpull.namerec_req.rec, NULL, 0);
    
    LOG (LOG_ALL, "Send name %u record(s) for owner %s versions %x.%x - %x.%x\n", reply.pushpull.namerec_resp.namerecs_cnt, 
         inet_ntoa (req->pushpull.namerec_req.rec.addr), req->pushpull.namerec_req.rec.min_version.high,
         req->pushpull.namerec_req.rec.min_version.low, req->pushpull.namerec_req.rec.max_version.high,
         req->pushpull.namerec_req.rec.max_version.low);
    if (reply.pushpull.namerec_resp.namerecs_cnt > 0)
    {
        reply.pushpull.namerec_resp.namerecs = lwins_alloc (reply.pushpull.namerec_resp.namerecs_cnt * sizeof (reply.pushpull.namerec_resp.namerecs[0]));
        if (!reply.pushpull.namerec_resp.namerecs)
            return LWINS_ERR;
        
        reply.pushpull.namerec_resp.namerecs_cnt = lwins_nrec_get_registry_entries (reg, &req->pushpull.namerec_req.rec, reply.pushpull.namerec_resp.namerecs, reply.pushpull.namerec_resp.namerecs_cnt);
    }
    else
        reply.pushpull.namerec_resp.namerecs = NULL;
    
    ret = replication_send_packet (service, assoc, &reply);
    
    /* Warning: Do not call replication_free_packet () because we don't want the name records
                to be freed.  For performance reasons we just copied the pointers into the
                array... */
    if (reply.pushpull.namerec_resp.namerecs_cnt > 0)
        lwins_free (reply.pushpull.namerec_resp.namerecs);
    return ret;
}

static int lwins_queue_owner_update_requests (struct replication_service *service, struct association *assoc, u32 count, struct replication_owner_record *owners)
{
    int i;
    u32 n;

    for (n = 0; n < count; n++)
    {
        if (is_own_replication_address (service->server, &owners[n].addr))
            continue;

        /* Search the queue for this owner */
        for (i = 0; i < assoc->req_owners_cnt; i++)
        {
            if (assoc->req_owners[i].owner.s_addr == owners[n].addr.s_addr)
                break;
        }

        if (i < assoc->req_owners_cnt)
        {
            /* Found the record, check if it has a higher version number */
            if (lwins_is_version_higher (&owners[n].max_version, &assoc->req_owners[i].max_version))
            {
                LOG (LOG_ALL, "Owner update request: Update version for %s\n", inet_ntoa (owners[n].addr));
                assoc->req_owners[i].max_version = owners[n].max_version;
            }
            else
                LOG (LOG_ALL, "Owner update request: Already queued %s\n", inet_ntoa (owners[n].addr));
        }
        else if (owners[n].max_version.high > 0 || owners[n].max_version.low > 0)
        {
            if (!lwins_queue_owner_request (assoc, &owners[n]))
                return LWINS_ERR;
            
            LOG (LOG_ALL, "Owner update request: Queued %s\n", inet_ntoa (owners[n].addr));
        }
    }

    return 1;
}

static const char* lwins_rep_namerec_flags_to_str (struct replication_name_record *namerec)
{
    static char str[255];
    char state[12], entry_type[14], node_type[8];
    
    switch (namerec->type)
    {
        case NREC_TYPE_UNIQUE:
            strcpy (entry_type, "unique");
            break;
        case NREC_TYPE_GROUP:
            strcpy (entry_type, "group");
            break;
        case NREC_TYPE_GROUP_SPECIAL:
            strcpy (entry_type, "special_group");
            break;
        case NREC_TYPE_MULTIHOMED:
            strcpy (entry_type, "multihomed");
            break;
        default:
            sprintf (entry_type, "%x", namerec->type & 0xFF);
            break;
    }
    strcpy (str, entry_type);
    strcat (str, namerec->is_static ? ",static" : ",dynamic");
    strcat (str, namerec->is_replica ? ",replica" : ",local");
    switch (namerec->state)
    {
        case NREC_STATE_ACTIVE:
            strcpy (state, ",active");
            break;
        case NREC_STATE_TOMBSTONE:
            strcpy (state, ",tombstoned");
            break;
        default:
            sprintf (state, ",%x", namerec->state & 0xFF);
            break;
    }
    strcat (str, state);
    switch (namerec->node_type)
    {
        case NREC_NODE_B:
            strcpy (node_type, ",b_node");
            break;
        case NREC_NODE_P:
            strcpy (node_type, ",p_node");
            break;
        case NREC_NODE_M:
            strcpy (node_type, ",m_node");
            break;
        default:
            sprintf (node_type, ",%x", namerec->node_type & 0xFF);
            break;
    }
    strcat (str, node_type);
    return str;
}

static void lwins_rep_namerec_log (struct replication_name_record *namerec)
{
    size_t rec_size;
    char *rec;
    u8 i;
    
    rec_size = netbt_name_to_str (namerec->name, NULL, 0);
    ASSERT (rec_size > 0);
    rec = lwins_alloc (rec_size);
    rec_size = netbt_name_to_str (namerec->name, rec, rec_size);
    ASSERT (rec_size > 0);
    
    LOG (LOG_ALL, "Rec \"%s\"\n", rec);
    lwins_free (rec);
    LOG (LOG_ALL, "    Version %x.%x Flags: %s\n", namerec->version.high, namerec->version.low, lwins_rep_namerec_flags_to_str (namerec));
    for (i = 0; i < namerec->addrs_cnt; i++)
    {
        char owner[16], addr[16];
        strcpy (owner, inet_ntoa (namerec->addrs[i].owner));
        strcpy (addr, inet_ntoa (namerec->addrs[i].member));
        LOG (LOG_ALL, "    %s [Owner: %s]\n", addr, owner);
    }
}

static int lwins_merge_name_records (struct replication_service *service, struct association *assoc, struct replication_packet *packet, int nreq)
{
    struct replication_name_record *namerec;
    struct replication_owner_request *req;
    struct registry *reg;
    unsigned int delete_cnt;
    struct reg_entry *reg_entry;
    u32 i;
    u8 i2;
    
    reg = service->server->registry;
    ASSERT (reg);
    
    ASSERT (assoc->req_owners_cnt > nreq);
    req = &assoc->req_owners[nreq];
    
    LOG (LOG_ALL, "Merging %u name record(s) %x.%x - %x.%x...\n", packet->pushpull.namerec_resp.namerecs_cnt,
         req->min_version.high, req->min_version.low, req->max_version.high, req->max_version.low);
    
    lwins_registry_merge_begin (reg, req);
    
    for (i = 0; i < packet->pushpull.namerec_resp.namerecs_cnt; i++)
    {
        namerec = packet->pushpull.namerec_resp.namerecs[i];
        
        if (lwins_is_version_lower (&namerec->version, &req->min_version))
        {
            LOG (LOG_ERR, "Requested versions %x.%x or higher, but received version %x.%x\n",
                 req->min_version.high, req->min_version.low, namerec->version.high, namerec->version.low);
            continue;
        }
        
        if (lwins_is_version_higher (&namerec->version, &req->max_version))
        {
            LOG (LOG_ERR, "Requested versions %x.%x or lower, but received version %x.%x\n",
                 req->max_version.high, req->max_version.low, namerec->version.high, namerec->version.low);
            continue;
        }
        
        if (namerec->type == NREC_TYPE_UNIQUE || namerec->type == NREC_TYPE_GROUP)
        {
            /* Patch the owner to the owner that we requested. In the case of 
               unique and group records no owner is included in the response. */
            for (i2 = 0; i2 < namerec->addrs_cnt; i2++)
                namerec->addrs[i2].owner = req->owner;
        }
        
        /* Log the record */
        lwins_rep_namerec_log (namerec);
        
        if (namerec->type == NREC_TYPE_UNIQUE)
        {
            reg_entry = lwins_find_registry_entry (reg, namerec->name);
            if (reg_entry)
            {
                if (reg_entry->owner.s_addr != req->owner.s_addr)
                {
                    LOG (LOG_ERR, "Entry's owner does not match\n");
                    continue;
                }
                
                if (lwins_is_version_lower (&reg_entry->rec.version, &namerec->version))
                {
                    LOG (LOG_ERR, "Entry's version is lower\n");
                    goto skip_merge_entry;
                }
                
                if (lwins_update_registry_entry (reg, reg_entry, namerec))
                    lwins_log_regentry (reg_entry, "Merged");
                else
                {
skip_merge_entry:
                    lwins_log_regentry (reg_entry, "Merge failed");
                    /* Make sure this entry won't be deleted after the merge */
                    lwins_registry_merge_skip_entry (reg, reg_entry);
                    continue;
                }
            }
            else
            {
                reg_entry = lwins_create_registry_entry_from_namerec (reg, namerec, &req->owner);
                if (reg_entry)
                {
                    lwins_add_registry_entry (reg, reg_entry);
                    lwins_log_regentry (reg_entry, "Added");
                }
            }
        }
        else
        {
            /* TODO */
        }
    }
    
    delete_cnt = lwins_registry_merge_end (reg);
    
    LOG (LOG_ALL, "Merge complete, deleted %u entries\n", delete_cnt);
    return 1;
}

static int lwins_remove_nrec_request (struct replication_service *service, struct association *assoc, int nreq)
{
    ASSERT (nreq < assoc->req_owners_cnt);
    
    (void)service;
    
    if (--assoc->req_owners_cnt > 0)
    {
        memmove (&assoc->req_owners[nreq], &assoc->req_owners[nreq + 1], (assoc->req_owners_cnt - nreq) * sizeof (assoc->req_owners[0]));
        return 0;
    }
    
    lwins_free (assoc->req_owners);
    assoc->req_owners = NULL;
    return 1;
}

static int lwins_get_next_nrec_request (struct replication_service *service, struct association *assoc)
{
    struct reg_owner_version *ov_entry;
    int deleted;
    
    while (assoc->req_owners_cnt > 0)
    {
        deleted = 0;
        ov_entry = lwins_registry_find_owner_version (service->server->registry, &assoc->req_owners[0].owner);
        if (ov_entry)
        {
            if (lwins_is_version_higher (&ov_entry->max_version, &assoc->req_owners[0].max_version))
            {
                /* If the current request was updated by another association in the meanwhile,
                   delete it as we no longer need to request the records */
                lwins_remove_nrec_request (service, assoc, 0);
                deleted = 1;
            }
        }
        
        if (!deleted)
            return 0; /* Return the first queued request */
    }
    
    return -1;
}

static int lwins_get_pending_nrec_request (struct replication_service *service, struct association *assoc)
{
    (void)service;
    
    if (assoc->req_owners_cnt > 0)
        return 0; /* The first queued request is the pending request */
    return -1;
}

static int lwins_queue_un_request (struct replication_service *service, struct association *assoc, struct replication_packet *packet)
{
    struct replication_packet *packet_dup;
    struct replication_packet **tmp;
    
    (void)service;
    
    ASSERT (packet->header.msg_type == REPL_MSG_PUSHPULL);
    ASSERT (packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_NO_PROPAGATE ||
            packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_PROPAGATE ||
            packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE ||
            packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE);
    
    packet_dup = lwins_duplicate_replication_packet (packet);
    if (!packet_dup)
        return LWINS_ERR;
    
    if (assoc->un_requests_cnt == 0)
    {
        assoc->un_requests = lwins_alloc (sizeof (assoc->un_requests[0]));
        if (!assoc->un_requests)
        {
            lwins_free_replication_packet (packet_dup);
            return LWINS_ERR;
        }
    }
    else
    {
        ASSERT (assoc->un_requests != NULL);
        
        tmp = lwins_alloc ((assoc->un_requests_cnt + 1) * sizeof (assoc->un_requests[0]));
        if (!tmp)
        {
            lwins_free_replication_packet (packet_dup);
            return LWINS_ERR;
        }
        
        memcpy (tmp, assoc->un_requests, assoc->un_requests_cnt * sizeof (assoc->un_requests[0]));
        lwins_free (assoc->un_requests);
        assoc->un_requests = tmp;
    }
    
    assoc->un_requests[assoc->un_requests_cnt++] = packet_dup;
    return 1;
}

static void lwins_dequeue_un_request (struct replication_service *service, struct association *assoc, struct replication_packet *packet)
{
    struct replication_packet *next_packet;
    
    (void)service;
    
    if (assoc->un_requests_cnt > 0)
    {
        ASSERT (assoc->un_requests != NULL);
        
        next_packet = assoc->un_requests[0];
        ASSERT (next_packet != NULL);
        
        /* Free the current packet */
        replication_free_packet (packet);
        
        /* Copy the queued packet */
        *packet = *next_packet;
        
        /* Free the queued packet (but not it's content that we are using) */
        lwins_free (next_packet);
        
        /* Remove from the queue */
        if (--assoc->un_requests_cnt == 0)
        {
            lwins_free (assoc->un_requests);
            assoc->un_requests = NULL;
        }
        else
            memmove (&assoc->un_requests[0], &assoc->un_requests[1], assoc->un_requests_cnt * sizeof (assoc->un_requests[0]));
        
        /* Set a flag so that we immediately process the dequeued packet */
        assoc->reprocess_packet = 1;
    }
}

static void lwins_association_apply_un_flags (struct replication_service *service, struct association *assoc, struct replication_packet *packet)
{
    (void)service;
    
    assoc->propagate = 0;
    assoc->persistent = 0;
    
    if (packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_PROPAGATE)
        assoc->propagate = 1;
    else if (packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE)
        assoc->persistent = 1;
    else if (packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE)
    {
        assoc->persistent = 1;
        assoc->propagate = 1;
    }
    else
        ASSERT (packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_NO_PROPAGATE);
    
    if (assoc->propagate)
    {
        ASSERT (assoc->un_req_propagate == NULL);
        assoc->un_req_propagate = lwins_duplicate_replication_packet (packet);
        if (!assoc->un_req_propagate)
        {
            LOG (LOG_ERR, "Could not save update notification, disable propagation\n");
            assoc->propagate = 0;
        }
        else if (assoc->un_req_propagate->pushpull.updatenotify.initiator_addr.s_addr == htonl (INADDR_ANY))
            assoc->un_req_propagate->pushpull.updatenotify.initiator_addr = assoc->client.sin_addr;
    }
}

static int lwins_complete_un_request (struct replication_service *service, struct association *assoc, struct replication_packet *packet)
{
    LOG (LOG_ALL, "Incoming push request completed\n");
    
    if (assoc->propagate)
    {
        ASSERT (assoc->un_req_propagate != NULL);
        
        LOG (LOG_ALL, "Propagate push request initiated by %s\n", inet_ntoa (assoc->un_req_propagate->pushpull.updatenotify.initiator_addr));
        
        lwins_free_replication_packet (assoc->un_req_propagate);
        assoc->un_req_propagate = NULL;
    }
    else
        ASSERT (assoc->un_req_propagate == NULL);
    
    if (assoc->persistent)
    {
        /* Dequeue any pending requests for processing */
        lwins_dequeue_un_request (service, assoc, packet);
    }
    else
    {
        /* This connection is not persistent, close it */
        LOG (LOG_ALL, "Close non-persistent connection\n");
        assoc->shutdown_conn = 1;
        assoc->completed = 1;
    }
    return 1;
}

static int replication_process_start_req (struct replication_service *service, struct association *assoc, struct replication_packet *packet)
{
    int ret;
    
    ASSERT (packet->header.msg_type == REPL_MSG_ASSOC_START_REQ);
    
    if (packet->header.assoc_handle != 0)
    {
        LOG (LOG_ERR, "Invalid association handle");
        return 0;
    }

    if (packet->assoc_start.nbns_version_major != 2 || packet->assoc_start.nbns_version_minor != 5)
    {
        LOG (LOG_ERR, "Unsupported NBNS version: %u.%u\n", packet->assoc_start.nbns_version_major & 0xFFFF, packet->assoc_start.nbns_version_minor & 0xFFFF);
        assoc->shutdown_conn = 1; /* FIXME: Send stop request with error? */
        return 1;
    }

    assoc->sender_handle = packet->assoc_start.sdr_assoc_handle;
    assoc->started = 1;
    assoc->persistent = 1; /* Assume persistent connection */
    
    /* Delete the timeout event once the association has been established */
    ASSERT (assoc->timeout_event);
    association_delete_timeout_event (service, assoc);
    
    ret = replication_send_start_response (service, assoc);
    if (ret)
        assoc->step++;
    return ret;
}

static int replication_process_stop_req (struct replication_service *service, struct association *assoc, struct replication_packet *packet)
{
    (void)service;
    
    ASSERT (packet->header.msg_type == REPL_MSG_ASSOC_STOP_REQ);
    
    switch (packet->assoc_stop.reason)
    {
        case REPL_ASSOC_STOP_NORMAL:
            LOG (LOG_ALL, "Association stop requested (normal)\n");
            break;

        case REPL_ASSOC_STOP_ERROR:
            assoc->error = 1;
            LOG (LOG_ALL, "Association stop requested (error)\n");
            break;

        default:
            LOG (LOG_ERR, "Association stop requested (unknown reason: %x)\n", packet->assoc_stop.reason);
            break;
    }
    
    assoc->shutdown_conn = 1;
    assoc->stopped = 1;
    return 1;
}

static int replication_process_nrec_response (struct replication_service *service, struct association *assoc, struct replication_packet *packet)
{
    int ret, nreq;
    
    ASSERT (packet->header.msg_type == REPL_MSG_PUSHPULL);
    ASSERT (packet->pushpull.op_code == REPL_PUSHPULL_OP_NREC_RESP);
    
    nreq = lwins_get_pending_nrec_request (service, assoc);
    if (nreq < 0)
    {
        LOG (LOG_ERR, "No pending name record request found\n");
        return 0;
    }
    
    ret = lwins_merge_name_records (service, assoc, packet, nreq);
    if (ret)
    {
        if (lwins_remove_nrec_request (service, assoc, nreq))
            lwins_complete_un_request (service, assoc, packet);
        else
        {
            nreq = lwins_get_next_nrec_request (service, assoc);
            if (nreq >= 0)
                ret = lwins_send_name_records_request (service, assoc, nreq);
            else
            {
                /* Nothing to do for this update notification */
                lwins_complete_un_request (service, assoc, packet);
            }
        }
    }
    
    return ret;
}

static int replication_process_update_notification (struct replication_service *service, struct association *assoc, struct replication_packet *packet)
{
    int ret, nreq;
    
    ASSERT (packet->header.msg_type == REPL_MSG_PUSHPULL);
    ASSERT (packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_PROPAGATE ||
            packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE ||
            packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE ||
            packet->pushpull.op_code == REPL_PUSHPULL_OP_UN_NO_PROPAGATE);
    
    if (!assoc->persistent && assoc->req_owners_cnt > 0)
    {
        LOG (LOG_ERR, "Multiple update notifications not allowed for non-persistent association\n");
        return 0;
    }
    
    if (assoc->persistent && assoc->req_owners_cnt > 0)
    {
        if (lwins_queue_un_request (service, assoc, packet))
        {
            /* TODO: Go through the list of pending name record requests and see if we
                     can upgrade the maximum version number to avoid having to send
                     yet another request for the same owner later on... */
            
            LOG (LOG_ALL, "Update notification queued, push request in progress\n");
            /* Queued the update notification message for processing after the currently
               processed push request completed */
            return 1;
        }
        else
            LOG (LOG_ERR, "Error queueing update notification, discard\n");
    }
    
    lwins_association_apply_un_flags (service, assoc, packet);

    LOG (LOG_ALL, "Incoming push request started: propagate: %d persistent: %d\n", assoc->propagate, assoc->persistent);
    
    ret = lwins_queue_owner_update_requests (service, assoc, packet->pushpull.updatenotify.owners_cnt, 
                                             packet->pushpull.updatenotify.owners);
    if (ret)
    {
        nreq = lwins_get_next_nrec_request (service, assoc);
        if (nreq >= 0)
            ret = lwins_send_name_records_request (service, assoc, nreq);
        else
        {
            /* Nothing to do for this update notification */
            lwins_complete_un_request (service, assoc, packet);
        }
    }
    
    return ret;
}

static int replication_process_packet (struct replication_service *service, struct association *assoc, struct replication_packet *packet)
{
    int ret = 0;
    
    if (packet)
        LOG (LOG_ALL, "Process replication packet: step %u\n", assoc->step);

    if (packet && assoc->step > 0 && packet->header.assoc_handle != assoc->handle)
    {
        LOG (LOG_ERR, "Invalid association handle");
        goto step_err;
    }

    switch (assoc->step)
    {
        case 0:
            ASSERT (packet);

            if (packet->header.msg_type != REPL_MSG_ASSOC_START_REQ)
            {
                LOG (LOG_ERR, "Expected REPL_MSG_ASSOC_START_REQ but received %u\n", packet->header.msg_type);
                break;
            }
            
            ret = replication_process_start_req (service, assoc, packet);
            break;

        case 1:
        {
            ASSERT (packet);

            if (packet->header.msg_type == REPL_MSG_ASSOC_STOP_REQ)
                return replication_process_stop_req (service, assoc, packet);
            else if (packet->header.msg_type != REPL_MSG_PUSHPULL)
            {
                LOG (LOG_ERR, "Expected REPL_MSG_PUSHPULL but received %u\n", packet->header.msg_type);
                break;
            }

            switch (packet->pushpull.op_code)
            {
                case REPL_PUSHPULL_OP_OVMAP_REQ:
                    ret = lwins_send_owner_version_map_reply (service, assoc);
                    break;
                
                case REPL_PUSHPULL_OP_NREC_REQ:
                    ret = lwins_send_namerec_reply (service, assoc, packet);
                    break;
                
                case REPL_PUSHPULL_OP_NREC_RESP:
                    ret = replication_process_nrec_response (service, assoc, packet);
                    break;
                
                case REPL_PUSHPULL_OP_UN_PROPAGATE:
                case REPL_PUSHPULL_OP_UN_PERSIST_NO_PROPAGATE:
                case REPL_PUSHPULL_OP_UN_PERSIST_PROPAGATE:
                case REPL_PUSHPULL_OP_UN_NO_PROPAGATE:
                    ret = replication_process_update_notification (service, assoc, packet);
                    break;
                
                default:
                    LOG (LOG_ERR, "Unexpected push/pull op_code %u\n", packet->pushpull.op_code);
                    ret = 1; /* Silently discard packet */
                    break;
            }
            break;
        }

        case 0xFF:
            /* packet may be NULL! */
            LOG (LOG_ALL, "Replication completed\n");
            assoc->shutdown_conn = 1;
            assoc->completed = 1;
            ret = 1; /* TODO: Merge name records */
            break;

        default:
            LOG (LOG_ERR, "Invalid step %u\n", assoc->step);
            break;
    }

    if (!ret)
    {
step_err:
        LOG (LOG_ERR, "Close connection due to error in step %u\n", assoc->step);
        assoc->shutdown_conn = 1;
        assoc->error = 1;
        ret = 1;
    }

    return ret;
}

static int association_read_raw_packet (struct replication_service *service, struct association *assoc, unsigned char *raw_packet, size_t packet_size)
{
    struct replication_packet packet;
    int ret = 0;
    
    (void)service;
    (void)assoc;
    
    memset (&packet, 0, sizeof (packet));
    if (replication_parse_raw_packet (raw_packet, packet_size, &packet))
    {
        do
        {
            assoc->reprocess_packet = 0;
            ret = replication_process_packet (service, assoc, &packet);
        }
        while (ret && assoc->reprocess_packet);
        
        if (ret && assoc->step == 0xFF && !assoc->shutdown_conn)
        {
            do
            {
                assoc->reprocess_packet = 0;
                ret = replication_process_packet (service, assoc, NULL);
            } while (ret && assoc->reprocess_packet);
        }
        replication_free_packet (&packet);
    }
    
    return ret;
}

int association_buffer_receive (struct replication_service *service, struct association *assoc, unsigned char *buffer, size_t buffer_size)
{
    u32 packet_len;
    
    if (service->max_packet_size != 0 && assoc->buffer_length + buffer_size > service->max_packet_size)
    {
        LOG (LOG_PACKET, "Maximum replication packet size %u exceeded!\n", service->max_packet_size);
        return LWINS_ERR;
    }
    
    if (!assoc->buffer)
    {
        assoc->buffer = lwins_alloc (buffer_size);
        if (!assoc->buffer)
            return LWINS_ERR;
        assoc->buffer_size = buffer_size;
        assoc->buffer_length = buffer_size;
        memcpy (assoc->buffer, buffer, buffer_size);
    }
    else if (assoc->buffer_size < assoc->buffer_length + buffer_size)
    {
        unsigned char *buf;
        
        buf = lwins_alloc (assoc->buffer_length + buffer_size);
        if (!buf)
            return LWINS_ERR;
        memcpy (buf, assoc->buffer, assoc->buffer_length);
        memcpy (buf + assoc->buffer_length, buffer, buffer_size);
        ASSERT (assoc->buffer != NULL);
        lwins_free (assoc->buffer);
        assoc->buffer = buf;
        assoc->buffer_length += buffer_size;
        assoc->buffer_size = assoc->buffer_length;
    }
    else
    {
        ASSERT (assoc->buffer != NULL);
        ASSERT (assoc->buffer_size >= assoc->buffer_length + buffer_size);
        
        memcpy (assoc->buffer + assoc->buffer_length, buffer, buffer_size);
        assoc->buffer_length += buffer_size;
    }
    
    while (assoc->buffer_length >= sizeof (u32))
    {
        memcpy (&packet_len, assoc->buffer, sizeof (u32));
        packet_len = ntohl (packet_len) + sizeof (u32);
        
        if (service->max_packet_size != 0 && packet_len > service->max_packet_size)
        {
            LOG (LOG_PACKET, "Maximum replication packet size %u exceeded!\n", service->max_packet_size);
            return LWINS_ERR;
        }
        
        if (assoc->buffer_length >= packet_len)
        {
            LOGPACKET (assoc->buffer, (size_t)packet_len, &assoc->client, lwins_dump_replication_raw_packet_from);
            if (!association_read_raw_packet (service, assoc, assoc->buffer, packet_len))
                return LWINS_ERR;
            if (assoc->buffer_length > packet_len)
                memmove (assoc->buffer, assoc->buffer + packet_len, assoc->buffer_length - packet_len);
            assoc->buffer_length -= packet_len;
            
            if (assoc->shutdown_conn)
            {
                shutdown_association (service, assoc);
                break;
            }
        }
        else
            break;
    }
    
    return 1;
}

static void shutdown_association_timeout_handler (struct netbios_server *server, struct lwins_event *event)
{
    struct association *assoc = (struct association *)event->context;
    
    lwins_dbg_start_assoc (assoc->handle);
    
    LOG (LOG_ALL, "Timed out waiting for connection to be closed\n");
    assoc->timeout = 1;
    free_association (server->replication, assoc);
}

static void association_flushed (struct netbios_server *server, void *ctx)
{
    struct association *assoc = (struct association *)ctx;
    struct timeval due;
    
    lwins_dbg_start_assoc (assoc->handle);
    
    lwins_calculate_due_time (server, &due, 5);
    if (!assoc->incoming && assoc->stop_requested && lwins_add_event (server, shutdown_association_timeout_handler, NULL, assoc, &due))
        LOG (LOG_ALL, "Waiting for connection to be closed\n");
    else
        free_association (server->replication, assoc);
}

void shutdown_association (struct replication_service *service, struct association *assoc)
{
    lwins_dbg_start_assoc (assoc->handle);
    
    assoc->shutdown_conn = 1;
    
    association_delete_timeout_event (service, assoc);
    
    if (assoc->sd < 0)
    {
        LOG (LOG_ALL, "Association with %s lost\n", inet_ntoa (assoc->client.sin_addr));
        
        ASSERT (assoc->error);
        
        free_association (service, assoc);
    }
    else
    {
        if (!assoc->started)
            assoc->error = 1;
        
        LOG (LOG_ALL, "Terminating association with %s (%s)\n", inet_ntoa (assoc->client.sin_addr), association_get_exit_reason (assoc));
        
        if (!assoc->incoming && !assoc->persistent && !assoc->stop_requested && 
            lwins_send_stop_assoc_request (service, assoc, assoc->error))
            assoc->stop_requested = 1;
        
        if (lwins_is_socket_sending (service->server, assoc->sd))
            lwins_register_socket_flushed (service->server, assoc->sd, association_flushed, assoc);
        else
            association_flushed (service->server, (void *)assoc);
    }
}
