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

struct registry* lwins_create_registry (struct netbios_server *server)
{
    struct registry *reg;

    reg = lwins_alloc (sizeof (*reg));
    if (!reg)
        return NULL;
    
    reg->owner_version = lwins_alloc (sizeof (reg->owner_version[0]));
    if (!reg->owner_version)
    {
        lwins_free (reg);
        return NULL;
    }
    reg->owner_version_cnt = 1;
    
    reg->server = server;
    
    reg->renewal_interval = 6 * 24 * 60 * 60;
    reg->extinction_interval = 4 * 24 * 60 * 60;
    reg->extinction_timeout = reg->renewal_interval;
    
    return reg;
}

void lwins_free_reg_entry (struct registry *reg, struct reg_entry *entry)
{
    (void)reg;
    
    if (entry->rec.name)
        lwins_free (entry->rec.name);
    if (entry->rec.addrs)
        lwins_free (entry->rec.addrs);
    lwins_free (entry);
}

void lwins_destroy_registry (struct registry *reg)
{
    struct reg_entry *next;

    while (reg->entries)
    {
        next = reg->entries->next;
        lwins_free_reg_entry (reg, reg->entries);
        reg->entries = next;
    }
    
    if (reg->owner_version)
        lwins_free (reg->owner_version);

    lwins_free (reg);
}

static int lwins_match_reg_entry (struct reg_entry *entry, const char *match)
{
    int ret;
    
    ret = memcmp (entry->rec.name, match, NETBT_NAME_LENGTH);
    if (ret == 0)
        ret = strcmp (&entry->rec.name[NETBT_NAME_LENGTH], &match[NETBT_NAME_LENGTH]);
    
    return ret;
}

int lwins_find_registry_entries (struct registry *reg, const char *match, plwins_enum_proc enum_proc, void *ctx)
{
    struct reg_entry *cur_entry;
    int fnd = 0;
    
    for (cur_entry = reg->entries; cur_entry != NULL; cur_entry = cur_entry->next)
    {
        if (lwins_match_reg_entry (cur_entry, match))
        {
            if (!enum_proc (reg, cur_entry, ctx))
                return 0;
            fnd++;
        }
    }
    
    return fnd;
}

struct reg_entry* lwins_find_registry_entry (struct registry *reg, const char *match)
{
    struct reg_entry *entry;
    
    for (entry = reg->entries; entry != NULL; entry = entry->next)
    {
        if (lwins_match_reg_entry (entry, match) == 0)
            return entry;
    }
    
    return NULL;
}

static int lwins_scavenge_next_due (struct registry *reg, struct timeval *due)
{
    if (reg->event_entries)
    {
        due->tv_sec = reg->event_entries->event_time;
        due->tv_usec = 0;
        return 1;
    }
    
    return 0;
}

static void lwins_reg_scavenge_handler (struct netbios_server *server, struct lwins_event *event)
{
    struct timeval due;
    struct registry *reg = (struct registry *)event->context;
    
    ASSERT (reg->scavenge_event == event);
    ASSERT (reg->event_entries != NULL);
    
    reg->in_scavenge_event = 1;
    lwins_registry_scavenge (reg, reg->event_entries);
    reg->in_scavenge_event = 0;
    
    ASSERT (reg->scavenge_event == event);
    if (lwins_scavenge_next_due (reg, &due))
        lwins_set_event_due (server, event, &due);
}

static void lwins_reg_scavenge_delete (struct netbios_server *server, struct lwins_event *event)
{
    struct registry *reg = (struct registry *)event->context;
    
    (void)server;
    
    ASSERT (reg->scavenge_event == event);
    reg->scavenge_event = NULL;
}

static void lwins_reg_update_event_timer (struct registry *reg)
{
    struct timeval due;
    
    if (!reg->in_scavenge_event)
    {
        /* If this was called while the scavenge event is running, don't reset the event.
           This will be done automatically before the event handler returns */
        if (reg->scavenge_event)
        {
            lwins_delete_event (reg->server, reg->scavenge_event);
            reg->scavenge_event = NULL;
        }
        
        if (lwins_scavenge_next_due (reg, &due))
        {
            reg->scavenge_event = lwins_add_event (reg->server, lwins_reg_scavenge_handler, lwins_reg_scavenge_delete, reg, &due);
            if (!reg->scavenge_event)
                LOG (LOG_ERR, "Error queuing scavenge event\n");
        }
    }
}

static void lwins_reg_link_entry (struct registry *reg, struct reg_entry *entry)
{
    struct reg_entry *cur, **prev;
    
    ASSERT (entry->next == NULL);
    
    prev = &reg->entries;
    cur = reg->entries;
    while (cur && lwins_match_reg_entry (cur, entry->rec.name) < 0)
    {
        prev = &cur->next;
        cur = cur->next;
    }
    
    *prev = entry;
    entry->next = cur;
    
    if (entry->event_time)
    {
        prev = &reg->event_entries;
        cur = reg->event_entries;
        while (cur && cur->event_time <= entry->event_time)
        {
            prev = &cur->next_event;
            cur = cur->next_event;
        }
        
        *prev = entry;
        entry->next_event = cur->next_event;
        
        if (prev == &reg->event_entries)
            lwins_reg_update_event_timer (reg);
    }
}

static void lwins_reg_unlink_entry (struct registry *reg, struct reg_entry *entry)
{
    struct reg_entry *cur, **prev;
    
    prev = &reg->entries;
    cur = reg->entries;
    while (cur != entry)
    {
        prev = &cur->next;
        cur = cur->next;
    }
    
    ASSERT (cur == entry);
    
    *prev = entry->next;
    entry->next = NULL;
    
    if (entry->event_time)
    {
        prev = &reg->event_entries;
        cur = reg->event_entries;
        while (cur != entry)
        {
            prev = &cur->next_event;
            cur = cur->next_event;
        }
        
        *prev = entry->next_event;
        entry->next_event = NULL;
        
        if (prev == &reg->event_entries)
            lwins_reg_update_event_timer (reg);
    }
}

static void lwins_reg_update_event_time (struct registry *reg, struct reg_entry *entry, time_t event_time)
{
    struct reg_entry *cur, **prev;
    int update_events = 0;
    
    if (entry->event_time)
    {
        prev = &reg->event_entries;
        cur = reg->event_entries;
        while (cur != entry)
        {
            prev = &cur->next_event;
            cur = cur->next_event;
        }
        
        *prev = entry->next_event;
        entry->next_event = NULL;
        
        if (prev == &reg->event_entries)
            update_events = 1;
    }
    entry->last_update = reg->server->current_time.tv_sec;
    entry->event_time = event_time;
    if (entry->event_time)
    {
        prev = &reg->event_entries;
        cur = reg->event_entries;
        while (cur && cur->event_time <= entry->event_time)
        {
            prev = &cur->next_event;
            cur = cur->next_event;
        }
        
        *prev = entry;
        entry->next_event = cur->next_event;
        
        if (prev == &reg->event_entries)
            update_events = 1;
    }
    
    if (update_events)
        lwins_reg_update_event_timer (reg);
}

struct replication_name_record* lwins_get_namerec_from_registry_entry (struct registry *reg, struct reg_entry *reg_entry)
{
    (void)reg;
    
    return &reg_entry->rec;
}

struct reg_entry* lwins_create_registry_entry_from_namerec (struct registry *reg, struct replication_name_record *namerec, struct in_addr *owner)
{
    struct reg_entry *entry;
    u8 i;
    
    (void)reg;
    
    entry = lwins_alloc (sizeof (*entry));
    if (entry)
    {
        entry->next = NULL;
        entry->next_event = NULL;
        
        entry->owner = *owner;
        
        entry->rec = *namerec;
        entry->rec.name = netbt_dup_name (namerec->name);
        if (!entry->rec.name)
        {
            lwins_free (entry);
            return NULL;
        }
        
        if (namerec->addrs_cnt > 0)
        {
            entry->rec.addrs = lwins_alloc ((size_t)namerec->addrs_cnt * sizeof (entry->rec.addrs[0]));
            if (!entry->rec.addrs)
            {
                lwins_free (entry->rec.name);
                lwins_free (entry);
                return NULL;
            }
            
            for (i = 0; i < namerec->addrs_cnt; i++)
            {
                entry->rec.addrs[i].owner = namerec->addrs[i].owner;
                entry->rec.addrs[i].member = namerec->addrs[i].member;
            }
        }
        
        entry->rec.addrs_cnt = namerec->addrs_cnt;
    }
    
    return entry;
}

struct reg_owner_version *lwins_registry_find_owner_version (struct registry *reg, struct in_addr *owner)
{
    unsigned int i;
    for (i = 0; i < reg->owner_version_cnt; i++)
    {
        if (reg->owner_version[i].owner.s_addr == owner->s_addr)
            return &reg->owner_version[i];
    }
    
    return NULL;
}

static struct reg_owner_version *lwins_registry_add_owner_version (struct registry *reg, struct in_addr *owner)
{
    struct reg_owner_version *tmp;
    
    ASSERT (reg->owner_version_cnt != 0);
    ASSERT (owner->s_addr != htonl (INADDR_ANY));
    
    tmp = lwins_alloc ((reg->owner_version_cnt + 1) * sizeof (reg->owner_version[0]));
    if (!tmp)
        return NULL;
    memcpy (tmp, reg->owner_version, reg->owner_version_cnt * sizeof (reg->owner_version[0]));
    lwins_free (reg->owner_version);
    reg->owner_version = tmp;
    
    reg->owner_version[reg->owner_version_cnt].owner = *owner;
    reg->owner_version[reg->owner_version_cnt].max_version.high = 0;
    reg->owner_version[reg->owner_version_cnt].max_version.low = 0;
    reg->owner_version[reg->owner_version_cnt].min_version.high = 0;
    reg->owner_version[reg->owner_version_cnt].min_version.low = 0;
    reg->owner_version[reg->owner_version_cnt].entries_cnt = 0;
    
    return &reg->owner_version[reg->owner_version_cnt++];
}

static void lwins_registry_del_owner_version (struct registry *reg, struct reg_owner_version *ov_entry)
{
    unsigned int i;
    
    ASSERT (ov_entry != NULL);
    ASSERT (ov_entry != &reg->owner_version[0]);
    ASSERT (reg->owner_version_cnt != 0);
    
    i = (unsigned int)(ov_entry - reg->owner_version);
    if (i < reg->owner_version_cnt - 1)
        memmove (ov_entry, ov_entry + 1, reg->owner_version_cnt - i - 1);
    reg->owner_version_cnt--;
}

static void lwins_registry_owner_version_add_entry (struct registry *reg, struct reg_entry *entry, struct reg_owner_version *ov_entry)
{
    (void)reg;
    
    if (ov_entry->entries_cnt++ == 0)
    {
        ov_entry->max_version = entry->rec.version;
        ov_entry->min_version = entry->rec.version;
    }
    else
    {
        if (lwins_is_version_higher (&entry->rec.version, &ov_entry->max_version))
            ov_entry->max_version = entry->rec.version;
    }
}

static void lwins_registry_owner_version_upd_entry (struct registry *reg, struct reg_owner_version *ov_entry, int rescan_min, int rescan_max)
{
    struct reg_entry *cur;
    
    if (rescan_min || rescan_max)
    {
        cur = reg->entries;
        if (cur)
        {
            if (rescan_min)
                ov_entry->min_version = cur->rec.version;
            
            if (rescan_max)
                ov_entry->max_version = cur->rec.version;
            
            cur = cur->next;
        }
        
        while (cur)
        {
            if (rescan_min)
            {
                if (lwins_is_version_lower (&cur->rec.version, &ov_entry->min_version))
                    ov_entry->min_version = cur->rec.version;
            }
            
            if (rescan_max)
            {
                if (lwins_is_version_higher (&cur->rec.version, &ov_entry->max_version))
                    ov_entry->max_version = cur->rec.version;
            }
            
            cur = cur->next;
        }
    }
}

static void lwins_registry_owner_version_del_entry (struct registry *reg, struct reg_entry *entry, struct reg_owner_version *ov_entry)
{
    if (--ov_entry->entries_cnt != 0)
    {
        int rescan_max = 0, rescan_min = 0;
        
        if (lwins_is_version_equal (&ov_entry->max_version, &entry->rec.version))
        {
            ov_entry->max_version.high = 0;
            ov_entry->max_version.low = 0;
            
            rescan_max = 1;
        }
        
        if (lwins_is_version_equal (&ov_entry->min_version, &entry->rec.version))
        {
            ov_entry->min_version.high = 0;
            ov_entry->min_version.low = 0;
            
            rescan_min = 1;
        }
        
        lwins_registry_owner_version_upd_entry (reg, ov_entry, rescan_min, rescan_max);
    }
    else
        lwins_registry_del_owner_version (reg, ov_entry);
}

static void lwins_update_registry_entry_version (struct registry *reg, struct reg_entry *entry)
{
    struct reg_owner_version *ov_entry;
    int rescan_min = 0;
    
    ASSERT (entry->owner.s_addr == htonl (INADDR_ANY));
    ov_entry = &reg->owner_version[0];
    ASSERT (ov_entry != NULL);
    
    /* If this was the entry with the lowest version we need to recalculate that value */
    if (lwins_is_version_equal (&entry->rec.version, &ov_entry->min_version))
        rescan_min = 1;
    
    /* Increase the version to a new max version */
    if (++ov_entry->max_version.low == 0)
        ov_entry->max_version.high++;
    
    entry->rec.version = ov_entry->max_version;
    
    lwins_registry_owner_version_upd_entry (reg, ov_entry, rescan_min, 0);
}

static void lwins_update_registry_entry_state (struct registry *reg, struct reg_entry *entry, u8 new_state)
{
    time_t current_time, event_time = 0;
    
    ASSERT (entry->rec.state != new_state);
    
    lwins_update_registry_entry_version (reg, entry);
    
    current_time = reg->server->current_time.tv_sec;
    entry->last_update = current_time;
    
    entry->rec.state = new_state;
    switch (new_state)
    {
        case NREC_STATE_ACTIVE:
            event_time = current_time + reg->renewal_interval;
            break;
        case NREC_STATE_RELEASED:
            event_time = current_time + reg->extinction_interval;
            break;
        case NREC_STATE_TOMBSTONE:
        default:
            event_time = current_time + reg->extinction_timeout;
            break;
    }
    
    lwins_reg_update_event_time (reg, entry, event_time);
}

int lwins_update_registry_entry (struct registry *reg, struct reg_entry *entry, struct replication_name_record *namerec)
{
    struct reg_owner_version *ov_entry;
    
    ASSERT (lwins_is_version_lower_equal (&entry->rec.version, &namerec->version));
    
    entry->last_update = reg->server->current_time.tv_sec;
    
    ov_entry = lwins_registry_find_owner_version (reg, &entry->owner);
    if (ov_entry)
    {
        /* TODO: This is a hack and should be optimized instead of pretending like we remove this
                 entry and add it back to the registry... */
        
        ov_entry->entries_cnt++; /* Temporarily increase numbers of entries to avoid deletion */
        lwins_registry_owner_version_del_entry (reg, entry, ov_entry);
    }
    
    entry->rec.version = namerec->version;
    
    if (ov_entry)
    {
        /* TODO: This is part of the hack above... */
        lwins_registry_owner_version_add_entry (reg, entry, ov_entry);
        ov_entry->entries_cnt--;
    }
    
    /* Reset the delete_tmp flag.  This flag is set when a name record merge is in progress */
    entry->delete_tmp = 0;
    return 1;
}

void lwins_add_registry_entry (struct registry *reg, struct reg_entry *reg_entry)
{
    struct reg_owner_version *ov_entry;
    
    ASSERT (!lwins_find_registry_entry (reg, reg_entry->rec.name));
    
    ov_entry = lwins_registry_find_owner_version (reg, &reg_entry->owner);
    if (!ov_entry)
        ov_entry = lwins_registry_add_owner_version (reg, &reg_entry->owner);
    
    if (ov_entry)
        lwins_registry_owner_version_add_entry (reg, reg_entry, ov_entry);
    
    lwins_reg_link_entry (reg, reg_entry);
}

void lwins_del_registry_entry (struct registry *reg, struct reg_entry *reg_entry)
{
    struct reg_owner_version *ov_entry;
    
    ASSERT (!reg_entry->locked);
    
    lwins_reg_unlink_entry (reg, reg_entry);
    ov_entry = lwins_registry_find_owner_version (reg, &reg_entry->owner);
    if (ov_entry)
        lwins_registry_owner_version_del_entry (reg, reg_entry, ov_entry);
}

static int lwins_registry_parse_record (struct registry *reg, char *line)
{
    struct reg_entry *entry = NULL;
    char *str;
    int i = 0, i2;
    size_t size;
    char owner[16];
    
    (void)reg;
    
    if (line[i++] != '\"')
    {
parse_err:
        LOG (LOG_ERR, "Error parsing database name record \"%s\"\n", line);
err:
        if (entry)
            lwins_free_reg_entry (reg, entry);
        return -1;
    }
    str = line + i;
    for (i2 = i; str[i2] != '\0'; i2++)
    {
        if (str[i2] == '\"')
            break;
    }
    
    if (str[i2] != '\"')
        goto parse_err;
    str[i2++] = '\0';
    
    size = netbt_str_to_name (str, NULL, 0);
    if (!size)
        goto parse_err;
    
    entry = lwins_alloc (sizeof (*entry));
    if (!entry)
        goto err;
    
    entry->rec.name = lwins_alloc (size);
    if (!entry->rec.name)
        goto err;
    
    if (!netbt_str_to_name (str, entry->rec.name, size))
        goto parse_err;
    
    i = sscanf (str + i2, ",%x,%x,%15s,", &entry->rec.version.high, &entry->rec.version.low, owner);
    if (i < 3)
        goto parse_err;
    if (!inet_aton (owner, &entry->owner))
        goto parse_err;
    
    lwins_add_registry_entry (reg, entry);
    return 1;
}

static int lwins_enum_proc_names_secion (char *line, size_t line_size, void *ctx)
{
    struct registry *reg = (struct registry *)ctx;
    
    (void)line_size;
    
    ASSERT (reg != NULL);
    
    return lwins_registry_parse_record (reg, line);
}

int lwins_registry_load (struct registry *reg, int fd)
{
    return lwins_enum_section_lines (fd, "NAMES", 16 * 1024, lwins_enum_proc_names_secion, reg) > 0;
}

int lwins_registry_save (struct registry *reg, int fd)
{
    struct reg_entry *cur;
    char *name, line[1024];
    size_t size;
    
    if (!lwins_write_line (fd, "[NAMES]"))
        return LWINS_ERR;
    
    for (cur = reg->entries; cur != NULL; cur = cur->next)
    {
        size = netbt_name_to_str (cur->rec.name, NULL, 0);
        if (!size)
            return LWINS_ERR;
        name = lwins_alloc (size);
        if (!name)
            return LWINS_ERR;
        size = netbt_name_to_str (cur->rec.name, name, size);
        if (!name)
        {
            lwins_free (name);
            return LWINS_ERR;
        }
        
        sprintf (line, "\"%s\",%x,%x,%s", name, cur->rec.version.high, cur->rec.version.low, inet_ntoa (cur->owner));
        lwins_free (name);
        
        if (!lwins_write_line (fd, line))
            return LWINS_ERR;
    }
    
    return 1;
}

void lwins_registry_scavenge (struct registry *reg, struct reg_entry *event_entry)
{
    struct reg_entry *cur, *next;
    struct in_addr owner;
    time_t current_time;
    
    owner.s_addr = htonl (INADDR_ANY);
    current_time = reg->server->current_time.tv_sec;
    
    if (event_entry)
    {
        /* This path is called when a scavenge event occurs. We only examine owned records
           in this case. */
        cur = event_entry;
        while (cur && cur->event_time <= current_time && cur->owner.s_addr == owner.s_addr)
        {
            next = cur->next_event;
            
            if (cur->rec.state == NREC_STATE_ACTIVE)
                lwins_update_registry_entry_state (reg, cur, NREC_STATE_RELEASED);
            else if (cur->rec.state == NREC_STATE_RELEASED)
                lwins_update_registry_entry_state (reg, cur, NREC_STATE_TOMBSTONE);
            else
                lwins_del_registry_entry (reg, cur);
            
            cur = next;
        }
    }
    else
    {
        /* This path is called during database verification. */
        cur = reg->entries;
        while (cur)
        {
            next = cur->next;
            
            if (cur->owner.s_addr == owner.s_addr)
            {
                /* Verify local entry */
            }
            else
            {
                /* If this is a tombstoned entry that hasn't been updated in a while,
                   get rid of it! */
                if (cur->rec.state == NREC_STATE_TOMBSTONE &&
                    current_time - cur->last_update > reg->extinction_timeout)
                {
                    LOG (LOG_ALL, "Scavenge: delete not owned tombstone\n");
                    lwins_del_registry_entry (reg, cur);
                }
                else
                {
                    /* Verify entry we don't own through a pull from the owner... */
                }
            }
            
            cur = next;
        }
    }
}

void lwins_registry_merge_begin (struct registry *reg, struct replication_owner_request *req)
{
    struct reg_entry *cur;
    
    for (cur = reg->entries; cur != NULL; cur = cur->next)
    {
        ASSERT (!cur->delete_tmp);
        
        if (cur->owner.s_addr == req->owner.s_addr)
        {
            if (lwins_is_version_higher_equal (&cur->rec.version, &req->min_version))
            {
                if (lwins_is_version_lower_equal (&cur->rec.version, &req->max_version))
                {
                    /* This entry is within the version range */
                    lwins_log_regentry (cur, "Mark for merge");
                    cur->delete_tmp = 1;
                }
            }
        }
    }
}

u32 lwins_nrec_get_registry_entries (struct registry *reg, struct replication_owner_record *req, struct replication_name_record **namerecs, u32 namerecs_cnt)
{
    struct reg_entry *cur;
    u32 cnt = 0;
    
    for (cur = reg->entries; cur != NULL; cur = cur->next)
    {
        ASSERT (!cur->delete_tmp);
        
        if (cur->owner.s_addr == req->addr.s_addr)
        {
            if (lwins_is_version_higher_equal (&cur->rec.version, &req->min_version))
            {
                if (lwins_is_version_lower_equal (&cur->rec.version, &req->max_version))
                {
                    /* This entry is within the version range */
                    if (namerecs)
                    {
                        if (cnt < namerecs_cnt)
                            namerecs[cnt] = &cur->rec;
                        else
                            break;
                    }
                    
                    cnt++;
                }
            }
        }
    }
    
    return cnt;
}

unsigned int lwins_registry_merge_end (struct registry *reg)
{
    struct reg_entry *cur, *next;
    unsigned int deleted = 0;
    
    cur = reg->entries;
    while (cur)
    {
        next = cur->next;
        if (cur->delete_tmp)
        {
            lwins_log_regentry (cur, "Delete after merge");
            lwins_del_registry_entry (reg, cur);
            deleted++;
        }
        cur = next;
    }
    
    return deleted;
}

void lwins_registry_merge_skip_entry (struct registry *reg, struct reg_entry *entry)
{
    (void)reg;
    
    ASSERT (entry->delete_tmp);
    entry->delete_tmp = 0;
}

void lwins_log_regentry (struct reg_entry *entry, const char *description)
{
    size_t rec_size;
    char *rec;
    
    rec_size = netbt_name_to_str (entry->rec.name, NULL, 0);
    ASSERT (rec_size > 0);
    rec = lwins_alloc (rec_size);
    rec_size = netbt_name_to_str (entry->rec.name, rec, rec_size);
    ASSERT (rec_size > 0);
    
    LOG (LOG_ALL, "%s \"%s\" Version %x.%x Owner: %s\n", description, 
         rec, entry->rec.version.high, entry->rec.version.low, inet_ntoa (entry->owner));
    lwins_free (rec);
}

