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

#ifndef DBG_MEM_LEAK
static int alloc_cnt = 0;

void *lwins_alloc (size_t size)
{
    void *ptr = malloc (size);
    if (ptr)
    {
        memset (ptr, 0, size);
        alloc_cnt++;
    }
    return ptr;
}

void lwins_free (void *ptr)
{
    ASSERT (ptr);
    free (ptr);
    alloc_cnt--;
}
#endif

static char* lwins_nbns_tran_desc (struct nbns_req *trans)
{
    static char desc[128];
    sprintf (desc, "%x@%s:%u", trans->tran_id & 0xFFFF, inet_ntoa (trans->client.sin_addr), ntohs(trans->client.sin_port) & 0xFFFF);
    return desc;
}

static void lwins_update_current_time (struct netbios_server *server)
{
    if (gettimeofday (&server->current_time, NULL) < 0)
    {
        server->current_time.tv_sec = time (NULL);
        server->current_time.tv_usec = 0;
    }
}

void lwins_calculate_due_time (struct netbios_server *server, struct timeval *due, int seconds)
{
    due->tv_sec = server->current_time.tv_sec + seconds;
    due->tv_usec = server->current_time.tv_usec;
}

static int lwins_get_ip_addresses (struct lwins_config *cfg, const char *option, struct in_addr **paddrs)
{
    struct in_addr addr, *addrs;
    const char *value;
    int i, j, cnt, ncnt = 0;

    cnt = lwins_config_get_option_param_cnt (cfg, option);
    if (cnt > 0)
    {
        if (lwins_config_option_has_param (cfg, option, "all") ||
            lwins_config_option_has_param (cfg, option, "*"))
        {
            cnt = 1;
            addrs = lwins_alloc (sizeof (addrs[0]));
            if (!addrs)
                return LWINS_ERR;

            addrs[0].s_addr = htonl (INADDR_ANY);
            *paddrs = addrs;
            return cnt;
        }

        addrs = lwins_alloc (cnt * sizeof (addrs[0]));
        if (!addrs)
            return LWINS_ERR;
        
        for (i = 0; i < cnt; i++)
        {
            if (!lwins_get_config_param (cfg, option, i, &value))
                continue;
            if (!lwins_convert_to_ip (value, &addr))
                continue;

            for (j = 0; j < ncnt; j++)
            {
                if (addrs[j].s_addr == addr.s_addr)
                    break;
            }

            if (j >= ncnt)
                addrs[ncnt++].s_addr = addr.s_addr;
        }

        if (ncnt == 0)
        {
            lwins_free (addrs);
            return 0;
        }

        cnt = ncnt;
        *paddrs = addrs;
    }

    return cnt;
}

int lwins_make_socket_nonblocking (int sd)
{
    long flags = fcntl (sd, F_GETFL);
    if (fcntl (sd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        LOGSYSERR ("fcntl");
        return 0;
    }

    return 1;
}

int lwins_set_socket_broadcast (int sd, int enable)
{
    int on;
    
    on = enable != 0;
    if (setsockopt (sd, SOL_SOCKET, SO_BROADCAST, &on, sizeof (on)) < 0)
    {
        LOGSYSERR ("setsocketopt");
        return 0;
    }
    
    return 1;
}

static int lwins_set_multicast_if (int sd, struct in_addr *ifc)
{
    struct in_addr ifcaddr = *ifc;
    
    if (setsockopt (sd, IPPROTO_IP, IP_MULTICAST_IF, &ifcaddr, sizeof (ifcaddr)) < 0)
    {
        LOGSYSERR ("setsockopt");
        return LWINS_ERR;
    }
    return 1;
}

static int lwins_multicast_group (int sd, struct in_addr *addr, struct in_addr *ifcs, unsigned int ifcs_cnt, int add)
{
    struct ip_mreq mr;
    unsigned int i, cnt = 0;
    
    if (ifcs_cnt == 0 || ifcs_cnt > IP_MAX_MEMBERSHIPS)
        return LWINS_ERR;
    
    for (i = 0; i < ifcs_cnt; i++)
    {
        mr.imr_multiaddr = *addr;
        mr.imr_interface = ifcs[i];
        
        if (setsockopt (sd, IPPROTO_IP, add ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, &mr, sizeof (mr)) == 0)
            cnt++;
        else
            LOGSYSERR ("setsockopt");
    }
    
    return cnt;
}

static int lwins_get_interface_addresses (int sd, struct in_addr **paddrs)
{
    struct in_addr *addrs;
    struct ifconf ifc;
    struct ifreq *buf = NULL;
    struct ifreq *pifc;
    int i, j, cnt, addr_cnt;
    size_t nbuf = 1;

    for (;;)
    {
        if (buf)
            lwins_free (buf);
        buf = lwins_alloc (nbuf * sizeof (*buf));
        if (!buf)
            return LWINS_ERR;
        
        ifc.ifc_len = nbuf * sizeof (*buf);
        ifc.ifc_buf = (char *)buf;
        
        if (ioctl (sd, SIOCGIFCONF, &ifc) < 0)
        {
            lwins_free (buf);
            LOGSYSERR ("ioctl");
            return LWINS_ERR;
        }
        
        if (ifc.ifc_len == (int)(nbuf * sizeof (*buf)))
            nbuf += 1;
        else
            break;
    }
    
    pifc = ifc.ifc_req;
    cnt = ifc.ifc_len / sizeof (struct ifreq);
    j = addr_cnt = 0;
    
    for (i = 0; i < cnt; i++)
    {
        if (ioctl (sd, SIOCGIFFLAGS, &pifc[i]) < 0)
        {
            if (buf)
                lwins_free (buf);
            
            LOGSYSERR ("ioctl");
            return LWINS_ERR;
        }
        if (!(pifc[i].ifr_flags & IFF_UP))
            continue;
        
        if (!(pifc[i].ifr_flags & IFF_LOOPBACK))
            addr_cnt++;
    }
    
    addrs = lwins_alloc (addr_cnt * sizeof (*addrs));
    if (!addrs)
    {
        if (buf)
            lwins_free (buf);
        return LWINS_ERR;
    }
    
    for (i = 0; i < cnt; i++)
    {
        if (!(pifc[i].ifr_flags & IFF_UP))
            continue;
        
        if (!(pifc[i].ifr_flags & IFF_LOOPBACK))
            addrs[j++].s_addr = ((struct sockaddr_in *)&pifc[i].ifr_addr)->sin_addr.s_addr;
    }
    
    if (buf)
        lwins_free (buf);
    
    *paddrs = addrs;
    return addr_cnt;
}

int lwins_broadcast_discover_msg (struct netbios_server *server, u32 op_code)
{
    struct nbns_discover_packet packet;
    unsigned char *raw_packet;
    size_t raw_packet_size;
    ssize_t s;
    struct sockaddr_in addr_multicast;
    int i, addr_cnt, cnt = 0;
    
    ASSERT (op_code == DISCOVER_OP_UP || op_code == DISCOVER_OP_DOWN);
    
    addr_multicast.sin_family = AF_INET;
    addr_multicast.sin_port = htons (42);
    if (!inet_aton ("224.0.1.24", &addr_multicast.sin_addr))
        return LWINS_ERR;
    
    packet.addresses = NULL;
    addr_cnt = server->replication_cnt;
    if (addr_cnt >= 0xFFFF)
        return LWINS_ERR;
    else if (addr_cnt == 0)
        return 0;
    else if (addr_cnt == 1 && server->replication_svc[0].addr.s_addr == htonl (INADDR_ANY))
    {
        addr_cnt = lwins_get_interface_addresses (server->discovery_sd, &packet.addresses);
        if (addr_cnt >= 0xFFFF)
        {
            lwins_free (packet.addresses);
            return LWINS_ERR;
        }
        else if (addr_cnt == 0)
            return 0;
    }
    else
    {
        packet.addresses = lwins_alloc (addr_cnt * sizeof (packet.addresses[0]));
        if (!packet.addresses)
            return LWINS_ERR;

        for (i = 0; i < addr_cnt; i++)
            packet.addresses[i].s_addr = server->replication_svc[i].addr.s_addr;
    }
    
    packet.op_code = op_code;
    packet.addresses_cnt = addr_cnt & 0xFFFF;
    
    raw_packet_size = calculate_nbns_discover_packet_size (&packet);
    raw_packet = lwins_alloc (raw_packet_size);
    if (!raw_packet)
    {
        lwins_free (packet.addresses);
        return LWINS_ERR;
    }
    
    if (!build_raw_nbns_discover_packet (raw_packet, raw_packet_size, &packet))
    {
        lwins_free (packet.addresses);
        lwins_free (raw_packet);
        return LWINS_ERR;
    }
    
    for (i = 0; i < addr_cnt; i++)
    {
        if (!lwins_set_multicast_if (server->discovery_sd, &packet.addresses[i]))
        {
            LOG (LOG_ERR, "Could not broadcast discovery packet\n");
            continue;
        }
        
        s = sendto (server->discovery_sd, raw_packet, (size_t)raw_packet_size, 0,
            (const struct sockaddr *)&addr_multicast, sizeof (struct sockaddr));
        if ((size_t)s == raw_packet_size)
            cnt++;
        else if (s < 0)
            LOGSYSERR ("sendto");
    }
    
    lwins_free (packet.addresses);
    lwins_free (raw_packet);
    return cnt;
}

static int lwins_setup_nbns_listener (struct netbios_server *server)
{
    struct sockaddr_in srv;
    struct in_addr *nbns_addrs;
    int i, addr_cnt;
    
    addr_cnt = lwins_get_ip_addresses (server->config, "nbns-bind", &nbns_addrs);
    if (addr_cnt > 0)
    {
        server->nbns_cnt = addr_cnt;

        server->nbns_svc = lwins_alloc (addr_cnt * sizeof (server->nbns_svc[0]));
        if (!server->nbns_svc)
        {
            lwins_free (nbns_addrs);
            return LWINS_ERR;
        }

        for (i = 0; i < addr_cnt; i++)
        {
            server->nbns_svc[i].sd = -1;
            server->nbns_svc[i].addr.s_addr = nbns_addrs[i].s_addr;
        }

        for (i = 0; i < addr_cnt; i++)
        {
            server->nbns_svc[i].sd = socket (AF_INET, SOCK_DGRAM, 0);
            if (server->nbns_svc[i].sd < 0)
            {
                lwins_free (nbns_addrs);
                return LWINS_ERR;
            }

            if (!lwins_make_socket_nonblocking (server->nbns_svc[i].sd))
            {
                lwins_free (nbns_addrs);
                return LWINS_ERR;
            }
            
            srv.sin_family = AF_INET;
            srv.sin_port = htons (137);
            srv.sin_addr.s_addr = server->nbns_svc[i].addr.s_addr;
            if (bind (server->nbns_svc[i].sd, (struct sockaddr*)&srv, sizeof (srv)) < 0)
            {
                LOGSYSERR ("bind");
                lwins_free (nbns_addrs);
                return LWINS_ERR;
            }

            LOG (LOG_ALL, "NBNS service listening on %s\n", inet_ntoa (server->nbns_svc[i].addr));
        }

        lwins_free (nbns_addrs);
        return 1;
    }

    return LWINS_ERR;
}

static int lwins_setup_discovery_listener (struct netbios_server *server)
{
    struct sockaddr_in srv;
    struct in_addr *addrs;
    int addrs_cnt;
    
    srv.sin_family = AF_INET;
    srv.sin_port = htons (42);
    if (!inet_aton ("224.0.1.24", &srv.sin_addr))
        return LWINS_ERR;
    
    server->discovery_sd = socket (AF_INET, SOCK_DGRAM, 0);
    if (server->discovery_sd < 0)
    {
        LOGSYSERR ("socket");
        return LWINS_ERR;
    }
    
    if (!lwins_make_socket_nonblocking (server->discovery_sd))
        return LWINS_ERR;
    if (!lwins_set_socket_broadcast (server->discovery_sd, 1))
        return LWINS_ERR;
    
    if (bind (server->discovery_sd, (struct sockaddr*)&srv, sizeof (srv)) < 0)
    {
    
        LOGSYSERR ("bind");
        return LWINS_ERR;
    }
    
    addrs_cnt = lwins_get_ip_addresses (server->config, "replication-bind", &addrs);
    if (addrs_cnt > 0)
    {
        /* Join the multicast group */
        if (!lwins_multicast_group (server->discovery_sd, &srv.sin_addr, addrs, addrs_cnt, 1))
            return LWINS_ERR;
        
        if (addrs)
            lwins_free (addrs);
    }
    
    return 1;
}

static int lwins_setup_replication_listener (struct netbios_server *server)
{
    struct sockaddr_in srv;
    struct in_addr *replication_addrs;
    int i;
    unsigned long val;
    
    if (lwins_get_config_param_long (server->config, "replication-port", 0, &val))
    {
        if (val > 0xFFFF)
        {
            LOG (LOG_ERR, "Invalid replication-port %lu, using default\n", val);
            srv.sin_port = htons (42);
        }
        else
            srv.sin_port = htons (val & 0xFFFF);
    }
    else
        srv.sin_port = htons (42);
    
    server->replication_cnt = lwins_get_ip_addresses (server->config, "replication-bind", &replication_addrs);
    if (server->replication_cnt > 0)
    {
        server->replication_svc = lwins_alloc (server->replication_cnt * sizeof (server->replication_svc[0]));
        if (!server->replication_svc)
        {
            lwins_free (replication_addrs);
            return LWINS_ERR;
        }

        for (i = 0; i < server->replication_cnt; i++)
        {
            server->replication_svc[i].sd = -1;
            server->replication_svc[i].addr.s_addr = replication_addrs[i].s_addr;
        }

        for (i = 0; i < server->replication_cnt; i++)
        {
            server->replication_svc[i].sd = socket (AF_INET, SOCK_STREAM, 0);
            if (server->replication_svc[i].sd < 0)
            {
                LOGSYSERR ("socket");
                lwins_free (replication_addrs);
                return LWINS_ERR;
            }

            srv.sin_family = AF_INET;
            srv.sin_addr = server->replication_svc[i].addr;
            if (bind (server->replication_svc[i].sd, (struct sockaddr*)&srv, sizeof (srv)) < 0)
            {
                LOGSYSERR ("bind");
                lwins_free (replication_addrs);
                return LWINS_ERR;
            }

            if (listen (server->replication_svc[i].sd, 32) < 0)
            {
                LOGSYSERR ("listen");
                lwins_free (replication_addrs);
                return LWINS_ERR;
            }

            LOG (LOG_ALL, "Replication service listening on %s\n", inet_ntoa (server->replication_svc[i].addr));
        }

        lwins_free (replication_addrs);
    }
    
    return 1;
}

int lwins_write_line (int fd, const char *line)
{
    ssize_t bytes_written;
    size_t len;
    
    len = strlen (line);
    bytes_written = write (fd, line, len);
    if (bytes_written < 0)
    {
        LOGSYSERR ("write");
        return LWINS_ERR;
    }
    else if ((size_t)bytes_written != len)
        return LWINS_ERR;
    bytes_written = write (fd, "\n", 1);
    if (bytes_written < 0)
    {
        LOGSYSERR ("write");
        return LWINS_ERR;
    }
    else if (bytes_written != 1)
        return LWINS_ERR;
    
    return 1;
}

static int lwins_save_database (struct netbios_server *server)
{
    int fd;
    
    fd = open (server->database_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        LOGSYSERR ("open");
        return LWINS_ERR;
    }
    
    lwins_write_line (fd, "# This file is generated by LWINS.");
    lwins_write_line (fd, "# Do NOT edit this file!");
        
    if (server->registry)
    {
        if (!lwins_registry_save (server->registry, fd))
            LOG (LOG_ERR, "Error saving name records to database\n");
    }
    
    close (fd);

    (void)server;
    return 1;
}

static ssize_t lwins_read_line (int fd, char *buffer, size_t buffer_size)
{
    char buf[128];
    ssize_t bytes_read;
    size_t i, dest = 0;
    int eol = 0, stop = 0;
    
    do
    {
        bytes_read = read (fd, buf, sizeof (buf));
        if (bytes_read < 0)
        {
            LOGSYSERR ("read");
            return -1;
        }
        
        if (bytes_read == 0)
            break;
        
        for (i = 0; i < (size_t)bytes_read; i++)
        {
            if (buf[i] == '\0' || buf[i] == '\n')
            {
                if ((ssize_t)i < bytes_read - 1 &&
                    lseek (fd, (off_t)i - (off_t)bytes_read + 1, SEEK_CUR) < 0)
                {
                    LOGSYSERR ("lseek");
                    return -1;
                }
                eol = 1;
                stop = 1;
                break;
            }
            
            if (dest < buffer_size - 1)
                buffer[dest++] = buf[i];
            else
                eol = 1;
        }
        
        if ((size_t)bytes_read < sizeof (buf))
            eol = stop = 1;
        
    } while (!stop);
    
    if (eol)
    {
        buffer[dest++] = '\0';
        return (ssize_t)dest;
    }
    return 0;
}

static int lwins_skip_whitespace (const char *str)
{
    int i = 0;
    while (str[i] != '\0' && isspace (str[i]))
        i++;
    return i;
}

static int lwins_count_alpha (const char *str)
{
    int i = 0;
    while (str[i] != '\0' && isalpha (str[i]))
        i++;
    return i;
}

int lwins_enum_section_lines (int fd, const char *section, size_t max_line_size, plwins_enum_section_line enum_proc, void *ctx)
{
    char *sec, *line;
    ssize_t len;
    int i, i2, found = 0;
    
    line = lwins_alloc (max_line_size);
    if (!line)
        return LWINS_ERR;
    
    if (lseek (fd, 0, SEEK_SET) < 0)
    {
        lwins_free (line);
        LOGSYSERR ("lseek");
        return LWINS_ERR;
    }
    
    do
    {
        len = lwins_read_line (fd, line, max_line_size);
        if (len < 0)
        {
            lwins_free (line);
            return LWINS_ERR;
        }
        else if (len == 0)
            break;
        
        /* Skip whitespace */
        i = lwins_skip_whitespace (line);
        
        if (line[i] == '#')
            continue; /* Skip comments */
        
        if (line[i] == '[')
        {
            if (found)
                break;
            
            i++;
            i += lwins_skip_whitespace (line + i);
            sec = line + i;
            i2 = lwins_count_alpha (sec);
            if (i2 == 0)
                goto parse_err;
            i += i2;
            i += lwins_skip_whitespace (line + i);
            if (line[i++] != ']')
                goto parse_err;
            
            i += lwins_skip_whitespace (line + i);
            if (line[i] != '\0' && line[i] != '#')
            {
parse_err:
                LOG (LOG_ERR, "Error parsing database\n");
                lwins_free (line);
                return LWINS_ERR;
            }
            
            if (strlen (section) == (size_t)i2 && !strncmp (section, sec, i2))
                found = 1;
        }
        else if (found && line[i] != '\0')
        {
            i2 = enum_proc (line + i, max_line_size - (size_t)i, ctx);
            if (i2 < 0)
            {
                lwins_free (line);
                return LWINS_ERR;
            }
            else if (i2 == 0)
                break;
        }

    } while (len > 0);
    
    lwins_free (line);
    return found;
}

static int lwins_load_database (struct netbios_server *server)
{
    int fd;
    
    (void)server;
    
    fd = open (server->database_file, O_RDONLY, 0);
    if (fd < 0)
    {
        if (errno == ENOENT)
        {
            LOG (LOG_ERR, "Database does not exist\n");
            return 1;
        }
        
        LOGSYSERR ("open");
        return LWINS_ERR;
    }
    
    if (server->registry)
    {
        if (!lwins_registry_load (server->registry, fd))
            LOG (LOG_ERR, "Error loading name records\n");
    }
    
    close (fd);
    
    return 1;
}

static void discovery_timer_handler (struct netbios_server *server, struct lwins_event *event)
{
    struct timeval due;
    
    if (server->discovery_interval > 0)
    {
        if (!lwins_broadcast_discover_msg (server, DISCOVER_OP_UP))
            LOG (LOG_ERR, "Error broadcasting discovery (up) message\n");
        
        /* Update due date of timer */
        lwins_calculate_due_time (server, &due, server->discovery_interval);
        lwins_set_event_due (server, event, &due);
    }
}

static void database_save_timer_handler (struct netbios_server *server, struct lwins_event *event)
{
    struct timeval due;
    
    if (server->database_save_interval > 0)
    {
        if (!lwins_save_database (server))
            LOG (LOG_ALL, "Error saving database to %s\n", server->database_file);
        
        /* Update due date of timer */
        lwins_calculate_due_time (server, &due, server->database_save_interval);
        lwins_set_event_due (server, event, &due);
    }
}

static int lwins_alloc_fd_set (struct lwins_fd_set *fds, int max_fd)
{
    lwins_fd_bits *fd;
    int cur_size, max_size;
    
    if (max_fd > fds->cnt)
    {
        cur_size = LWINS_FD_ROUND_SIZE(fds->cnt);
        max_size = LWINS_FD_ROUND_SIZE(max_fd);
        
        if (max_size > cur_size)
        {
            /* Add a little more space */
            max_size += 2 * sizeof (lwins_fd_bits);
            if (max_size < cur_size)
                return 0;
            
            fd = lwins_alloc (max_size);
            if (!fd)
                return 0;
            
            if (fds->fd_set)
            {
                memcpy (fd, fds->fd_set, cur_size);
                lwins_free (fds->fd_set);
            }
            
            fds->fd_set = fd;
            fds->cnt = max_size * 8;
        }
    }
    
    return 1;
}

static void lwins_init_fd_set (struct lwins_fd_set *fds, int max_fd)
{
    fds->cnt = 0;
    fds->max_fd = -1;
    fds->fd_set = NULL;
    if (max_fd <= 0)
        max_fd = FD_SETSIZE - 1;
    lwins_alloc_fd_set (fds, max_fd);
}

static void lwins_free_fd_set (struct lwins_fd_set *fds)
{
    if (fds->fd_set)
        lwins_free (fds->fd_set);
    fds->cnt = 0;
    fds->max_fd = -1;
    fds->fd_set = NULL;
}

static __inline int lwins_clone_fd_set (struct lwins_fd_set *fds_dest, struct lwins_fd_set *fds_src)
{
    if (fds_src->cnt > fds_dest->cnt)
    {
        if (!lwins_alloc_fd_set (fds_dest, fds_src->cnt))
            return 0;
    }
    /* TODO: Zero memory if source is smaller than dest */
    
    memcpy (fds_dest->fd_set, fds_src->fd_set, fds_src->cnt / 8);
    fds_dest->max_fd = fds_src->max_fd;
    return 1;
}

static __inline int lwins_set_fd (struct lwins_fd_set *fds, int fd)
{
    if (fd > fds->cnt && !lwins_alloc_fd_set (fds, fd))
        return 0;
    
    fds->fd_set[LWINS_FD_INDEX(fd)] |= LWINS_FD_MASK(fd);
    if (fd > fds->max_fd)
        fds->max_fd = fd;
    return 1;
}

static __inline int lwins_clear_fd (struct lwins_fd_set *fds, int fd)
{
    if (fd > fds->cnt && !lwins_alloc_fd_set (fds, fd))
        return 0;
    
    fds->fd_set[LWINS_FD_INDEX(fd)] &= ~LWINS_FD_MASK(fd);
    
    if (fd == fds->max_fd)
    {
        while (fds->max_fd > 0 && (fds->fd_set[LWINS_FD_INDEX(fd)] & LWINS_FD_MASK(fd)) != 0)
            fds->max_fd--;
    }
    return 1;
}

static __inline int lwins_isset_fd (struct lwins_fd_set *fds, int fd)
{
    if (fd > fds->cnt && !lwins_alloc_fd_set (fds, fd))
        return 0;
    
    return (fds->fd_set[LWINS_FD_INDEX(fd)] & LWINS_FD_MASK(fd)) != 0;
}

struct netbios_server* lwins_setup_server (struct lwins_config *cfg, volatile unsigned int *terminate)
{
    struct netbios_server *server;
    struct timeval due;
    const char *value;
    uid_t uid = 0;
    gid_t gid = 0;
    int found_usr = 0;
    int found_grp = 0;
    int discover = 0;
    
    server = lwins_alloc (sizeof (*server));
    if (!server)
        return NULL;
    
    server->status = SERVER_INITIALIZING;

    server->registry = lwins_create_registry (server);
    if (!server->registry)
    {
        lwins_free (server);
        return NULL;
    }
    
    lwins_init_fd_set(&server->master_fds, 0);
    lwins_init_fd_set(&server->sending_fds, 0);
    
    lwins_update_current_time (server);
    
    server->terminate = terminate;
    server->config = cfg;
    
    server->discovery_sd = -1;
    
    server->replication = NULL;
    
    if (!lwins_setup_nbns_listener (server))
    {
        lwins_free_server (server);
        return NULL;
    }
    
    if (lwins_config_get_option_param_cnt (cfg, "replication-bind") > 0)
    {
        server->replication = init_replication_service (server->config);
        if (!server->replication ||
            !lwins_setup_replication_listener (server))
        {
            lwins_free_server (server);
            return NULL;
        }

        server->replication->server = server;
        
        if (lwins_get_config_param (server->config, "replication-auto-discovery", 0, &value) &&
            lwins_convert_to_bool (value, &discover) && discover &&
            !lwins_setup_discovery_listener (server))
        {
            lwins_free_server (server);
            return NULL;
        }

        if (discover && lwins_get_config_param_long (server->config, "replication-auto-discovery-interval", 0, &server->discovery_interval) &&
            server->discovery_interval * 60 > server->discovery_interval)
        {
            server->discovery_interval *= 60;
            lwins_calculate_due_time (server, &due, server->discovery_interval);
            lwins_add_event (server, discovery_timer_handler, NULL, NULL, &due);
        }
    }
    
    if (lwins_get_config_param (server->config, "user", 0, &value))
    {
        struct passwd *pwd;
        
        if (!lwins_convert_to_integer (value, &uid))
        {
            pwd = getpwnam (value);
            if (!pwd)
            {
                LOG (LOG_ERR, "User %s could not be found\n", value);
                lwins_free_server (server);
                return NULL;
            }
            
            uid = pwd->pw_uid;
            gid = pwd->pw_gid;
            found_grp = 1;
        }
        found_usr = 1;
    }
    
    if (lwins_get_config_param (server->config, "group", 0, &value))
    {
        struct group *grp;
        
        if (!lwins_convert_to_integer (value, &gid))
        {
            grp = getgrnam (value);
            if (!grp)
            {
                LOG (LOG_ERR, "Group %s could not be found\n", value);
                lwins_free_server (server);
                return NULL;
            }
            
            gid = grp->gr_gid;
        }
        found_grp = 1;
    }
    
    if (found_grp && setgid (gid) != 0)
    {
        LOGSYSERR ("setgid");
        LOG (LOG_ERR, "Could not set the process group identity\n");
        lwins_free_server (server);
        return NULL;
    }
    
    if (found_usr && setuid (uid) != 0)
    {
        LOGSYSERR ("setuid");
        LOG (LOG_ALL, "Could not set the process user identity\n");
        lwins_free_server (server);
        return NULL;
    }
    
    if (!lwins_get_config_param (server->config, "nbns-database-save-interval", 0, &value) ||
        !lwins_convert_to_integer (value, &server->database_save_interval))
    {
        server->database_save_interval = 0;
    }
    
    if (lwins_get_config_param (server->config, "nbns-database-file", 0, &value) && value[0] != '\0')
    {
        server->database_file = value;
        
        if (server->database_save_interval > 0)
        {
            lwins_calculate_due_time (server, &due, server->database_save_interval);
            lwins_add_event (server, database_save_timer_handler, NULL, NULL, &due);
        }
        
        if (!lwins_load_database (server))
            LOG (LOG_ERR, "Error loading database from %s\n", server->database_file);
    }
    else
    {
        server->database_file = NULL;
        server->database_save_interval = 0;
    }
    
    return server;
}

static void lwins_delete_nbns_requests (struct netbios_server *server)
{
    while (server->nbns_req)
        lwins_delete_event (server, server->nbns_req->event);
}

static void lwins_delete_nbns_req (struct netbios_server *server, struct nbns_req *trans)
{
    struct nbns_req *current, **prev;
    
    /* Remove the transaction from the list */
    prev = &server->nbns_req;
    current = server->nbns_req;
    while (current != trans)
    {
        ASSERT (current);
        
        prev = &current->next;
        current = current->next;
    }
    
    ASSERT (current == trans);
    *prev = current->next;
    
    server->nbns_tran_cnt--;
    
    if (trans->reply_packet)
        netbt_free_packet (trans->reply_packet);

    lwins_free (trans);
}

static struct send_buffer* lwins_send_create_buffer (int sd, unsigned char *buffer, size_t len, struct send_buffer *other_buf)
{
    struct send_buffer *buf;
    
    buf = lwins_alloc (sizeof (*buf));
    if (!buf)
        return NULL;
    
    buf->next = NULL;
    buf->sd = sd;
    buf->buffer = buffer;
    buf->sent = 0;
    buf->size = len;
    if (other_buf)
    {
        buf->flushed = other_buf->flushed;
        buf->ctx = other_buf->ctx;
    }
    else
    {
        buf->flushed = NULL;
        buf->ctx = NULL;
    }
    return buf;
}

static void lwins_free_socket_queued (struct netbios_server *server, int sd)
{
    struct send_buffer *buf, *next, **prev;
    
    buf = server->send;
    prev = &server->send;
    while (buf)
    {
        next = buf->next;
        if (buf->sd == sd)
        {
            lwins_free (buf->buffer);
            lwins_free (buf);
            
            *prev = next;
            
            lwins_clear_fd (&server->sending_fds, sd);
        }
        else
            prev = &buf->next;
        
        buf = next;
    }
}

static int lwins_send_socket_queued (struct netbios_server *server, int sd)
{
    struct send_buffer *buf, *next, **prev;
    send_buffer_flushed flushed = NULL;
    void *ctx = NULL;
    ssize_t cnt;
    int ret = 0;
    
    buf = server->send;
    prev = &server->send;
    while (buf)
    {
        next = buf->next;
        
        if (buf->sd == sd)
        {
            ASSERT (buf->sent < buf->size);
            
            cnt = send (sd, buf->buffer + buf->sent, buf->size - buf->sent, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (cnt < 0)
            {
                if (errno == ECONNRESET || errno == ECONNABORTED)
                {
                    lwins_free_socket_queued (server, sd);
                    return 0;
                }
                else if (errno != EAGAIN)
                {
                    LOGSYSERR ("send");
                    return LWINS_ERR;
                }
                
                return 0;
            }
            
            if (cnt < (ssize_t)(buf->size - buf->sent))
            {
                ASSERT (cnt >= 0);
                
                buf->sent += (size_t)cnt;
                ret = 0;
                break;
            }
            else
            {
                flushed = buf->flushed;
                ctx = buf->ctx;
                
                lwins_free (buf->buffer);
                lwins_free (buf);
                
                *prev = next;
                
                lwins_clear_fd (&server->sending_fds, sd);
                
                ret = 1;
            }
        }
        else
            prev = &buf->next;
        
        buf = next;
    }
    
    if (ret && flushed)
        flushed (server, ctx);
    
    return ret;
}

int lwins_send_socket (struct netbios_server *server, int sd, unsigned char *buffer, size_t len)
{
    struct send_buffer *buf, **prev;
    ssize_t cnt;
    
    /* Check if there is any pending data, queue it if there is */
    buf = server->send;
    while (buf)
    {
        if (buf->sd == sd)
        {
            do
            {
                prev = &buf->next;
                buf = buf->next;
            } while (buf);
            
            buf = lwins_send_create_buffer (sd, buffer, len, buf);
            if (!buf)
            {
                lwins_free (buffer);
                return LWINS_ERR;
            }
            
            *prev = buf;
            return 1;
        }
        
        buf = buf->next;
    }
    
    /* No pending data for this socket, try to send it */
    cnt = send (sd, buffer, len, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (cnt < 0)
    {
        if (errno == ECONNRESET || errno == ECONNABORTED)
        {
            lwins_free_socket_queued (server, sd);
            lwins_free (buffer);
            return 0;
        }
        else if (errno != EAGAIN)
        {
            LOGSYSERR ("send");
            lwins_free (buffer);
            return LWINS_ERR;
        }
    }
    
    if (cnt < (ssize_t)len)
    {
        if (cnt < 0)
            ASSERT (errno == EAGAIN);
        
        buf = server->send;
        prev = &server->send;
        while (buf)
        {
            prev = &buf->next;
            buf = buf->next;
        }
        
        buf = lwins_send_create_buffer (sd, buffer, len, NULL);
        if (!buf)
        {
            lwins_free (buffer);
            return LWINS_ERR;
        }
        
        if (cnt >= 0)
            buf->sent = (size_t)cnt;
        
        *prev = buf;
        
        lwins_set_fd (&server->sending_fds, sd);
    }
    else
        lwins_free (buffer);
    
    return 1;
}

int lwins_register_socket_flushed (struct netbios_server *server, int sd, send_buffer_flushed flushed, void *ctx)
{
    struct send_buffer *buf;
    int ret = 0;
    
    for (buf = server->send; buf != NULL; buf = buf->next)
    {
        if (buf->sd == sd)
        {
            buf->flushed = flushed;
            buf->ctx = ctx;
        }
    }
    
    return ret;
}

int lwins_is_socket_sending (struct netbios_server *server, int sd)
{
    struct send_buffer *buf;
    
    for (buf = server->send; buf != NULL; buf = buf->next)
    {
        if (buf->sd == sd)
            return 1;
    }
    
    return 0;
}

static void lwins_free_send_buffers (struct send_buffer **send_buffers)
{
    struct send_buffer *next;
    
    while (*send_buffers)
    {
        next = (*send_buffers)->next;
        lwins_free ((*send_buffers)->buffer);
        *send_buffers = next;
    }
}

void lwins_free_server (struct netbios_server *server)
{
    int i;
    
    lwins_dbg_start ();
    
    ASSERT (server->status == SERVER_INITIALIZING || server->status == SERVER_STOPPED);
    
    if (server->discovery_sd >= 0)
        close (server->discovery_sd);
    
    if (server->replication)
    {
        free_replication_service (server->replication);
        lwins_dbg_start ();
    }
    
    if (server->replication_svc)
    {
        for (i = 0; i < server->replication_cnt; i++)
        {
            if (server->replication_svc[i].sd >= 0)
                close (server->replication_svc[i].sd);
        }

        lwins_free (server->replication_svc);
    }

    if (server->nbns_svc)
    {
        for (i = 0; i < server->nbns_cnt; i++)
        {
            if (server->nbns_svc[i].sd >= 0)
                close (server->nbns_svc[i].sd);
        }

        lwins_free (server->nbns_svc);
    }

    lwins_dbg_start ();
    while (server->events)
    {
        lwins_delete_event (server, server->events);
        lwins_dbg_start ();
    }
    
    if (server->registry)
        lwins_destroy_registry (server->registry);
    
    lwins_free_fd_set (&server->master_fds);
    lwins_free_fd_set (&server->sending_fds);
    
    lwins_free_send_buffers (&server->send);
    
    lwins_free (server);
}

static int lwins_name_query (struct netbios_server *server, struct netbt_packet *packet)
{
    (void)server;
    
    if (!packet->header.recursion_desired)
        return 0;
    LOG (LOG_ALL, "Process name question: %s\n", netbt_packet_question (packet, 0));
    return 0;
}

static __inline int lwins_is_time_greater (const struct timeval *tme, const struct timeval *cmp)
{
    if (tme->tv_sec > cmp->tv_sec ||
        (tme->tv_sec == cmp->tv_sec && tme->tv_usec > cmp->tv_usec))
        return 1;
    return 0;
}

static __inline int lwins_is_time_greater_equal (const struct timeval *tme, const struct timeval *cmp)
{
    if (tme->tv_sec > cmp->tv_sec ||
        (tme->tv_sec == cmp->tv_sec && tme->tv_usec >= cmp->tv_usec))
        return 1;
    return 0;
}

static __inline int lwins_is_time_lower (const struct timeval *tme, const struct timeval *cmp)
{
    if (tme->tv_sec < cmp->tv_sec ||
        (tme->tv_sec == cmp->tv_sec && tme->tv_usec < cmp->tv_usec))
        return 1;
    return 0;
}

static __inline int lwins_is_time_lower_equal (const struct timeval *tme, const struct timeval *cmp)
{
    if (tme->tv_sec < cmp->tv_sec ||
        (tme->tv_sec == cmp->tv_sec && tme->tv_usec <= cmp->tv_usec))
        return 1;
    return 0;
}

static void lwins_timeout_events (struct netbios_server *server)
{
    struct lwins_event *event;
    
    event = server->events;
    while (event && lwins_is_time_greater_equal (&server->current_time, &event->due))
    {
        server->events = event->next;
        
        ASSERT (event->flags & LWINS_EVENT_INSERTED);
        ASSERT (!(event->flags & LWINS_EVENT_DELETING));
        event->flags &= ~LWINS_EVENT_INSERTED;
        event->flags |= LWINS_EVENT_TIMEDOUT;
        
        event->handler (server, event);
        
        if (!(event->flags & LWINS_EVENT_INSERTED))
        {
            if (!(event->flags & LWINS_EVENT_DELETING))
            {
                event->flags |= LWINS_EVENT_DELETING;
                
                if (event->deletion_handler)
                    event->deletion_handler (server, event);

                ASSERT (!(event->flags & LWINS_EVENT_INSERTED));
                ASSERT (event->flags & LWINS_EVENT_DELETING);
                
                lwins_free (event);
            }
        }
        
        event = server->events;
    }
}

void lwins_set_event_due (struct netbios_server *server, struct lwins_event *event, const struct timeval *new_due)
{
    struct lwins_event *current, **prev;
    
    ASSERT (!(event->flags & LWINS_EVENT_DELETING));
    
    if (event->due.tv_sec != new_due->tv_sec || event->due.tv_usec != new_due->tv_usec)
    {
        event->due = *new_due;
        
        event->flags &= ~LWINS_EVENT_TIMEDOUT;
        if (event->flags & LWINS_EVENT_INSERTED)
        {
            /* Remove it from the sorted list */
            prev = &server->events;
            current = server->events;
            while (current != event)
            {
                ASSERT (current);
                prev = &current->next;
                current = current->next;
            }
            
            ASSERT (current == event);
            *prev = current->next;
            current = current->next;
            
            /* Insert it again */
            if (!current || lwins_is_time_lower (&current->due, new_due))
            {
                prev = &server->events;
                current = server->events;
            }
        }
        else
        {
            prev = &server->events;
            current = server->events;
        }
        
        while (current && lwins_is_time_lower (&current->due, new_due))
        {
            ASSERT (current != event);
            prev = &current->next;
            current = current->next;
        }
        
        event->next = current;
        *prev = event;
        
        event->flags |= LWINS_EVENT_INSERTED;
    }
}

struct lwins_event* lwins_add_event (struct netbios_server *server, lwins_event_handler handler, lwins_event_handler deletion_handler, void *context, const struct timeval *due)
{
    struct lwins_event *event, *current, **prev;
    
    event = lwins_alloc (sizeof (*event));
    if (!event)
        return NULL;
    
    event->due = *due;
    event->context = context;
    event->handler = handler;
    event->deletion_handler = deletion_handler;
    
    /* Insert it */
    prev = &server->events;
    current = server->events;
    while (current && lwins_is_time_lower_equal (&current->due, due))
    {
        ASSERT (current != event);
        prev = &current->next;
        current = current->next;
    }
    
    event->flags = LWINS_EVENT_INSERTED;
    
    event->next = current;
    *prev = event;
    
    return event;
}

void lwins_delete_event (struct netbios_server *server, struct lwins_event *event)
{
    struct lwins_event *current, **prev;
    
    ASSERT (!(event->flags & LWINS_EVENT_DELETING));
    
    if (event->flags & LWINS_EVENT_INSERTED)
    {
        prev = &server->events;
        current = server->events;
        while (current != event)
        {
            ASSERT (current);
            prev = &current->next;
            current = current->next;
        }
        
        ASSERT (current == event);
        *prev = current->next;
        
        event->flags &= ~LWINS_EVENT_INSERTED;
    }

    event->flags |= LWINS_EVENT_DELETING;
    
    if (event->deletion_handler)
        event->deletion_handler (server, event);
    
    ASSERT (!(event->flags & LWINS_EVENT_INSERTED));
    lwins_free (event);
}

int lwins_delete_event_by_context (struct netbios_server *server, void *context)
{
    struct lwins_event *current, **prev;
    int cnt = 0;
    
    prev = &server->events;
    current = server->events;
    while (current)
    {
        if (current->context == context)
        {
            ASSERT (current->flags & LWINS_EVENT_INSERTED);
            ASSERT (!(current->flags & LWINS_EVENT_DELETING));
            
            *prev = current->next;
            current->flags &= ~LWINS_EVENT_INSERTED;            
            
            if (current->deletion_handler)
                current->deletion_handler (server, current);
            
            ASSERT (!(current->flags & LWINS_EVENT_INSERTED));
            lwins_free (current);
            
            cnt++;
            
            /* Restart search because the event list may have changed */
            prev = &server->events;
            current = server->events;
        }
        else
        {
            prev = &current->next;
            current = current->next;
        }
    }
    
    return cnt;
}

static void lwins_trans_event_handler (struct netbios_server *server, struct lwins_event *event)
{
    struct nbns_req *request;

    (void)server;
    
    request = (struct nbns_req *)event->context;
    
    lwins_dbg_start_nbns (request->tran_id);
    
    LOG (LOG_ALL, "Transaction %s timed out\n", lwins_nbns_tran_desc (request));
}

static void lwins_trans_deletion_handler (struct netbios_server *server, struct lwins_event *event)
{
    struct nbns_req *request;

    (void)event;

    request = (struct nbns_req *)event->context;
    
    lwins_dbg_start_nbns (request->tran_id);
    
    LOG (LOG_ALL, "Transaction %s deleted\n", lwins_nbns_tran_desc (request));
    lwins_delete_nbns_req (server, request);
}

static struct nbns_req* lwins_add_transaction (struct netbios_server *server, struct netbt_packet *packet)
{
    struct nbns_req *trans;
    struct timeval due;

    trans = lwins_alloc (sizeof (*trans));
    if (trans)
    {
        trans->tran_id = packet->header.tran_id;
        trans->req_cnt = 0;
        trans->client = packet->addr;
        lwins_calculate_due_time (server, &due, 5); /* TODO: Make configurable */
        trans->event = lwins_add_event (server, lwins_trans_event_handler, lwins_trans_deletion_handler, trans, &due);
        if (!trans->event)
        {
            lwins_free (trans);
            return NULL;
        }

        /* Add transaction to request list */
        trans->next = server->nbns_req;
        server->nbns_req = trans;
    }

    return trans;
}

static struct nbns_req* lwins_find_or_add_transaction (struct netbios_server *server, struct netbt_packet *packet)
{
    struct nbns_req *trans;

    trans = server->nbns_req;
    while (trans)
    {
        if (trans->tran_id == packet->header.tran_id &&
            trans->client.sin_addr.s_addr == packet->addr.sin_addr.s_addr)
        {
            break;
        }

        trans = trans->next;
    }

    if (!trans)
        trans = lwins_add_transaction (server, packet);
    else
        LOG (LOG_ALL, "Found tran %s\n", lwins_nbns_tran_desc (trans));

    return trans;
}

static int lwins_process_response (struct netbios_server *server, struct netbt_packet *packet)
{
    (void)server;
    
    LOG (LOG_ALL, "Response from %x@%s:%u op_code: %u\n", packet->header.tran_id & 0xFFFF, inet_ntoa (packet->addr.sin_addr), ntohs(packet->addr.sin_port), packet->header.op_code);
    
    /* TODO: Find pending outgoing transaction */
    
    switch (packet->header.op_code)
    {
        case NETBT_OP_QUERY:
        case NETBT_OP_REGISTRATION:
        case NETBT_OP_RELEASE:
        case NETBT_OP_WACK:
        case NETBT_OP_REFRESH:
        case NETBT_OP_REFRESH_ALTERNATIVE:
        case NETBT_OP_MULTIHOMED_REGISTRATION:
            LOG (LOG_ALL, "Unimplemented packet op code: %u\n", packet->header.op_code);
            break;
        default:
            LOG (LOG_ERR, "Invalid packet op code: %u\n", packet->header.op_code);
            break;
    }
    
    return 1;
}

static int lwins_process_request (struct netbios_server *server, struct netbt_packet *packet)
{
    struct nbns_req *trans;
    const char *name;
    struct timeval due;
    int ret = 0;

    trans = lwins_find_or_add_transaction (server, packet);
    if (!trans)
        return 0;

    if (trans->req_cnt >= 3) /* TODO: Make configurable */
    {
        LOG (LOG_ALL, "Too many requests for %s\n", lwins_nbns_tran_desc (trans));
        return 0;
    }

    trans->req_cnt++;
    
    LOG (LOG_ALL, "Request from %s: op_code: %u req_cnt: %u\n", lwins_nbns_tran_desc (trans), packet->header.op_code, trans->req_cnt);
    
    ASSERT (trans->event);
    lwins_calculate_due_time (server, &due, 5); /* TODO: Make configurable */
    lwins_set_event_due (server, trans->event, &due);

    name = netbt_packet_question (packet, 0);

    switch (packet->header.op_code)
    {
        case NETBT_OP_QUERY:
            LOG (LOG_ALL, "Name query request: \"%.15s%s\"<%02X>\n", name, &name[NETBT_NAME_LENGTH], name[NETBT_NAME_LENGTH - 1] & 0xFF);
            ret = lwins_name_query (server, packet);
            break;
        case NETBT_OP_REGISTRATION:
            LOG (LOG_ALL, "Name registration request: \"%.15s%s\"<%02X>\n", name, &name[NETBT_NAME_LENGTH], name[NETBT_NAME_LENGTH - 1] & 0xFF);
            break;
        case NETBT_OP_MULTIHOMED_REGISTRATION:
            LOG (LOG_ALL, "Multi-homed name registration request: \"%.15s%s\"<%02X>\n", name, &name[NETBT_NAME_LENGTH], name[NETBT_NAME_LENGTH - 1] & 0xFF);
            break;
        case NETBT_OP_RELEASE:
            LOG (LOG_ALL, "Name release request: \"%.15s%s\"<%02X>\n", name, &name[NETBT_NAME_LENGTH], name[NETBT_NAME_LENGTH - 1] & 0xFF);
            break;
        case NETBT_OP_REFRESH:
        case NETBT_OP_REFRESH_ALTERNATIVE:
            LOG (LOG_ALL, "Name refresh request: \"%.15s%s\"<%02X>\n", name, &name[NETBT_NAME_LENGTH], name[NETBT_NAME_LENGTH - 1] & 0xFF);
            break;
        case NETBT_OP_WACK:
            LOG (LOG_ERR, "WACK\n");
            break;
        default:
            LOG (LOG_ERR, "Invalid packet op code: %u\n", packet->header.op_code);
            break;
    }
    
    return ret;
}

static int lwins_read_nbns_udp_packet (struct netbios_server *server, struct wins_svc *svc)
{
    struct netbt_packet packet;
    unsigned char buf[576];
    struct sockaddr_in client;
    ssize_t len;
    socklen_t slen;
    int ret;
    
    memset (buf, 0, sizeof (buf));
    memset (&client, 0, sizeof (client));
    slen = sizeof (client);
    len = recvfrom (svc->sd, buf, sizeof (buf), 0, (struct sockaddr *)&client, &slen);
    if (len < 0)
    {
        LOGSYSERR ("recvfrom");
        return LWINS_ERR;
    }
    
    ret = 0;
    
    if (netbt_parse_raw_packet (buf, (size_t)len, &client, &packet))
    {
        lwins_dbg_start_nbns (packet.header.tran_id);
        
        if (!packet.header.broadcast) // don't handle broadcast packets...
        {
            if (packet.header.is_response)
                ret = lwins_process_response (server, &packet);
            else
                ret = lwins_process_request (server, &packet);
        }
        
        netbt_free_packet_mem (&packet);
        ret = 1; //fixme
    }
    
    if (!ret)
        LOGPACKET (buf, (size_t)len, &client, lwins_dump_nbns_raw_packet);
    return 1;
}

int is_own_replication_address (struct netbios_server *server, struct in_addr *addr)
{
    struct in_addr *addrs;
    int i, addr_cnt, found = 0;

    if (addr->s_addr == htonl (INADDR_ANY))
        return 1;
    
    if (server->replication_cnt == 1 && server->replication_svc[0].addr.s_addr == htonl (INADDR_ANY))
    {
        addr_cnt = lwins_get_interface_addresses (server->discovery_sd, &addrs);
        if (addr_cnt > 0)
        {
            for (i = 0; i < addr_cnt; i++)
            {
                if (addrs[i].s_addr == addr->s_addr)
                {
                    found = 1;
                    break;
                }
            }

            lwins_free (addrs);
        }
    }
    else
    {
        for (i = 0; i < server->replication_cnt; i++)
        {
            if (server->replication_svc[i].addr.s_addr == addr->s_addr)
            {
                found = 1;
                break;
            }
        }
    }

    return found;
}

static int read_discovery_packet (struct netbios_server *server)
{
    struct nbns_discover_packet packet;
    unsigned char buf[576];
    struct sockaddr_in client;
    ssize_t len;
    socklen_t slen;
    int ret;
    
    memset (buf, 0, sizeof (buf));
    memset (&client, 0, sizeof (client));
    memset (&packet, 0, sizeof (packet));
    
    slen = sizeof (client);
    len = recvfrom (server->discovery_sd, buf, sizeof (buf), 0, (struct sockaddr *)&client, &slen);
    if (len < 0)
    {
        LOGSYSERR ("recvfrom");
        return LWINS_ERR;
    }
    
    ret = 0;
    
    if (parse_raw_nbns_discover_packet (buf, (size_t)len, &packet))
    {
        if (!is_own_replication_address (server, &client.sin_addr))
        {
            LOG (LOG_ALL, "Received discovery packet from %s:%d\n", inet_ntoa (client.sin_addr), ntohs(client.sin_port));
            
            ret = 0; // FIXME
        }
    }
    
    if (!ret)
        LOGPACKET (buf, (size_t)len, &client, lwins_dump_discovery_raw_packet);
    
    free_nbns_discover_packet (&packet);
    return 1;
}

static int lwins_set_master (struct netbios_server *server, int sd, struct lwins_fd_set *read_fds, struct lwins_fd_set *write_fds)
{
    if (!lwins_set_fd (&server->master_fds, sd))
    {
        LOG (LOG_ERR, "Not enough memory to accept connection\n");
        return 0;
    }
    
    if ((sd > server->sending_fds.cnt && !lwins_alloc_fd_set (&server->sending_fds, sd)) || 
        (sd > read_fds->cnt && !lwins_alloc_fd_set (read_fds, sd)) ||
        (sd > write_fds->cnt && !lwins_alloc_fd_set (write_fds, sd)))
    {
        lwins_clear_fd (&server->master_fds, sd);
        LOG (LOG_ERR, "Not enough memory to accept connection\n");
        return 0;
    }
    
    return 1;
}

static int lwins_accept_connection (struct netbios_server *server, struct wins_svc *svc, struct sockaddr_in *client, struct lwins_fd_set *read_fds, struct lwins_fd_set *write_fds)
{
    socklen_t client_len;
    int sd;
    
    client_len = sizeof (*client);
    sd = accept (svc->sd, (struct sockaddr *)client, &client_len);
    if (sd < 0)
    {
        LOGSYSERR ("accept");
        return -1;
    }
    
    if (!lwins_set_master (server, sd, read_fds, write_fds))
    {
        LOG (LOG_ERR, "Not enough memory to accept connection\n");
        close (sd);
        return -1;
    }
    
    return sd;
}

void lwins_close_socket (struct netbios_server *server, int sd)
{
    lwins_free_socket_queued (server, sd);
    lwins_clear_fd (&server->master_fds, sd);
    if (close (sd) < 0)
        LOGSYSERR ("close");
}

static void lwins_read_replication_connection (struct netbios_server *server, struct association *assoc)
{
    unsigned char buffer[512];
    int len;
    
    len = recv (assoc->sd, buffer, sizeof (buffer), MSG_DONTWAIT);
    if (len < 0)
    {
        if (errno == EAGAIN)
            return; /* no data available */
        
        if (errno == ECONNRESET || errno == ECONNABORTED)
        {
            assoc->error = 1;
            
            lwins_close_socket (server, assoc->sd);
            assoc->sd = -1;
            
            shutdown_association (server->replication, assoc);
        }
        else
        {
            LOGSYSERR ("recv");
            return;
        }
    }
    else if (len > 0)
    {
        if (!association_buffer_receive (server->replication, assoc, buffer, (size_t)len))
        {
            assoc->error = 1;
            shutdown_association (server->replication, assoc); /* Close the socket immediately */
        }
    }
    else
        shutdown_association (server->replication, assoc);
}

static struct wins_svc* lwins_find_svc (int sd, struct wins_svc *svc, int count)
{
    int i;

    if (svc)
    {
        for (i = 0; i < count; i++)
        {
            if (svc[i].sd == sd)
                return &svc[i];
        }
    }

    return NULL;
}

static int lwins_calculate_timeout (struct netbios_server *server, struct timeval *timeout, const struct timeval *due)
{
    struct timeval current;
    
    current = server->current_time;
    if (due->tv_sec > current.tv_sec ||
        (due->tv_sec == current.tv_sec && due->tv_usec > current.tv_usec))
    {
        timeout->tv_sec = due->tv_sec - current.tv_sec;
        if (due->tv_usec >= current.tv_usec)
            timeout->tv_usec = due->tv_usec - current.tv_usec;
        else
        {
            timeout->tv_usec = 1000000 - (current.tv_usec - due->tv_usec);
            timeout->tv_sec--;
        }
        
        /* Add a 100 ms delay so we don't attempt to timeout events that
           are due just very shortly after */
        timeout->tv_usec += 100000;
        if (timeout->tv_usec >= 1000000)
        {
            timeout->tv_usec -= 1000000;
            timeout->tv_sec++;
        }
        
        return 1;
    }
    
    return 0;
}

static int lwins_is_terminated (struct netbios_server *server)
{
    ASSERT (server->status == SERVER_TERMINATING);
    
    if (server->send)
        return 0;
    
    if (server->replication && !is_replication_service_terminated (server->replication))
        return 0;
    
    return 1;
}

void lwins_run_server (struct netbios_server *server)
{
    struct association *assoc;
    struct timeval timeout;
    int ret, i, sd, max_fd;
    struct lwins_fd_set read_fds, write_fds;
    struct wins_svc *svc;
    struct sockaddr_in client;
    fd_set *writefds;
    //struct lwins_control_client *control;
    
#ifdef DBG_MEM_LEAK
    lwins_init_memstat (server);
#endif
    
    lwins_init_fd_set (&read_fds, 0);
    lwins_init_fd_set (&write_fds, 0);

    for (i = 0; i < server->nbns_cnt; i++)
    {
        if (!lwins_set_master (server, server->nbns_svc[i].sd, &read_fds, &write_fds))
        {
            LOG (LOG_ERR, "Not enough memory\n");
            goto cleanup;
        }
    }
    
    for (i = 0; i < server->replication_cnt; i++)
    {
        if (!lwins_set_master (server, server->replication_svc[i].sd, &read_fds, &write_fds))
        {
            LOG (LOG_ERR, "Not enough memory\n");
            goto cleanup;
        }
    }

    if (server->discovery_sd >= 0)
    {
        if (!lwins_set_master (server, server->discovery_sd, &read_fds, &write_fds))
        {
            LOG (LOG_ERR, "Not enough memory\n");
            goto cleanup;
        }
    }
    else
        server->discovery_interval = 0;
    
    server->status = SERVER_RUNNING;
    LOG (LOG_ALL, "WINS server running\n");
    
    if (server->discovery_sd >= 0 &&
        !lwins_broadcast_discover_msg (server, DISCOVER_OP_UP))
    {
        LOG (LOG_ERR, "Error broadcasting discovery (up) message\n");
    }
    
    do
    {
        lwins_dbg_start ();
        
        lwins_update_current_time (server);
        
        if (server->status != SERVER_TERMINATING || !lwins_is_terminated (server))
        {
            if (!lwins_clone_fd_set (&read_fds, &server->master_fds))
            {
                LOG (LOG_ERR, "Not enough memory\n");
                /* This should never happen because read_fds should always be big enough at this point */
                ASSERT (0);
                break;
            }
            
            max_fd = server->master_fds.max_fd;
            
            if (server->send)
            {
                if (!lwins_clone_fd_set (&write_fds, &server->sending_fds))
                {
                    LOG (LOG_ERR, "Not enough memory\n");
                    /* This should never happen because write_fds should always be big enough at this point */
                    ASSERT (0);
                    break;
                }
                
                if (server->sending_fds.max_fd > max_fd)
                    max_fd = server->sending_fds.max_fd;
                
                writefds = (fd_set *)write_fds.fd_set;
            }
            else
                writefds = NULL;
            
            ASSERT (max_fd <= server->master_fds.cnt);
            ASSERT (max_fd <= server->sending_fds.cnt);
            
            if (server->events &&
                lwins_calculate_timeout (server, &timeout, &server->events->due))
            {
                ret = select (max_fd + 1, (fd_set *)read_fds.fd_set, writefds, NULL, &timeout);
                if (ret < 0 && errno != EINTR)
                {
                    LOGSYSERR ("select");
                    server->status = SERVER_STOPPED;
                    break;
                }
                
                lwins_update_current_time (server);
                lwins_timeout_events (server);
            }
            else
            {
                ret = select (max_fd + 1, (fd_set *)read_fds.fd_set, writefds, NULL, NULL);
                if (ret < 0 && errno != EINTR)
                {
                    LOGSYSERR ("select");
                    server->status = SERVER_STOPPED;
                    break;
                }
                
                lwins_update_current_time (server);
                if (server->events)
                    lwins_timeout_events (server);
            }

            if (ret > 0)
            {
                for (i = 0; i <= max_fd && ret > 0; i++)
                {
                    if (!lwins_isset_fd (&read_fds, i))
                        continue;
                    
                    ret--;
                    
                    lwins_dbg_start ();
                    
                    /* See if this is a incoming NetBT UDP packet */
                    svc = lwins_find_svc (i, server->nbns_svc, server->nbns_cnt);
                    if (svc)
                    {
                        lwins_read_nbns_udp_packet (server, svc);
                        continue;
                    }

                    /* See if this is a incoming replication connection */
                    svc = lwins_find_svc (i, server->replication_svc, server->replication_cnt);
                    if (svc)
                    {
                        if (server->status == SERVER_RUNNING)
                        {
                            sd = lwins_accept_connection (server, svc, &client, &read_fds, &write_fds);
                            if (sd >= 0)
                            {
                                assoc = alloc_association (server->replication, sd, &client);
                                if (assoc)
                                    assoc->incoming = 1;
                                else
                                {
                                    close (sd);
                                    LOG (LOG_ERR, "Not enough memory, cannot accept client connection\n");
                                }
                            }
                        }
                        else
                            LOG (LOG_ALL, "Ignore replication connection because server is terminating");
                        
                        continue;
                    }
                    
                    if (i == server->discovery_sd)
                    {
                        if (server->status == SERVER_RUNNING)
                        {
                            lwins_dbg_start_discover ();
                            read_discovery_packet (server);
                        }
                        else
                            LOG (LOG_ALL, "Ignore discovery packet because server is terminating");
                    }
                    else
                    {
                        if (server->replication)
                        {
                            assoc = find_association (server->replication, i);
                            if (assoc)
                            {
                                /* replication connection */
                                
                                lwins_dbg_start_assoc (assoc->handle);
                                
                                lwins_read_replication_connection (server, assoc);
                                continue;
                            }
                        }

                        /* TODO: NETBIOS TCP connection */

                        if (server->control)
                        {
                            //control = find_control (server->control, i);
                            //if (control)
                            //{
                                /* control connection */
                            //    continue;
                            //}
                        }
                    }
                }
                
                if (ret > 0)
                {
                    ASSERT (writefds != NULL);
                    for (i = 0; i <= max_fd && ret > 0; i++)
                    {
                        if (!lwins_isset_fd (&write_fds, i))
                            continue;
                        
                        ret--;
                        
                        if (lwins_send_socket_queued (server, i))
                        {
                            /* All pending data sent */
                            LOG (LOG_ALL, "All pending data for socket %d sent\n", i);
                        }
                    }
                }
                
                ASSERT (ret == 0);
            }
        }
        
        switch (server->status)
        {
            case SERVER_RUNNING:
                if (*server->terminate)
                {
                    server->status = SERVER_TERMINATING;
                    
                    lwins_dbg_start ();
                    
                    LOG (LOG_ALL, "Shutting server down...\n");
                    
                    if (server->discovery_sd >= 0 &&
                        !lwins_broadcast_discover_msg (server, DISCOVER_OP_DOWN))
                    {
                        LOG (LOG_ERR, "Error broadcasting discovery (down) message\n");
                    }
                    
                    lwins_dbg_start ();
                    
                    if (server->replication)
                        terminate_replication_service (server->replication);
                }
                break;
            case SERVER_TERMINATING:
                /* Stop the server if everything shut down properly */
                if (lwins_is_terminated (server))
                {
                    lwins_delete_nbns_requests (server);
                    
                    server->status = SERVER_STOPPED;
                    
                    lwins_dbg_start ();
                    
                    LOG (LOG_ALL, "Server stopped\n");
                }
                break;
        }

    } while (server->status <= SERVER_TERMINATING);
    
    ASSERT (server->status == SERVER_STOPPED);
    
    lwins_update_current_time (server);
    if (server->database_file && !lwins_save_database (server))
    {
        LOG (LOG_ERR, "Error saving database to %s\n", server->database_file);
    }
    
cleanup:
    lwins_free_fd_set (&read_fds);
    lwins_free_fd_set (&write_fds);
    
    LOG (LOG_ALL, "WINS server terminated\n");
}

static volatile unsigned int terminate_server = 0;

static void handle_sigint (int signum)
{
    (void)signum;
    terminate_server = 1;
    signal (SIGINT, SIG_IGN);
}

int main (int argc, const char *argv[])
{
    struct netbios_server *server;
    struct lwins_config config;
    
    lwins_setup_stack_traces ();
    
    memset (&config, 0, sizeof (config));
    if (!lwins_read_config_args (argc, argv, &config))
    {
        lwins_free_config (&config);
        return 1;
    }
    
    server = lwins_setup_server (&config, &terminate_server);
    if (!server)
    {
        lwins_free_config (&config);
        fprintf (stderr, "Initialization failed!\n");
        return 1;
    }
    
    (void)signal (SIGINT, handle_sigint);
    
    lwins_run_server (server);
    lwins_free_server (server);
    lwins_free_config (&config);
    
#ifdef DBG_MEM_LEAK
    lwins_dbg_mem_check ();
#else
    if (alloc_cnt != 0)
        fprintf (stderr, "Memory leak detected: %d blocks\n", alloc_cnt);
#endif
    exit (0);
}

