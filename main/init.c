#include "init.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <cjson/cJSON.h>

#include "log.h"
#include "fd_entry.h"
#include "worker.h"
#include "ip.h"
#include "ipv6.h"
#include "xdp.h"

enum {
    NETFAST_CONFIG_MAX_SIZE = 1024 * 1024,
    NETFAST_CONFIG_MAX_WORKERS = 64,
    NETFAST_CONFIG_MAX_XSK_QUEUES = 32,
    NETFAST_RESERVED_PORT_BITMAP_SIZE = (UINT16_MAX + 1u) / 8u,
    NETFAST_RESERVED_PORT_TEXT_MAX = (UINT16_MAX + 1u) * 8u + 2u,
};

#define NETFAST_IP_LOCAL_RESERVED_PORTS \
    "/proc/sys/net/ipv4/ip_local_reserved_ports"

g_config g_cfg = {
    .source_port_range = {
        .first = NETFAST_SOURCE_PORT_FIRST_DEFAULT,
        .last = NETFAST_SOURCE_PORT_LAST_DEFAULT,
    },
};

static uint8_t netfast_reserved_ports_before[
    NETFAST_RESERVED_PORT_BITMAP_SIZE];
static netfast_port_range netfast_reserved_port_range;
static pid_t netfast_reserved_ports_owner_pid;
static bool netfast_source_ports_reserved;

static bool netfast_port_is_reserved(const uint8_t *bitmap, uint32_t port)
{
    return (bitmap[port >> 3] & (uint8_t)(1u << (port & 7u))) != 0;
}

static void netfast_set_port_reserved(uint8_t *bitmap, uint32_t port,
                                      bool reserved)
{
    uint8_t mask = (uint8_t)(1u << (port & 7u));
    if (reserved)
        bitmap[port >> 3] |= mask;
    else
        bitmap[port >> 3] &= (uint8_t)~mask;
}

static bool netfast_reserved_port_space(char value)
{
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

static int netfast_parse_reserved_ports(const char *text, uint8_t *bitmap)
{
    memset(bitmap, 0, NETFAST_RESERVED_PORT_BITMAP_SIZE);
    const char *pos = text;

    for (;;) {
        while (netfast_reserved_port_space(*pos))
            pos++;
        if (!*pos)
            return 0;

        errno = 0;
        char *end = NULL;
        unsigned long first = strtoul(pos, &end, 10);
        if (end == pos || errno || first > UINT16_MAX)
            goto invalid;
        pos = end;

        unsigned long last = first;
        if (*pos == '-') {
            pos++;
            errno = 0;
            last = strtoul(pos, &end, 10);
            if (end == pos || errno || last > UINT16_MAX || last < first)
                goto invalid;
            pos = end;
        }

        for (uint32_t port = (uint32_t)first;; port++) {
            netfast_set_port_reserved(bitmap, port, true);
            if (port == last)
                break;
        }

        while (netfast_reserved_port_space(*pos))
            pos++;
        if (!*pos)
            return 0;
        if (*pos != ',')
            goto invalid;
        pos++;
        const char *next = pos;
        while (netfast_reserved_port_space(*next))
            next++;
        if (!*next)
            goto invalid;
    }

invalid:
    errno = EINVAL;
    return -1;
}

static int netfast_read_reserved_ports(uint8_t *bitmap)
{
    FILE *fp = fopen(NETFAST_IP_LOCAL_RESERVED_PORTS, "r");
    if (!fp) {
        ERR_LOG("config: cannot read %s: %s",
                NETFAST_IP_LOCAL_RESERVED_PORTS, strerror(errno));
        return -1;
    }

    char *text = NULL;
    size_t capacity = 0;
    errno = 0;
    ssize_t length = getline(&text, &capacity, fp);
    bool failed = ferror(fp) != 0;
    int saved_errno = errno;
    if (fclose(fp) != 0) {
        failed = true;
        saved_errno = errno;
    }
    if (failed) {
        free(text);
        errno = saved_errno ? saved_errno : EIO;
        ERR_LOG("config: cannot read %s: %s",
                NETFAST_IP_LOCAL_RESERVED_PORTS, strerror(errno));
        return -1;
    }

    int ret = netfast_parse_reserved_ports(
        length < 0 || !text ? "" : text, bitmap);
    free(text);
    if (ret < 0)
        ERR_LOG("config: invalid value in %s",
                NETFAST_IP_LOCAL_RESERVED_PORTS);
    return ret;
}

static int netfast_write_reserved_ports(const uint8_t *bitmap)
{
    char *text = malloc(NETFAST_RESERVED_PORT_TEXT_MAX);
    if (!text)
        return -1;

    size_t length = 0;
    for (uint32_t first = 0; first <= UINT16_MAX;) {
        while (first <= UINT16_MAX &&
               !netfast_port_is_reserved(bitmap, first))
            first++;
        if (first > UINT16_MAX)
            break;

        uint32_t last = first;
        while (last < UINT16_MAX &&
               netfast_port_is_reserved(bitmap, last + 1u))
            last++;

        int written = first == last
            ? snprintf(text + length,
                       NETFAST_RESERVED_PORT_TEXT_MAX - length,
                       "%s%u", length ? "," : "", first)
            : snprintf(text + length,
                       NETFAST_RESERVED_PORT_TEXT_MAX - length,
                       "%s%u-%u", length ? "," : "", first, last);
        if (written < 0 ||
            (size_t)written >= NETFAST_RESERVED_PORT_TEXT_MAX - length) {
            free(text);
            errno = EOVERFLOW;
            return -1;
        }
        length += (size_t)written;
        first = last + 1u;
    }

    text[length++] = '\n';
    FILE *fp = fopen(NETFAST_IP_LOCAL_RESERVED_PORTS, "w");
    if (!fp) {
        ERR_LOG("config: cannot update %s: %s",
                NETFAST_IP_LOCAL_RESERVED_PORTS, strerror(errno));
        free(text);
        return -1;
    }

    bool failed = fwrite(text, 1, length, fp) != length;
    int saved_errno = failed ? errno : 0;
    if (fclose(fp) != 0) {
        failed = true;
        saved_errno = errno;
    }
    free(text);
    if (failed) {
        errno = saved_errno ? saved_errno : EIO;
        ERR_LOG("config: cannot update %s: %s",
                NETFAST_IP_LOCAL_RESERVED_PORTS, strerror(errno));
        return -1;
    }
    return 0;
}
static int netfast_init_workers(void)
{
    int n = g_cfg.thread_num;
    g_workers = calloc((size_t)n, sizeof(*g_workers));
    if (!g_workers)
        return -1;

    g_worker_num = n;
    main_worker = &g_workers[0];
    for (int i = 0; i < n; i++) {
        if (worker_init(&g_workers[i]) < 0)
            return -1;
    }

    return worker_start_all();
}

static int netfast_parse_open_interfaces(cJSON *root, g_config *cfg)
{
    cJSON *ifs = cJSON_GetObjectItem(root, "open_if");
    if (!ifs || !cJSON_IsArray(ifs)) {
        errno = EINVAL;
        ERR_LOG("config_load: open_if missing or invalid");
        return -1;
    }

    int count = cJSON_GetArraySize(ifs);
    if (count <= 0) {
        errno = EINVAL;
        ERR_LOG("config_load: open_if empty");
        return -1;
    }

    cfg->ifs = calloc((size_t)count, sizeof(*cfg->ifs));
    if (!cfg->ifs)
        return -1;
    cfg->ifs_count = count;

    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_GetArrayItem(ifs, i);
        if (!cJSON_IsObject(item)) {
            errno = EINVAL;
            ERR_LOG("config_load: open_if[%d] must be object {name,queues}", i);
            return -1;
        }

        cJSON *jname = cJSON_GetObjectItem(item, "name");
        if (!jname || !cJSON_IsString(jname) || !jname->valuestring || !jname->valuestring[0]) {
            errno = EINVAL;
            ERR_LOG("config_load: open_if[%d].name missing or invalid", i);
            return -1;
        }

        size_t name_len = strlen(jname->valuestring);
        if (name_len >= sizeof(cfg->ifs[i].name)) {
            errno = ENAMETOOLONG;
            ERR_LOG("config_load: open_if[%d].name is too long", i);
            return -1;
        }
        for (int j = 0; j < i; j++) {
            if (strcmp(cfg->ifs[j].name, jname->valuestring) == 0) {
                errno = EINVAL;
                ERR_LOG("config_load: duplicate interface %s",
                        jname->valuestring);
                return -1;
            }
        }

        int queues = 0;
        cJSON *jqueues = cJSON_GetObjectItem(item, "queues");
        if (jqueues && cJSON_IsNumber(jqueues))
            queues = jqueues->valueint;
        if (queues == 0)
            queues = cfg->thread_num;
        if (queues < 1 || queues > NETFAST_CONFIG_MAX_XSK_QUEUES) {
            errno = EINVAL;
            ERR_LOG("config_load: open_if[%d].queues must be in [1,%d]",
                    i, NETFAST_CONFIG_MAX_XSK_QUEUES);
            return -1;
        }

        memcpy(cfg->ifs[i].name, jname->valuestring, name_len + 1);
        cfg->ifs[i].queues = queues;
    }

    return 0;
}

static int netfast_parse_source_port_range(cJSON *root, g_config *cfg)
{
    cJSON *range = cJSON_GetObjectItem(root, "source_port_range");
    if (!range)
        return 0;
    if (!cJSON_IsArray(range) || cJSON_GetArraySize(range) != 2) {
        errno = EINVAL;
        ERR_LOG("config_load: source_port_range must be [first,last]");
        return -1;
    }

    cJSON *first = cJSON_GetArrayItem(range, 0);
    cJSON *last = cJSON_GetArrayItem(range, 1);
    if (!cJSON_IsNumber(first) || !cJSON_IsNumber(last) ||
        first->valuedouble < 1 || first->valuedouble > UINT16_MAX ||
        last->valuedouble < 1 || last->valuedouble > UINT16_MAX ||
        first->valuedouble != first->valueint ||
        last->valuedouble != last->valueint ||
        first->valueint > last->valueint) {
        errno = EINVAL;
        ERR_LOG("config_load: source_port_range must contain two ordered "
                "integer ports in [1,65535]");
        return -1;
    }

    cfg->source_port_range.first = (uint16_t)first->valueint;
    cfg->source_port_range.last = (uint16_t)last->valueint;
    return 0;
}

static int netfast_reserve_linux_source_ports(void)
{
    if (netfast_source_ports_reserved)
        return 0;

    uint8_t *ports = malloc(NETFAST_RESERVED_PORT_BITMAP_SIZE);
    if (!ports)
        return -1;
    if (netfast_read_reserved_ports(ports) < 0) {
        free(ports);
        return -1;
    }

    memcpy(netfast_reserved_ports_before, ports,
           NETFAST_RESERVED_PORT_BITMAP_SIZE);
    netfast_reserved_port_range = g_cfg.source_port_range;
    for (uint32_t port = netfast_reserved_port_range.first;; port++) {
        netfast_set_port_reserved(ports, port, true);
        if (port == netfast_reserved_port_range.last)
            break;
    }

    int ret = netfast_write_reserved_ports(ports);
    free(ports);
    if (ret < 0) {
        memset(netfast_reserved_ports_before, 0,
               sizeof(netfast_reserved_ports_before));
        return -1;
    }

    netfast_reserved_ports_owner_pid = getpid();
    netfast_source_ports_reserved = true;
    return 0;
}

static int netfast_release_linux_source_ports(void)
{
    if (!netfast_source_ports_reserved ||
        netfast_reserved_ports_owner_pid != getpid())
        return 0;

    uint8_t *ports = malloc(NETFAST_RESERVED_PORT_BITMAP_SIZE);
    if (!ports)
        return -1;
    if (netfast_read_reserved_ports(ports) < 0) {
        free(ports);
        return -1;
    }

    for (uint32_t port = netfast_reserved_port_range.first;; port++) {
        netfast_set_port_reserved(
            ports, port,
            netfast_port_is_reserved(netfast_reserved_ports_before, port));
        if (port == netfast_reserved_port_range.last)
            break;
    }

    int ret = netfast_write_reserved_ports(ports);
    free(ports);
    if (ret < 0)
        return -1;

    memset(netfast_reserved_ports_before, 0,
           sizeof(netfast_reserved_ports_before));
    netfast_reserved_ports_owner_pid = 0;
    netfast_source_ports_reserved = false;
    return 0;
}

int config_get_interface_queues(const char *ifname)
{
	if (!ifname)
		return 0;

    for (int i = 0; i < g_cfg.ifs_count; i++) {
        if (strcmp(ifname, g_cfg.ifs[i].name) == 0)
            return g_cfg.ifs[i].queues;
    }
    return 0;
}

int config_load(void)
{
    g_config new_cfg = {
        .source_port_range = {
            .first = NETFAST_SOURCE_PORT_FIRST_DEFAULT,
            .last = NETFAST_SOURCE_PORT_LAST_DEFAULT,
        },
    };
    cJSON *root = NULL;
    int ret = -1;
    const char *config_path = NETFAST_LOCAL_CONFIG_FILE;
    FILE *fp = fopen(config_path, "rb");
    if (!fp && errno == ENOENT) {
        config_path = NETFAST_CONFIG_FILE;
        fp = fopen(config_path, "rb");
    }
    if (!fp) {
        ERR_LOG("config_load: cannot open file %s", config_path);
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long len = ftell(fp);
    if (len < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    if (len == 0) {
        fclose(fp);
        ERR_LOG("config_load: empty config file");
        errno = EINVAL;
        return -1;
    }

    if (len > NETFAST_CONFIG_MAX_SIZE) {
        fclose(fp);
        ERR_LOG("config_load: config file is too large");
        errno = EFBIG;
        return -1;
    }

    size_t config_len = (size_t)len;

    char *buf = calloc(config_len + 1u, 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    errno = 0;
    size_t bytes_read = fread(buf, 1, config_len, fp);
    if (bytes_read != config_len) {
        int read_error = ferror(fp) ? errno : EIO;
        free(buf);
        fclose(fp);
        errno = read_error ? read_error : EIO;
        return -1;
    }
    fclose(fp);

    root = cJSON_Parse(buf);
    free(buf);

    if (!root) {
        ERR_LOG("config_load: invalid json");
        errno = EINVAL;
        return -1;
    }

    cJSON *thread = cJSON_GetObjectItem(root, "thread_num");
    if (thread && cJSON_IsNumber(thread)) {
        new_cfg.thread_num = thread->valueint;
    } else {
        ERR_LOG("config_load: thread_num missing or invalid");
        errno = EINVAL;
        goto out;
    }
    if (new_cfg.thread_num < 1 ||
        new_cfg.thread_num > NETFAST_CONFIG_MAX_WORKERS) {
        ERR_LOG("config_load: thread_num must be in [1,%d]",
                NETFAST_CONFIG_MAX_WORKERS);
        errno = EINVAL;
        goto out;
    }

    cJSON *logfile = cJSON_GetObjectItem(root, "logfile");
    if (!logfile || !cJSON_IsString(logfile) || !logfile->valuestring ||
        !logfile->valuestring[0] ||
        strlen(logfile->valuestring) >= sizeof(new_cfg.logfile)) {
        ERR_LOG("config_load: logfile missing or invalid");
        errno = EINVAL;
        goto out;
    }
    size_t logfile_len = strlen(logfile->valuestring);
    memcpy(new_cfg.logfile, logfile->valuestring, logfile_len + 1);

    if (netfast_parse_open_interfaces(root, &new_cfg) != 0)
        goto out;

    if (netfast_parse_source_port_range(root, &new_cfg) != 0)
        goto out;

    cJSON *redirect_fragments =
        cJSON_GetObjectItem(root, "redirect_fragments");
    if (redirect_fragments && !cJSON_IsBool(redirect_fragments)) {
        ERR_LOG("config_load: redirect_fragments must be boolean");
        errno = EINVAL;
        goto out;
    }
    new_cfg.redirect_fragments = cJSON_IsTrue(redirect_fragments);

    free(g_cfg.ifs);
    g_cfg = new_cfg;
    new_cfg.ifs = NULL;
    ret = 0;

out:
    cJSON_Delete(root);
    free(new_cfg.ifs);
    return ret;
}
bool config_interface_is_filtered(const char *ifname)
{
    return config_get_interface_queues(ifname) == 0;
}

__attribute__((destructor))
static void netfast_library_cleanup(void)
{
    if (netfast_release_linux_source_ports() < 0)
        WARN_LOG("netfast_library_cleanup: releasing source_port_range failed");
}

__attribute__((constructor))
static void netfast_library_init(void)
{
	if (fd_table_init() < 0) {
		fprintf(stderr, "netfast_library_init: fd_table_init failed\n");
		goto fail;
	}

	/* Unit tests initialize the raw frame pool explicitly and must not attach
	 * XDP programs or start detached workers from the shared-library ctor. */
	if (getenv("NETFAST_TEST_NO_AUTO_INIT"))
		return;

    if (config_load() < 0) {
        fprintf(stderr, "netfast_library_init: config_load failed\n");
        goto fail;
    }
    if (log_init() < 0) {
        fprintf(stderr, "netfast_library_init: log_init failed for %s\n", g_cfg.logfile);
        goto fail;
    }
    if (netfast_reserve_linux_source_ports() < 0) {
        ERR_LOG("netfast_library_init: reserving source_port_range failed");
        goto fail;
    }
    if (xdp_init() < 0) {
        ERR_LOG("netfast_library_init: xdp_init failed");
        goto fail;
    }
    if (netfast_init_workers() < 0){
        ERR_LOG("netfast_library_init: netfast_init_workers failed");
        goto fail;
    }

    if (ipv4_init() < 0) {
        ERR_LOG("netfast_library_init: ipv4_init failed");
        goto fail;
    }
    if (ipv6_init() < 0) {
        ERR_LOG("netfast_library_init: ipv6_init failed");
        goto fail;
    }

    return;
fail:
    fprintf(stderr, "netfast_library_init: fatal init failure, aborting\n");
    /* _exit() intentionally skips atexit handlers.  Detach any persistent
     * XDP program explicitly; XSK/UMEM file descriptors are closed by the
     * process exit itself. */
    xdp_cleanup_programs();
    if (netfast_release_linux_source_ports() < 0)
        ERR_LOG("netfast_library_init: releasing source_port_range failed");
    _exit(1);
}
