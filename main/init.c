#include "init.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <cjson/cJSON.h>

#include "log.h"
#include "worker.h"
#include "ip.h"
#include "ipv6.h"
#include "xdp.h"

enum {
    NETFAST_CONFIG_MAX_SIZE = 1024 * 1024,
    NETFAST_CONFIG_MAX_WORKERS = 64,
    NETFAST_CONFIG_MAX_XSK_QUEUES = 32,
};


g_config g_cfg;
static int init_workers(void)
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

    return worker_detach_all();
}

static int parse_open_if(cJSON *root, g_config *cfg)
{
    cJSON *ifs = cJSON_GetObjectItem(root, "open_if");
    if (!ifs || !cJSON_IsArray(ifs)) {
        errno = EINVAL;
        ERR_LOG("configure_init: open_if missing or invalid");
        return -1;
    }

    int count = cJSON_GetArraySize(ifs);
    if (count <= 0) {
        errno = EINVAL;
        ERR_LOG("configure_init: open_if empty");
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
            ERR_LOG("configure_init: open_if[%d] must be object {name,queues}", i);
            return -1;
        }

        cJSON *jname = cJSON_GetObjectItem(item, "name");
        if (!jname || !cJSON_IsString(jname) || !jname->valuestring || !jname->valuestring[0]) {
            errno = EINVAL;
            ERR_LOG("configure_init: open_if[%d].name missing or invalid", i);
            return -1;
        }

        size_t name_len = strlen(jname->valuestring);
        if (name_len >= sizeof(cfg->ifs[i].name)) {
            errno = ENAMETOOLONG;
            ERR_LOG("configure_init: open_if[%d].name is too long", i);
            return -1;
        }
        for (int j = 0; j < i; j++) {
            if (strcmp(cfg->ifs[j].name, jname->valuestring) == 0) {
                errno = EINVAL;
                ERR_LOG("configure_init: duplicate interface %s",
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
            ERR_LOG("configure_init: open_if[%d].queues must be in [1,%d]",
                    i, NETFAST_CONFIG_MAX_XSK_QUEUES);
            return -1;
        }

        memcpy(cfg->ifs[i].name, jname->valuestring, name_len + 1);
        cfg->ifs[i].queues = queues;
    }

    return 0;
}

int cfg_get_if_queues(const char *ifname)
{
	if (!ifname)
		return 0;

    for (int i = 0; i < g_cfg.ifs_count; i++) {
        if (strcmp(ifname, g_cfg.ifs[i].name) == 0)
            return g_cfg.ifs[i].queues;
    }
    return 0;
}

int configure_init(void)
{
    g_config new_cfg = {0};
    cJSON *root = NULL;
    int ret = -1;
    const char *config_path = NETFAST_LOCAL_CONFIG_FILE;
    FILE *fp = fopen(config_path, "rb");
    if (!fp && errno == ENOENT) {
        config_path = NETFAST_CONFIG_FILE;
        fp = fopen(config_path, "rb");
    }
    if (!fp) {
        ERR_LOG("configure_init: cannot open file %s", config_path);
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
        ERR_LOG("configure_init: empty config file");
        errno = EINVAL;
        return -1;
    }

    if (len > NETFAST_CONFIG_MAX_SIZE) {
        fclose(fp);
        ERR_LOG("configure_init: config file is too large");
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
        ERR_LOG("configure_init: invalid json");
        errno = EINVAL;
        return -1;
    }

    cJSON *thread = cJSON_GetObjectItem(root, "thread_num");
    if (thread && cJSON_IsNumber(thread)) {
        new_cfg.thread_num = thread->valueint;
    } else {
        ERR_LOG("configure_init: thread_num missing or invalid");
        errno = EINVAL;
        goto out;
    }
    if (new_cfg.thread_num < 1 ||
        new_cfg.thread_num > NETFAST_CONFIG_MAX_WORKERS) {
        ERR_LOG("configure_init: thread_num must be in [1,%d]",
                NETFAST_CONFIG_MAX_WORKERS);
        errno = EINVAL;
        goto out;
    }

    cJSON *logfile = cJSON_GetObjectItem(root, "logfile");
    if (!logfile || !cJSON_IsString(logfile) || !logfile->valuestring ||
        !logfile->valuestring[0] ||
        strlen(logfile->valuestring) >= sizeof(new_cfg.logfile)) {
        ERR_LOG("configure_init: logfile missing or invalid");
        errno = EINVAL;
        goto out;
    }
    size_t logfile_len = strlen(logfile->valuestring);
    memcpy(new_cfg.logfile, logfile->valuestring, logfile_len + 1);

    if (parse_open_if(root, &new_cfg) != 0)
        goto out;

    free(g_cfg.ifs);
    g_cfg = new_cfg;
    new_cfg.ifs = NULL;
    ret = 0;

out:
    cJSON_Delete(root);
    free(new_cfg.ifs);
    return ret;
}
bool filter_ifname(const char *ifname)
{
    return cfg_get_if_queues(ifname) == 0;
}
__attribute__((constructor))
static void lib_init(void)
{
	/* Unit tests initialize the raw frame pool explicitly and must not attach
	 * XDP programs or start detached workers from the shared-library ctor. */
	if (getenv("NETFAST_TEST_NO_AUTO_INIT"))
		return;

    if (configure_init() < 0) {
        fprintf(stderr, "lib_init: configure_init failed\n");
        goto fail;
    }
    if (log_init() < 0) {
        fprintf(stderr, "lib_init: log_init failed for %s\n", g_cfg.logfile);
        goto fail;
    }
    if (xdp_init() < 0) {
        ERR_LOG("lib_init: xdp_init failed");
        goto fail;
    }
    if (init_workers() < 0){
        ERR_LOG("lib_init: init_workers_by_cpu failed");
        goto fail;
    }

    if (ipv4_init() < 0) {
        ERR_LOG("lib_init: ipv4_init failed");
        goto fail;
    }
    if (ipv6_init() < 0) {
        ERR_LOG("lib_init: ipv6_init failed");
        goto fail;
    }

    return;
fail:
    fprintf(stderr, "lib_init: fatal init failure, aborting\n");
    /* _exit() intentionally skips atexit handlers.  Detach any persistent
     * XDP program explicitly; XSK/UMEM file descriptors are closed by the
     * process exit itself. */
    xdp_cleanup_programs();
    _exit(1);
}
