/* Concurrent HTTP/1.1 server using NetFast's asynchronous request API. */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "netfast.h"

#define HTTP_PORT 8888U
#define HTTP_BACKLOG 256
#define HTTP_ACCEPT_DEPTH 32U
#define HTTP_COMPLETION_BATCH 128U
#define HTTP_REQUEST_CAPACITY (16U * 1024U)

typedef struct http_server http_server;
typedef struct http_connection http_connection;
typedef struct http_operation http_operation;

typedef enum http_operation_kind {
    HTTP_OP_ACCEPT,
    HTTP_OP_READ,
    HTTP_OP_WRITE,
    HTTP_OP_CLOSE,
} http_operation_kind;

struct http_connection {
    http_server *server;
    uint64_t id;
    int fd;
    char request[HTTP_REQUEST_CAPACITY + 1U];
    size_t request_length;
    char *response;
    size_t response_length;
    size_t response_offset;
    bool failed;
};

struct http_operation {
    http_operation *next;
    net_async_req *request;
    http_operation_kind kind;
    http_connection *connection;
    struct sockaddr_storage peer;
    socklen_t peer_length;
};

struct http_server {
    int cq_fd;
    int listen_fd;
    uint32_t accepts_pending;
    uint64_t next_connection_id;
    uint64_t accepted;
    uint64_t requests;
    uint64_t completed;
    uint64_t failed;
    uint64_t active;
    struct timespec started;
    http_operation *operations;
};

static volatile sig_atomic_t g_stop;

static const char INDEX_HTML[] =
    "<!doctype html>\n"
    "<html lang=\"zh-CN\" data-bs-theme=\"dark\">\n"
    "<head>\n"
    "  <meta charset=\"utf-8\">\n"
    "  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
    "  <title>NetFast Async HTTP</title>\n"
    "  <meta name=\"description\" content=\"NetFast asynchronous HTTP server dashboard\">\n"
    "  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n"
    "  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n"
    "  <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&amp;family=JetBrains+Mono:wght@500;600&amp;display=swap\" rel=\"stylesheet\">\n"
    "  <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB\" crossorigin=\"anonymous\">\n"
    "  <link href=\"https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.min.css\" rel=\"stylesheet\">\n"
    "  <style>\n"
    "    :root{--nf-cyan:#67e8f9;--nf-blue:#38bdf8;--nf-green:#34d399;--nf-panel:rgba(15,23,42,.76)}\n"
    "    body{min-height:100vh;font-family:Inter,sans-serif;background:radial-gradient(circle at 10% 8%,#17315c 0,transparent 30%),radial-gradient(circle at 90% 25%,#164e63 0,transparent 27%),#080d1a;background-attachment:fixed}\n"
    "    code,.mono{font-family:'JetBrains Mono',monospace;color:#7dd3fc}\n"
    "    .glass{background:var(--nf-panel);border:1px solid rgba(148,163,184,.2);backdrop-filter:blur(16px);box-shadow:0 24px 80px rgba(0,0,0,.28)}\n"
    "    .navbar-glass{background:rgba(8,13,26,.78);border-bottom:1px solid rgba(148,163,184,.16);backdrop-filter:blur(16px)}\n"
    "    .pulse{width:.7rem;height:.7rem;background:#34d399;border-radius:50%;box-shadow:0 0 0 .35rem rgba(52,211,153,.15)}\n"
    "    .hero-img{width:100%;height:100%;min-height:330px;object-fit:cover;filter:saturate(.82) contrast(1.08)}\n"
    "    .hero-frame{position:relative;overflow:hidden;border:1px solid rgba(103,232,249,.22)}\n"
    "    .hero-frame:after{content:'';position:absolute;inset:0;background:linear-gradient(135deg,transparent 45%,rgba(8,13,26,.78))}\n"
    "    .metric{transition:transform .2s,border-color .2s}.metric:hover,.resource:hover{transform:translateY(-3px);border-color:rgba(103,232,249,.5)}\n"
    "    .metric-icon{width:2.7rem;height:2.7rem;display:grid;place-items:center;border-radius:.85rem;background:rgba(56,189,248,.12);color:var(--nf-cyan);font-size:1.25rem}\n"
    "    .chart-box{position:relative;height:290px}\n"
    "    .resource{transition:transform .2s,border-color .2s;text-decoration:none;color:inherit}\n"
    "    .resource i{font-size:1.65rem;color:var(--nf-cyan)}\n"
    "    .section-kicker{color:var(--nf-cyan);letter-spacing:.12em;text-transform:uppercase;font-size:.76rem;font-weight:700}\n"
    "  </style>\n"
    "</head>\n"
    "<body>\n"
    "  <nav class=\"navbar navbar-expand-lg navbar-glass sticky-top\"><div class=\"container py-2\">\n"
    "    <a class=\"navbar-brand fw-bold\" href=\"/\"><i class=\"bi bi-diagram-3-fill text-info me-2\"></i>NetFast</a>\n"
    "    <div class=\"d-flex align-items-center gap-2 small\"><span class=\"pulse\"></span><span id=\"nav-status\" class=\"text-success\">Async server online</span></div>\n"
    "  </div></nav>\n"
    "  <main class=\"container py-5\">\n"
    "    <section class=\"glass rounded-4 overflow-hidden mb-4\"><div class=\"row g-0 align-items-stretch\">\n"
    "      <div class=\"col-lg-7 p-4 p-md-5 d-flex flex-column justify-content-center\">\n"
    "        <div class=\"section-kicker mb-3\">Userspace network stack</div>\n"
    "        <h1 class=\"display-4 fw-bold lh-1 mb-4\">异步 HTTP<br><span class=\"text-info\">实时控制台</span></h1>\n"
    "        <p class=\"lead text-secondary mb-4\">从 accept、read、write 到 close 全部通过 NetFast completion queue 驱动。页面资源由多个公网 CDN 实时加载。</p>\n"
    "        <div class=\"d-flex flex-wrap gap-2\"><a class=\"btn btn-info\" href=\"/api/status\"><i class=\"bi bi-braces me-2\"></i>JSON 状态</a><a class=\"btn btn-outline-light\" href=\"/healthz\"><i class=\"bi bi-heart-pulse me-2\"></i>健康检查</a></div>\n"
    "      </div>\n"
    "      <div class=\"col-lg-5 hero-frame\"><img class=\"hero-img\" src=\"https://images.unsplash.com/photo-1543355584-e708a2e4d2f6?auto=format&amp;fit=crop&amp;w=1200&amp;q=82\" alt=\"蓝色数据中心服务器机架\"></div>\n"
    "    </div></section>\n"
    "    <section class=\"row g-3 mb-4\">\n"
    "      <div class=\"col-6 col-lg-3\"><div class=\"glass metric rounded-4 p-3 h-100 d-flex gap-3 align-items-center\"><span class=\"metric-icon\"><i class=\"bi bi-activity\"></i></span><div><div class=\"small text-secondary\">活动连接</div><div id=\"active\" class=\"fs-3 fw-bold\">--</div></div></div></div>\n"
    "      <div class=\"col-6 col-lg-3\"><div class=\"glass metric rounded-4 p-3 h-100 d-flex gap-3 align-items-center\"><span class=\"metric-icon\"><i class=\"bi bi-arrow-left-right\"></i></span><div><div class=\"small text-secondary\">HTTP 请求</div><div id=\"requests\" class=\"fs-3 fw-bold\">--</div></div></div></div>\n"
    "      <div class=\"col-6 col-lg-3\"><div class=\"glass metric rounded-4 p-3 h-100 d-flex gap-3 align-items-center\"><span class=\"metric-icon\"><i class=\"bi bi-check2-circle\"></i></span><div><div class=\"small text-secondary\">完成连接</div><div id=\"completed\" class=\"fs-3 fw-bold\">--</div></div></div></div>\n"
    "      <div class=\"col-6 col-lg-3\"><div class=\"glass metric rounded-4 p-3 h-100 d-flex gap-3 align-items-center\"><span class=\"metric-icon\"><i class=\"bi bi-stopwatch\"></i></span><div><div class=\"small text-secondary\">运行时间</div><div class=\"fs-3 fw-bold\"><span id=\"uptime\">--</span><small class=\"fs-6 text-secondary\">s</small></div></div></div></div>\n"
    "    </section>\n"
    "    <section class=\"row g-4 mb-5\">\n"
    "      <div class=\"col-lg-8\"><div class=\"glass rounded-4 p-4 h-100\"><div class=\"d-flex justify-content-between align-items-start mb-3\"><div><div class=\"section-kicker\">Live telemetry</div><h2 class=\"h4 mt-2 mb-0\">请求与连接趋势</h2></div><span class=\"badge text-bg-info\">2 秒刷新</span></div><div class=\"chart-box\"><canvas id=\"traffic-chart\"></canvas></div></div></div>\n"
    "      <div class=\"col-lg-4\"><div class=\"glass rounded-4 p-4 h-100\"><div class=\"section-kicker\">Endpoint</div><h2 class=\"h4 mt-2\">服务信息</h2><ul class=\"list-group list-group-flush mt-3\"><li class=\"list-group-item bg-transparent px-0 d-flex justify-content-between\"><span class=\"text-secondary\">监听</span><code>0.0.0.0:8888</code></li><li class=\"list-group-item bg-transparent px-0 d-flex justify-content-between\"><span class=\"text-secondary\">协议</span><span>HTTP/1.1</span></li><li class=\"list-group-item bg-transparent px-0 d-flex justify-content-between\"><span class=\"text-secondary\">Accept depth</span><span class=\"mono\">32</span></li><li class=\"list-group-item bg-transparent px-0 d-flex justify-content-between\"><span class=\"text-secondary\">失败</span><span id=\"failed\" class=\"mono\">--</span></li></ul><p id=\"updated\" class=\"small text-secondary mt-4 mb-0\">正在读取服务器状态…</p></div></div>\n"
    "    </section>\n"
    "    <section class=\"mb-5\"><div class=\"section-kicker\">Network resources</div><div class=\"d-flex justify-content-between align-items-end mb-3\"><h2 class=\"h3 mt-2 mb-0\">在线资源</h2><span class=\"small text-secondary\">均从公网按需加载</span></div><div class=\"row g-3\">\n"
    "      <div class=\"col-md-6 col-xl-3\"><a class=\"glass resource rounded-4 p-4 h-100 d-block\" href=\"https://getbootstrap.com/\" target=\"_blank\" rel=\"noopener\"><i class=\"bi bi-bootstrap-fill\"></i><h3 class=\"h5 mt-3\">Bootstrap 5.3.8</h3><p class=\"small text-secondary mb-0\">响应式布局、组件和主题基础。</p></a></div>\n"
    "      <div class=\"col-md-6 col-xl-3\"><a class=\"glass resource rounded-4 p-4 h-100 d-block\" href=\"https://icons.getbootstrap.com/\" target=\"_blank\" rel=\"noopener\"><i class=\"bi bi-stars\"></i><h3 class=\"h5 mt-3\">Bootstrap Icons</h3><p class=\"small text-secondary mb-0\">两千余个开源矢量图标。</p></a></div>\n"
    "      <div class=\"col-md-6 col-xl-3\"><a class=\"glass resource rounded-4 p-4 h-100 d-block\" href=\"https://www.chartjs.org/\" target=\"_blank\" rel=\"noopener\"><i class=\"bi bi-graph-up-arrow\"></i><h3 class=\"h5 mt-3\">Chart.js 4.5.1</h3><p class=\"small text-secondary mb-0\">Canvas 实时状态趋势图。</p></a></div>\n"
    "      <div class=\"col-md-6 col-xl-3\"><a class=\"glass resource rounded-4 p-4 h-100 d-block\" href=\"https://fonts.google.com/specimen/Inter\" target=\"_blank\" rel=\"noopener\"><i class=\"bi bi-fonts\"></i><h3 class=\"h5 mt-3\">Google Fonts</h3><p class=\"small text-secondary mb-0\">Inter 与 JetBrains Mono 在线字体。</p></a></div>\n"
    "    </div></section>\n"
    "    <footer class=\"d-flex flex-column flex-md-row justify-content-between gap-2 border-top border-secondary border-opacity-25 py-4 text-secondary small\"><span>NetFast asynchronous userspace TCP/IP stack</span><a class=\"text-secondary\" href=\"https://unsplash.com/collections/9279263/cloud-datacenter\" target=\"_blank\" rel=\"noopener\">数据中心图片来源：Unsplash</a></footer>\n"
    "  </main>\n"
    "  <script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js\" integrity=\"sha384-FKyoEForCGlyvwx9Hj09JcYn3nv7wiPVlz7YYwJrWVcXK/BmnVDxM+D2scQbITxI\" crossorigin=\"anonymous\"></script>\n"
    "  <script src=\"https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js\"></script>\n"
    "  <script>\n"
    "    const labels=[],requestPoints=[],activePoints=[];\n"
    "    const chart=window.Chart?new Chart(document.querySelector('#traffic-chart'),{type:'line',data:{labels,datasets:[{label:'累计请求',data:requestPoints,borderColor:'#38bdf8',backgroundColor:'rgba(56,189,248,.12)',fill:true,tension:.35},{label:'活动连接',data:activePoints,borderColor:'#34d399',backgroundColor:'rgba(52,211,153,.08)',fill:true,tension:.35}]},options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{labels:{color:'#cbd5e1',usePointStyle:true}}},scales:{x:{ticks:{color:'#64748b'},grid:{color:'rgba(148,163,184,.08)'}},y:{beginAtZero:true,ticks:{color:'#64748b',precision:0},grid:{color:'rgba(148,163,184,.08)'}}}}}):null;\n"
    "    async function refresh(){try{const r=await fetch('/api/status',{cache:'no-store'});if(!r.ok)throw new Error(`HTTP ${r.status}`);const s=await r.json();for(const [id,key] of [['active','active'],['requests','requests'],['completed','completed'],['uptime','uptime_seconds'],['failed','failed']])document.querySelector('#'+id).textContent=s[key];const stamp=new Date().toLocaleTimeString();document.querySelector('#updated').textContent=`最后更新 ${stamp} · 已接受 ${s.accepted} 个连接`;document.querySelector('#nav-status').textContent='Async server online';if(chart){labels.push(stamp);requestPoints.push(s.requests);activePoints.push(s.active);if(labels.length>20){labels.shift();requestPoints.shift();activePoints.shift();}chart.update('none');}}catch(e){document.querySelector('#updated').textContent='状态读取失败：'+e.message;document.querySelector('#nav-status').textContent='Status unavailable';}}\n"
    "    refresh();setInterval(refresh,2000);\n"
    "  </script>\n"
    "</body>\n"
    "</html>\n";

static void http_log(const char *level, const char *format, ...)
{
    struct timespec now;
    struct tm local;
    char stamp[32];
    va_list arguments;

    clock_gettime(CLOCK_REALTIME, &now);
    localtime_r(&now.tv_sec, &local);
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &local);
    fprintf(stderr, "%s.%03ld [http-async] [%s] ", stamp,
            now.tv_nsec / 1000000L, level);
    va_start(arguments, format);
    vfprintf(stderr, format, arguments);
    va_end(arguments);
    fputc('\n', stderr);
    fflush(stderr);
}

static void stop_server(int signal_number)
{
    (void)signal_number;
    g_stop = 1;
}

static const char *operation_name(http_operation_kind kind)
{
    switch (kind) {
    case HTTP_OP_ACCEPT: return "accept";
    case HTTP_OP_READ:   return "read";
    case HTTP_OP_WRITE:  return "write";
    case HTTP_OP_CLOSE:  return "close";
    }
    return "unknown";
}

static http_operation *operation_create(http_operation_kind kind,
                                        http_connection *connection)
{
    http_operation *operation = calloc(1, sizeof(*operation));
    if (!operation)
        return NULL;
    operation->kind = kind;
    operation->connection = connection;
    return operation;
}

static void operation_link(http_server *server, http_operation *operation)
{
    operation->next = server->operations;
    server->operations = operation;
}

static void operation_unlink(http_server *server, http_operation *operation)
{
    http_operation **link = &server->operations;
    while (*link && *link != operation)
        link = &(*link)->next;
    if (*link)
        *link = operation->next;
    operation->next = NULL;
}

static http_operation *operation_find(http_server *server,
                                      net_async_req *request)
{
    for (http_operation *operation = server->operations; operation;
         operation = operation->next) {
        if (operation->request == request)
            return operation;
    }
    return NULL;
}

static void connection_free(http_connection *connection)
{
    if (!connection)
        return;
    free(connection->response);
    free(connection);
}

static int submit_operation(http_server *server, http_operation *operation)
{
    http_connection *connection = operation->connection;

    switch (operation->kind) {
    case HTTP_OP_ACCEPT:
        operation->peer_length = sizeof(operation->peer);
        operation->request = net_async_req_create(
            server->listen_fd, NET_ASYNC_ACCEPT,
            (struct sockaddr *)&operation->peer, &operation->peer_length);
        break;
    case HTTP_OP_READ:
        operation->request = net_async_req_create(
            connection->fd, NET_ASYNC_READ,
            connection->request + connection->request_length,
            (uint32_t)(HTTP_REQUEST_CAPACITY - connection->request_length));
        break;
    case HTTP_OP_WRITE:
        operation->request = net_async_req_create(
            connection->fd, NET_ASYNC_WRITE,
            connection->response + connection->response_offset,
            (uint32_t)(connection->response_length -
                       connection->response_offset));
        break;
    case HTTP_OP_CLOSE:
        operation->request = net_async_req_create(connection->fd,
                                                   NET_ASYNC_CLOSE);
        break;
    }

    if (!operation->request)
        return -1;
    operation_link(server, operation);
    if (net_async_submit(server->cq_fd, operation->request) == 0)
        return 0;

    int saved_errno = errno;
    operation_unlink(server, operation);
    net_async_req_destroy(operation->request);
    operation->request = NULL;
    errno = saved_errno;
    return -1;
}

static int submit_accept(http_server *server)
{
    http_operation *operation = operation_create(HTTP_OP_ACCEPT, NULL);
    if (!operation)
        return -1;
    if (submit_operation(server, operation) == 0) {
        server->accepts_pending++;
        return 0;
    }
    free(operation);
    return -1;
}

static int fill_accept_pipeline(http_server *server)
{
    while (!g_stop && server->accepts_pending < HTTP_ACCEPT_DEPTH) {
        if (submit_accept(server) != 0)
            return -1;
    }
    return 0;
}

static int submit_connection_operation(http_connection *connection,
                                       http_operation_kind kind)
{
    http_operation *operation = operation_create(kind, connection);
    if (!operation)
        return -1;
    if (submit_operation(connection->server, operation) == 0)
        return 0;
    free(operation);
    return -1;
}

static void connection_discard(http_connection *connection, int error)
{
    http_server *server = connection->server;
    connection->failed = true;
    server->failed++;
    server->active--;
    http_log("ERROR", "conn=%llu fd=%d discarded: %s",
             (unsigned long long)connection->id, connection->fd,
             strerror(error));
    (void)net_close(connection->fd);
    connection_free(connection);
}

static int close_connection(http_connection *connection, bool failed)
{
    connection->failed |= failed;
    if (submit_connection_operation(connection, HTTP_OP_CLOSE) == 0)
        return 0;
    connection_discard(connection, errno);
    return -1;
}

static int build_response(http_connection *connection, int status,
                          const char *reason, const char *content_type,
                          const char *body, size_t body_length,
                          bool head_only)
{
    char header[512];
    int header_length = snprintf(
        header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Server: netfast-async\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n",
        status, reason, content_type, body_length);
    if (header_length < 0 || (size_t)header_length >= sizeof(header)) {
        errno = EOVERFLOW;
        return -1;
    }

    size_t wire_body_length = head_only ? 0 : body_length;
    connection->response_length = (size_t)header_length + wire_body_length;
    connection->response = malloc(connection->response_length);
    if (!connection->response)
        return -1;
    memcpy(connection->response, header, (size_t)header_length);
    if (wire_body_length)
        memcpy(connection->response + header_length, body, wire_body_length);
    return 0;
}

static int prepare_response(http_connection *connection)
{
    http_server *server = connection->server;
    char method[8];
    char path[512];
    char version[16];
    char *line_end;

    connection->request[connection->request_length] = '\0';
    line_end = strstr(connection->request, "\r\n");
    if (!line_end || sscanf(connection->request, "%7s %511s %15s",
                            method, path, version) != 3) {
        static const char body[] = "bad request\n";
        return build_response(connection, 400, "Bad Request", "text/plain; charset=utf-8",
                              body, sizeof(body) - 1U, false);
    }

    bool head_only = strcmp(method, "HEAD") == 0;
    if (strcmp(method, "GET") != 0 && !head_only) {
        static const char body[] = "method not allowed\n";
        return build_response(connection, 405, "Method Not Allowed",
                              "text/plain; charset=utf-8", body,
                              sizeof(body) - 1U, false);
    }
    if (strncmp(version, "HTTP/1.", 7) != 0) {
        static const char body[] = "HTTP version not supported\n";
        return build_response(connection, 505, "HTTP Version Not Supported",
                              "text/plain; charset=utf-8", body,
                              sizeof(body) - 1U, head_only);
    }

    char *query = strchr(path, '?');
    if (query)
        *query = '\0';
    server->requests++;
    http_log("INFO", "conn=%llu fd=%d %s %s",
             (unsigned long long)connection->id, connection->fd, method, path);

    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        return build_response(connection, 200, "OK", "text/html; charset=utf-8",
                              INDEX_HTML, sizeof(INDEX_HTML) - 1U, head_only);
    }
    if (strcmp(path, "/healthz") == 0) {
        static const char body[] = "ok\n";
        return build_response(connection, 200, "OK", "text/plain; charset=utf-8",
                              body, sizeof(body) - 1U, head_only);
    }
    if (strcmp(path, "/api/status") == 0) {
        struct timespec now;
        char body[256];
        clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t uptime = (uint64_t)(now.tv_sec - server->started.tv_sec);
        int length = snprintf(
            body, sizeof(body),
            "{\"status\":\"ok\",\"uptime_seconds\":%llu,"
            "\"active\":%llu,\"accepted\":%llu,\"requests\":%llu,"
            "\"completed\":%llu,\"failed\":%llu}\n",
            (unsigned long long)uptime,
            (unsigned long long)server->active,
            (unsigned long long)server->accepted,
            (unsigned long long)server->requests,
            (unsigned long long)server->completed,
            (unsigned long long)server->failed);
        if (length < 0 || (size_t)length >= sizeof(body)) {
            errno = EOVERFLOW;
            return -1;
        }
        return build_response(connection, 200, "OK",
                              "application/json; charset=utf-8", body,
                              (size_t)length, head_only);
    }
    if (strcmp(path, "/favicon.ico") == 0)
        return build_response(connection, 204, "No Content", "text/plain", "", 0, true);

    static const char body[] = "not found\n";
    return build_response(connection, 404, "Not Found", "text/plain; charset=utf-8",
                          body, sizeof(body) - 1U, head_only);
}

static int complete_accept(http_server *server, http_operation *operation,
                           int result)
{
    server->accepts_pending--;
    if (fill_accept_pipeline(server) != 0)
        http_log("ERROR", "replenish accept pipeline: %s", strerror(errno));
    if (result < 0) {
        if (!g_stop)
            http_log("ERROR", "accept failed: %s", strerror(-result));
        return g_stop ? 0 : -1;
    }

    http_connection *connection = calloc(1, sizeof(*connection));
    if (!connection) {
        (void)net_close(result);
        return -1;
    }
    connection->server = server;
    connection->id = server->next_connection_id++;
    connection->fd = result;
    server->accepted++;
    server->active++;

    char peer[INET6_ADDRSTRLEN] = "unknown";
    uint16_t port = 0;
    if (operation->peer.ss_family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)&operation->peer;
        (void)inet_ntop(AF_INET, &address->sin_addr, peer, sizeof(peer));
        port = ntohs(address->sin_port);
    } else if (operation->peer.ss_family == AF_INET6) {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)&operation->peer;
        (void)inet_ntop(AF_INET6, &address->sin6_addr, peer, sizeof(peer));
        port = ntohs(address->sin6_port);
    }
    http_log("INFO", "conn=%llu accepted fd=%d peer=%s:%u",
             (unsigned long long)connection->id, connection->fd, peer, port);

    if (submit_connection_operation(connection, HTTP_OP_READ) == 0)
        return 0;
    connection_discard(connection, errno);
    return -1;
}

static int complete_read(http_connection *connection, int result)
{
    if (result <= 0)
        return close_connection(connection, result < 0);
    connection->request_length += (size_t)result;
    connection->request[connection->request_length] = '\0';

    if (!strstr(connection->request, "\r\n\r\n")) {
        if (connection->request_length < HTTP_REQUEST_CAPACITY) {
            if (submit_connection_operation(connection, HTTP_OP_READ) == 0)
                return 0;
            return close_connection(connection, true);
        }
        static const char body[] = "request header too large\n";
        if (build_response(connection, 431, "Request Header Fields Too Large",
                           "text/plain; charset=utf-8", body,
                           sizeof(body) - 1U, false) != 0)
            return close_connection(connection, true);
    } else if (prepare_response(connection) != 0) {
        http_log("ERROR", "conn=%llu build response: %s",
                 (unsigned long long)connection->id, strerror(errno));
        return close_connection(connection, true);
    }
    if (submit_connection_operation(connection, HTTP_OP_WRITE) == 0)
        return 0;
    return close_connection(connection, true);
}

static int complete_write(http_connection *connection, int result)
{
    if (result <= 0)
        return close_connection(connection, true);
    connection->response_offset += (size_t)result;
    if (connection->response_offset < connection->response_length) {
        if (submit_connection_operation(connection, HTTP_OP_WRITE) == 0)
            return 0;
        return close_connection(connection, true);
    }
    return close_connection(connection, false);
}

static int complete_operation(http_server *server, net_async_req *request)
{
    http_operation *operation = operation_find(server, request);
    if (!operation) {
        net_async_req_destroy(request);
        errno = ENOENT;
        return -1;
    }
    operation_unlink(server, operation);
    http_connection *connection = operation->connection;
    int result = request->ret;
    int type = request->type;
    int async_fd = request->async_fd;
    http_log("DEBUG", "op=%s type=%d fd=%d ret=%d",
             operation_name(operation->kind), type, async_fd, result);
    net_async_req_destroy(request);

    int ret;
    switch (operation->kind) {
    case HTTP_OP_ACCEPT:
        ret = complete_accept(server, operation, result);
        break;
    case HTTP_OP_READ:
        ret = complete_read(connection, result);
        break;
    case HTTP_OP_WRITE:
        ret = complete_write(connection, result);
        break;
    case HTTP_OP_CLOSE:
        server->active--;
        if (connection->failed || result < 0)
            server->failed++;
        else
            server->completed++;
        http_log(result < 0 ? "ERROR" : "INFO",
                 "conn=%llu closed fd=%d ret=%d",
                 (unsigned long long)connection->id, connection->fd, result);
        connection_free(connection);
        ret = result < 0 ? -1 : 0;
        break;
    default:
        errno = EINVAL;
        ret = -1;
        break;
    }
    free(operation);
    return ret;
}

static int wait_setup_request(http_server *server, net_async_req *request,
                              const char *name)
{
    if (!request)
        return -1;
    if (net_async_submit(server->cq_fd, request) != 0) {
        int saved_errno = errno;
        net_async_req_destroy(request);
        errno = saved_errno;
        return -1;
    }

    net_async_req *completed = NULL;
    int count = net_async_wait(server->cq_fd, &completed, 1, 1, 5000);
    if (count != 1 || completed != request) {
        if (completed)
            net_async_req_destroy(completed);
        errno = count < 0 ? errno : ETIMEDOUT;
        return -1;
    }
    int result = completed->ret;
    http_log("DEBUG", "setup=%s type=%d fd=%d ret=%d", name,
             completed->type, completed->async_fd, result);
    net_async_req_destroy(completed);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}

static int setup_listener(http_server *server)
{
    server->listen_fd = wait_setup_request(
        server, net_async_req_create(-1, NET_ASYNC_SOCKET,
                                     AF_INET, SOCK_STREAM, IPPROTO_TCP),
        "socket");
    if (server->listen_fd < 0)
        return -1;

    int reuse = 1;
    if (wait_setup_request(
            server, net_async_req_create(server->listen_fd,
                NET_ASYNC_SETSOCKOPT, SOL_SOCKET, SO_REUSEADDR, &reuse,
                (socklen_t)sizeof(reuse)), "setsockopt") < 0)
        return -1;

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(HTTP_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (wait_setup_request(
            server, net_async_req_create(server->listen_fd, NET_ASYNC_BIND,
                (const struct sockaddr *)&address,
                (socklen_t)sizeof(address)), "bind") < 0)
        return -1;
    if (wait_setup_request(
            server, net_async_req_create(server->listen_fd, NET_ASYNC_LISTEN,
                                         HTTP_BACKLOG), "listen") < 0)
        return -1;
    return 0;
}

int main(void)
{
    http_server server = {
        .cq_fd = -1,
        .listen_fd = -1,
        .next_connection_id = 1,
    };
    signal(SIGINT, stop_server);
    signal(SIGTERM, stop_server);
    clock_gettime(CLOCK_MONOTONIC, &server.started);

    server.cq_fd = net_async_create();
    if (server.cq_fd < 0) {
        perror("net_async_create");
        return 1;
    }
    if (setup_listener(&server) != 0) {
        perror("setup async HTTP listener");
        (void)net_async_close(server.cq_fd);
        return 1;
    }
    if (fill_accept_pipeline(&server) != 0) {
        perror("submit async accepts");
        (void)net_close(server.listen_fd);
        (void)net_async_close(server.cq_fd);
        return 1;
    }

    http_log("INFO", "listening on 0.0.0.0:%u accept-depth=%u",
             HTTP_PORT, HTTP_ACCEPT_DEPTH);
    while (!g_stop) {
        net_async_req *completed[HTTP_COMPLETION_BATCH];
        int count = net_async_wait(server.cq_fd, completed, 1,
                                   HTTP_COMPLETION_BATCH, 1000);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            http_log("ERROR", "completion wait: %s", strerror(errno));
            break;
        }
        for (int index = 0; index < count; ++index) {
            if (complete_operation(&server, completed[index]) != 0 && !g_stop)
                http_log("ERROR", "completion handling failed: %s",
                         strerror(errno));
        }
    }

    http_log("INFO",
             "stopping accepted=%llu requests=%llu completed=%llu failed=%llu active=%llu",
             (unsigned long long)server.accepted,
             (unsigned long long)server.requests,
             (unsigned long long)server.completed,
             (unsigned long long)server.failed,
             (unsigned long long)server.active);
    if (server.listen_fd >= 0)
        (void)net_close(server.listen_fd);
    (void)net_async_close(server.cq_fd);
    return 0;
}
