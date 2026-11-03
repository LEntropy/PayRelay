/*
 * Reactor: one epoll thread owns every merchant connection.
 *
 * It only does cheap, non-blocking work: accept, buffer bytes, cut complete frames out of
 * the stream, enforce connection-level limits, and write replies. Anything that can block
 * (MySQL, the VAN round trip) runs on worker threads; workers hand replies back through a
 * queue and an eventfd, so sockets are only ever touched by this thread.
 */
#include "gateway.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_INFLIGHT_PER_CONN 32

typedef struct {
    int in_use;
    int fd;
    uint32_t gen;
    char ip[46];
    char buf[TG_MAX_FRAME * 2];
    size_t used;
    long long frame_start_ms;   /* when the current partial frame began, 0 if none */
    long long last_ms;
    int inflight;
    char *out;
    size_t out_len, out_cap;
    int close_after_flush;
} conn;

static conn conns[MAX_CONNS];
static int epfd, listen_fd, event_fd;
static atomic_int conn_count;

/* ---- job queue (reactor -> workers) ---------------------------------------------------- */

static gw_job *jobq;
static int jq_head, jq_tail, jq_n;
static pthread_mutex_t jq_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t jq_cond = PTHREAD_COND_INITIALIZER;

int jobq_push(const gw_job *j) {
    pthread_mutex_lock(&jq_lock);
    if (jq_n == JOB_QUEUE_CAP) {
        pthread_mutex_unlock(&jq_lock);
        return -1;
    }
    jobq[jq_tail] = *j;
    jq_tail = (jq_tail + 1) % JOB_QUEUE_CAP;
    jq_n++;
    pthread_cond_signal(&jq_cond);
    pthread_mutex_unlock(&jq_lock);
    return 0;
}

void jobq_pop(gw_job *j) {
    pthread_mutex_lock(&jq_lock);
    while (jq_n == 0) pthread_cond_wait(&jq_cond, &jq_lock);
    *j = jobq[jq_head];
    jq_head = (jq_head + 1) % JOB_QUEUE_CAP;
    jq_n--;
    pthread_mutex_unlock(&jq_lock);
}

int jobq_depth(void) {
    pthread_mutex_lock(&jq_lock);
    int n = jq_n;
    pthread_mutex_unlock(&jq_lock);
    return n;
}

/* ---- reply queue (workers -> reactor) -------------------------------------------------- */

typedef struct reply {
    struct reply *next;
    uint64_t conn_id;
    int close_ip;           /* close every connection from ip instead of replying */
    char ip[46];
    int close_after;
    size_t len;
    char data[];
} reply;

static reply *rq_head, *rq_tail;
static pthread_mutex_t rq_lock = PTHREAD_MUTEX_INITIALIZER;

static void rq_push(reply *r) {
    pthread_mutex_lock(&rq_lock);
    r->next = NULL;
    if (rq_tail) rq_tail->next = r;
    else rq_head = r;
    rq_tail = r;
    pthread_mutex_unlock(&rq_lock);
    uint64_t one = 1;
    ssize_t w = write(event_fd, &one, sizeof(one));
    (void)w;
}

void reply_post(uint64_t conn_id, const char *data, size_t len, int close_after) {
    reply *r = malloc(sizeof(reply) + len);
    if (!r) return;
    r->conn_id = conn_id;
    r->close_ip = 0;
    r->ip[0] = '\0';
    r->close_after = close_after;
    r->len = len;
    if (len) memcpy(r->data, data, len);
    rq_push(r);
}

void reactor_close_ip(const char *ip) {
    reply *r = malloc(sizeof(reply));
    if (!r) return;
    r->conn_id = 0;
    r->close_ip = 1;
    snprintf(r->ip, sizeof(r->ip), "%s", ip);
    r->close_after = 1;
    r->len = 0;
    rq_push(r);
}

int reactor_conn_count(void) { return atomic_load(&conn_count); }

/* ---- connections ---------------------------------------------------------------------- */

static uint64_t conn_id_of(int slot) { return ((uint64_t)conns[slot].gen << 32) | (uint32_t)slot; }

static conn *conn_by_id(uint64_t id) {
    uint32_t slot = (uint32_t)(id & 0xffffffffu);
    if (slot >= MAX_CONNS) return NULL;
    conn *c = &conns[slot];
    return c->in_use && c->gen == (uint32_t)(id >> 32) ? c : NULL;
}

static void conn_close(conn *c, const char *why) {
    if (!c->in_use) return;
    epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    free(c->out);
    c->out = NULL;
    c->out_len = c->out_cap = 0;
    c->in_use = 0;
    c->gen++;   /* replies still queued for the old id are dropped */
    atomic_fetch_sub(&conn_count, 1);
    atomic_fetch_sub(&STATS.conn_active, 1);
    if (why) LOG_INFO("reactor", "event=conn_closed ip=%s reason=%s", c->ip, why);
}

static void flush_out(conn *c) {
    while (c->out_len > 0) {
        ssize_t w = send(c->fd, c->out, c->out_len, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            conn_close(c, "write_error");
            return;
        }
        memmove(c->out, c->out + w, c->out_len - (size_t)w);
        c->out_len -= (size_t)w;
    }
    struct epoll_event ev = { .events = EPOLLIN | (c->out_len ? EPOLLOUT : 0) };
    ev.data.u32 = (uint32_t)(c - conns);
    epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
    if (c->out_len == 0 && c->close_after_flush) conn_close(c, "closed_after_reply");
}

static void queue_out(conn *c, const char *data, size_t len) {
    if (c->out_len + len > c->out_cap) {
        size_t cap = c->out_cap ? c->out_cap * 2 : 1024;
        while (cap < c->out_len + len) cap *= 2;
        char *p = realloc(c->out, cap);
        if (!p) {
            conn_close(c, "oom");
            return;
        }
        c->out = p;
        c->out_cap = cap;
    }
    memcpy(c->out + c->out_len, data, len);
    c->out_len += len;
}

static int ip_conn_count(const char *ip) {
    int n = 0;
    for (int i = 0; i < MAX_CONNS; i++) {
        if (conns[i].in_use && strcmp(conns[i].ip, ip) == 0) n++;
    }
    return n;
}

static void do_accept(void) {
    for (;;) {
        struct sockaddr_in a;
        socklen_t al = sizeof(a);
        int fd = accept4(listen_fd, (struct sockaddr *)&a, &al, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) return;
        char ip[46];
        inet_ntop(AF_INET, &a.sin_addr, ip, sizeof(ip));

        /* In-process deny list: still works if nftables is unavailable. */
        if (guard_is_banned(ip)) {
            close(fd);
            atomic_fetch_add(&STATS.conn_rejected, 1);
            continue;
        }
        if (ip_conn_count(ip) >= CFG.max_conn_per_ip) {
            close(fd);
            atomic_fetch_add(&STATS.conn_rejected, 1);
            guard_violation(ip, "conn_limit");
            continue;
        }
        int slot = -1;
        for (int i = 0; i < MAX_CONNS; i++) {
            if (!conns[i].in_use) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            close(fd);
            atomic_fetch_add(&STATS.conn_rejected, 1);
            continue;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        conn *c = &conns[slot];
        uint32_t gen = c->gen;
        memset(c, 0, sizeof(*c));
        c->gen = gen;
        c->in_use = 1;
        c->fd = fd;
        snprintf(c->ip, sizeof(c->ip), "%s", ip);
        c->last_ms = now_ms();
        struct epoll_event ev = { .events = EPOLLIN };
        ev.data.u32 = (uint32_t)slot;
        epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
        atomic_fetch_add(&conn_count, 1);
        atomic_fetch_add(&STATS.conn_accepted, 1);
        atomic_fetch_add(&STATS.conn_active, 1);
    }
}

/* Cuts complete frames out of the buffer and hands them to the workers. */
static void extract_frames(conn *c) {
    size_t off = 0;
    long long now = now_ms();
    while (c->used - off > 0) {
        size_t flen;
        tg_status st = tg_frame_length(c->buf + off, c->used - off, &flen);
        if (st == TG_E_INCOMPLETE) break;
        if (st != TG_OK) {
            /* The stream cannot be resynchronised after a bad length: drop the connection. */
            guard_violation(c->ip, "bad_length");
            atomic_fetch_add(&STATS.bad_format, 1);
            conn_close(c, "bad_length");
            return;
        }
        if (c->used - off < flen) break;
        if (c->inflight >= MAX_INFLIGHT_PER_CONN) {
            guard_violation(c->ip, "too_many_inflight");
            conn_close(c, "too_many_inflight");
            return;
        }
        gw_job j;
        j.conn_id = conn_id_of((int)(c - conns));
        snprintf(j.ip, sizeof(j.ip), "%s", c->ip);
        j.received_ms = now;
        j.len = flen;
        memcpy(j.data, c->buf + off, flen);
        if (jobq_push(&j) != 0) {
            atomic_fetch_add(&STATS.queue_full, 1);
            conn_close(c, "server_busy");
            return;
        }
        c->inflight++;
        atomic_fetch_add(&STATS.received, 1);
        off += flen;
    }
    if (off > 0) {
        memmove(c->buf, c->buf + off, c->used - off);
        c->used -= off;
        c->frame_start_ms = c->used ? now : 0;   /* leftover bytes start a new frame */
    } else if (c->used && !c->frame_start_ms) {
        c->frame_start_ms = now;
    }
}

static void do_read(conn *c) {
    for (;;) {
        if (c->used == sizeof(c->buf)) {
            guard_violation(c->ip, "buffer_full");
            conn_close(c, "buffer_full");
            return;
        }
        ssize_t r = recv(c->fd, c->buf + c->used, sizeof(c->buf) - c->used, 0);
        if (r > 0) {
            c->used += (size_t)r;
            c->last_ms = now_ms();
            extract_frames(c);
            if (!c->in_use) return;
            continue;
        }
        if (r == 0) {
            conn_close(c, NULL);
            return;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        conn_close(c, "read_error");
        return;
    }
}

static void drain_replies(void) {
    uint64_t v;
    ssize_t r = read(event_fd, &v, sizeof(v));
    (void)r;
    pthread_mutex_lock(&rq_lock);
    reply *list = rq_head;
    rq_head = rq_tail = NULL;
    pthread_mutex_unlock(&rq_lock);

    while (list) {
        reply *rp = list;
        list = list->next;
        if (rp->close_ip) {
            for (int i = 0; i < MAX_CONNS; i++) {
                if (conns[i].in_use && strcmp(conns[i].ip, rp->ip) == 0) conn_close(&conns[i], "banned");
            }
        } else {
            conn *c = conn_by_id(rp->conn_id);
            if (c) {
                if (c->inflight > 0) c->inflight--;
                if (rp->len) queue_out(c, rp->data, rp->len);
                if (c->in_use) {
                    if (rp->close_after) c->close_after_flush = 1;
                    flush_out(c);
                }
            }
        }
        free(rp);
    }
}

/* Slowloris defence and idle cleanup, run twice a second. */
static void check_timers(void) {
    long long now = now_ms();
    for (int i = 0; i < MAX_CONNS; i++) {
        conn *c = &conns[i];
        if (!c->in_use) continue;
        if (c->frame_start_ms && now - c->frame_start_ms > CFG.frame_timeout_ms) {
            guard_violation(c->ip, "slow_frame");
            conn_close(c, "slow_frame");
        } else if (c->inflight == 0 && now - c->last_ms > CFG.idle_timeout_ms) {
            conn_close(c, "idle");
        }
    }
}

int reactor_run(void) {
    jobq = calloc(JOB_QUEUE_CAP, sizeof(gw_job));
    if (!jobq) return -1;

    listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)CFG.listen_port),
                             .sin_addr.s_addr = INADDR_ANY };
    if (bind(listen_fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(listen_fd, 1024) != 0) {
        LOG_ERR("reactor", "event=listen_failed port=%d errno=%d", CFG.listen_port, errno);
        return -1;
    }
    epfd = epoll_create1(EPOLL_CLOEXEC);
    event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

    struct epoll_event ev = { .events = EPOLLIN };
    ev.data.u32 = UINT32_MAX;       /* listen socket */
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);
    ev.data.u32 = UINT32_MAX - 1;   /* worker replies */
    epoll_ctl(epfd, EPOLL_CTL_ADD, event_fd, &ev);
    LOG_INFO("reactor", "event=listening port=%d", CFG.listen_port);

    struct epoll_event events[256];
    long long last_timer = now_ms();
    for (;;) {
        int n = epoll_wait(epfd, events, 256, 500);
        for (int i = 0; i < n; i++) {
            uint32_t tag = events[i].data.u32;
            if (tag == UINT32_MAX) {
                do_accept();
            } else if (tag == UINT32_MAX - 1) {
                drain_replies();
            } else if (tag < MAX_CONNS && conns[tag].in_use) {
                conn *c = &conns[tag];
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    conn_close(c, NULL);
                    continue;
                }
                if (events[i].events & EPOLLOUT) flush_out(c);
                if (c->in_use && (events[i].events & EPOLLIN)) do_read(c);
            }
        }
        long long now = now_ms();
        if (now - last_timer >= 500) {
            check_timers();
            last_timer = now;
        }
    }
}
