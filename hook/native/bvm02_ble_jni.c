/*
 * BVM02 Battery Monitor for Gen5W (Android 4.4.2 KitKat, ARMv7-A)
 * Coexistence-safe Broadcom Bluedroid (bplus.default.so) HCI LE / ACL bridge.
 *
 * Loaded strictly inside com.android.bluetooth via standard System.load() on the
 * PackageManager-extracted APK library (/data/app-lib/bvm02.app-1/libbvm02_ble.so).
 *
 * Coexistence invariants:
 *  1. Never calls HCI_Reset and never touches Classic BR/EDR HFP or A2DP ACL handles.
 *  2. Intercepts HCI_BLE_EVENT (0x3E) which stock Gen5W bplus.default.so (BLE_INCLUDED=FALSE)
 *     otherwise drops, and tracks active LE connection handles immediately upon subevent
 *     0x01 / 0x0A so early peripheral ACL frames never race userspace.
 *  3. Filters Disconnection_Complete (0x05), Encryption_Change (0x08), Key_Refresh (0x30),
 *     Number_Of_Completed_Packets (0x13), and inbound ACL (0x1100) strictly for the active
 *     LE connection handle so Classic L2CAP credit windows are never perturbed.
 *  4. Sends HCI commands on Bluedroid's own BTU_TASK (0x1600 -> btu_hcif_send_cmd) so
 *     HCI Command_Complete / Command_Status credit accounting stays 100% serialized.
 */

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uintptr_t;
typedef long ssize_t;
typedef unsigned int size_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

#define ANDROID_LOG_INFO  4
#define ANDROID_LOG_WARN  5
#define ANDROID_LOG_ERROR 6
#define LOG_TAG           "bvm02-jni"

#define RTLD_LAZY 1
#define F_GETFL   3
#define F_SETFL   4
#define O_NONBLOCK_ARM 0x0800

/* Bluedroid HC_BT_HDR event masks (verified in bplus.default.so) */
#define MSG_MASK_SUB_EVENT        0xFF00u
#define MSG_HC_TO_STACK_HCI_ACL   0x1100u
#define MSG_HC_TO_STACK_HCI_EVT   0x1000u
#define MSG_STACK_TO_HC_HCI_ACL   0x2100u
#define BT_EVT_TO_BTU_HCIT_CMD    0x1600u

#define BTU_TASK_ID               0u
#define BTU_HCI_RCV_MBOX          0u

/* Pipe framing between Java (BtNativeBridge) and C */
#define TX_CMD_SEND_HCI           1u
#define TX_CMD_SEND_ACL           2u

#define RX_TYPE_ACL               0x02u
#define RX_TYPE_EVT               0x04u

#define INVALID_LE_HANDLE         0xFFFFu

/* Linked dynamically against Android 4.4 Bionic libc.so, libdl.so, liblog.so */
extern int __android_log_print(int prio, const char *tag, const char *fmt, ...);
extern void *dlopen(const char *filename, int flag);
extern void *dlsym(void *handle, const char *symbol);
extern const char *dlerror(void);

extern ssize_t read(int fd, void *buf, size_t count);
extern ssize_t write(int fd, const void *buf, size_t count);
extern int close(int fd);
extern int dup(int oldfd);
extern int fcntl(int fd, int cmd, ...);
extern int usleep(unsigned int usec);
extern void *memcpy(void *dest, const void *src, size_t n);
extern void *memset(void *s, int c, size_t n);

typedef long pthread_t;
extern int pthread_create(pthread_t *thread, const void *attr, void *(*start_routine)(void *), void *arg);
extern int pthread_detach(pthread_t thread);

/* Bluedroid HC_BT_HDR (8-byte header immediately preceding packet payload) */
typedef struct {
    uint16_t event;
    uint16_t len;
    uint16_t offset;
    uint16_t layer_specific;
} hc_bt_hdr_t;

typedef const void *(*fn_bt_hc_get_interface_t)(void);
typedef int (*fn_transmit_buf_t)(void *p_mem, char *p_buf, int len);
typedef int (*fn_dealloc_t)(void *p_transac, char *p_buf);
typedef int (*fn_data_ind_t)(void *p_transac, char *p_buf, int len);

typedef void *(*fn_gki_getbuf_t)(uint16_t size);
typedef void (*fn_gki_freebuf_t)(void *p_buf);
typedef uint8_t (*fn_gki_send_msg_t)(uint8_t task_id, uint8_t mbox, void *p_msg);

/* Global state */
static void ***g_p_bt_hc_cbacks = NULL;
static void **g_orig_cbacks_ptr = NULL;
static void *g_my_cbacks[10];

static fn_bt_hc_get_interface_t g_bt_hc_get_interface = NULL;
static fn_transmit_buf_t g_fn_transmit_buf = NULL;
static fn_dealloc_t g_orig_dealloc = NULL;
static fn_data_ind_t g_orig_data_ind = NULL;

static fn_gki_getbuf_t g_gki_getbuf = NULL;
static fn_gki_freebuf_t g_gki_freebuf = NULL;
static fn_gki_send_msg_t g_gki_send_msg = NULL;

#define MAX_LE_HANDLES            8u
#define HANDLE_OP_KEEP            (-1)
#define HANDLE_OP_CLEAR_ALL       (-2)
#define HANDLE_OP_UNTRACK_FLAG    0x10000

static volatile int g_hook_installed = 0;
static volatile int g_worker_running = 0;
static volatile int g_ble_listening = 0;
static volatile unsigned int g_le_handles[MAX_LE_HANDLES] = {
    INVALID_LE_HANDLE, INVALID_LE_HANDLE, INVALID_LE_HANDLE, INVALID_LE_HANDLE,
    INVALID_LE_HANDLE, INVALID_LE_HANDLE, INVALID_LE_HANDLE, INVALID_LE_HANDLE
};

static int g_tx_read_fd = -1;
static int g_rx_write_fd = -1;

static volatile int g_stat_rx_evt = 0;
static volatile int g_stat_rx_acl = 0;
static volatile int g_stat_tx_hci = 0;
static volatile int g_stat_tx_acl = 0;
static volatile int g_stat_rx_drop = 0;

static int is_tracked_le_handle(unsigned int h) {
    unsigned int i;
    if (h > 0x0EFFu) {
        return 0;
    }
    for (i = 0; i < MAX_LE_HANDLES; i++) {
        if (g_le_handles[i] == h) {
            return 1;
        }
    }
    return 0;
}

static void track_le_handle(unsigned int h) {
    unsigned int i;
    if (h > 0x0EFFu) {
        return;
    }
    for (i = 0; i < MAX_LE_HANDLES; i++) {
        if (g_le_handles[i] == h) {
            return;
        }
    }
    for (i = 0; i < MAX_LE_HANDLES; i++) {
        if (g_le_handles[i] == INVALID_LE_HANDLE) {
            g_le_handles[i] = h;
            __sync_synchronize();
            return;
        }
    }
    /* Table full: overwrite last slot as safety fallback */
    g_le_handles[MAX_LE_HANDLES - 1u] = h;
    __sync_synchronize();
}

static void untrack_le_handle(unsigned int h) {
    unsigned int i;
    if (h > 0x0EFFu) {
        return;
    }
    for (i = 0; i < MAX_LE_HANDLES; i++) {
        if (g_le_handles[i] == h) {
            g_le_handles[i] = INVALID_LE_HANDLE;
        }
    }
    __sync_synchronize();
}

static void clear_all_le_handles(void) {
    unsigned int i;
    for (i = 0; i < MAX_LE_HANDLES; i++) {
        g_le_handles[i] = INVALID_LE_HANDLE;
    }
    __sync_synchronize();
}

static unsigned int first_tracked_le_handle(void) {
    unsigned int i;
    for (i = 0; i < MAX_LE_HANDLES; i++) {
        unsigned int h = g_le_handles[i];
        if (h <= 0x0EFFu) {
            return h;
        }
    }
    return INVALID_LE_HANDLE;
}

static int count_tracked_le_handles(void) {
    unsigned int i;
    int cnt = 0;
    for (i = 0; i < MAX_LE_HANDLES; i++) {
        if (g_le_handles[i] <= 0x0EFFu) {
            cnt++;
        }
    }
    return cnt;
}

static void emit_rx_frame(uint8_t pkt_type, const uint8_t *payload, uint16_t payload_len) {
    int fd = g_rx_write_fd;
    uint8_t frame[1040];
    uint32_t total;
    ssize_t wr;

    if (fd < 0 || payload == NULL || payload_len == 0 || payload_len > 1028u) {
        return;
    }
    frame[0] = pkt_type;
    frame[1] = 0;
    frame[2] = (uint8_t)(payload_len & 0xFFu);
    frame[3] = (uint8_t)((payload_len >> 8) & 0xFFu);
    memcpy(&frame[4], payload, payload_len);
    total = (uint32_t)payload_len + 4u;

    /* Single write <= PIPE_BUF (4096) on non-blocking pipe is atomic in Linux */
    wr = write(fd, frame, total);
    if (wr != (ssize_t)total) {
        g_stat_rx_drop++;
    }
}

static int my_data_ind(void *p_transac, char *p_buf, int len) {
    fn_data_ind_t orig_ind = g_orig_data_ind;
    fn_dealloc_t orig_dealloc = g_orig_dealloc;
    hc_bt_hdr_t *hdr;
    uint16_t ev_hi;
    uint16_t pkt_len;
    uint8_t *pkt;

    if (p_transac == NULL) {
        return orig_ind ? orig_ind(p_transac, p_buf, len) : 0;
    }

    hdr = (hc_bt_hdr_t *)p_transac;
    ev_hi = (uint16_t)(hdr->event & MSG_MASK_SUB_EVENT);
    pkt_len = hdr->len;
    pkt = ((uint8_t *)hdr) + 8u + hdr->offset;

    if (ev_hi == MSG_HC_TO_STACK_HCI_EVT && pkt_len >= 2u) {
        uint8_t ev_code = pkt[0];

        /* 1. HCI_BLE_EVENT (0x3E): stock Gen5W bplus.default.so drops 0x3E (BLE_INCLUDED=FALSE) */
        if (ev_code == 0x3Eu) {
            if (pkt_len >= 6u && g_ble_listening) {
                uint8_t sub = pkt[2];
                uint8_t status = pkt[3];
                /* Subevent 0x01 (LE_Connection_Complete) or 0x0A (LE_Enhanced_Connection_Complete) */
                if ((sub == 0x01u || sub == 0x0Au) && status == 0x00u) {
                    unsigned int h = (unsigned int)pkt[4] | (((unsigned int)(pkt[5] & 0x0Fu)) << 8);
                    track_le_handle(h);
                }
            }
            if (g_ble_listening) {
                g_stat_rx_evt++;
                emit_rx_frame(RX_TYPE_EVT, pkt, pkt_len);
            }
            if (orig_dealloc != NULL) {
                orig_dealloc(p_transac, p_buf);
            } else if (g_gki_freebuf != NULL) {
                g_gki_freebuf(p_transac);
            }
            return 0;
        }

        /* 2. Disconnection_Complete (0x05), Encryption_Change (0x08), Encryption_Key_Refresh (0x30) */
        if ((ev_code == 0x05u && pkt_len >= 6u)
                || (ev_code == 0x08u && pkt_len >= 5u)
                || (ev_code == 0x30u && pkt_len >= 5u)) {
            unsigned int ev_h = (unsigned int)pkt[3] | (((unsigned int)(pkt[4] & 0x0Fu)) << 8);
            if (is_tracked_le_handle(ev_h)) {
                if (ev_code == 0x05u && pkt[2] == 0x00u) {
                    untrack_le_handle(ev_h);
                }
                g_stat_rx_evt++;
                emit_rx_frame(RX_TYPE_EVT, pkt, pkt_len);
                if (orig_dealloc != NULL) {
                    orig_dealloc(p_transac, p_buf);
                } else if (g_gki_freebuf != NULL) {
                    g_gki_freebuf(p_transac);
                }
                return 0;
            }
        }

        /* 3. Number_Of_Completed_Packets (0x13): protect Classic L2CAP controller_xmit_window */
        if (ev_code == 0x13u && pkt_len >= 3u) {
            uint8_t num_h = pkt[2];
            if (num_h > 0u && (uint16_t)(3u + ((uint16_t)num_h * 4u)) <= pkt_len) {
                uint8_t i;
                uint8_t matched_count = 0u;
                for (i = 0; i < num_h; i++) {
                    uint16_t base = (uint16_t)(3u + ((uint16_t)i * 4u));
                    unsigned int eh = (unsigned int)pkt[base] | (((unsigned int)(pkt[base + 1u] & 0x0Fu)) << 8);
                    if (is_tracked_le_handle(eh)) {
                        matched_count++;
                    }
                }
                if (matched_count > 0u) {
                    g_stat_rx_evt++;
                    emit_rx_frame(RX_TYPE_EVT, pkt, pkt_len);
                    if (matched_count == num_h) {
                        if (orig_dealloc != NULL) {
                            orig_dealloc(p_transac, p_buf);
                        } else if (g_gki_freebuf != NULL) {
                            g_gki_freebuf(p_transac);
                        }
                        return 0;
                    }
                    /* Batched Classic + LE credits: zero all tracked LE handle counts before forwarding to Bluedroid */
                    for (i = 0; i < num_h; i++) {
                        uint16_t base = (uint16_t)(3u + ((uint16_t)i * 4u));
                        unsigned int eh = (unsigned int)pkt[base] | (((unsigned int)(pkt[base + 1u] & 0x0Fu)) << 8);
                        if (is_tracked_le_handle(eh)) {
                            pkt[base + 2u] = 0;
                            pkt[base + 3u] = 0;
                        }
                    }
                    return orig_ind ? orig_ind(p_transac, p_buf, len) : 0;
                }
            }
        }

        /* 4. Command_Complete (0x0E) & Command_Status (0x0F): copy to Java AND pass to Bluedroid */
        if ((ev_code == 0x0Eu || ev_code == 0x0Fu) && g_ble_listening) {
            g_stat_rx_evt++;
            emit_rx_frame(RX_TYPE_EVT, pkt, pkt_len);
        }

        return orig_ind ? orig_ind(p_transac, p_buf, len) : 0;
    }

    if (ev_hi == MSG_HC_TO_STACK_HCI_ACL && pkt_len >= 4u) {
        unsigned int acl_h = (unsigned int)pkt[0] | (((unsigned int)(pkt[1] & 0x0Fu)) << 8);
        if (is_tracked_le_handle(acl_h)) {
            g_stat_rx_acl++;
            emit_rx_frame(RX_TYPE_ACL, pkt, pkt_len);
            if (orig_dealloc != NULL) {
                orig_dealloc(p_transac, p_buf);
            } else if (g_gki_freebuf != NULL) {
                g_gki_freebuf(p_transac);
            }
            return 0;
        }
    }

    return orig_ind ? orig_ind(p_transac, p_buf, len) : 0;
}

static int ensure_cbacks_hooked(void) {
    void **cur;
    int i;

    if (g_p_bt_hc_cbacks == NULL || g_bt_hc_get_interface == NULL) {
        return -4;
    }

    if (g_fn_transmit_buf == NULL) {
        const void *hc_if = g_bt_hc_get_interface();
        if (hc_if != NULL) {
            void * const *if_words = (void * const *)hc_if;
            g_fn_transmit_buf = (fn_transmit_buf_t)if_words[6];
        }
    }
    if (g_fn_transmit_buf == NULL) {
        return -6;
    }

    cur = *g_p_bt_hc_cbacks;
    if (cur == NULL) {
        g_hook_installed = 0;
        return -5; /* Bluetooth adapter currently OFF / hc_if not initialized yet */
    }
    if (cur == g_my_cbacks) {
        g_hook_installed = 1;
        return 0;
    }

    /* bt_hc_callbacks_t size on Android 4.4 KitKat is 40 bytes (0x28 = 10 32-bit words) */
    if ((uintptr_t)cur[0] != 0x28u || cur[7] == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                "Unexpected bt_hc_callbacks_t header size=0x%x data_ind=%p",
                (unsigned int)(uintptr_t)cur[0], cur[7]);
        return -7;
    }

    for (i = 0; i < 10; i++) {
        g_my_cbacks[i] = cur[i];
    }
    g_orig_cbacks_ptr = cur;
    g_orig_dealloc = (fn_dealloc_t)cur[6];
    g_orig_data_ind = (fn_data_ind_t)cur[7];
    g_my_cbacks[7] = (void *)&my_data_ind;

    __sync_synchronize();
    *g_p_bt_hc_cbacks = g_my_cbacks;
    __sync_synchronize();

    g_hook_installed = 1;
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "Installed coexistence-safe bt_hc_cbacks->data_ind filter (orig=%p, tx=%p)",
            (void *)g_orig_data_ind, (void *)g_fn_transmit_buf);
    return 0;
}

static int read_exact(int fd, uint8_t *buf, uint32_t len) {
    uint32_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n <= 0) {
            return -1;
        }
        off += (uint32_t)n;
    }
    return 0;
}

static void *tx_worker_loop(void *arg) {
    int fd = (int)(uintptr_t)arg;
    uint8_t hdr_buf[4];
    uint8_t payload[1028];

    g_worker_running = 1;
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "TX worker started on fd=%d", fd);

    while (read_exact(fd, hdr_buf, 4u) == 0) {
        uint8_t cmd = hdr_buf[0];
        uint16_t plen = (uint16_t)hdr_buf[2] | ((uint16_t)hdr_buf[3] << 8);

        if (plen == 0u || plen > 1024u) {
            if (plen > 0u) {
                uint16_t rem = plen;
                while (rem > 0u) {
                    uint16_t chunk = rem > 512u ? 512u : rem;
                    if (read_exact(fd, payload, chunk) != 0) {
                        goto out;
                    }
                    rem = (uint16_t)(rem - chunk);
                }
            }
            continue;
        }

        if (read_exact(fd, payload, plen) != 0) {
            break;
        }

        if (ensure_cbacks_hooked() != 0) {
            continue;
        }

        if (cmd == TX_CMD_SEND_HCI && plen >= 3u) {
            hc_bt_hdr_t *msg = (hc_bt_hdr_t *)g_gki_getbuf((uint16_t)(plen + 16u));
            if (msg != NULL) {
                msg->event = BT_EVT_TO_BTU_HCIT_CMD;
                msg->len = plen;
                msg->offset = 0;
                msg->layer_specific = 0;
                memcpy(((uint8_t *)msg) + 8u, payload, plen);
                if (g_gki_send_msg(BTU_TASK_ID, BTU_HCI_RCV_MBOX, msg) == 0u) {
                    g_stat_tx_hci++;
                }
            }
        } else if (cmd == TX_CMD_SEND_ACL && plen >= 4u && g_fn_transmit_buf != NULL) {
            hc_bt_hdr_t *msg = (hc_bt_hdr_t *)g_gki_getbuf((uint16_t)(plen + 16u));
            if (msg != NULL) {
                msg->event = MSG_STACK_TO_HC_HCI_ACL;
                msg->len = plen;
                msg->offset = 0;
                msg->layer_specific = 0;
                memcpy(((uint8_t *)msg) + 8u, payload, plen);
                g_fn_transmit_buf(msg, ((char *)msg) + 8, (int)plen);
                g_stat_tx_acl++;
            }
        }
    }

out:
    close(fd);
    if (g_tx_read_fd == fd) {
        g_tx_read_fd = -1;
    }
    g_worker_running = 0;
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "TX worker exiting");
    return NULL;
}

/*
 * Standard JNI exports for package bvm02.hook.BtNativeBridge.
 * Uses strictly primitive 32-bit integer arguments (ARM AAPCS r0..r3) so zero
 * JNINativeInterface vtable indices or NDK headers are required.
 */
__attribute__((visibility("default")))
int Java_bvm02_hook_BtNativeBridge_nativeInit(void *env, void *clazz, int tx_read_fd, int rx_write_fd) {
    void *h;
    int dup_tx;
    int dup_rx;
    int fl;
    int rc;
    pthread_t tid;

    (void)env;
    (void)clazz;

    if (g_worker_running && g_rx_write_fd >= 0) {
        rc = ensure_cbacks_hooked();
        return (rc == 0 || rc == -5) ? 0 : rc;
    }

    if (tx_read_fd < 0 || rx_write_fd < 0) {
        return -1;
    }

    h = dlopen("/system/lib/hw/bplus.default.so", RTLD_LAZY);
    if (h == NULL) {
        h = dlopen("bplus.default.so", RTLD_LAZY);
    }
    if (h == NULL) {
        const char *err = dlerror();
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                "dlopen(bplus.default.so) failed: %s", err ? err : "unknown");
        return -2;
    }

    g_p_bt_hc_cbacks = (void ***)dlsym(h, "bt_hc_cbacks");
    g_bt_hc_get_interface = (fn_bt_hc_get_interface_t)dlsym(h, "bt_hc_get_interface");
    g_gki_getbuf = (fn_gki_getbuf_t)dlsym(h, "GKI_getbuf");
    g_gki_freebuf = (fn_gki_freebuf_t)dlsym(h, "GKI_freebuf");
    g_gki_send_msg = (fn_gki_send_msg_t)dlsym(h, "GKI_send_msg");

    if (g_p_bt_hc_cbacks == NULL
            || g_bt_hc_get_interface == NULL
            || g_gki_getbuf == NULL
            || g_gki_freebuf == NULL
            || g_gki_send_msg == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
                "Missing bplus symbols: cbacks=%p get_if=%p getbuf=%p freebuf=%p send_msg=%p",
                (void *)g_p_bt_hc_cbacks,
                (void *)g_bt_hc_get_interface,
                (void *)g_gki_getbuf,
                (void *)g_gki_freebuf,
                (void *)g_gki_send_msg);
        return -3;
    }

    dup_tx = dup(tx_read_fd);
    dup_rx = dup(rx_write_fd);
    if (dup_tx < 0 || dup_rx < 0) {
        if (dup_tx >= 0) close(dup_tx);
        if (dup_rx >= 0) close(dup_rx);
        return -8;
    }

    fl = fcntl(dup_rx, F_GETFL, 0);
    if (fl >= 0) {
        fcntl(dup_rx, F_SETFL, fl | O_NONBLOCK_ARM);
    }

    g_tx_read_fd = dup_tx;
    g_rx_write_fd = dup_rx;
    __sync_synchronize();

    rc = ensure_cbacks_hooked();
    if (rc != 0 && rc != -5) {
        close(dup_tx);
        close(dup_rx);
        g_tx_read_fd = -1;
        g_rx_write_fd = -1;
        return rc;
    }

    tid = 0;
    if (pthread_create(&tid, NULL, &tx_worker_loop, (void *)(uintptr_t)dup_tx) != 0) {
        close(dup_tx);
        close(dup_rx);
        g_tx_read_fd = -1;
        g_rx_write_fd = -1;
        return -9;
    }
    pthread_detach(tid);
    return 0;
}

__attribute__((visibility("default")))
int Java_bvm02_hook_BtNativeBridge_nativeSetState(void *env, void *clazz, int ble_listening, int active_le_handle) {
    (void)env;
    (void)clazz;

    g_ble_listening = ble_listening ? 1 : 0;
    if (active_le_handle == HANDLE_OP_CLEAR_ALL) {
        clear_all_le_handles();
    } else if (active_le_handle == HANDLE_OP_KEEP) {
        /* Keep existing tracked LE handles intact */
    } else if (active_le_handle > 0 && (active_le_handle & HANDLE_OP_UNTRACK_FLAG) != 0) {
        untrack_le_handle((unsigned int)(active_le_handle & 0x0FFF));
    } else if (active_le_handle >= 0 && active_le_handle <= 0x0EFF) {
        track_le_handle((unsigned int)active_le_handle);
    }
    __sync_synchronize();

    if (g_ble_listening) {
        return ensure_cbacks_hooked();
    }
    return 0;
}

__attribute__((visibility("default")))
int Java_bvm02_hook_BtNativeBridge_nativeGetStat(void *env, void *clazz, int which) {
    (void)env;
    (void)clazz;

    switch (which) {
        case 0:
            ensure_cbacks_hooked();
            return g_hook_installed;
        case 1: return g_worker_running;
        case 2: return g_stat_rx_evt;
        case 3: return g_stat_rx_acl;
        case 4: return g_stat_tx_hci;
        case 5: return g_stat_tx_acl;
        case 6: return g_stat_rx_drop;
        case 7: return (int)first_tracked_le_handle();
        case 8: return count_tracked_le_handles();
        default: return -1;
    }
}

__attribute__((visibility("default")))
void Java_bvm02_hook_BtNativeBridge_nativeShutdown(void *env, void *clazz) {
    (void)env;
    (void)clazz;

    g_ble_listening = 0;
    clear_all_le_handles();
    __sync_synchronize();

    if (g_p_bt_hc_cbacks != NULL && *g_p_bt_hc_cbacks == g_my_cbacks && g_orig_cbacks_ptr != NULL) {
        *g_p_bt_hc_cbacks = g_orig_cbacks_ptr;
        __sync_synchronize();
    }
    g_hook_installed = 0;
}

