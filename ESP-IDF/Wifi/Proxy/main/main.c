#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "esp_http_client.h"
#include <inttypes.h>
#include "cJSON.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_http_server.h"

#define ESP_POOL_SIZE 10

static TaskHandle_t relay_tasks[ESP_POOL_SIZE] = {0};


#define LISTEN_PORT 4000
#define TAG "ESP_RELAY"

static EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

#include "driver/gpio.h"

#define LED_WIFI GPIO_NUM_48
#define LED_VPS  GPIO_NUM_38

static volatile bool wifi_connected = false;
static volatile bool vps_connected  = false;

static char public_ip[48]   = "unknown";
static char geo_city[48]   = "unknown";
static char geo_region[48] = "unknown";
static char geo_postal[16] = "unknown";
static char geo_country[48]= "unknown";
static char geo_continent[32]= "unknown";

static uint64_t forwarded_connections = 0;

typedef struct {
    uint32_t ip;
    uint32_t count;
} ip_stat_t;

#define MAX_IP_STATS 32
static ip_stat_t ip_stats[MAX_IP_STATS];

static void record_ip(uint32_t ip)
{
    for (int i = 0; i < MAX_IP_STATS; i++) {
        if (ip_stats[i].ip == ip) {
            ip_stats[i].count++;
            return;
        }
        if (ip_stats[i].ip == 0) {
            ip_stats[i].ip = ip;
            ip_stats[i].count = 1;
            return;
        }
    }
}

static void led_init(void)
{
    gpio_config_t io = {
        .pin_bit_mask = (1ULL << LED_WIFI) | (1ULL << LED_VPS),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = 0,
        .pull_down_en = 0,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&io);

    gpio_set_level(LED_WIFI, 0);
    gpio_set_level(LED_VPS, 0);
}

static void log_sta_ip(void) {
    esp_netif_ip_info_t ip_info;
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");

    if (esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK) {
        ESP_LOGI(TAG, "STA IP: " IPSTR, IP2STR(&ip_info.ip));
    } else {
        ESP_LOGW(TAG, "Failed to get STA IP");
    }
}

static void clear_wifi_creds(void)
{
    ESP_LOGI(TAG, "clear_wifi_creds(): START");

    nvs_handle_t nvs;
    esp_err_t err = nvs_open("wifi", NVS_READWRITE, &nvs);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "clear_wifi_creds(): nvs_open failed: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG, "clear_wifi_creds(): nvs_erase_all()");
    err = nvs_erase_all(nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "clear_wifi_creds(): nvs_erase_all failed: %s", esp_err_to_name(err));
    }

    ESP_LOGI(TAG, "clear_wifi_creds(): nvs_commit()");
    err = nvs_commit(nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "clear_wifi_creds(): nvs_commit failed: %s", esp_err_to_name(err));
    }

    nvs_close(nvs);
    ESP_LOGI(TAG, "clear_wifi_creds(): DONE");
}

static void save_wifi_creds(const char *ssid, const char *pass)
{
    ESP_LOGI(TAG, "save_wifi_creds(): START");

    if (!ssid || !pass) {
        ESP_LOGE(TAG, "save_wifi_creds(): NULL argument (ssid=%p pass=%p)", ssid, pass);
        return;
    }

    ESP_LOGI(TAG, "save_wifi_creds(): SSID='%s' PASS='%s'", ssid, pass);

    nvs_handle_t nvs;
    esp_err_t err = nvs_open("wifi", NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save_wifi_creds(): nvs_open failed: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG, "save_wifi_creds(): nvs_set_str(ssid)");
    err = nvs_set_str(nvs, "ssid", ssid);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save_wifi_creds(): nvs_set_str(ssid) failed: %s", esp_err_to_name(err));
    }

    ESP_LOGI(TAG, "save_wifi_creds(): nvs_set_str(pass)");
    err = nvs_set_str(nvs, "pass", pass);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save_wifi_creds(): nvs_set_str(pass) failed: %s", esp_err_to_name(err));
    }

    ESP_LOGI(TAG, "save_wifi_creds(): nvs_commit()");
    err = nvs_commit(nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "save_wifi_creds(): nvs_commit failed: %s", esp_err_to_name(err));
    }

    nvs_close(nvs);
    ESP_LOGI(TAG, "save_wifi_creds(): DONE");
}

static esp_err_t load_wifi_creds(char *ssid, size_t ssid_max, char *pass, size_t pass_max)
{
    ESP_LOGI(TAG, "load_wifi_creds(): START");

    if (!ssid || !pass) {
        ESP_LOGE(TAG, "load_wifi_creds(): NULL pointer (ssid=%p pass=%p)", ssid, pass);
        return ESP_ERR_INVALID_ARG;
    }

    if (ssid_max < 2 || pass_max < 2) {
        ESP_LOGE(TAG, "load_wifi_creds(): buffers too small (ssid_max=%d pass_max=%d)", ssid_max, pass_max);
        return ESP_ERR_INVALID_SIZE;
    }

    memset(ssid, 0, ssid_max);
    memset(pass, 0, pass_max);

    ESP_LOGI(TAG, "load_wifi_creds(): Opening NVS (wifi)");
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("wifi", NVS_READONLY, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "load_wifi_creds(): nvs_open failed: %s", esp_err_to_name(err));
        return err;
    }

    size_t ssid_len = ssid_max;
    ESP_LOGI(TAG, "load_wifi_creds(): Reading SSID (max=%d)", ssid_max);
    err = nvs_get_str(nvs, "ssid", ssid, &ssid_len);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "load_wifi_creds(): SSID not found in NVS");
        nvs_close(nvs);
        return ESP_ERR_NVS_NOT_FOUND;
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "load_wifi_creds(): nvs_get_str(ssid) failed: %s", esp_err_to_name(err));
        nvs_close(nvs);
        return err;
    }

    ESP_LOGI(TAG, "load_wifi_creds(): SSID read OK (len=%d)", ssid_len);

    size_t pass_len = pass_max;
    ESP_LOGI(TAG, "load_wifi_creds(): Reading PASS (max=%d)", pass_max);
    err = nvs_get_str(nvs, "pass", pass, &pass_len);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "load_wifi_creds(): PASS not found in NVS");
        nvs_close(nvs);
        return ESP_ERR_NVS_NOT_FOUND;
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "load_wifi_creds(): nvs_get_str(pass) failed: %s", esp_err_to_name(err));
        nvs_close(nvs);
        return err;
    }

    ESP_LOGI(TAG, "load_wifi_creds(): PASS read OK (len=%d)", pass_len);

    nvs_close(nvs);

    if (ssid_len >= ssid_max || pass_len >= pass_max) {
        ESP_LOGE(TAG, "load_wifi_creds(): String too long or not null terminated (ssid_len=%d pass_len=%d)", ssid_len, pass_len);
        return ESP_ERR_INVALID_SIZE;
    }

    if (ssid_len == 0 || pass_len == 0) {
        ESP_LOGW(TAG, "load_wifi_creds(): SSID or PASS empty (ssid_len=%d pass_len=%d)", ssid_len, pass_len);
        return ESP_ERR_INVALID_SIZE;
    }

    ESP_LOGI(TAG, "load_wifi_creds(): SSID='%s' PASS='%s'", ssid, pass);

    // Print hex dump for debugging corruption
    ESP_LOGI(TAG, "load_wifi_creds(): SSID HEX DUMP");
    for (size_t i = 0; i < ssid_len; i++) {
        ESP_LOGI(TAG, "  ssid[%d]=0x%02X '%c'", i, (unsigned char)ssid[i], ssid[i]);
    }

    ESP_LOGI(TAG, "load_wifi_creds(): PASS HEX DUMP");
    for (size_t i = 0; i < pass_len; i++) {
        ESP_LOGI(TAG, "  pass[%d]=0x%02X '%c'", i, (unsigned char)pass[i], pass[i]);
    }

    ESP_LOGI(TAG, "load_wifi_creds(): DONE");

    return ESP_OK;
}

static void wifi_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        wifi_connected = true;
        gpio_set_level(LED_WIFI, 1);
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }

    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_connected = false;
        gpio_set_level(LED_WIFI, 0);
    }
}

// ================= WIFI =================

static void wifi_init_apsta(void) {
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    wifi_config_t ap = {
        .ap = {
            .ssid = "ESP_Config",
            .ssid_len = 0,
            .password = "datapowercable",
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK
        }
    };

    wifi_event_group = xEventGroupCreate();

    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_handler, NULL);
    esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &wifi_handler, NULL);

    wifi_config_t sta;
    memset(&sta, 0, sizeof(sta));

    esp_err_t creds_ok = load_wifi_creds(
    (char *)sta.sta.ssid, sizeof(sta.sta.ssid),
    (char *)sta.sta.password, sizeof(sta.sta.password)
);
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP, &ap);

    if (sta.sta.ssid[31] != '\0' || sta.sta.password[63] != '\0') {
        ESP_LOGE(TAG, "Corrupted WiFi creds, erasing");
        clear_wifi_creds();
    }

    if (creds_ok == ESP_OK &&
    sta.sta.ssid[0] != '\0' &&
    sta.sta.password[0] != '\0') {
        ESP_LOGI(TAG, "Using stored WiFi credentials: %s", sta.sta.ssid);
        esp_wifi_set_config(WIFI_IF_STA, &sta);
    }

    esp_wifi_start();

    if (creds_ok == ESP_OK)
        esp_wifi_connect();
}

static esp_err_t wifi_scan(wifi_ap_record_t **out, uint16_t *count) {
    wifi_scan_config_t scan = { 0 };
    esp_wifi_scan_start(&scan, true);

    esp_wifi_scan_get_ap_num(count);
    *out = malloc(sizeof(wifi_ap_record_t) * (*count));
    return esp_wifi_scan_get_ap_records(count, *out);
}

static esp_err_t scan_handler(httpd_req_t *req) {
    wifi_ap_record_t *aps;
    uint16_t count;

    wifi_scan(&aps, &count);

    httpd_resp_sendstr_chunk(req, "[");
    for (int i = 0; i < count; i++) {
        httpd_resp_sendstr_chunk(req, "\"");
        httpd_resp_sendstr_chunk(req, (char *)aps[i].ssid);
        httpd_resp_sendstr_chunk(req, i == count - 1 ? "\"" : "\",");
    }
    httpd_resp_sendstr_chunk(req, "]");
    httpd_resp_sendstr_chunk(req, NULL);

    free(aps);
    return ESP_OK;
}

static esp_err_t status_handler(httpd_req_t *req)
{
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"wifi\":%s,"
        "\"vps\":%s,"
        "\"ip\":\"%s\","
        "\"continent\":\"%s\","
        "\"country\":\"%s\","
        "\"region\":\"%s\","
        "\"postal\":\"%s\","
        "\"city\":\"%s\","
        "\"forwarded\":%" PRIu64
        "}",
        wifi_connected ? "true" : "false",
        vps_connected  ? "true" : "false",
        public_ip,
        geo_continent,
        geo_country,
        geo_region,
        geo_postal,
        geo_city,
        forwarded_connections
    );

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t stats_handler(httpd_req_t *req)
{
    httpd_resp_sendstr_chunk(req, "{");

    for (int i = 0; i < MAX_IP_STATS; i++) {
        if (ip_stats[i].ip) {
            char ip[16];
            snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
                ((uint8_t*)&ip_stats[i].ip)[0],
                ((uint8_t*)&ip_stats[i].ip)[1],
                ((uint8_t*)&ip_stats[i].ip)[2],
                ((uint8_t*)&ip_stats[i].ip)[3]);

            char line[64];
            snprintf(line, sizeof(line),
    "\"%s\":%" PRIu32 ",", ip, ip_stats[i].count);
            httpd_resp_sendstr_chunk(req, line);
        }
    }
    httpd_resp_sendstr_chunk(req, "\"_\":\"_\"}");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t clear_handler(httpd_req_t *req) {
    clear_wifi_creds();
    httpd_resp_sendstr(req, "Credentials erased. Rebooting...");
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    esp_restart();
    return ESP_OK;
}

static char hex2char(char h) {
    if (h >= '0' && h <= '9') return h - '0';
    if (h >= 'A' && h <= 'F') return h - 'A' + 10;
    if (h >= 'a' && h <= 'f') return h - 'a' + 10;
    return 0;
}

static void url_decode(char *dst, const char *src) {
    while (*src) {
        if (*src == '%') {
            char hi = hex2char(*(src + 1));
            char lo = hex2char(*(src + 2));
            *dst++ = (hi << 4) | lo;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = 0;
}


static esp_err_t save_handler(httpd_req_t *req) {
    char buf[128];
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    buf[len] = 0;

    char ssid_enc[64], pass_enc[128];
    sscanf(buf, "ssid=%63[^&]&pass=%127s", ssid_enc, pass_enc);

    char ssid[32], pass[64];
    url_decode(ssid, ssid_enc);
    url_decode(pass, pass_enc);

    ESP_LOGI(TAG, "Saving WiFi creds: SSID=%s PASS=%s", ssid, pass);
    save_wifi_creds(ssid, pass);

    httpd_resp_sendstr(req, "Saved. Rebooting...");
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    esp_restart();
    return ESP_OK;
}

static esp_err_t root_handler(httpd_req_t *req) {
    const char html[] =
"<!DOCTYPE html>\n"
"<html>\n"
"<head>\n"
"<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
"<style>\n"
"body { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 20px; }\n"
"h2, h3 { color: #ffffff; margin-bottom: 8px; }\n"
"select, input { width: 100%; max-width: 400px; padding: 8px; margin: 6px 0; border-radius: 6px; border: 1px solid #444; background-color: #1e1e1e; color: #fff; font-size: 14px; box-sizing: border-box; }\n"
"button { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; }\n"
"button:hover { opacity: 0.9; }\n"
"button.erase { background-color:#ff4c4c;color:#fff; }\n"
"hr { border: 1px solid #333; margin: 12px 0; }\n"
"#pieContainer { position: relative; width: 100%; max-width: 300px; margin-top: 12px; }\n"
"#pie { width: 100%; height: auto; display:block; }\n"
"#pieLegend { margin-top: 12px; font-size: 12px; }\n"
".legend-item { display: flex; align-items: center; margin-bottom: 4px; }\n"
".legend-color { width: 14px; height: 14px; margin-right: 6px; border-radius: 3px; display: inline-block; transition: transform 0.2s; }\n"
".legend-item.highlight .legend-color { transform: scale(1.3); }\n"
"@media (max-width: 500px) { body { padding: 10px; } select, input { font-size: 16px; } button { font-size: 16px; padding: 10px 20px; } }\n"
"</style>\n"
"</head>\n"
"<body>\n"

"<h2>WiFi Setup</h2>\n"
"<select id='s'></select><br><br>\n"
"<input id='p' type='password' placeholder='Password'><br><br>\n"
"<button onclick='save()'>Save</button><br><br>\n"
"<hr>\n"
"<button class='erase' onclick='clearCreds()'>Erase WiFi Credentials</button>\n"

"<h3>Status</h3>\n"
"WiFi: <span id='wifi'></span><br>\n"
"VPS: <span id='vps'></span><br>\n"
"<hr>\n"
"<h3>Public Location</h3>\n"
"IP: <span id='ip'></span><br>\n"
"Continent: <span id='continent'></span><br>\n"
"Country: <span id='country'></span><br>\n"
"Region: <span id='region'></span><br>\n"
"City: <span id='city'></span><br>\n"
"Postal: <span id='postal'></span><br>\n"
"Forwarded connections: <span id='cnt'></span><br>\n"

"<div id='pieContainer'>\n"
"<canvas id='pie' width='300' height='300'></canvas>\n"
"<div id='pieLegend'></div>\n"
"</div>\n"

"<script>\n"
"fetch('/scan').then(r=>r.json()).then(l=>{\n"
"  let s = document.getElementById('s');\n"
"  l.forEach(x=>{\n"
"    let o = document.createElement('option');\n"
"    o.text = x;\n"
"    s.add(o);\n"
"  });\n"
"});\n"

"function save() {\n"
"  let ssid = document.getElementById('s').value;\n"
"  let p = document.getElementById('p').value;\n"
"  fetch('/save', {\n"
"    method: 'POST',\n"
"    headers: {'Content-Type': 'application/x-www-form-urlencoded'},\n"
"    body: 'ssid=' + ssid + '&pass=' + p\n"
"  });\n"
"}\n"

"function clearCreds() {\n"
"  if(confirm('Erase stored WiFi credentials?')) {\n"
"    fetch('/clear', {method:'POST'});\n"
"  }\n"
"}\n"

"function updateStatus() {\n"
"  fetch('/status').then(r=>r.json()).then(s=>{\n"
"    wifi.textContent = s.wifi?'✅':'❌';\n"
"    vps.textContent  = s.vps?'✅':'❌';\n"
"    ip.textContent        = s.ip;\n"
"    continent.textContent = s.continent;\n"
"    country.textContent   = s.country;\n"
"    region.textContent    = s.region;\n"
"    city.textContent      = s.city;\n"
"    postal.textContent    = s.postal;\n"
"    cnt.textContent       = s.forwarded;\n"
"  });\n"
"}\n"

"let hoverIndex = -1;\n"

"function drawPie(data) {\n"
"  let entries = Object.entries(data).filter(([k,v]) => k !== '_');\n"
"  let total = entries.reduce((a,[k,v]) => a+v, 0);\n"
"  if(!total) return;\n"
"  let c = document.getElementById('pie');\n"
"  let ctx = c.getContext('2d');\n"
"  ctx.clearRect(0,0,c.width,c.height);\n"
"  let start = 0;\n"
"  let legendHTML = '';\n"
"  entries.forEach(([k,v],i)=>{\n"
"    let slice = v/total * Math.PI*2;\n"
"    ctx.beginPath();\n"
"    ctx.moveTo(c.width/2, c.height/2);\n"
"    ctx.arc(c.width/2, c.height/2, c.width/2-10, start, start+slice);\n"
"    ctx.fillStyle = `hsl(${i*40},70%,60%)`;\n"
"    ctx.fill();\n"
"    legendHTML += `<div class='legend-item ${i===hoverIndex?'highlight':''}' data-index='${i}'><span class='legend-color' style='background:${ctx.fillStyle}'></span>${k}: ${v}</div>`;\n"
"    start += slice;\n"
"  });\n"
"  document.getElementById('pieLegend').innerHTML = legendHTML;\n"
"  document.querySelectorAll('.legend-item').forEach(item=>{\n"
"    item.onmouseenter = ()=>{ hoverIndex=parseInt(item.dataset.index); drawPie(data); };\n"
"    item.onmouseleave = ()=>{ hoverIndex=-1; drawPie(data); };\n"
"  });\n"
"}\n"

"document.getElementById('pie').onmousemove = e=>{\n"
"  let rect = e.target.getBoundingClientRect();\n"
"  let x = e.clientX - rect.left - rect.width/2;\n"
"  let y = e.clientY - rect.top - rect.height/2;\n"
"  let angle = Math.atan2(y,x);\n"
"  if(angle<0) angle+=Math.PI*2;\n"
"  let entries = Object.entries(data).filter(([k,v])=>k!=='_');\n"
"  let total = entries.reduce((a,[k,v])=>a+v,0);\n"
"  let start = 0;\n"
"  for(let i=0;i<entries.length;i++){\n"
"    let slice = entries[i][1]/total * Math.PI*2;\n"
"    if(angle>=start && angle<=start+slice){ hoverIndex=i; drawPie(data); break; }\n"
"    start += slice;\n"
"  }\n"
"};\n"

"let data={};\n"
"setInterval(()=>{fetch('/stats').then(r=>r.json()).then(j=>{data=j; drawPie(data);});},4000);\n"
"setInterval(updateStatus, 2000);\n"
"updateStatus();\n"

"</script>\n"
"</body>\n"
"</html>";

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t favicon_handler(httpd_req_t *req) {
    httpd_resp_send(req, "", 0);
    return ESP_OK;
}


static void start_web(void) {
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size = 8192; 
    httpd_handle_t srv;

    httpd_start(&srv, &cfg);
        httpd_uri_t stats = {
        .uri = "/stats",
        .method = HTTP_GET,
        .handler = stats_handler
    };
    httpd_register_uri_handler(srv, &stats);

    httpd_uri_t fav = {
        .uri = "/favicon.ico",
        .method = HTTP_GET,
        .handler = favicon_handler
    };
    httpd_register_uri_handler(srv, &fav);

    httpd_uri_t root = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_handler
    };

    httpd_uri_t clear = {
        .uri = "/clear",
        .method = HTTP_POST,
        .handler = clear_handler
    };

    httpd_register_uri_handler(srv, &clear);


    httpd_register_uri_handler(srv, &root);

    httpd_uri_t scan = {
        .uri = "/scan",
        .method = HTTP_GET,
        .handler = scan_handler
    };

    httpd_uri_t save = {
        .uri = "/save",
        .method = HTTP_POST,
        .handler = save_handler
    };

    httpd_register_uri_handler(srv, &scan);
    httpd_register_uri_handler(srv, &save);

    httpd_uri_t status = {
        .uri = "/status",
        .method = HTTP_GET,
        .handler = status_handler
    };
    httpd_register_uri_handler(srv, &status);
}

// ================= RELAY =================

static void relay(int a, int b) {
    char buf[1460];
    fd_set r;

    while (1) {
        FD_ZERO(&r);
        FD_SET(a, &r);
        FD_SET(b, &r);

        int m = a > b ? a : b;
        if (select(m + 1, &r, NULL, NULL, NULL) <= 0)
            break;

        if (FD_ISSET(a, &r)) {
            int n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(b, buf, n, 0);
        }

        if (FD_ISSET(b, &r)) {
            int n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(a, buf, n, 0);
        }
    }
}

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };
    struct addrinfo *res = NULL;

    int err = getaddrinfo(host, port, &hints, &res);
    if (err != 0 || res == NULL) {
        ESP_LOGE(TAG, "getaddrinfo failed (%d)", err);
        return -1;
    }

    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) {
        ESP_LOGE(TAG, "socket() failed");
        freeaddrinfo(res);
        return -1;
    }

    if (connect(s, res->ai_addr, res->ai_addrlen) != 0) {
        ESP_LOGE(TAG, "connect() failed");
        close(s);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return s;
}

typedef struct {
    char *buffer;
    size_t len;
    size_t capacity;
} http_buffer_t;

esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    http_buffer_t *buf = evt->user_data;

    switch (evt->event_id) {
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;

        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGI(TAG, "HTTP_EVENT_HEADER_SENT");
            break;

        case HTTP_EVENT_ON_HEADER:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_HEADER: %.*s", evt->data_len, (char*)evt->data);
            break;

        case HTTP_EVENT_ON_DATA:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_DATA: %d bytes", evt->data_len);
            if (!buf) break;

            // Reallocate if buffer is not enough
            if (buf->len + evt->data_len >= buf->capacity) {
                size_t new_cap = buf->capacity * 2 + evt->data_len;
                char *new_buf = realloc(buf->buffer, new_cap);
                if (!new_buf) {
                    ESP_LOGE(TAG, "Failed to realloc buffer");
                    break;
                }
                buf->buffer = new_buf;
                buf->capacity = new_cap;
            }

            memcpy(buf->buffer + buf->len, evt->data, evt->data_len);
            buf->len += evt->data_len;
            break;

        case HTTP_EVENT_ON_FINISH:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
            break;

        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            break;

        case HTTP_EVENT_REDIRECT:
            ESP_LOGI(TAG, "HTTP_EVENT_REDIRECT: %.*s", evt->data_len, (char*)evt->data);
            break;

        default:
            ESP_LOGI(TAG, "HTTP_EVENT_UNKNOWN: %d", evt->event_id);
            break;
    }
    return ESP_OK;
}

static void fetch_public_ip_task(void *arg) {
    ESP_LOGI(TAG, "=== Starting public IP fetch task ===");

    while(!wifi_connected) {
        ESP_LOGI(TAG, "WiFi not connected, waiting 500ms...");
        vTaskDelay(500 / portTICK_PERIOD_MS);
    }
    ESP_LOGI(TAG, "WiFi connected.");
    log_sta_ip();

    vTaskDelay(5000 / portTICK_PERIOD_MS); // small delay before first fetch
    ESP_LOGI(TAG, "Initial delay done, preparing HTTP client...");

    while (1) {
        ESP_LOGI(TAG, "--- Fetching public IP from ipwho.is ---");

        http_buffer_t buf = {0};
        buf.capacity = 2048;
        buf.buffer = malloc(buf.capacity);
        if (!buf.buffer) {
            ESP_LOGE(TAG, "Failed to allocate initial buffer");
            vTaskDelay(5 * 60 * 1000 / portTICK_PERIOD_MS);
            continue;
        }
        buf.len = 0;

        esp_http_client_config_t cfg = {
            .url = "http://ipwho.is/",
            .timeout_ms = 5000,
            .transport_type = HTTP_TRANSPORT_OVER_TCP,
            .disable_auto_redirect = false,
            .event_handler = http_event_handler,
            .user_data = &buf,
        };

        esp_http_client_handle_t cli = esp_http_client_init(&cfg);
        if (!cli) {
            ESP_LOGE(TAG, "Failed to init HTTP client");
            free(buf.buffer);
            vTaskDelay(5 * 60 * 1000 / portTICK_PERIOD_MS);
            continue;
        }

        esp_http_client_set_method(cli, HTTP_METHOD_GET);
        esp_http_client_set_header(cli, "Connection", "close");
        esp_err_t err = esp_http_client_set_header(cli, "Accept-Encoding", "identity");
        ESP_LOGI(TAG, "Set header Accept-Encoding: identity, result: %d", err);

        ESP_LOGI(TAG, "Performing HTTP GET...");
        err = esp_http_client_perform(cli);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "HTTP GET failed: %s", esp_err_to_name(err));
            esp_http_client_cleanup(cli);
            free(buf.buffer);
            vTaskDelay(5 * 60 * 1000 / portTICK_PERIOD_MS);
            continue;
        }
        ESP_LOGI(TAG, "HTTP GET completed. Total data collected: %d bytes", buf.len);

        // Null-terminate
        if (buf.len >= buf.capacity) buf.len = buf.capacity - 1;
        buf.buffer[buf.len] = 0;

        ESP_LOGI(TAG, "Full response:\n%s", buf.buffer);

        // --- JSON parsing ---
        ESP_LOGI(TAG, "Parsing JSON...");
        cJSON *j = cJSON_Parse(buf.buffer);
        if (!j) {
            ESP_LOGE(TAG, "Failed to parse JSON");
        } else {
            ESP_LOGI(TAG, "JSON parsed successfully.");

            cJSON *ok = cJSON_GetObjectItem(j, "success");
            if (ok && ok->valueint) {
                ESP_LOGI(TAG, "success=true in JSON");

                #define COPY(dst, obj, key) \
                    do { cJSON *x = cJSON_GetObjectItem(obj, key); \
                    if (x && cJSON_IsString(x)) { \
                        snprintf(dst, sizeof(dst), "%s", x->valuestring); \
                        ESP_LOGI(TAG, "Copied %s: %s", key, dst); \
                    } } while(0)

                COPY(public_ip, j, "ip");
                COPY(geo_city, j, "city");
                COPY(geo_region, j, "region");
                COPY(geo_postal, j, "postal");
                COPY(geo_country, j, "country");
                COPY(geo_continent, j, "continent");

            } else {
                ESP_LOGE(TAG, "JSON success field not true");
            }

            cJSON_Delete(j);
        }

        ESP_LOGI(TAG, "Cleaning up HTTP client...");
        esp_http_client_cleanup(cli);
        free(buf.buffer);

        ESP_LOGI(TAG, "Task sleeping for 5 minutes before next fetch.");
        vTaskDelay(5 * 60 * 1000 / portTICK_PERIOD_MS);
    }
}
// ================= MAIN TASK =================

static void relay_worker_task(void *arg) {
    while (1) {
        int vps = tcp_connect("138.2.180.155", "4000");
        if (vps < 0) {
            vps_connected = false;
            gpio_set_level(LED_VPS, 0);
            vTaskDelay(8000 / portTICK_PERIOD_MS);
            continue;
        }

        vps_connected = true;
        gpio_set_level(LED_VPS, 1);
        ESP_LOGI(TAG, "Connected to VPS");


        uint8_t hdr[6];
        if (recv(vps, hdr, 6, MSG_WAITALL) != 6) {
            close(vps);
            vps_connected = false;
            gpio_set_level(LED_VPS, 0);
            continue;
        }
        ESP_LOGI(TAG, "Received request to %d.%d.%d.%d:%d",
                 hdr[0], hdr[1], hdr[2], hdr[3],
                 *(uint16_t *)(hdr + 4));

        struct sockaddr_in tgt = {
            .sin_family = AF_INET,
            .sin_port = *(uint16_t *)(hdr + 4)
        };
        memcpy(&tgt.sin_addr, hdr, 4);
        
        uint32_t dst_ip;
        memcpy(&dst_ip, hdr, 4);
        record_ip(dst_ip);

        int t = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(t, (struct sockaddr *)&tgt, sizeof(tgt)) != 0) {
            close(t);
            close(vps);
            vps_connected = false;
            gpio_set_level(LED_VPS, 0);
            continue;
        }

        relay(vps, t);
        forwarded_connections++;

        close(t);
        close(vps);

        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
}

static void relay_supervisor_task() {
        for (int i = 0; i < ESP_POOL_SIZE; i++) {
        ESP_LOGI(TAG, "Starting relay worker %d", i);
        xTaskCreate(
            relay_worker_task,
            "relay_worker",
            8192,
            NULL,
            5,
            NULL
        );
    }
}

void app_main(void) {
    led_init();
    wifi_init_apsta();
    start_web();
    xTaskCreate(fetch_public_ip_task, "ip_fetch", 8192, NULL, 5, NULL);
    relay_supervisor_task();
}
