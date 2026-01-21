idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_wifi esp_netif lwip esp_http_client esp_http_server cJSON esp_http_client
                    PRIV_REQUIRES nvs_flash esp_driver_gpio)
