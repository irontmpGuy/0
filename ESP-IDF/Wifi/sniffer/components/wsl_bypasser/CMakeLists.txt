idf_component_register(
    SRCS "src/wsl_bypasser.c"
    REQUIRES esp_wifi nvs_flash esp_http_server driver
    INCLUDE_DIRS "include"
)
target_link_libraries(${COMPONENT_LIB} -Wl,-zmuldefs)