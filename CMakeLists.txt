idf_component_register(SRCS "src/ProvisioningManager.cpp" "src/esp_qrcode_main.c" "src/qrcodegen.c"
                    INCLUDE_DIRS "include"
                    REQUIRES
                    nvs_flash
                    wifi_provisioning
                    esp_http_client
                    esp_https_ota
                    app_update
                    )

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-missing-field-initializers)