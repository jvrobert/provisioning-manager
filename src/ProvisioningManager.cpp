#include "ProvisioningManager.h"

#include "qrcode.h"
#include "string.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"

#include <vector>

static const char *TAG = "ProvisioningManager";
#define PROV_TRANSPORT_SOFTAP "softap"
const int WIFI_CONNECTED_EVENT = BIT0;
#define PROV_QR_VERSION "v1"
#define QRCODE_BASE_URL "https://espressif.github.io/esp-jumpstart/qrcode.html"



ProvisioningManager *ProvisioningManager::s_instance = nullptr;

ProvisioningManager *ProvisioningManager::GetInstance()
{
    if (s_instance == nullptr)
    {
        s_instance = new ProvisioningManager();
    }
    return s_instance;
}

void ProvisioningManager::Start(bool autoUpdate)
{
    auto inst = GetInstance();
    inst->m_autoUpdate = autoUpdate;
    inst->Initialize();
}

esp_err_t ProvisioningManager::onHttpEvent(esp_http_client_event_t *evt)
{
    int code;
    switch (evt->event_id)
    {
    case HTTP_EVENT_ON_DATA:
        code = esp_http_client_get_status_code(evt->client);
        if (code != 200)
        {
            return ESP_OK;
        }
        if (evt->data_len > 64)
        {
            ESP_LOGE(TAG, "HTTP_EVENT_ON_DATA TOO LONG");
            return ESP_OK;
        }
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            memcpy(evt->user_data, evt->data, evt->data_len);
        }
        break;
    default:
        break;
    }
    return ESP_OK;
}

void Tokenize(const std::string &str,
              std::vector<std::string> &tokens,
              const std::string &delimiters = " ")
{
    // Skip delimiters at beginning.
    std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);
    // Find first "non-delimiter".
    std::string::size_type pos = str.find_first_of(delimiters, lastPos);

    while (std::string::npos != pos || std::string::npos != lastPos)
    {
        // Found a token, add it to the vector.
        tokens.push_back(str.substr(lastPos, pos - lastPos));
        // Skip delimiters.  Note the "not_of"
        lastPos = str.find_first_not_of(delimiters, pos);
        // Find next "non-delimiter"
        pos = str.find_first_of(delimiters, lastPos);
    }
}


FirmwareInfo ProvisioningManager::GetFirmwareInfo()
{
    auto ret = FirmwareInfo{};
    ret.Valid = false;

    char buf[64] = {0};
    const std::string url = std::string(CONFIG_PROVISIONING_MANAGER_FIRMWARE_URL) + "/" + CONFIG_PROVISIONING_MANAGER_FIRMWARE_CONTROL_FILE;
    esp_http_client_config_t config = {
        .url = url.c_str(),
        .method = HTTP_METHOD_GET,
        .event_handler = ProvisioningManager::onHttpEvent,
        .user_data = buf,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == nullptr)
    {
        ESP_LOGE(TAG, "GetFirmwareInfo(): Failed to open esp_http_client_init");
        return ret;
    }
    esp_err_t err = esp_http_client_perform(client);
    auto code = esp_http_client_get_status_code(client);
    if (err == ESP_OK)
    {
        if (code != 200)
        {
            ESP_LOGE(TAG, "GetFirmwareInfo(): unable to load firmware.txt, HTTP Response %d", code);
        }
        else
        {
            int len = esp_http_client_get_content_length(client);
            std::string txt(buf, len);
            std::vector<std::string> tokens;
            Tokenize(txt, tokens, " \r\n\t");
            if (tokens.size() == 2 || tokens.size() == 3)
            {
                ret.Version = stoi(tokens[0]);
                ret.RelativeUrl = tokens[1];
                if (tokens.size() == 3 && tokens[2] == "force")
                {
                    ret.Force = true;
                }
                ret.Valid = true;
            }
            else
            {
                ESP_LOGE(TAG, "GetFirmwareInfo(): Got %d tokens from firmware.txt, expected exactly 2 - version and url.", tokens.size());
            }
        }
    }
    else
    {
        ESP_LOGE(TAG, "GetFirmwareInfo(): HTTP GET request failed code %d: %s", code, esp_err_to_name(err));
    }
    if (esp_http_client_cleanup(client) != ESP_OK)
    {
        ESP_LOGE(TAG, "GetFirmwareInfo(): esp_http_client_cleanup returned error");
    }
    return ret;
}

void ProvisioningManager::UpdateFirmware()
{
    auto fw = GetFirmwareInfo();
    if (fw.Valid)
    {
        if (fw.Version > m_runningFwVersion)
        {
            ESP_LOGI(TAG, "UpdateFirmware(): Firmware update available.");
            ApplyFirmware(fw);
        }
        else if (fw.Version == m_runningFwVersion)
        {
            ESP_LOGI(TAG, "UpdateFirmware(): Firmware up to date.");
        }
        else
        {
            ESP_LOGI(TAG, "UpdateFirmware(): Running firmware newer than OTA.");
        }
    }
    else
    {
        ESP_LOGI(TAG, "UpdateFirmwarE(): Unable to fetch firmware info.");
    }
}

void ProvisioningManager::ApplyFirmware(const FirmwareInfo &info)
{
    const auto url = std::string(CONFIG_PROVISIONING_MANAGER_FIRMWARE_URL) + "/" + info.RelativeUrl;
    ESP_LOGI(TAG, "Applying Firmware v%d from %s", info.Version, url.c_str());

    esp_err_t ota_finish_err = ESP_OK;
    esp_http_client_config_t config = {
        .url = url.c_str(),
        .timeout_ms = 5000,
        .skip_cert_common_name_check = true,
        .keep_alive_enable = true,
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &config,
    };

    esp_https_ota_handle_t https_ota_handle = NULL;
    esp_err_t err = esp_https_ota_begin(&ota_config, &https_ota_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "ApplyFirmware(): ESP HTTPS OTA Begin failed");
        return;
    }

    esp_app_desc_t app_desc;
    err = esp_https_ota_get_img_desc(https_ota_handle, &app_desc);
    int v;
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "ApplyFirmware(): esp_https_ota_read_img_desc failed");
        goto finish_ota;
    }
    ESP_LOGI(TAG, "ApplyFirmware(): Remote firmware version: %s", app_desc.version);
    v = atoi(app_desc.version);
    if (v != info.Version)
    {
        ESP_LOGE(TAG, "ApplyFirmware(): Remote binary firmware version %s doesn't match expected from firmware.txt %d", app_desc.version, info.Version);
        goto finish_ota;
    }
    ESP_LOGI(TAG, "ApplyFirmware(): Loading image from %s", url.c_str());
    while (1)
    {
        err = esp_https_ota_perform(https_ota_handle);
        if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS)
        {
            break;
        }
        //ESP_LOGI(TAG, "ApplyFirmware(): Image bytes read: %d", esp_https_ota_get_image_len_read(https_ota_handle));
    }

    if (esp_https_ota_is_complete_data_received(https_ota_handle) != true)
    {
        // the OTA image was not completely received and user can customise the response to this situation.
        ESP_LOGE(TAG, "ApplyFirmware(): Complete data was not received.");
    }
    else
    {
        ota_finish_err = esp_https_ota_finish(https_ota_handle);
        if ((err == ESP_OK) && (ota_finish_err == ESP_OK))
        {
            ESP_LOGI(TAG, "ApplyFirmware(): ESP_HTTPS_OTA upgrade successful. Rebooting ...");
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            esp_restart();
        }
        else
        {
            if (ota_finish_err == ESP_ERR_OTA_VALIDATE_FAILED)
            {
                ESP_LOGE(TAG, "ApplyFirmware(): Image validation failed, image is corrupted");
            }
            ESP_LOGE(TAG, "ApplyFirmware(): ESP_HTTPS_OTA upgrade failed 0x%x", ota_finish_err);
        }
    }
finish_ota:
    esp_https_ota_abort(https_ota_handle);
    ESP_LOGE(TAG, "ApplyFirmware(): ESP_HTTPS_OTA upgrade failed");
}

std::string ProvisioningManager::GetServiceName()
{
    uint8_t eth_mac[6];
    char buf[12];
    esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
    snprintf(buf, sizeof(buf), "PROV_%x%x%x", static_cast<unsigned>(eth_mac[3]), static_cast<unsigned>(eth_mac[4]), static_cast<unsigned>(eth_mac[5]));
    return std::string(buf);
}

std::string ProvisioningManager::GetHostName()
{
    uint8_t eth_mac[6];
    char buf[16];
    esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
    snprintf(buf, sizeof(buf), "bscanner_%x%x%x", static_cast<unsigned>(eth_mac[3]), static_cast<unsigned>(eth_mac[4]), static_cast<unsigned>(eth_mac[5]));
    return std::string(buf);
}

ProvisioningManager::ProvisioningManager()
{
}

void ProvisioningManager::Initialize()
{
    esp_log_level_set(TAG, ESP_LOG_INFO);
    esp_err_t ret = nvs_flash_init();
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_app_desc_t running_app_info;

    if (esp_ota_get_partition_description(running, &running_app_info) == ESP_OK)
    {
        m_runningFwVersion = stoi(std::string(running_app_info.version));
        ESP_LOGI(TAG, "ProvisioningManager(): Firmware version : %d", m_runningFwVersion);
    }
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        /* NVS partition was truncated
         * and needs to be erased */
        ESP_ERROR_CHECK(nvs_flash_erase());

        /* Retry nvs_flash_init */
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    /* Initialize TCP/IP */
    ESP_ERROR_CHECK(esp_netif_init());

    /* Initialize TCP/IP */
    ESP_ERROR_CHECK(esp_netif_init());

    /* Initialize the event loop */
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    //m_wifiEventGroup = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_PROV_EVENT, ESP_EVENT_ANY_ID, ProvisioningManager::ProvisioningEventHandler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, ProvisioningManager::ProvisioningEventHandler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, ProvisioningManager::ProvisioningEventHandler, NULL, NULL));

    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    m_wifiEventGroup = xEventGroupCreate();

    /* Configuration for the provisioning manager */
    wifi_prov_mgr_config_t config = {
        /* What is the Provisioning Scheme that we want ?
         * wifi_prov_scheme_softap or wifi_prov_scheme_ble */
        .scheme = wifi_prov_scheme_softap,
        /* Any default scheme specific event handler that you would
         * like to choose. Since our example application requires
         * neither BT nor BLE, we can choose to release the associated
         * memory once provisioning is complete, or not needed
         * (in case when device is already provisioned). Choosing
         * appropriate scheme specific event handler allows the manager
         * to take care of this automatically. This can be set to
         * WIFI_PROV_EVENT_HANDLER_NONE when using wifi_prov_scheme_softap*/
        .scheme_event_handler = WIFI_PROV_EVENT_HANDLER_NONE,
        .app_event_handler = WIFI_PROV_EVENT_HANDLER_NONE};

    /* Initialize provisioning manager with the
     * configuration parameters set above */
    ESP_ERROR_CHECK(wifi_prov_mgr_init(config));

    bool provisioned = false;
#if 0
    wifi_prov_mgr_reset_provisioning();
#else
    /* Let's find out if the device is provisioned */
    ESP_ERROR_CHECK(wifi_prov_mgr_is_provisioned(&provisioned));

#endif
    /* If device is not yet provisioned start provisioning service */
    if (!provisioned)
    {
        ESP_LOGI(TAG, "Starting provisioning");

        /* What is the Device Service Name that we want
         * This translates to :
         *     - Wi-Fi SSID when scheme is wifi_prov_scheme_softap
         *     - device name when scheme is wifi_prov_scheme_ble
         */
        auto service_name = GetServiceName();

        /* What is the security level that we want (0 or 1):
         *      - WIFI_PROV_SECURITY_0 is simply plain text communication.
         *      - WIFI_PROV_SECURITY_1 is secure communication which consists of secure handshake
         *          using X25519 key exchange and proof of possession (pop) and AES-CTR
         *          for encryption/decryption of messages.
         */
        wifi_prov_security_t security = WIFI_PROV_SECURITY_1;

        /* Do we want a proof-of-possession (ignored if Security 0 is selected):
         *      - this should be a string with length > 0
         *      - NULL if not used
         */
        const char *pop = "abcd1234";

        /* What is the service key (could be NULL)
         * This translates to :
         *     - Wi-Fi password when scheme is wifi_prov_scheme_softap
         *          (Minimum expected length: 8, maximum 64 for WPA2-PSK)
         *     - simply ignored when scheme is wifi_prov_scheme_ble
         */
        const char *service_key = NULL;

        /* An optional endpoint that applications can create if they expect to
         * get some additional custom data during provisioning workflow.
         * The endpoint name can be anything of your choice.
         * This call must be made before starting the provisioning.
         */
        wifi_prov_mgr_endpoint_create("custom-data");
        /* Start provisioning service */
        ESP_ERROR_CHECK(wifi_prov_mgr_start_provisioning(security, pop, service_name.c_str(), service_key));

        /* The handler for the optional endpoint created above.
         * This call must be made after starting the provisioning, and only if the endpoint
         * has already been created above.
         */
        wifi_prov_mgr_endpoint_register("custom-data", ProvisioningManager::CustomProvisioningDataHandler, this);

        /* Uncomment the following to wait for the provisioning to finish and then release
         * the resources of the manager. Since in this case de-initialization is triggered
         * by the default event loop handler, we don't need to call the following */
        // wifi_prov_mgr_wait();
        // wifi_prov_mgr_deinit();
        /* Print QR code for provisioning */
        PrintQr(service_name.c_str(), pop, PROV_TRANSPORT_SOFTAP);
    }
    else
    {
        ESP_LOGI(TAG, "Already provisioned, starting Wi-Fi STA");

        /* We don't need the manager as device is already provisioned,
         * so let's release it's resources */
        wifi_prov_mgr_deinit();

        /* Start Wi-Fi station */
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_start());
    }

    /* Wait for Wi-Fi connection */
    xEventGroupWaitBits(m_wifiEventGroup, WIFI_CONNECTED_EVENT, false, true, portMAX_DELAY);

    if (m_autoUpdate)
    {
        xTaskCreate(FirmwareUpdater, "FirmwareUpdater", 2048*4, nullptr, tskIDLE_PRIORITY, &m_updateTask);
    }
}

void ProvisioningManager::FirmwareUpdater(void*)
{
    auto me = ProvisioningManager::GetInstance();
    for (;;)
    {
        me->UpdateFirmware();
        vTaskDelay((CONFIG_PROVISIONING_MANAGER_AUTOUPDATE_INTERVAL * 1000) / portTICK_PERIOD_MS);
    }
}

void ProvisioningManager::PrintQr(const char *name, const char *pop, const char *transport)
{
    if (!name || !transport)
    {
        ESP_LOGW(TAG, "Cannot generate QR code payload. Data missing.");
        return;
    }
    char payload[150] = {0};
    if (pop)
    {
        snprintf(payload, sizeof(payload), "{\"ver\":\"%s\",\"name\":\"%s\""
                                           ",\"pop\":\"%s\",\"transport\":\"%s\"}",
                 PROV_QR_VERSION, name, pop, transport);
    }
    else
    {
        snprintf(payload, sizeof(payload), "{\"ver\":\"%s\",\"name\":\"%s\""
                                           ",\"transport\":\"%s\"}",
                 PROV_QR_VERSION, name, transport);
    }
    //#ifdef CONFIG_EXAMPLE_PROV_SHOW_QR
    ESP_LOGI(TAG, "Scan this QR code from the provisioning application for Provisioning.");
    esp_qrcode_config_t cfg = ESP_QRCODE_CONFIG_DEFAULT();
    esp_qrcode_generate(&cfg, payload);
    //#endif /* CONFIG_APP_WIFI_PROV_SHOW_QR */
    ESP_LOGI(TAG, "If QR code is not visible, copy paste the below URL in a browser.\n%s?data=%s", QRCODE_BASE_URL, payload);
}
/* Handler for the optional provisioning endpoint registered by the application.
 * The data format can be chosen by applications. Here, we are using plain ascii text.
 * Applications can choose to use other formats like protobuf, JSON, XML, etc.
 */
esp_err_t ProvisioningManager::CustomProvisioningDataHandler(uint32_t session_id, const uint8_t *inbuf, ssize_t inlen,
                                                             uint8_t **outbuf, ssize_t *outlen, void *priv_data)
{
    if (inbuf)
    {
        ESP_LOGI(TAG, "Received data: %.*s", inlen, (char *)inbuf);
    }
    char response[] = "SUCCESS";
    *outbuf = (uint8_t *)strdup(response);
    if (*outbuf == NULL)
    {
        ESP_LOGE(TAG, "System out of memory");
        return ESP_ERR_NO_MEM;
    }
    *outlen = strlen(response) + 1; /* +1 for NULL terminating byte */

    return ESP_OK;
}

void ProvisioningManager::ProvisioningEventHandler(void *arg, esp_event_base_t event_base,
                                                   int32_t event_id, void *event_data)
{
    ProvisioningManager *inst = ProvisioningManager::GetInstance();
    static int retries;
    if (event_base == WIFI_PROV_EVENT)
    {
        switch (event_id)
        {
        case WIFI_PROV_START:
            ESP_LOGI(TAG, "Provisioning started");
            break;
        case WIFI_PROV_CRED_RECV:
        {
            wifi_sta_config_t *wifi_sta_cfg = (wifi_sta_config_t *)event_data;
            ESP_LOGI(TAG, "Received Wi-Fi credentials"
                          "\n\tSSID     : %s\n\tPassword : %s",
                     (const char *)wifi_sta_cfg->ssid,
                     (const char *)wifi_sta_cfg->password);
            break;
        }
        case WIFI_PROV_CRED_FAIL:
        {
            wifi_prov_sta_fail_reason_t *reason = (wifi_prov_sta_fail_reason_t *)event_data;
            ESP_LOGE(TAG, "Provisioning failed!\n\tReason : %s"
                          "\n\tPlease reset to factory and retry provisioning",
                     (*reason == WIFI_PROV_STA_AUTH_ERROR) ? "Wi-Fi station authentication failed" : "Wi-Fi access-point not found");
            retries++;
            if (retries >= 5)
            {
                ESP_LOGI(TAG, "Failed to connect with provisioned AP, reseting provisioned credentials");
                wifi_prov_mgr_reset_sm_state_on_failure();
                retries = 0;
            }
            break;
        }
        case WIFI_PROV_CRED_SUCCESS:
            ESP_LOGI(TAG, "Provisioning successful");
            retries = 0;
            break;
        case WIFI_PROV_END:
            /* De-initialize manager once provisioning is finished */
            ESP_LOGI(TAG, "WI CONNEND");
            wifi_prov_mgr_deinit();
            break;
        default:
            break;
        }
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        if(esp_wifi_connect() != ESP_OK) {
            ESP_LOGE(TAG, "WIFI CONNECT FAILED"); // sometimes wifi connection seems to fail if initiated too soon.
        }
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Connected with IP Address:" IPSTR, IP2STR(&event->ip_info.ip));
        auto hostname = inst->GetHostName();
        esp_err_t ret = tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA, hostname.c_str());
        if (ret != ESP_OK)
        {
            ESP_LOGE(TAG, "failed to set hostname:%d", ret);
        }
        else
        {
            ESP_LOGI(TAG, "Hostname: %s", hostname.c_str());
        }
        /* Signal main application to continue execution */
        xEventGroupSetBits(inst->m_wifiEventGroup, WIFI_CONNECTED_EVENT);
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        ESP_LOGI(TAG, "Disconnected. Connecting to the AP again...");
        esp_wifi_connect();
    }
}