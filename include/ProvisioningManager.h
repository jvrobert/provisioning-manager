
#include <wifi_provisioning/manager.h>
#include <wifi_provisioning/scheme_softap.h>
#undef LOG_LOCAL_LEVEL
#define LOG_LOCAL_LEVEL ESP_LOG_INFO
#include <esp_log.h>
#include <esp_wifi.h>
#include <esp_event.h>
#include <nvs_flash.h>
#include <freertos/event_groups.h>
#include "esp_http_client.h"
#include "sdkconfig.h"

#include <string>

struct FirmwareInfo
{
    bool Valid;
    unsigned Version;
    bool Force;
    std::string RelativeUrl;
};

class ProvisioningManager
{
public:
    static ProvisioningManager *GetInstance();
    static void Start();
    unsigned GetFirmwareVersion() { return m_runningFwVersion; }
    void UpdateFirmware();
protected:
    ProvisioningManager();
    std::string GetHostName();
    void Initialize();
    static ProvisioningManager* s_instance;
    static void ProvisioningEventHandler(void *arg, esp_event_base_t event_base,
                                         int32_t event_id, void *event_data);
    static esp_err_t CustomProvisioningDataHandler(uint32_t session_id, const uint8_t *inbuf, ssize_t inlen,
                                                   uint8_t **outbuf, ssize_t *outlen, void *priv_data);

    EventGroupHandle_t m_wifiEventGroup;
    std::string GetServiceName();
    void PrintQr(const char *name, const char *pop, const char *transport);
    void ApplyFirmware(const FirmwareInfo &info);
    static esp_err_t onHttpEvent(esp_http_client_event_t *evt);
    FirmwareInfo GetFirmwareInfo();
    unsigned m_runningFwVersion;

};