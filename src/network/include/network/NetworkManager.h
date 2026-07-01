#pragma once

#include "network/INetworkManager.h"
#include "network/IPBlocklist.h"
#include "network/GeoIPDatabase.h"
#include "network/DNSFilter.h"
#include "network/BandwidthMonitor.h"
#include "network/IntrusionDetector.h"
#include "network/NetworkIsolation.h"
#include "network/ConnectionLogger.h"
#include "network/ApplicationControl.h"
#include "core/Logger.h"

#include <memory>
#include <mutex>

namespace ThreatOne::Network {

class NetworkManager : public INetworkManager {
public:
    NetworkManager();
    ~NetworkManager() override = default;

    HttpResponse sendRequest(const HttpRequest& request) override;
    bool openWebSocket(const std::string& url) override;
    std::vector<NetworkConnection> getConnections() override;
    TrafficStats getTraffic() override;
    DNSResult dnsLookup(const std::string& hostname) override;
    PingResult ping(const std::string& host) override;

    // Sub-component access
    IPBlocklist& getBlocklist() override;
    GeoBlocker& getGeoBlocker() override;
    DNSFilter& getDNSFilter() override;
    BandwidthMonitor& getBandwidthMonitor() override;
    IntrusionDetector& getIntrusionDetector() override;
    NetworkIsolation& getNetworkIsolation() override;
    ConnectionLogger& getConnectionLogger() override;
    ApplicationControl& getApplicationControl() override;

private:
    mutable std::mutex mutex_;
    ThreatOne::Core::ModuleLogger logger_;

    // Sub-components
    IPBlocklist blocklist_;
    std::shared_ptr<GeoIPDatabase> geoDatabase_;
    GeoBlocker geoBlocker_;
    DNSFilter dnsFilter_;
    BandwidthMonitor bandwidthMonitor_;
    IntrusionDetector intrusionDetector_;
    NetworkIsolation networkIsolation_;
    ConnectionLogger connectionLogger_;
    ApplicationControl applicationControl_;
};

} // namespace ThreatOne::Network
