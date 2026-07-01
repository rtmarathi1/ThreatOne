#pragma once

#include "network/INetworkManager.h"
#include "core/Logger.h"

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

private:
    ThreatOne::Core::ModuleLogger logger_;
};

} // namespace ThreatOne::Network
