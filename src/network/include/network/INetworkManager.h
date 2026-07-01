#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ThreatOne::Network {

struct HttpResponse {
    int statusCode = 0;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

struct NetworkConnection {
    std::string localAddress;
    std::string remoteAddress;
    uint16_t localPort = 0;
    uint16_t remotePort = 0;
    std::string protocol;
    std::string state;
};

struct TrafficStats {
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;
    uint64_t packetsSent = 0;
    uint64_t packetsReceived = 0;
};

struct DNSResult {
    std::string hostname;
    std::vector<std::string> addresses;
    uint32_t ttl = 0;
};

struct PingResult {
    std::string host;
    double latencyMs = 0.0;
    bool reachable = false;
    int ttl = 0;
};

class INetworkManager {
public:
    virtual ~INetworkManager() = default;

    virtual HttpResponse sendRequest(const HttpRequest& request) = 0;
    virtual bool openWebSocket(const std::string& url) = 0;
    virtual std::vector<NetworkConnection> getConnections() = 0;
    virtual TrafficStats getTraffic() = 0;
    virtual DNSResult dnsLookup(const std::string& hostname) = 0;
    virtual PingResult ping(const std::string& host) = 0;
};

} // namespace ThreatOne::Network
