#include "xdr/EndpointCorrelation.h"

#include <algorithm>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <cmath>

namespace ThreatOne::XDR {

EndpointCorrelation::EndpointCorrelation()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("EndpointCorrelation")) {
    logger_.info("EndpointCorrelation initialized");
}

std::string EndpointCorrelation::generateEventId() {
    return "EPEVT-" + std::to_string(nextEventId_++);
}

std::string EndpointCorrelation::generateChainId() {
    return "CHAIN-" + std::to_string(nextChainId_++);
}

int EndpointCorrelation::severityToInt(const std::string& severity) const {
    if (severity == "critical") return 4;
    if (severity == "high") return 3;
    if (severity == "medium") return 2;
    if (severity == "low") return 1;
    return 0;
}

bool EndpointCorrelation::eventsWithinTimeWindow(const EndpointEvent& a, const EndpointEvent& b, int windowSeconds) const {
    if (a.timestamp.empty() || b.timestamp.empty()) {
        return true;
    }

    auto parseTimestamp = [](const std::string& ts) -> std::time_t {
        std::tm tm = {};
        std::istringstream ss(ts);
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
        if (ss.fail()) {
            return 0;
        }
#ifdef _WIN32
        return _mkgmtime(&tm);
#else
        return timegm(&tm);
#endif
    };

    std::time_t timeA = parseTimestamp(a.timestamp);
    std::time_t timeB = parseTimestamp(b.timestamp);

    if (timeA == 0 || timeB == 0) {
        return true;
    }

    double diff = std::difftime(timeA, timeB);
    return std::abs(diff) <= static_cast<double>(windowSeconds);
}

std::string EndpointCorrelation::submitEvent(const EndpointEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string id = event.id.empty() ? generateEventId() : event.id;

    EndpointEvent stored = event;
    stored.id = id;
    events_[id] = stored;
    eventsByEndpoint_[stored.endpointId].push_back(id);

    logger_.info("Submitted endpoint event: id={}, endpoint={}, type={}",
                 id, event.endpointId, event.eventType);
    return id;
}

std::vector<Correlation> EndpointCorrelation::correlateByEndpoint(const std::vector<std::string>& eventIds) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (eventIds.empty()) {
        return {};
    }

    // Gather events by endpoint
    std::map<std::string, std::vector<EndpointEvent>> eventsByEp;
    for (const auto& eventId : eventIds) {
        auto it = events_.find(eventId);
        if (it != events_.end()) {
            eventsByEp[it->second.endpointId].push_back(it->second);
        }
    }

    std::vector<Correlation> newCorrelations;

    for (auto& [endpointId, endpointEvents] : eventsByEp) {
        if (endpointEvents.size() < 2) {
            continue;
        }

        // Sort by timestamp
        std::sort(endpointEvents.begin(), endpointEvents.end(),
                  [](const EndpointEvent& a, const EndpointEvent& b) {
                      return a.timestamp < b.timestamp;
                  });

        // Group events within 5-minute windows
        std::vector<std::string> windowEventIds;
        int maxSeverity = 0;

        for (size_t i = 0; i < endpointEvents.size(); ++i) {
            if (windowEventIds.empty()) {
                windowEventIds.push_back(endpointEvents[i].id);
                maxSeverity = severityToInt(endpointEvents[i].severity);
            } else {
                if (eventsWithinTimeWindow(endpointEvents[0], endpointEvents[i], 300)) {
                    windowEventIds.push_back(endpointEvents[i].id);
                    int sev = severityToInt(endpointEvents[i].severity);
                    if (sev > maxSeverity) {
                        maxSeverity = sev;
                    }
                }
            }
        }

        if (windowEventIds.size() >= 2) {
            Correlation corr;
            corr.id = "CORR-EP-" + std::to_string(nextChainId_++);
            corr.eventIds = windowEventIds;
            corr.description = "Multi-event correlation on endpoint " + endpointId;
            corr.confidence = std::min(1.0, 0.3 + (windowEventIds.size() * 0.15));

            // Detect escalating severity
            bool escalating = false;
            int prevSev = 0;
            for (const auto& evt : endpointEvents) {
                int sev = severityToInt(evt.severity);
                if (sev > prevSev && prevSev > 0) {
                    escalating = true;
                }
                prevSev = sev;
            }

            if (escalating) {
                corr.confidence = std::min(1.0, corr.confidence + 0.2);
                corr.description = "Multi-stage attack detected on endpoint " + endpointId;
            }

            switch (maxSeverity) {
                case 4: corr.severity = "critical"; break;
                case 3: corr.severity = "high"; break;
                case 2: corr.severity = "medium"; break;
                default: corr.severity = "low"; break;
            }

            newCorrelations.push_back(corr);
            logger_.info("Created endpoint correlation: id={}, events={}, confidence={}",
                         corr.id, windowEventIds.size(), corr.confidence);
        }
    }

    return newCorrelations;
}

void EndpointCorrelation::addProcessNode(const ProcessNode& node) {
    std::lock_guard<std::mutex> lock(mutex_);
    processTree_[node.processId] = node;

    // Update parent's child list
    if (!node.parentProcessId.empty()) {
        auto parentIt = processTree_.find(node.parentProcessId);
        if (parentIt != processTree_.end()) {
            parentIt->second.childProcessIds.push_back(node.processId);
        }
    }

    logger_.debug("Added process node: id={}, parent={}", node.processId, node.parentProcessId);
}

std::vector<ProcessNode> EndpointCorrelation::getProcessTree(const std::string& rootProcessId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ProcessNode> tree;

    auto it = processTree_.find(rootProcessId);
    if (it == processTree_.end()) {
        return tree;
    }

    // BFS to build tree
    std::vector<std::string> toVisit = {rootProcessId};
    while (!toVisit.empty()) {
        std::string current = toVisit.front();
        toVisit.erase(toVisit.begin());

        auto nodeIt = processTree_.find(current);
        if (nodeIt != processTree_.end()) {
            tree.push_back(nodeIt->second);
            for (const auto& childId : nodeIt->second.childProcessIds) {
                toVisit.push_back(childId);
            }
        }
    }

    return tree;
}

bool EndpointCorrelation::isProcessSuspicious(const std::string& processId) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = processTree_.find(processId);
    if (it == processTree_.end()) {
        return false;
    }

    const auto& node = it->second;
    // Suspicious patterns: cmd.exe/powershell spawned by unusual parent
    static const std::vector<std::string> suspiciousNames = {
        "cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe",
        "certutil.exe", "bitsadmin.exe", "regsvr32.exe"
    };

    for (const auto& name : suspiciousNames) {
        if (node.processName.find(name) != std::string::npos) {
            return true;
        }
    }

    // Check for deeply nested processes (possible injection chain)
    int depth = 0;
    std::string current = processId;
    while (!current.empty() && depth < 10) {
        auto nodeIt = processTree_.find(current);
        if (nodeIt == processTree_.end()) break;
        current = nodeIt->second.parentProcessId;
        depth++;
    }
    if (depth >= 5) {
        return true;
    }

    return false;
}

std::vector<AttackChain> EndpointCorrelation::detectAttackChains(const std::string& endpointId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AttackChain> chains;

    auto it = eventsByEndpoint_.find(endpointId);
    if (it == eventsByEndpoint_.end() || it->second.size() < 2) {
        return chains;
    }

    // Check for known attack patterns
    std::vector<EndpointEvent> epEvents;
    for (const auto& eid : it->second) {
        auto evtIt = events_.find(eid);
        if (evtIt != events_.end()) {
            epEvents.push_back(evtIt->second);
        }
    }

    // Sort by timestamp
    std::sort(epEvents.begin(), epEvents.end(),
              [](const EndpointEvent& a, const EndpointEvent& b) {
                  return a.timestamp < b.timestamp;
              });

    // Look for recon -> exploitation -> persistence pattern
    bool hasRecon = false;
    bool hasExploit = false;
    bool hasPersistence = false;

    std::vector<std::string> chainEventIds;
    for (const auto& evt : epEvents) {
        if (evt.eventType.find("recon") != std::string::npos ||
            evt.eventType.find("scan") != std::string::npos) {
            hasRecon = true;
            chainEventIds.push_back(evt.id);
        } else if (evt.eventType.find("exploit") != std::string::npos ||
                   evt.eventType.find("execution") != std::string::npos) {
            hasExploit = true;
            chainEventIds.push_back(evt.id);
        } else if (evt.eventType.find("persist") != std::string::npos ||
                   evt.eventType.find("registry") != std::string::npos) {
            hasPersistence = true;
            chainEventIds.push_back(evt.id);
        }
    }

    if (hasRecon && hasExploit) {
        AttackChain chain;
        chain.id = "CHAIN-" + std::to_string(nextChainId_);
        chain.endpointId = endpointId;
        chain.eventIds = chainEventIds;
        chain.description = "Attack chain detected: recon -> exploitation";
        chain.severity = "high";
        chain.confidence = 0.7;
        chain.tactics = {"reconnaissance", "execution"};

        if (hasPersistence) {
            chain.description += " -> persistence";
            chain.severity = "critical";
            chain.confidence = 0.85;
            chain.tactics.push_back("persistence");
        }

        chains.push_back(chain);
    }

    return chains;
}

EndpointEvent EndpointCorrelation::getEvent(const std::string& eventId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = events_.find(eventId);
    if (it != events_.end()) {
        return it->second;
    }
    return EndpointEvent{};
}

std::vector<EndpointEvent> EndpointCorrelation::getEventsByEndpoint(const std::string& endpointId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<EndpointEvent> result;

    auto it = eventsByEndpoint_.find(endpointId);
    if (it != eventsByEndpoint_.end()) {
        for (const auto& eid : it->second) {
            auto evtIt = events_.find(eid);
            if (evtIt != events_.end()) {
                result.push_back(evtIt->second);
            }
        }
    }

    return result;
}

size_t EndpointCorrelation::getEventCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_.size();
}

} // namespace ThreatOne::XDR
