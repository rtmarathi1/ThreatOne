#include "xdr/ThreatHunting.h"

#include <algorithm>

namespace ThreatOne::XDR {

ThreatHunting::ThreatHunting()
    : logger_(ThreatOne::Core::Logger::instance().getModuleLogger("ThreatHunting")) {
    logger_.info("ThreatHunting initialized");
}

std::string ThreatHunting::generateHypothesisId() {
    return "HUNT-" + std::to_string(nextHypothesisId_++);
}

std::string ThreatHunting::generateIOCId() {
    return "IOC-" + std::to_string(nextIOCId_++);
}

std::string ThreatHunting::generateResultId() {
    return "HUNTRES-" + std::to_string(nextResultId_++);
}

std::string ThreatHunting::generatePatternId() {
    return "PATTERN-" + std::to_string(nextPatternId_++);
}

std::string ThreatHunting::createHypothesis(const HuntingHypothesis& hypothesis) {
    std::lock_guard<std::mutex> lock(mutex_);
    HuntingHypothesis stored = hypothesis;
    if (stored.id.empty()) {
        stored.id = generateHypothesisId();
    }
    if (stored.status.empty()) {
        stored.status = "active";
    }
    hypotheses_[stored.id] = stored;
    logger_.info("Created hypothesis: id={}, name={}", stored.id, stored.name);
    return stored.id;
}

std::vector<HuntingHypothesis> ThreatHunting::getHypotheses(const std::string& status) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<HuntingHypothesis> result;
    for (const auto& [id, h] : hypotheses_) {
        if (status.empty() || h.status == status) {
            result.push_back(h);
        }
    }
    return result;
}

bool ThreatHunting::updateHypothesisStatus(const std::string& id, const std::string& status) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hypotheses_.find(id);
    if (it != hypotheses_.end()) {
        it->second.status = status;
        logger_.info("Updated hypothesis status: id={}, status={}", id, status);
        return true;
    }
    return false;
}

std::string ThreatHunting::addIOC(const IOC& ioc) {
    std::lock_guard<std::mutex> lock(mutex_);
    IOC stored = ioc;
    if (stored.id.empty()) {
        stored.id = generateIOCId();
    }
    iocs_[stored.id] = stored;
    logger_.info("Added IOC: id={}, type={}, value={}", stored.id, stored.type, stored.value);
    return stored.id;
}

std::vector<IOC> ThreatHunting::getIOCs(const std::string& type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<IOC> result;
    for (const auto& [id, ioc] : iocs_) {
        if (type.empty() || ioc.type == type) {
            result.push_back(ioc);
        }
    }
    return result;
}

bool ThreatHunting::deactivateIOC(const std::string& iocId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = iocs_.find(iocId);
    if (it != iocs_.end()) {
        it->second.active = false;
        logger_.info("Deactivated IOC: id={}", iocId);
        return true;
    }
    return false;
}

std::vector<HuntResult> ThreatHunting::sweepIOCs(const std::vector<EndpointEvent>& events) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<HuntResult> results;

    for (const auto& [iocId, ioc] : iocs_) {
        if (!ioc.active) continue;

        std::vector<std::string> matchedIds;
        for (const auto& evt : events) {
            bool matched = false;

            // Match IOC against event details
            if (ioc.type == "ip") {
                auto it = evt.details.find("ip");
                if (it != evt.details.end() && it->second == ioc.value) {
                    matched = true;
                }
            } else if (ioc.type == "hash") {
                auto it = evt.details.find("hash");
                if (it != evt.details.end() && it->second == ioc.value) {
                    matched = true;
                }
            } else if (ioc.type == "file_path") {
                auto it = evt.details.find("file_path");
                if (it != evt.details.end() && it->second.find(ioc.value) != std::string::npos) {
                    matched = true;
                }
            } else if (ioc.type == "domain") {
                auto it = evt.details.find("domain");
                if (it != evt.details.end() && it->second == ioc.value) {
                    matched = true;
                }
            }

            // Also check event type matches
            if (!matched && evt.eventType.find(ioc.value) != std::string::npos) {
                matched = true;
            }

            if (matched) {
                matchedIds.push_back(evt.id);
            }
        }

        if (!matchedIds.empty()) {
            HuntResult result;
            result.id = "HUNTRES-" + std::to_string(results.size() + 1);
            result.matchedEventIds = matchedIds;
            result.matchedIOCs = {iocId};
            result.summary = "IOC match: " + ioc.type + "=" + ioc.value + " found in " +
                             std::to_string(matchedIds.size()) + " events";
            result.confidence = std::min(1.0, 0.6 + (matchedIds.size() * 0.1));
            result.severity = ioc.severity;
            results.push_back(result);
        }
    }

    return results;
}

std::string ThreatHunting::addBehavioralPattern(const BehavioralPattern& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);
    BehavioralPattern stored = pattern;
    if (stored.id.empty()) {
        stored.id = generatePatternId();
    }
    patterns_[stored.id] = stored;
    logger_.info("Added behavioral pattern: id={}, name={}", stored.id, stored.name);
    return stored.id;
}

std::vector<HuntResult> ThreatHunting::matchBehavioralPatterns(const std::vector<EndpointEvent>& events) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<HuntResult> results;

    for (const auto& [patternId, pattern] : patterns_) {
        if (pattern.eventSequence.empty()) continue;

        // Look for matching event type sequences
        size_t seqIdx = 0;
        std::vector<std::string> matchedIds;

        for (const auto& evt : events) {
            if (seqIdx < pattern.eventSequence.size() &&
                evt.eventType.find(pattern.eventSequence[seqIdx]) != std::string::npos) {
                matchedIds.push_back(evt.id);
                seqIdx++;
            }
        }

        // If full sequence matched
        if (seqIdx == pattern.eventSequence.size()) {
            HuntResult result;
            result.id = "HUNTRES-" + std::to_string(results.size() + 1);
            result.matchedEventIds = matchedIds;
            result.summary = "Behavioral pattern match: " + pattern.name;
            result.confidence = 0.8;
            result.severity = pattern.severity;
            results.push_back(result);
        }
    }

    return results;
}

HuntResult ThreatHunting::executeHunt(const std::string& hypothesisId, const std::vector<EndpointEvent>& events) {
    std::lock_guard<std::mutex> lock(mutex_);

    HuntResult result;
    result.id = generateResultId();
    result.hypothesisId = hypothesisId;

    auto hypIt = hypotheses_.find(hypothesisId);
    if (hypIt == hypotheses_.end()) {
        result.summary = "Hypothesis not found";
        result.confidence = 0.0;
        results_[result.id] = result;
        return result;
    }

    const auto& hypothesis = hypIt->second;

    // Search events matching hypothesis indicators
    for (const auto& evt : events) {
        for (const auto& indicator : hypothesis.indicators) {
            if (evt.eventType.find(indicator) != std::string::npos ||
                evt.endpointId.find(indicator) != std::string::npos) {
                result.matchedEventIds.push_back(evt.id);
                break;
            }
            // Check details
            for (const auto& [key, val] : evt.details) {
                if (val.find(indicator) != std::string::npos) {
                    result.matchedEventIds.push_back(evt.id);
                    break;
                }
            }
        }
    }

    if (!result.matchedEventIds.empty()) {
        result.summary = "Hunt found " + std::to_string(result.matchedEventIds.size()) +
                         " matching events for hypothesis: " + hypothesis.name;
        result.confidence = std::min(1.0, 0.4 + (result.matchedEventIds.size() * 0.15));
        result.severity = "medium";
        if (result.matchedEventIds.size() >= 3) {
            result.severity = "high";
        }
    } else {
        result.summary = "No matches found for hypothesis: " + hypothesis.name;
        result.confidence = 0.0;
    }

    results_[result.id] = result;
    logger_.info("Executed hunt: id={}, hypothesis={}, matches={}",
                 result.id, hypothesisId, result.matchedEventIds.size());
    return result;
}

std::vector<HuntResult> ThreatHunting::getHuntResults(const std::string& hypothesisId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<HuntResult> result;
    for (const auto& [id, hr] : results_) {
        if (hypothesisId.empty() || hr.hypothesisId == hypothesisId) {
            result.push_back(hr);
        }
    }
    return result;
}

size_t ThreatHunting::getHypothesisCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return hypotheses_.size();
}

size_t ThreatHunting::getIOCCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return iocs_.size();
}

size_t ThreatHunting::getResultCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return results_.size();
}

} // namespace ThreatOne::XDR
