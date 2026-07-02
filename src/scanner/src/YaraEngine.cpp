#include "scanner/YaraEngine.h"

#include <fstream>
#include <sstream>
#include <regex>
#include <cctype>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ThreatOne::Scanner {

#ifdef HAS_YARA

// ============================================================================
// Real YARA library implementation
// ============================================================================

YaraEngine::YaraEngine()
    : logger_(Core::Logger::instance().getModuleLogger("YaraEngine"))
    , status_(YaraEngineStatus::Uninitialized)
    , compiled_(false)
    , compiler_(nullptr)
    , rules_(nullptr) {
}

YaraEngine::~YaraEngine() {
    if (rules_) {
        yr_rules_destroy(rules_);
        rules_ = nullptr;
    }
    if (compiler_) {
        yr_compiler_destroy(compiler_);
        compiler_ = nullptr;
    }
    if (status_ != YaraEngineStatus::Uninitialized) {
        yr_finalize();
    }
}

Core::Result<void, Core::Error> YaraEngine::initialize() {
    logger_.info("Initializing YARA engine (libyara)");

    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        status_ = YaraEngineStatus::Error;
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to initialize YARA library", Core::ErrorCategory::Internal));
    }

    result = yr_compiler_create(&compiler_);
    if (result != ERROR_SUCCESS) {
        yr_finalize();
        status_ = YaraEngineStatus::Error;
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to create YARA compiler", Core::ErrorCategory::Internal));
    }

    status_ = YaraEngineStatus::Ready;
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<size_t, Core::Error> YaraEngine::loadRules(
    const std::filesystem::path& rulesPath) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    std::ifstream file(rulesPath);
    if (!file.is_open()) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("Cannot open YARA rules file: " + rulesPath.string(),
                       Core::ErrorCategory::IO));
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return loadRulesFromString(ss.str());
}

Core::Result<size_t, Core::Error> YaraEngine::loadRulesFromString(const std::string& rulesText) {
    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (!compiler_) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("YARA compiler not available", Core::ErrorCategory::Internal));
    }

    int errors = yr_compiler_add_string(compiler_, rulesText.c_str(), nullptr);
    if (errors > 0) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("YARA compilation errors: " + std::to_string(errors),
                       Core::ErrorCategory::Validation));
    }

    auto names = parseRuleNames(rulesText);
    size_t count = names.size();

    ruleSources_.push_back(rulesText);
    for (auto& name : names) {
        ruleNames_.push_back(std::move(name));
    }

    compiled_ = false;
    logger_.info("Loaded {} YARA rules from text (total: {})", count, ruleNames_.size());

    return Core::Result<size_t, Core::Error>::ok(count);
}

Core::Result<void, Core::Error> YaraEngine::compileRules() {
    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (ruleNames_.empty()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("No rules loaded to compile", Core::ErrorCategory::Validation));
    }

    if (rules_) {
        yr_rules_destroy(rules_);
        rules_ = nullptr;
    }

    int result = yr_compiler_get_rules(compiler_, &rules_);
    if (result != ERROR_SUCCESS) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to compile YARA rules", Core::ErrorCategory::Internal));
    }

    compiled_ = true;
    logger_.info("Compiled {} YARA rules", ruleNames_.size());

    return Core::Result<void, Core::Error>::ok();
}

int YaraEngine::scanCallback(YR_SCAN_CONTEXT* /*context*/, int message,
                            void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* matches = static_cast<std::vector<YaraMatch>*>(user_data);
        auto* rule = static_cast<YR_RULE*>(message_data);

        YaraMatch match;
        match.ruleName = rule->identifier;
        match.ruleNamespace = rule->ns->name;

        // Collect tags
        const char* tag = nullptr;
        yr_rule_tags_foreach(rule, tag) {
            match.tags.emplace_back(tag);
        }

        // Collect meta strings
        YR_META* meta = nullptr;
        yr_rule_metas_foreach(rule, meta) {
            if (meta->type == META_TYPE_STRING) {
                match.metaStrings.emplace_back(meta->string);
            }
        }

        matches->push_back(std::move(match));
    }

    return CALLBACK_CONTINUE;
}

Core::Result<std::vector<YaraMatch>, Core::Error> YaraEngine::matchFile(
    const std::filesystem::path& filePath) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (!compiled_ || !rules_) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("Rules not compiled", Core::ErrorCategory::Internal));
    }

    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec)) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("File not found: " + filePath.string(), Core::ErrorCategory::IO));
    }

    std::vector<YaraMatch> matches;
    int result = yr_rules_scan_file(rules_, filePath.string().c_str(),
                                    0, scanCallback, &matches, 0);
    if (result != ERROR_SUCCESS) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA scan failed on file: " + filePath.string(),
                       Core::ErrorCategory::Internal));
    }

    logger_.debug("YARA scan on file: {} - {} matches", filePath.string(), matches.size());
    return Core::Result<std::vector<YaraMatch>, Core::Error>::ok(std::move(matches));
}

Core::Result<std::vector<YaraMatch>, Core::Error> YaraEngine::matchBuffer(
    const std::vector<uint8_t>& data) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (!compiled_ || !rules_) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("Rules not compiled", Core::ErrorCategory::Internal));
    }

    std::vector<YaraMatch> matches;
    int result = yr_rules_scan_mem(rules_, data.data(), data.size(),
                                   0, scanCallback, &matches, 0);
    if (result != ERROR_SUCCESS) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA scan failed on buffer", Core::ErrorCategory::Internal));
    }

    logger_.debug("YARA scan on buffer ({} bytes) - {} matches", data.size(), matches.size());
    return Core::Result<std::vector<YaraMatch>, Core::Error>::ok(std::move(matches));
}

#else

// ============================================================================
// Built-in Aho-Corasick pattern matching engine (when libyara unavailable)
// ============================================================================

YaraEngine::YaraEngine()
    : logger_(Core::Logger::instance().getModuleLogger("YaraEngine"))
    , status_(YaraEngineStatus::Uninitialized)
    , compiled_(false)
    , automatonBuilt_(false) {
}

YaraEngine::~YaraEngine() = default;

Core::Result<void, Core::Error> YaraEngine::initialize() {
    logger_.info("Initializing YARA engine (built-in Aho-Corasick)");
    status_ = YaraEngineStatus::Ready;
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<size_t, Core::Error> YaraEngine::loadRules(
    const std::filesystem::path& rulesPath) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    std::ifstream file(rulesPath);
    if (!file.is_open()) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("Cannot open YARA rules file: " + rulesPath.string(),
                       Core::ErrorCategory::IO));
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return loadRulesFromString(ss.str());
}

Core::Result<size_t, Core::Error> YaraEngine::loadRulesFromString(const std::string& rulesText) {
    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<size_t, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    auto names = parseRuleNames(rulesText);
    size_t count = names.size();

    ruleSources_.push_back(rulesText);
    for (auto& name : names) {
        ruleNames_.push_back(std::move(name));
    }

    compiled_ = false;
    automatonBuilt_ = false;
    logger_.info("Loaded {} YARA rules from text (total: {})", count, ruleNames_.size());

    return Core::Result<size_t, Core::Error>::ok(count);
}

// Parse a single rule from text block
YaraEngine::RuleDef YaraEngine::parseRule(const std::string& ruleText) {
    RuleDef rule;
    rule.ns = "default";

    // Extract rule name and tags
    auto rulePos = ruleText.find("rule");
    if (rulePos == std::string::npos) return rule;

    size_t nameStart = rulePos + 4;
    while (nameStart < ruleText.size() && std::isspace(static_cast<unsigned char>(ruleText[nameStart])))
        nameStart++;

    size_t nameEnd = nameStart;
    while (nameEnd < ruleText.size() &&
           (std::isalnum(static_cast<unsigned char>(ruleText[nameEnd])) || ruleText[nameEnd] == '_'))
        nameEnd++;

    rule.name = ruleText.substr(nameStart, nameEnd - nameStart);

    // Check for tags (colon after name)
    size_t tagPos = ruleText.find(':', nameEnd);
    size_t bracePos = ruleText.find('{', nameEnd);
    if (tagPos != std::string::npos && (bracePos == std::string::npos || tagPos < bracePos)) {
        std::string tagStr = ruleText.substr(tagPos + 1, bracePos - tagPos - 1);
        std::istringstream tagStream(tagStr);
        std::string tag;
        while (tagStream >> tag) {
            rule.tags.push_back(tag);
        }
    }

    // Extract strings section
    auto stringsPos = ruleText.find("strings:");
    auto conditionPos = ruleText.find("condition:");

    if (stringsPos != std::string::npos && conditionPos != std::string::npos) {
        std::string stringsSection = ruleText.substr(stringsPos + 8, conditionPos - stringsPos - 8);
        std::istringstream ss(stringsSection);
        std::string line;
        while (std::getline(ss, line)) {
            // Trim
            size_t start = line.find_first_not_of(" \t\r\n");
            if (start == std::string::npos) continue;
            line = line.substr(start);
            if (line.empty() || line[0] != '$') continue;

            PatternDef pat;
            // Extract identifier
            size_t eqPos = line.find('=');
            if (eqPos == std::string::npos) continue;
            pat.identifier = line.substr(0, eqPos);
            // Trim identifier
            while (!pat.identifier.empty() && std::isspace(static_cast<unsigned char>(pat.identifier.back())))
                pat.identifier.pop_back();

            std::string value = line.substr(eqPos + 1);
            // Trim value
            size_t valStart = value.find_first_not_of(" 	");
            if (valStart != std::string::npos)
                value = value.substr(valStart);

            // Check for nocase modifier
            pat.nocase = (value.find("nocase") != std::string::npos);

            if (!value.empty() && value[0] == '{') {
                // Hex pattern
                pat.type = PatternDef::Hex;
                size_t hexEnd = value.find('}');
                std::string hexStr = (hexEnd != std::string::npos) ?
                    value.substr(1, hexEnd - 1) : value.substr(1);
                // Parse hex bytes
                std::istringstream hexStream(hexStr);
                std::string byte;
                while (hexStream >> byte) {
                    if (byte == "??") {
                        pat.bytes.push_back(0);
                        pat.mask.push_back(false);
                    } else if (byte.size() == 2) {
                        unsigned int val = 0;
                        bool valid = true;
                        for (char c : byte) {
                            if (!std::isxdigit(static_cast<unsigned char>(c))) { valid = false; break; }
                        }
                        if (valid) {
                            val = static_cast<unsigned int>(std::stoul(byte, nullptr, 16));
                            pat.bytes.push_back(static_cast<uint8_t>(val));
                            pat.mask.push_back(true);
                        }
                    }
                }
            } else if (!value.empty() && value[0] == '"') {
                // Text pattern
                pat.type = PatternDef::Text;
                size_t strEnd = value.find('"', 1);
                std::string textStr = (strEnd != std::string::npos) ?
                    value.substr(1, strEnd - 1) : value.substr(1);
                for (char c : textStr) {
                    pat.bytes.push_back(static_cast<uint8_t>(c));
                    pat.mask.push_back(true);
                }
            } else {
                continue;
            }

            rule.patterns.push_back(std::move(pat));
        }
    }

    // Extract condition
    if (conditionPos != std::string::npos) {
        size_t condStart = conditionPos + 10;
        size_t condEnd = ruleText.find('}', condStart);
        if (condEnd == std::string::npos) condEnd = ruleText.size();
        rule.condition = ruleText.substr(condStart, condEnd - condStart);
        // Trim
        size_t s = rule.condition.find_first_not_of(" \t\r\n");
        size_t e = rule.condition.find_last_not_of(" \t\r\n");
        if (s != std::string::npos && e != std::string::npos)
            rule.condition = rule.condition.substr(s, e - s + 1);
    }

    // Extract meta section
    auto metaPos = ruleText.find("meta:");
    if (metaPos != std::string::npos) {
        size_t metaEnd = (stringsPos != std::string::npos) ? stringsPos : conditionPos;
        if (metaEnd == std::string::npos) metaEnd = ruleText.size();
        std::string metaSection = ruleText.substr(metaPos + 5, metaEnd - metaPos - 5);
        std::istringstream ms(metaSection);
        std::string mline;
        while (std::getline(ms, mline)) {
            size_t eq = mline.find('=');
            if (eq == std::string::npos) continue;
            std::string key = mline.substr(0, eq);
            std::string val = mline.substr(eq + 1);
            // trim
            while (!key.empty() && std::isspace(static_cast<unsigned char>(key.front()))) key.erase(key.begin());
            while (!key.empty() && std::isspace(static_cast<unsigned char>(key.back()))) key.pop_back();
            while (!val.empty() && std::isspace(static_cast<unsigned char>(val.front()))) val.erase(val.begin());
            while (!val.empty() && std::isspace(static_cast<unsigned char>(val.back()))) val.pop_back();
            // Remove quotes from value
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"') {
                val = val.substr(1, val.size() - 2);
            }
            if (!key.empty())
                rule.meta.emplace_back(key, val);
        }
    }

    return rule;
}

std::vector<std::string> YaraEngine::splitRules(const std::string& text) {
    std::vector<std::string> rules;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t ruleStart = text.find("rule", pos);
        if (ruleStart == std::string::npos) break;
        // Ensure it is preceded by whitespace or beginning
        if (ruleStart > 0 && !std::isspace(static_cast<unsigned char>(text[ruleStart - 1]))) {
            pos = ruleStart + 4;
            continue;
        }
        // Find the matching closing brace
        size_t braceStart = text.find('{', ruleStart);
        if (braceStart == std::string::npos) break;
        int depth = 1;
        size_t i = braceStart + 1;
        while (i < text.size() && depth > 0) {
            if (text[i] == '{') depth++;
            else if (text[i] == '}') depth--;
            i++;
        }
        rules.push_back(text.substr(ruleStart, i - ruleStart));
        pos = i;
    }
    return rules;
}

void YaraEngine::buildAutomaton() {
    compiledRules_.clear();
    allPatterns_.clear();
    automaton_.clear();
    automatonBuilt_ = false;

    // Parse all rule sources
    for (const auto& source : ruleSources_) {
        auto ruleTexts = splitRules(source);
        for (const auto& rt : ruleTexts) {
            auto ruleDef = parseRule(rt);
            if (!ruleDef.name.empty()) {
                compiledRules_.push_back(std::move(ruleDef));
            }
        }
    }

    // Collect all patterns
    for (auto& rule : compiledRules_) {
        for (auto& pat : rule.patterns) {
            allPatterns_.push_back(&pat);
        }
    }

    // Build Aho-Corasick automaton from fixed-byte patterns
    automaton_.clear();
    automaton_.emplace_back(); // root node (index 0)

    for (size_t patIdx = 0; patIdx < allPatterns_.size(); ++patIdx) {
        const auto& pat = *allPatterns_[patIdx];
        if (pat.bytes.empty()) continue;

        // For patterns with wildcards, insert only the first contiguous fixed segment
        int current = 0;
        for (size_t bi = 0; bi < pat.bytes.size(); ++bi) {
            if (!pat.mask[bi]) break; // stop at first wildcard

            uint8_t byte = pat.bytes[bi];
            // For case-insensitive text, we insert both cases into the trie
            std::vector<uint8_t> variants;
            variants.push_back(byte);
            if (pat.nocase && pat.type == PatternDef::Text) {
                if (byte >= 'A' && byte <= 'Z')
                    variants.push_back(static_cast<uint8_t>(byte + 32));
                else if (byte >= 'a' && byte <= 'z')
                    variants.push_back(static_cast<uint8_t>(byte - 32));
            }

            // For Aho-Corasick, we only follow one path (primary byte)
            int idx = static_cast<int>(byte);
            if (automaton_[static_cast<size_t>(current)].children[static_cast<size_t>(idx)] == -1) {
                automaton_[static_cast<size_t>(current)].children[static_cast<size_t>(idx)] =
                    static_cast<int>(automaton_.size());
                automaton_.emplace_back();
            }
            current = automaton_[static_cast<size_t>(current)].children[static_cast<size_t>(idx)];
        }
        automaton_[static_cast<size_t>(current)].outputs.push_back(patIdx);
    }

    // Build failure links using BFS
    std::vector<int> queue;
    // Initialize depth-1 nodes
    for (int c = 0; c < 256; ++c) {
        int next = automaton_[0].children[static_cast<size_t>(c)];
        if (next != -1) {
            automaton_[static_cast<size_t>(next)].failure = 0;
            queue.push_back(next);
        }
    }

    size_t qIdx = 0;
    while (qIdx < queue.size()) {
        int node = queue[qIdx++];
        for (int c = 0; c < 256; ++c) {
            int child = automaton_[static_cast<size_t>(node)].children[static_cast<size_t>(c)];
            if (child == -1) continue;

            int fail = automaton_[static_cast<size_t>(node)].failure;
            while (fail != 0 && automaton_[static_cast<size_t>(fail)].children[static_cast<size_t>(c)] == -1) {
                fail = automaton_[static_cast<size_t>(fail)].failure;
            }
            int failChild = automaton_[static_cast<size_t>(fail)].children[static_cast<size_t>(c)];
            automaton_[static_cast<size_t>(child)].failure =
                (failChild != -1 && failChild != child) ? failChild : 0;

            // Merge outputs from failure node
            int failNode = automaton_[static_cast<size_t>(child)].failure;
            if (failNode != 0) {
                const auto& failOutputs = automaton_[static_cast<size_t>(failNode)].outputs;
                automaton_[static_cast<size_t>(child)].outputs.insert(
                    automaton_[static_cast<size_t>(child)].outputs.end(),
                    failOutputs.begin(), failOutputs.end());
            }

            queue.push_back(child);
        }
    }

    automatonBuilt_ = true;
}

bool YaraEngine::evaluateCondition(const std::string& condition,
                                    const std::vector<PatternDef>& patterns,
                                    const std::unordered_map<std::string, std::vector<size_t>>& hits) const {
    // Handle common conditions
    std::string cond = condition;

    // Trim
    while (!cond.empty() && std::isspace(static_cast<unsigned char>(cond.front()))) cond.erase(cond.begin());
    while (!cond.empty() && std::isspace(static_cast<unsigned char>(cond.back()))) cond.pop_back();

    if (cond.empty()) return !hits.empty();

    // "all of them"
    if (cond.find("all of them") != std::string::npos) {
        for (const auto& pat : patterns) {
            if (hits.find(pat.identifier) == hits.end()) return false;
        }
        return !patterns.empty();
    }

    // "any of them"
    if (cond.find("any of them") != std::string::npos) {
        return !hits.empty();
    }

    // "N of them" (e.g. "2 of them")
    {
        std::regex nOfThem(R"((\d+)\s+of\s+them)");
        std::smatch m;
        if (std::regex_search(cond, m, nOfThem)) {
            int required = std::stoi(m[1].str());
            int found = static_cast<int>(hits.size());
            return found >= required;
        }
    }

    // Check for specific pattern identifiers (e.g. " and ")
    // Simple boolean evaluation: split by "and"/"or"
    bool hasAnd = (cond.find(" and ") != std::string::npos);
    bool hasOr = (cond.find(" or ") != std::string::npos);

    if (hasAnd || hasOr) {
        // Split tokens
        std::vector<std::string> tokens;
        std::istringstream iss(cond);
        std::string tok;
        while (iss >> tok) {
            if (tok != "and" && tok != "or" && tok != "not")
                tokens.push_back(tok);
        }

        if (hasAnd) {
            for (const auto& t : tokens) {
                if (t[0] == '$') {
                    if (hits.find(t) == hits.end()) return false;
                }
            }
            return true;
        } else {
            for (const auto& t : tokens) {
                if (t[0] == '$') {
                    if (hits.find(t) != hits.end()) return true;
                }
            }
            return false;
        }
    }

    // Single pattern reference
    if (!cond.empty() && cond[0] == '$') {
        return hits.find(cond) != hits.end();
    }

    // Default: true if any pattern matched
    return !hits.empty();
}

std::vector<YaraMatch> YaraEngine::scanData(const uint8_t* data, size_t length) const {
    std::vector<YaraMatch> results;
    if (!automatonBuilt_ || compiledRules_.empty()) return results;

    // Run Aho-Corasick scan
    // patIdx -> list of match offsets
    std::unordered_map<size_t, std::vector<size_t>> patternHits;

    int state = 0;
    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = data[i];

        // Follow failure links if no transition
        while (state != 0 && automaton_[static_cast<size_t>(state)].children[byte] == -1) {
            state = automaton_[static_cast<size_t>(state)].failure;
        }
        int next = automaton_[static_cast<size_t>(state)].children[byte];
        state = (next != -1) ? next : 0;

        // Check outputs at this state
        for (size_t patIdx : automaton_[static_cast<size_t>(state)].outputs) {
            if (patIdx < allPatterns_.size()) {
                const auto& pat = *allPatterns_[patIdx];
                // Calculate start offset of the match
                size_t patFixedLen = 0;
                for (size_t bi = 0; bi < pat.bytes.size(); ++bi) {
                    if (!pat.mask[bi]) break;
                    patFixedLen++;
                }
                if (i + 1 >= patFixedLen) {
                    size_t matchStart = i + 1 - patFixedLen;
                    // Verify full pattern (including wildcards and case-insensitive)
                    bool fullMatch = true;
                    if (matchStart + pat.bytes.size() <= length) {
                        for (size_t bi = 0; bi < pat.bytes.size(); ++bi) {
                            if (!pat.mask[bi]) continue; // wildcard
                            uint8_t expected = pat.bytes[bi];
                            uint8_t actual = data[matchStart + bi];
                            if (pat.nocase && pat.type == PatternDef::Text) {
                                if (std::tolower(static_cast<unsigned char>(expected)) !=
                                    std::tolower(static_cast<unsigned char>(actual))) {
                                    fullMatch = false;
                                    break;
                                }
                            } else {
                                if (expected != actual) {
                                    fullMatch = false;
                                    break;
                                }
                            }
                        }
                    } else {
                        fullMatch = false;
                    }
                    if (fullMatch) {
                        patternHits[patIdx].push_back(matchStart);
                    }
                }
            }
        }
    }

    // Also do a direct scan for patterns not well-served by the automaton
    // (short patterns, nocase patterns)
    for (size_t patIdx = 0; patIdx < allPatterns_.size(); ++patIdx) {
        if (patternHits.count(patIdx) > 0) continue; // Already found by Aho-Corasick
        const auto& pat = *allPatterns_[patIdx];
        if (pat.bytes.empty()) continue;
        if (pat.bytes.size() > length) continue;

        for (size_t offset = 0; offset <= length - pat.bytes.size(); ++offset) {
            bool match = true;
            for (size_t bi = 0; bi < pat.bytes.size(); ++bi) {
                if (!pat.mask[bi]) continue;
                uint8_t expected = pat.bytes[bi];
                uint8_t actual = data[offset + bi];
                if (pat.nocase && pat.type == PatternDef::Text) {
                    if (std::tolower(static_cast<unsigned char>(expected)) !=
                        std::tolower(static_cast<unsigned char>(actual))) {
                        match = false;
                        break;
                    }
                } else {
                    if (expected != actual) {
                        match = false;
                        break;
                    }
                }
            }
            if (match) {
                patternHits[patIdx].push_back(offset);
            }
        }
    }

    // Evaluate each rule
    for (const auto& rule : compiledRules_) {
        // Collect hits for this rule's patterns
        std::unordered_map<std::string, std::vector<size_t>> ruleHits;
        for (const auto& pat : rule.patterns) {
            // Find pattern index in allPatterns_
            for (size_t pi = 0; pi < allPatterns_.size(); ++pi) {
                if (allPatterns_[pi] == &pat) {
                    auto it = patternHits.find(pi);
                    if (it != patternHits.end()) {
                        ruleHits[pat.identifier] = it->second;
                    }
                    break;
                }
            }
        }

        // Evaluate condition
        if (evaluateCondition(rule.condition, rule.patterns, ruleHits)) {
            YaraMatch match;
            match.ruleName = rule.name;
            match.ruleNamespace = rule.ns;
            match.tags = rule.tags;
            for (const auto& [key, val] : rule.meta) {
                match.metaStrings.push_back(key + "=" + val);
            }
            for (const auto& [ident, offsets] : ruleHits) {
                match.matchedStrings.emplace_back(ident, offsets);
            }
            results.push_back(std::move(match));
        }
    }

    return results;
}

Core::Result<void, Core::Error> YaraEngine::compileRules() {
    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (ruleNames_.empty()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("No rules loaded to compile", Core::ErrorCategory::Validation));
    }

    buildAutomaton();
    compiled_ = true;
    logger_.info("Compiled {} YARA rules into Aho-Corasick automaton ({} nodes)",
                 ruleNames_.size(), automaton_.size());

    return Core::Result<void, Core::Error>::ok();
}

Core::Result<std::vector<YaraMatch>, Core::Error> YaraEngine::matchFile(
    const std::filesystem::path& filePath) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (!compiled_) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("Rules not compiled", Core::ErrorCategory::Internal));
    }

    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec)) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("File not found: " + filePath.string(), Core::ErrorCategory::IO));
    }

    // Read entire file into memory for scanning
    std::ifstream fileStream(filePath, std::ios::binary);
    if (!fileStream.is_open()) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("Cannot open file: " + filePath.string(), Core::ErrorCategory::IO));
    }

    fileStream.seekg(0, std::ios::end);
    auto fileSize = fileStream.tellg();
    fileStream.seekg(0, std::ios::beg);

    std::vector<uint8_t> fileData;
    if (fileSize > 0) {
        fileData.resize(static_cast<size_t>(fileSize));
        fileStream.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    }

    auto matches = scanData(fileData.data(), fileData.size());
    logger_.debug("YARA scan on file: {} - {} matches", filePath.string(), matches.size());
    return Core::Result<std::vector<YaraMatch>, Core::Error>::ok(std::move(matches));
}

Core::Result<std::vector<YaraMatch>, Core::Error> YaraEngine::matchBuffer(
    const std::vector<uint8_t>& data) {

    if (status_ == YaraEngineStatus::Uninitialized) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("YARA engine not initialized", Core::ErrorCategory::Internal));
    }

    if (!compiled_) {
        return Core::Result<std::vector<YaraMatch>, Core::Error>::err(
            Core::Error("Rules not compiled", Core::ErrorCategory::Internal));
    }

    auto matches = scanData(data.data(), data.size());
    logger_.debug("YARA scan on buffer ({} bytes) - {} matches", data.size(), matches.size());
    return Core::Result<std::vector<YaraMatch>, Core::Error>::ok(std::move(matches));
}

#endif // HAS_YARA

// ============================================================================
// Common implementation (shared between real and built-in engine)
// ============================================================================

size_t YaraEngine::ruleCount() const {
    return ruleNames_.size();
}

std::vector<std::string> YaraEngine::getRuleNames() const {
    return ruleNames_;
}

YaraEngineStatus YaraEngine::status() const {
    return status_;
}

void YaraEngine::clearRules() {
    ruleNames_.clear();
    ruleSources_.clear();
    compiled_ = false;
    logger_.info("Cleared all YARA rules");
}

std::vector<std::string> YaraEngine::parseRuleNames(const std::string& text) const {
    std::vector<std::string> names;

    // Simple parser: look for "rule <name>" pattern
    // YARA rule syntax: rule <identifier> [: tag1 tag2] { ... }
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        // Skip comments
        size_t pos = line.find("//");
        if (pos != std::string::npos) {
            line = line.substr(0, pos);
        }

        // Find "rule" keyword
        pos = line.find("rule");
        if (pos == std::string::npos) continue;

        // Check it starts at beginning or after whitespace
        if (pos > 0 && !std::isspace(static_cast<unsigned char>(line[pos - 1]))) {
            continue;
        }

        // Skip "rule" keyword and whitespace
        pos += 4;  // len("rule")
        while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) {
            pos++;
        }

        // Extract the rule name (identifier: alphanumeric + underscore)
        std::string name;
        while (pos < line.size() &&
               (std::isalnum(static_cast<unsigned char>(line[pos])) || line[pos] == '_')) {
            name.push_back(line[pos]);
            pos++;
        }

        if (!name.empty()) {
            names.push_back(std::move(name));
        }
    }

    return names;
}

} // namespace ThreatOne::Scanner
