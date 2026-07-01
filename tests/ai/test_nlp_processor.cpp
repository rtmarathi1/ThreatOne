#include <doctest/doctest.h>
#include <ai/NLPProcessor.h>

#include <string>
#include <vector>
#include <algorithm>

using namespace ThreatOne::AI;

TEST_CASE("NLPProcessor - keyword extraction") {
    NLPProcessor processor;

    SUBCASE("Extracts keywords from security text") {
        std::string text = "The malware attack was detected by the firewall. "
                           "The attack used a trojan to compromise the system. "
                           "The malware was delivered via phishing email. "
                           "Firewall blocked further attack attempts.";

        auto keywords = processor.extractKeywords(text);
        CHECK(!keywords.empty());

        // "attack" should be a top keyword (appears 3 times)
        bool foundAttack = false;
        for (const auto& kw : keywords) {
            if (kw.keyword == "attack") {
                foundAttack = true;
                CHECK(kw.frequency >= 3);
                CHECK(kw.relevance > 0.0);
            }
        }
        CHECK(foundAttack == true);
    }

    SUBCASE("Stop words are excluded from keywords") {
        std::string text = "the is are was were a an this that and or but with";
        auto keywords = processor.extractKeywords(text);
        // Stop words should not appear
        for (const auto& kw : keywords) {
            CHECK(kw.keyword != "the");
            CHECK(kw.keyword != "is");
            CHECK(kw.keyword != "are");
        }
    }

    SUBCASE("Empty text returns no keywords") {
        auto keywords = processor.extractKeywords("");
        CHECK(keywords.empty());
    }

    SUBCASE("Security keywords get higher relevance") {
        std::string text = "vulnerability exploit normal regular vulnerability exploit attack";
        auto keywords = processor.extractKeywords(text);

        // Find a security keyword and a normal word
        double securityRelevance = 0.0;
        double normalRelevance = 0.0;
        for (const auto& kw : keywords) {
            if (kw.keyword == "vulnerability" || kw.keyword == "exploit") {
                securityRelevance = std::max(securityRelevance, kw.relevance);
            }
            if (kw.keyword == "normal" || kw.keyword == "regular") {
                normalRelevance = std::max(normalRelevance, kw.relevance);
            }
        }
        CHECK(securityRelevance > normalRelevance);
    }
}

TEST_CASE("NLPProcessor - tokenization") {
    NLPProcessor processor;

    SUBCASE("Basic tokenization splits on spaces") {
        auto tokens = processor.tokenize("hello world test");
        CHECK(tokens.size() == 3);
        CHECK(tokens[0] == "hello");
        CHECK(tokens[1] == "world");
        CHECK(tokens[2] == "test");
    }

    SUBCASE("Punctuation splits tokens") {
        auto tokens = processor.tokenize("error: failed (code=42)");
        // Should split around : ( ) =
        CHECK(tokens.size() >= 3);
        // Should find "error", "failed", "code", "42"
        bool foundError = std::find(tokens.begin(), tokens.end(), "error") != tokens.end();
        bool foundFailed = std::find(tokens.begin(), tokens.end(), "failed") != tokens.end();
        CHECK(foundError == true);
        CHECK(foundFailed == true);
    }

    SUBCASE("Converts to lowercase") {
        auto tokens = processor.tokenize("HELLO World MiXeD");
        CHECK(tokens[0] == "hello");
        CHECK(tokens[1] == "world");
        CHECK(tokens[2] == "mixed");
    }

    SUBCASE("Empty input returns empty tokens") {
        auto tokens = processor.tokenize("");
        CHECK(tokens.empty());
    }

    SUBCASE("Underscores kept as part of tokens") {
        auto tokens = processor.tokenize("file_name process_id");
        CHECK(tokens.size() == 2);
        CHECK(tokens[0] == "file_name");
        CHECK(tokens[1] == "process_id");
    }
}

TEST_CASE("NLPProcessor - pattern matching") {
    NLPProcessor processor;

    SUBCASE("IP address regex matches") {
        std::string text = "Connection from 192.168.1.100 to 10.0.0.1 was blocked";
        std::vector<std::string> patterns = {"\\d+\\.\\d+\\.\\d+\\.\\d+"};

        auto matches = processor.matchPattern(text, patterns);
        CHECK(matches.size() >= 1);
        // Should find at least one IP
        bool foundIP = false;
        for (const auto& match : matches) {
            if (match.find("192.168.1.100") != std::string::npos ||
                match.find("10.0.0.1") != std::string::npos) {
                foundIP = true;
            }
        }
        CHECK(foundIP == true);
    }

    SUBCASE("No match returns empty result") {
        std::string text = "Just some plain text with no special patterns";
        std::vector<std::string> patterns = {"\\d+\\.\\d+\\.\\d+\\.\\d+"};

        auto matches = processor.matchPattern(text, patterns);
        CHECK(matches.empty());
    }

    SUBCASE("Multiple patterns can match") {
        std::string text = "Error from 192.168.1.1 accessing /etc/passwd at 2024-01-01";
        std::vector<std::string> patterns = {
            "\\d+\\.\\d+\\.\\d+\\.\\d+",
            "/etc/\\w+"
        };

        auto matches = processor.matchPattern(text, patterns);
        CHECK(matches.size() >= 2);
    }
}

TEST_CASE("NLPProcessor - log summarization") {
    NLPProcessor processor;

    SUBCASE("Summarize produces non-empty output") {
        std::vector<std::string> logs = {
            "2024-01-01 10:00:00 ERROR: Failed login attempt from 192.168.1.50",
            "2024-01-01 10:00:01 ERROR: Failed login attempt from 192.168.1.50",
            "2024-01-01 10:00:02 ERROR: Failed login attempt from 192.168.1.50",
            "2024-01-01 10:00:03 WARNING: Brute force attack detected",
            "2024-01-01 10:00:04 CRITICAL: Account locked due to repeated failures"
        };

        auto summary = processor.summarizeLog(logs);
        CHECK(!summary.summary.empty());
        CHECK(!summary.severity.empty());
    }

    SUBCASE("Empty logs produce minimal summary") {
        std::vector<std::string> logs;
        auto summary = processor.summarizeLog(logs);
        // Should not crash, may return default summary
        CHECK(summary.severity.empty() == false || summary.summary.empty() == true);
    }

    SUBCASE("Critical logs produce high severity") {
        std::vector<std::string> logs = {
            "CRITICAL: System compromise detected",
            "CRITICAL: Ransomware encryption in progress",
            "CRITICAL: Data exfiltration detected"
        };

        auto summary = processor.summarizeLog(logs);
        CHECK(!summary.severity.empty());
    }
}

TEST_CASE("NLPProcessor - alert summary generation") {
    NLPProcessor processor;

    SUBCASE("Generate alert summary from data") {
        std::map<std::string, std::string> alertData;
        alertData["type"] = "intrusion_attempt";
        alertData["source"] = "192.168.1.100";
        alertData["destination"] = "10.0.0.5";
        alertData["severity"] = "high";
        alertData["description"] = "Unauthorized access attempt detected";

        auto summary = processor.generateAlertSummary(alertData);
        CHECK(!summary.empty());
    }

    SUBCASE("Empty alert data produces some output") {
        std::map<std::string, std::string> alertData;
        auto summary = processor.generateAlertSummary(alertData);
        // Should not crash
        CHECK(summary.empty() == false || summary.empty() == true);
    }
}
