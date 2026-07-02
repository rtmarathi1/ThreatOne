#include <doctest/doctest.h>
#include <threat_intel/StixParser.h>
#include <threat_intel/CsvParser.h>
#include <threat_intel/PlainTextParser.h>
#include <threat_intel/OpenIOCParser.h>
#include <string>

using namespace ThreatOne::ThreatIntel;

TEST_CASE("StixParser - Valid STIX 2.1 bundle") {
    StixParser parser;

    SUBCASE("Parse bundle with IP indicator") {
        std::string data = R"({
            "type": "bundle",
            "id": "bundle-1",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator-1",
                    "pattern": "[ipv4-addr:value = '203.0.113.50']",
                    "confidence": 85,
                    "name": "Malicious IP"
                }
            ]
        })";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        REQUIRE(iocs.size() == 1);
        CHECK(iocs[0].type == IOCType::IP);
        CHECK(iocs[0].value == "203.0.113.50");
        CHECK(iocs[0].confidence == doctest::Approx(0.85));
        CHECK(iocs[0].severity == IOCSeverity::Critical);
    }

    SUBCASE("Parse bundle with domain indicator") {
        std::string data = R"({
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator-2",
                    "pattern": "[domain-name:value = 'bad-domain.xyz']",
                    "confidence": 50
                }
            ]
        })";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        REQUIRE(iocs.size() == 1);
        CHECK(iocs[0].type == IOCType::Domain);
        CHECK(iocs[0].value == "bad-domain.xyz");
        CHECK(iocs[0].confidence == doctest::Approx(0.5));
    }

    SUBCASE("Parse bundle with SHA-256 hash") {
        std::string data = R"({
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator-3",
                    "pattern": "[file:hashes.SHA256 = 'e3b0c44298fc1c149afbf4c8996fb924']",
                    "confidence": 95
                }
            ]
        })";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        REQUIRE(iocs.size() == 1);
        CHECK(iocs[0].type == IOCType::Hash_SHA256);
        CHECK(iocs[0].value == "e3b0c44298fc1c149afbf4c8996fb924");
    }

    SUBCASE("Parse bundle with multiple indicators") {
        std::string data = R"({
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "pattern": "[ipv4-addr:value = '10.0.0.1']",
                    "confidence": 70
                },
                {
                    "type": "indicator",
                    "pattern": "[url:value = 'http://malware.com/payload']",
                    "confidence": 90
                },
                {
                    "type": "malware",
                    "name": "NotAnIndicator"
                }
            ]
        })";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        CHECK(iocs.size() == 2);
    }
}

TEST_CASE("StixParser - Invalid input") {
    StixParser parser;

    SUBCASE("Malformed JSON returns error") {
        auto result = parser.parse("not json at all {{{");
        CHECK(result.isErr());
    }

    SUBCASE("Missing objects array returns error") {
        auto result = parser.parse(R"({"type": "bundle"})");
        CHECK(result.isErr());
    }

    SUBCASE("Empty objects array returns empty vector") {
        auto result = parser.parse(R"({"type": "bundle", "objects": []})");
        REQUIRE(result.isOk());
        CHECK(result.value().empty());
    }
}

TEST_CASE("CsvParser - Valid CSV data") {
    CsvParser parser;

    SUBCASE("Parse CSV with header") {
        std::string data =
            "type,value,confidence,source\n"
            "IP,192.168.1.1,0.8,feed1\n"
            "Domain,evil.com,0.9,feed2\n";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        REQUIRE(iocs.size() == 2);
        CHECK(iocs[0].type == IOCType::IP);
        CHECK(iocs[0].value == "192.168.1.1");
        CHECK(iocs[0].confidence == doctest::Approx(0.8));
        CHECK(iocs[1].type == IOCType::Domain);
        CHECK(iocs[1].value == "evil.com");
    }

    SUBCASE("Parse single row") {
        std::string data = "type,value,confidence,source\nHash_SHA256,abcdef123456,0.95,intel\n";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        REQUIRE(iocs.size() == 1);
        CHECK(iocs[0].type == IOCType::Hash_SHA256);
        CHECK(iocs[0].value == "abcdef123456");
    }
}

TEST_CASE("CsvParser - Invalid CSV input") {
    CsvParser parser;

    SUBCASE("Empty data returns empty vector") {
        auto result = parser.parse("");
        REQUIRE(result.isOk());
        CHECK(result.value().empty());
    }

    SUBCASE("Header only returns empty vector") {
        auto result = parser.parse("type,value,confidence,source\n");
        REQUIRE(result.isOk());
        CHECK(result.value().empty());
    }
}

TEST_CASE("PlainTextParser - Auto-detection of IOC types") {
    PlainTextParser parser;

    SUBCASE("IP addresses detected") {
        std::string data = "192.168.1.1\n10.0.0.5\n";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        REQUIRE(iocs.size() == 2);
        CHECK(iocs[0].type == IOCType::IP);
        CHECK(iocs[0].value == "192.168.1.1");
        CHECK(iocs[1].type == IOCType::IP);
        CHECK(iocs[1].value == "10.0.0.5");
    }

    SUBCASE("Domains detected") {
        std::string data = "evil.com\nmalware.example.org\n";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        REQUIRE(iocs.size() == 2);
        CHECK(iocs[0].type == IOCType::Domain);
        CHECK(iocs[1].type == IOCType::Domain);
    }

    SUBCASE("URLs detected") {
        std::string data = "http://malware.com/payload\nhttps://evil.org/c2\n";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        REQUIRE(iocs.size() == 2);
        CHECK(iocs[0].type == IOCType::URL);
        CHECK(iocs[1].type == IOCType::URL);
    }

    SUBCASE("Comments and empty lines are skipped") {
        std::string data = "# Comment line\n\n192.168.1.1\n# Another comment\nevil.com\n";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        CHECK(iocs.size() == 2);
    }

    SUBCASE("Empty data returns empty vector") {
        auto result = parser.parse("");
        REQUIRE(result.isOk());
        CHECK(result.value().empty());
    }
}

TEST_CASE("PlainTextParser - IOC type detection function") {
    SUBCASE("IPv4 addresses") {
        CHECK(PlainTextParser::detectIOCType("192.168.1.1") == IOCType::IP);
        CHECK(PlainTextParser::detectIOCType("10.0.0.1") == IOCType::IP);
    }

    SUBCASE("URLs") {
        CHECK(PlainTextParser::detectIOCType("http://example.com") == IOCType::URL);
        CHECK(PlainTextParser::detectIOCType("https://evil.com/path") == IOCType::URL);
    }

    SUBCASE("Email addresses") {
        CHECK(PlainTextParser::detectIOCType("bad@evil.com") == IOCType::EmailAddress);
    }
}

TEST_CASE("OpenIOCParser - Valid OpenIOC XML") {
    OpenIOCParser parser;

    SUBCASE("Parse single indicator item") {
        std::string data = R"(
<ioc>
  <IndicatorItem>
    <Context document="FileItem" search="FileItem/Md5sum" type="mir"/>
    <Content type="md5">d41d8cd98f00b204e9800998ecf8427e</Content>
  </IndicatorItem>
</ioc>
)";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        REQUIRE(iocs.size() >= 1);
        // OpenIOC should extract the hash
        CHECK(iocs[0].value == "d41d8cd98f00b204e9800998ecf8427e");
    }

    SUBCASE("Parse multiple indicator items") {
        std::string data = R"(
<ioc>
  <IndicatorItem>
    <Context document="Network" search="Network/DNS" type="mir"/>
    <Content type="domain">malicious-domain.com</Content>
  </IndicatorItem>
  <IndicatorItem>
    <Context document="Network" search="Network/IP" type="mir"/>
    <Content type="ip">203.0.113.1</Content>
  </IndicatorItem>
</ioc>
)";

        auto result = parser.parse(data);
        REQUIRE(result.isOk());
        auto& iocs = result.value();
        CHECK(iocs.size() >= 2);
    }
}

TEST_CASE("OpenIOCParser - Invalid input") {
    OpenIOCParser parser;

    SUBCASE("Empty data returns empty vector") {
        auto result = parser.parse("");
        REQUIRE(result.isOk());
        CHECK(result.value().empty());
    }

    SUBCASE("No indicator items returns empty vector") {
        auto result = parser.parse("<ioc></ioc>");
        REQUIRE(result.isOk());
        CHECK(result.value().empty());
    }
}
