#include <doctest/doctest.h>
#include <threat_intel/CVEDatabase.h>

#include <chrono>

using namespace ThreatOne::ThreatIntel;

TEST_CASE("CVEDatabase - Add and get CVE") {
    CVEDatabase db;
    CVEEntry entry;
    entry.cveId = "CVE-2023-12345";
    entry.description = "Test vulnerability";
    entry.cvssScore = 7.5;
    entry.severity = "High";
    entry.affectedProducts.push_back({"VendorA", "ProductX", "1.0"});

    auto addResult = db.addCVE(entry);
    REQUIRE(addResult.isOk());

    auto getResult = db.getCVEById("CVE-2023-12345");
    REQUIRE(getResult.isOk());
    CHECK(getResult.value().description == "Test vulnerability");
    CHECK(getResult.value().cvssScore == doctest::Approx(7.5));
    CHECK(getResult.value().severity == "High");
}

TEST_CASE("CVEDatabase - Get non-existent CVE fails") {
    CVEDatabase db;
    auto result = db.getCVEById("CVE-0000-00000");
    CHECK(result.isErr());
}

TEST_CASE("CVEDatabase - Size and clear") {
    CVEDatabase db;
    CVEEntry e1, e2;
    e1.cveId = "CVE-2023-00001";
    e1.description = "First";
    e1.cvssScore = 5.0;
    e2.cveId = "CVE-2023-00002";
    e2.description = "Second";
    e2.cvssScore = 9.0;

    db.addCVE(e1);
    db.addCVE(e2);
    CHECK(db.size() == 2);

    db.clear();
    CHECK(db.size() == 0);
}

TEST_CASE("CVEDatabase - Update CVE") {
    CVEDatabase db;
    CVEEntry entry;
    entry.cveId = "CVE-2023-99999";
    entry.description = "Original";
    entry.cvssScore = 4.0;
    db.addCVE(entry);

    CVEEntry updated;
    updated.cveId = "CVE-2023-99999";
    updated.description = "Updated description";
    updated.cvssScore = 8.5;
    auto updateResult = db.updateCVE(updated);
    CHECK(updateResult.isOk());

    auto getResult = db.getCVEById("CVE-2023-99999");
    REQUIRE(getResult.isOk());
    CHECK(getResult.value().description == "Updated description");
    CHECK(getResult.value().cvssScore == doctest::Approx(8.5));
}

TEST_CASE("CVEDatabase - Search by product") {
    CVEDatabase db;
    CVEEntry e1;
    e1.cveId = "CVE-2023-10001";
    e1.description = "Buffer overflow in WebServer";
    e1.cvssScore = 9.8;
    e1.severity = "Critical";
    e1.affectedProducts.push_back({"Apache", "WebServer", "2.4"});
    db.addCVE(e1);

    CVEEntry e2;
    e2.cveId = "CVE-2023-10002";
    e2.description = "XSS in CMS";
    e2.cvssScore = 6.1;
    e2.severity = "Medium";
    e2.affectedProducts.push_back({"WordPress", "CMS", "5.0"});
    db.addCVE(e2);

    auto results = db.searchByProduct("WebServer");
    REQUIRE(results.size() == 1);
    CHECK(results[0].cveId == "CVE-2023-10001");
}

TEST_CASE("CVEDatabase - Search by vendor") {
    CVEDatabase db;
    CVEEntry e1;
    e1.cveId = "CVE-2023-10001";
    e1.cvssScore = 9.8;
    e1.affectedProducts.push_back({"Apache", "WebServer", "2.4"});
    db.addCVE(e1);

    CVEEntry e2;
    e2.cveId = "CVE-2023-10003";
    e2.cvssScore = 7.8;
    e2.affectedProducts.push_back({"Apache", "Tomcat", "9.0"});
    db.addCVE(e2);

    CVEEntry e3;
    e3.cveId = "CVE-2023-10002";
    e3.cvssScore = 6.1;
    e3.affectedProducts.push_back({"WordPress", "CMS", "5.0"});
    db.addCVE(e3);

    auto results = db.searchByVendor("Apache");
    CHECK(results.size() == 2);
}

TEST_CASE("CVEDatabase - Filter by severity") {
    CVEDatabase db;
    CVEEntry e1;
    e1.cveId = "CVE-2023-10001";
    e1.cvssScore = 9.8;
    db.addCVE(e1);

    CVEEntry e2;
    e2.cveId = "CVE-2023-10002";
    e2.cvssScore = 6.1;
    db.addCVE(e2);

    CVEEntry e3;
    e3.cveId = "CVE-2023-10003";
    e3.cvssScore = 7.8;
    db.addCVE(e3);

    auto critical = db.filterBySeverity(9.0);
    CHECK(critical.size() == 1);
    CHECK(critical[0].cveId == "CVE-2023-10001");

    auto highAndAbove = db.filterBySeverity(7.0);
    CHECK(highAndAbove.size() == 2);
}
