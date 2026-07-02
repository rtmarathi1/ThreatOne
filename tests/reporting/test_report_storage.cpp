#include <doctest/doctest.h>
#include <reporting/ReportStorage.h>
#include <chrono>
#include <string>

using namespace ThreatOne::Reporting;

static Report makeStorageTestReport(const std::string& id, const std::string& title, ReportType type) {
    Report report;
    report.id = id;
    report.title = title;
    report.type = type;
    report.content = "Content for " + title;
    report.generatedAt = "2024-01-15 10:00:00";
    report.author = "TestAuthor";
    report.sizeBytes = 200;
    report.format = ExportFormat::JSON;
    return report;
}

TEST_CASE("ReportStorage - store and retrieve report") {
    ReportStorage storage;

    auto report = makeStorageTestReport("rpt-001", "Security Scan Results", ReportType::Scan);

    auto result = storage.storeReport(report);
    REQUIRE(result.isOk());
    CHECK(result.value() == "rpt-001");
    CHECK(storage.getStoredReportCount() == 1);

    auto retrieved = storage.retrieveReport("rpt-001");
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->title == "Security Scan Results");
    CHECK(retrieved->type == ReportType::Scan);
    CHECK(retrieved->sizeBytes == 200);
}

TEST_CASE("ReportStorage - empty ID returns error") {
    ReportStorage storage;

    Report report;
    report.id = "";
    report.title = "No ID Report";

    auto result = storage.storeReport(report);
    REQUIRE(result.isErr());
    CHECK(result.error().category() == ThreatOne::Core::ErrorCategory::Validation);
}

TEST_CASE("ReportStorage - retrieve nonexistent report") {
    ReportStorage storage;

    auto retrieved = storage.retrieveReport("nonexistent");
    CHECK_FALSE(retrieved.has_value());
}

TEST_CASE("ReportStorage - delete report") {
    ReportStorage storage;

    auto report = makeStorageTestReport("rpt-del", "To Delete", ReportType::Audit);
    storage.storeReport(report);

    CHECK(storage.deleteReport("rpt-del"));
    CHECK(storage.getStoredReportCount() == 0);
    CHECK_FALSE(storage.retrieveReport("rpt-del").has_value());
    CHECK_FALSE(storage.deleteReport("rpt-del")); // already deleted
}

TEST_CASE("ReportStorage - search by title") {
    ReportStorage storage;

    storage.storeReport(makeStorageTestReport("rpt-1", "Weekly Security Scan", ReportType::Scan));
    storage.storeReport(makeStorageTestReport("rpt-2", "Monthly Compliance Report", ReportType::Compliance));
    storage.storeReport(makeStorageTestReport("rpt-3", "Security Incident Analysis", ReportType::Incident));

    SUBCASE("Partial title match") {
        ReportFilter filter;
        filter.titleContains = "Security";
        auto results = storage.searchReports(filter);
        CHECK(results.size() == 2);
    }

    SUBCASE("Case-insensitive search") {
        ReportFilter filter;
        filter.titleContains = "security";
        auto results = storage.searchReports(filter);
        CHECK(results.size() == 2);
    }

    SUBCASE("No match") {
        ReportFilter filter;
        filter.titleContains = "Nonexistent";
        auto results = storage.searchReports(filter);
        CHECK(results.empty());
    }

    SUBCASE("Empty filter returns all") {
        ReportFilter filter;
        auto results = storage.searchReports(filter);
        CHECK(results.size() == 3);
    }
}

TEST_CASE("ReportStorage - filter by type") {
    ReportStorage storage;

    storage.storeReport(makeStorageTestReport("rpt-1", "Scan A", ReportType::Scan));
    storage.storeReport(makeStorageTestReport("rpt-2", "Scan B", ReportType::Scan));
    storage.storeReport(makeStorageTestReport("rpt-3", "Audit C", ReportType::Audit));
    storage.storeReport(makeStorageTestReport("rpt-4", "Risk D", ReportType::Risk));

    SUBCASE("Filter single type") {
        ReportFilter filter;
        filter.types = {ReportType::Scan};
        auto results = storage.searchReports(filter);
        CHECK(results.size() == 2);
    }

    SUBCASE("Filter multiple types") {
        ReportFilter filter;
        filter.types = {ReportType::Scan, ReportType::Audit};
        auto results = storage.searchReports(filter);
        CHECK(results.size() == 3);
    }

    SUBCASE("Filter type with no matches") {
        ReportFilter filter;
        filter.types = {ReportType::Executive};
        auto results = storage.searchReports(filter);
        CHECK(results.empty());
    }
}

TEST_CASE("ReportStorage - download tracking") {
    ReportStorage storage;

    auto report = makeStorageTestReport("rpt-dl", "Download Test", ReportType::Technical);
    storage.storeReport(report);

    CHECK(storage.getDownloadCount("rpt-dl") == 0);

    CHECK(storage.trackDownload("rpt-dl", "user-alice"));
    CHECK(storage.getDownloadCount("rpt-dl") == 1);

    CHECK(storage.trackDownload("rpt-dl", "user-bob"));
    CHECK(storage.trackDownload("rpt-dl", "user-alice"));
    CHECK(storage.getDownloadCount("rpt-dl") == 3);

    auto history = storage.getDownloadHistory("rpt-dl");
    CHECK(history.size() == 3);
    CHECK(history[0].userId == "user-alice");
    CHECK(history[1].userId == "user-bob");
    CHECK(history[2].userId == "user-alice");
}

TEST_CASE("ReportStorage - download tracking for nonexistent report") {
    ReportStorage storage;

    CHECK_FALSE(storage.trackDownload("nonexistent", "user-1"));
    CHECK(storage.getDownloadCount("nonexistent") == 0);
    CHECK(storage.getDownloadHistory("nonexistent").empty());
}

TEST_CASE("ReportStorage - metadata") {
    ReportStorage storage;

    auto report = makeStorageTestReport("rpt-meta", "Metadata Test", ReportType::Compliance);
    storage.storeReport(report);

    auto meta = storage.getMetadata("rpt-meta");
    REQUIRE(meta.has_value());
    CHECK(meta->id == "rpt-meta");
    CHECK(meta->title == "Metadata Test");
    CHECK(meta->type == ReportType::Compliance);
    CHECK(meta->sizeBytes == 200);
    CHECK(meta->downloadCount == 0);

    CHECK_FALSE(storage.getMetadata("nonexistent").has_value());
}

TEST_CASE("ReportStorage - total storage size") {
    ReportStorage storage;

    storage.storeReport(makeStorageTestReport("rpt-1", "Report 1", ReportType::Scan));
    storage.storeReport(makeStorageTestReport("rpt-2", "Report 2", ReportType::Scan));

    CHECK(storage.getTotalStorageSize() == 400); // 200 + 200
}

TEST_CASE("ReportStorage - clear") {
    ReportStorage storage;

    storage.storeReport(makeStorageTestReport("rpt-1", "R1", ReportType::Scan));
    storage.storeReport(makeStorageTestReport("rpt-2", "R2", ReportType::Audit));
    storage.trackDownload("rpt-1", "user");

    storage.clear();
    CHECK(storage.getStoredReportCount() == 0);
    CHECK(storage.getTotalStorageSize() == 0);
    CHECK(storage.getDownloadHistory("rpt-1").empty());
}

TEST_CASE("ReportStorage - get all metadata") {
    ReportStorage storage;

    storage.storeReport(makeStorageTestReport("rpt-1", "A", ReportType::Scan));
    storage.storeReport(makeStorageTestReport("rpt-2", "B", ReportType::Risk));

    auto all = storage.getAllMetadata();
    CHECK(all.size() == 2);
}

TEST_CASE("ReportStorage - date filter excludes reports outside range") {
    ReportStorage storage;

    // Store first report
    storage.storeReport(makeStorageTestReport("rpt-early", "Early Report", ReportType::Scan));

    // Use a date range that starts in the future to exclude all current reports
    ReportFilter filter;
    filter.hasDateFilter = true;
    filter.dateRange.start = std::chrono::system_clock::now() + std::chrono::hours(24);
    filter.dateRange.end = std::chrono::system_clock::now() + std::chrono::hours(48);

    auto results = storage.searchReports(filter);
    CHECK(results.empty());
}

TEST_CASE("ReportStorage - date filter includes reports within range") {
    ReportStorage storage;

    storage.storeReport(makeStorageTestReport("rpt-now", "Current Report", ReportType::Scan));

    // Use a date range that includes now
    ReportFilter filter;
    filter.hasDateFilter = true;
    filter.dateRange.start = std::chrono::system_clock::now() - std::chrono::hours(1);
    filter.dateRange.end = std::chrono::system_clock::now() + std::chrono::hours(1);

    auto results = storage.searchReports(filter);
    CHECK(results.size() == 1);
    CHECK(results[0].id == "rpt-now");
}
