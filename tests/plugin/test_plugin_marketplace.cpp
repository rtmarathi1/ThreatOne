#include <doctest/doctest.h>
#include <plugin/PluginMarketplace.h>

using namespace ThreatOne::Plugin;

TEST_CASE("PluginMarketplace - Add and get entries") {
    PluginMarketplace mkt;

    MarketplaceEntry entry;
    entry.id = "scanner_pro";
    entry.name = "Security Scanner Pro";
    entry.version = "2.0.0";
    entry.author = "SecCo";
    entry.description = "Advanced scanning";
    entry.downloads = 1000;
    entry.rating = 4.5;
    mkt.addEntry(entry);

    auto entries = mkt.getEntries();
    CHECK(entries.size() == 1);
    CHECK(entries[0].id == "scanner_pro");
}

TEST_CASE("PluginMarketplace - Remove entry") {
    PluginMarketplace mkt;

    MarketplaceEntry entry;
    entry.id = "to_remove";
    entry.name = "Remove Me";
    mkt.addEntry(entry);

    CHECK(mkt.removeEntry("to_remove"));
    CHECK(mkt.getEntryCount() == 0);
    CHECK_FALSE(mkt.removeEntry("to_remove"));
}

TEST_CASE("PluginMarketplace - Search by name") {
    PluginMarketplace mkt;

    MarketplaceEntry e1;
    e1.id = "scanner"; e1.name = "Security Scanner"; e1.description = "";
    mkt.addEntry(e1);

    MarketplaceEntry e2;
    e2.id = "monitor"; e2.name = "Network Monitor"; e2.description = "";
    mkt.addEntry(e2);

    auto results = mkt.search("scanner");
    CHECK(results.size() == 1);
    CHECK(results[0].id == "scanner");
}

TEST_CASE("PluginMarketplace - Search empty returns all") {
    PluginMarketplace mkt;

    MarketplaceEntry e1; e1.id = "p1"; e1.name = "P1"; e1.description = "";
    MarketplaceEntry e2; e2.id = "p2"; e2.name = "P2"; e2.description = "";
    mkt.addEntry(e1);
    mkt.addEntry(e2);

    CHECK(mkt.search("").size() == 2);
}

TEST_CASE("PluginMarketplace - Get specific entry") {
    PluginMarketplace mkt;

    MarketplaceEntry entry;
    entry.id = "test_entry";
    entry.name = "Test Entry";
    mkt.addEntry(entry);

    auto result = mkt.getEntry("test_entry");
    CHECK(result.has_value());
    CHECK(result->name == "Test Entry");

    CHECK_FALSE(mkt.getEntry("nonexistent").has_value());
}

TEST_CASE("PluginMarketplace - Compatibility check") {
    PluginMarketplace mkt;

    MarketplaceEntry entry;
    entry.id = "compat";
    entry.name = "Compatible";
    entry.compatibleVersions = {"1.0.0", "1.1.0", "2.0.0"};
    mkt.addEntry(entry);

    CHECK(mkt.checkCompatibility("compat", "1.0.0"));
    CHECK(mkt.checkCompatibility("compat", "2.0.0"));
    CHECK_FALSE(mkt.checkCompatibility("compat", "3.0.0"));
    CHECK_FALSE(mkt.checkCompatibility("nonexistent", "1.0.0"));
}

TEST_CASE("PluginMarketplace - Update rating") {
    PluginMarketplace mkt;

    MarketplaceEntry entry;
    entry.id = "rated";
    entry.name = "Rated Plugin";
    entry.rating = 3.0;
    mkt.addEntry(entry);

    CHECK(mkt.updateRating("rated", 4.5));
    auto e = mkt.getEntry("rated");
    CHECK(e->rating == doctest::Approx(4.5));
}

TEST_CASE("PluginMarketplace - Increment downloads") {
    PluginMarketplace mkt;

    MarketplaceEntry entry;
    entry.id = "popular";
    entry.name = "Popular";
    entry.downloads = 100;
    mkt.addEntry(entry);

    CHECK(mkt.incrementDownloads("popular"));
    auto e = mkt.getEntry("popular");
    CHECK(e->downloads == 101);
}

TEST_CASE("PluginMarketplace - Has entry") {
    PluginMarketplace mkt;

    MarketplaceEntry entry;
    entry.id = "exists";
    entry.name = "Exists";
    mkt.addEntry(entry);

    CHECK(mkt.hasEntry("exists"));
    CHECK_FALSE(mkt.hasEntry("nope"));
}
