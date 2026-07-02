#include <doctest/doctest.h>
#include <cloud/CloudAssetDiscovery.h>

using namespace ThreatOne::Cloud;

TEST_CASE("CloudAssetDiscovery - Register and list assets") {
    CloudAssetDiscovery discovery;

    CloudAsset asset;
    asset.name = "web-server-01";
    asset.type = CloudAssetType::Compute;
    asset.provider = CloudProvider::AWS;
    asset.region = "us-east-1";

    std::string id = discovery.registerAsset(asset);
    CHECK_FALSE(id.empty());
    CHECK(id.find("ASSET-") == 0);

    auto assets = discovery.getAssets();
    CHECK(assets.size() == 1);
    CHECK(assets[0].name == "web-server-01");
}

TEST_CASE("CloudAssetDiscovery - Remove asset") {
    CloudAssetDiscovery discovery;

    CloudAsset asset;
    asset.name = "temp-instance";
    std::string id = discovery.registerAsset(asset);

    CHECK(discovery.removeAsset(id));
    CHECK(discovery.getAssetCount() == 0);
}

TEST_CASE("CloudAssetDiscovery - Remove nonexistent fails") {
    CloudAssetDiscovery discovery;
    CHECK_FALSE(discovery.removeAsset("nonexistent"));
}

TEST_CASE("CloudAssetDiscovery - Get assets by type") {
    CloudAssetDiscovery discovery;

    CloudAsset compute;
    compute.name = "server";
    compute.type = CloudAssetType::Compute;
    discovery.registerAsset(compute);

    CloudAsset storage;
    storage.name = "bucket";
    storage.type = CloudAssetType::Storage;
    discovery.registerAsset(storage);

    CHECK(discovery.getAssetsByType(CloudAssetType::Compute).size() == 1);
    CHECK(discovery.getAssetsByType(CloudAssetType::Storage).size() == 1);
    CHECK(discovery.getAssetsByType(CloudAssetType::IAM).empty());
}

TEST_CASE("CloudAssetDiscovery - Get assets by provider") {
    CloudAssetDiscovery discovery;

    CloudAsset aws;
    aws.name = "aws-instance";
    aws.provider = CloudProvider::AWS;
    discovery.registerAsset(aws);

    CloudAsset azure;
    azure.name = "azure-vm";
    azure.provider = CloudProvider::Azure;
    discovery.registerAsset(azure);

    CHECK(discovery.getAssetsByProvider(CloudProvider::AWS).size() == 1);
    CHECK(discovery.getAssetsByProvider(CloudProvider::Azure).size() == 1);
    CHECK(discovery.getAssetsByProvider(CloudProvider::GCP).empty());
}

TEST_CASE("CloudAssetDiscovery - Get assets by region") {
    CloudAssetDiscovery discovery;

    CloudAsset a1;
    a1.name = "east-server";
    a1.region = "us-east-1";
    discovery.registerAsset(a1);

    CloudAsset a2;
    a2.name = "west-server";
    a2.region = "us-west-2";
    discovery.registerAsset(a2);

    CHECK(discovery.getAssetsByRegion("us-east-1").size() == 1);
    CHECK(discovery.getAssetsByRegion("eu-west-1").empty());
}

TEST_CASE("CloudAssetDiscovery - Search assets") {
    CloudAssetDiscovery discovery;

    CloudAsset a1;
    a1.name = "Production Web Server";
    a1.tags = {"production", "web"};
    discovery.registerAsset(a1);

    CloudAsset a2;
    a2.name = "Development DB";
    a2.tags = {"development", "database"};
    discovery.registerAsset(a2);

    auto results = discovery.searchAssets("production");
    CHECK(results.size() == 1);
    CHECK(results[0].name == "Production Web Server");

    results = discovery.searchAssets("database");
    CHECK(results.size() == 1);
}

TEST_CASE("CloudAssetDiscovery - Summary") {
    CloudAssetDiscovery discovery;

    CloudAsset c1, c2, s1;
    c1.name = "server-1"; c1.type = CloudAssetType::Compute;
    c2.name = "server-2"; c2.type = CloudAssetType::Compute;
    s1.name = "bucket-1"; s1.type = CloudAssetType::Storage;
    discovery.registerAsset(c1);
    discovery.registerAsset(c2);
    discovery.registerAsset(s1);

    auto summary = discovery.getSummary();
    CHECK(summary.totalAssets == 3);
    CHECK(summary.computeCount == 2);
    CHECK(summary.storageCount == 1);
}

TEST_CASE("CloudAssetDiscovery - Cost tracking") {
    CloudAssetDiscovery discovery;

    CloudAsset a1;
    a1.name = "expensive";
    a1.provider = CloudProvider::AWS;
    a1.costPerMonth = 10000;  // $100
    discovery.registerAsset(a1);

    CloudAsset a2;
    a2.name = "cheap";
    a2.provider = CloudProvider::GCP;
    a2.costPerMonth = 500;  // $5
    discovery.registerAsset(a2);

    CHECK(discovery.getTotalMonthlyCost() == 10500);
    CHECK(discovery.getCostByProvider(CloudProvider::AWS) == 10000);
    CHECK(discovery.getCostByProvider(CloudProvider::GCP) == 500);
}
