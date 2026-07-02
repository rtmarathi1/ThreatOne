#include <doctest/doctest.h>
#include <cloud/DeviceManager.h>

using namespace ThreatOne::Cloud;

TEST_CASE("DeviceManager - Register and list devices") {
    DeviceManager mgr;

    DeviceInfo dev;
    dev.hostname = "workstation-01";
    dev.ipAddress = "192.168.1.10";
    dev.osType = "Linux";
    dev.status = DeviceStatus::Online;

    std::string id = mgr.registerDevice(dev);
    CHECK_FALSE(id.empty());
    CHECK(id.find("DEV-") == 0);

    auto devices = mgr.getDevices();
    CHECK(devices.size() == 1);
    CHECK(devices[0].hostname == "workstation-01");
}

TEST_CASE("DeviceManager - Unregister device") {
    DeviceManager mgr;

    DeviceInfo dev;
    dev.hostname = "test-device";
    std::string id = mgr.registerDevice(dev);

    CHECK(mgr.unregisterDevice(id));
    CHECK(mgr.getDeviceCount() == 0);
}

TEST_CASE("DeviceManager - Unregister nonexistent fails") {
    DeviceManager mgr;
    CHECK_FALSE(mgr.unregisterDevice("nonexistent"));
}

TEST_CASE("DeviceManager - Update device status") {
    DeviceManager mgr;

    DeviceInfo dev;
    dev.hostname = "device-01";
    dev.status = DeviceStatus::Offline;
    std::string id = mgr.registerDevice(dev);

    CHECK(mgr.updateDeviceStatus(id, DeviceStatus::Online));
    auto device = mgr.getDevice(id);
    CHECK(device.status == DeviceStatus::Online);
}

TEST_CASE("DeviceManager - Online and offline device queries") {
    DeviceManager mgr;

    DeviceInfo dev1;
    dev1.hostname = "online-device";
    dev1.status = DeviceStatus::Online;
    mgr.registerDevice(dev1);

    DeviceInfo dev2;
    dev2.hostname = "offline-device";
    dev2.status = DeviceStatus::Offline;
    mgr.registerDevice(dev2);

    CHECK(mgr.getOnlineDevices().size() == 1);
    CHECK(mgr.getOfflineDevices().size() == 1);
}

TEST_CASE("DeviceManager - Health score tracking") {
    DeviceManager mgr;

    DeviceInfo dev;
    dev.hostname = "unhealthy-device";
    dev.healthScore = 30;
    std::string id = mgr.registerDevice(dev);

    auto unhealthy = mgr.getUnhealthyDevices(50);
    CHECK(unhealthy.size() == 1);

    CHECK(mgr.updateHealthScore(id, 80));
    CHECK(mgr.getUnhealthyDevices(50).empty());
}

TEST_CASE("DeviceManager - Has device check") {
    DeviceManager mgr;

    DeviceInfo dev;
    dev.hostname = "test";
    std::string id = mgr.registerDevice(dev);

    CHECK(mgr.hasDevice(id));
    CHECK_FALSE(mgr.hasDevice("nonexistent"));
}

TEST_CASE("DeviceManager - Update last seen") {
    DeviceManager mgr;

    DeviceInfo dev;
    dev.hostname = "device";
    std::string id = mgr.registerDevice(dev);

    CHECK(mgr.updateLastSeen(id, "2024-01-15T10:00:00"));
    auto device = mgr.getDevice(id);
    CHECK(device.lastSeen == "2024-01-15T10:00:00");
}
