# Tests CMakeLists.txt - Unit test runner using doctest

find_package(Threads REQUIRED)

# Collect all test source files
set(TEST_SOURCES
    test_main.cpp
    core/test_logger.cpp
    core/test_config.cpp
    core/test_event_bus.cpp
    core/test_service_locator.cpp
    database/test_query_builder.cpp
    database/test_migration.cpp
    scanner/test_file_hasher.cpp
    scanner/test_signature_database.cpp
    scanner/test_signature_matcher.cpp
    scanner/test_file_enumerator.cpp
    scanner/test_quarantine_manager.cpp
    scanner/test_scan_engine.cpp
    edr/test_process_monitor.cpp
    edr/test_file_monitor.cpp
    edr/test_memory_monitor.cpp
    edr/test_telemetry_collector.cpp
    edr/test_behavior_analyzer.cpp
    edr/test_detection_rules.cpp
    edr/test_alert_manager.cpp
    edr/test_ransomware_detection.cpp
    edr/test_incident_timeline.cpp
    edr/test_edr_engine.cpp
    edr/test_monitor_engine.cpp
    firewall/test_rule_engine.cpp
    firewall/test_connection_tracker.cpp
    firewall/test_packet_filter.cpp
    network/test_ip_blocklist.cpp
    network/test_dns_filter.cpp
    network/test_intrusion_detector.cpp
    network/test_bandwidth_monitor.cpp
    network/test_network_isolation.cpp
    network/test_application_control.cpp
    network/test_geo_blocking.cpp
    ai/test_feature_extractor.cpp
    ai/test_decision_tree.cpp
    ai/test_anomaly_detector.cpp
    ai/test_risk_scoring.cpp
    ai/test_threat_classifier.cpp
    ai/test_model_manager.cpp
    ai/test_nlp_processor.cpp
    ai/test_recommendation_engine.cpp
    ai/test_auto_investigation.cpp
    ai/test_prediction_engine.cpp
    analytics/test_behavior_analytics.cpp
    threat_intel/test_ioc_manager.cpp
    threat_intel/test_feed_parsers.cpp
    threat_intel/test_threat_feed_manager.cpp
    threat_intel/test_mitre_attack.cpp
    threat_intel/test_cve_database.cpp
    threat_intel/test_correlation.cpp
    threat_intel/test_ioc_matcher.cpp
    threat_intel/test_threat_scoring.cpp
    threat_intel/test_report_generator.cpp
    threat_intel/test_enrichment.cpp
)

# Create the test executable
add_executable(threatone_tests ${TEST_SOURCES})

target_include_directories(threatone_tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core/include
        ${CMAKE_SOURCE_DIR}/src/database/include
        ${CMAKE_SOURCE_DIR}/src/utils/include
        ${CMAKE_SOURCE_DIR}/src/scanner/include
        ${CMAKE_SOURCE_DIR}/src/edr/include
        ${CMAKE_SOURCE_DIR}/src/monitor/include
        ${CMAKE_SOURCE_DIR}/src/firewall/include
        ${CMAKE_SOURCE_DIR}/src/network/include
        ${CMAKE_SOURCE_DIR}/src/ai/include
        ${CMAKE_SOURCE_DIR}/src/analytics/include
        ${CMAKE_SOURCE_DIR}/src/threat_intel/include
        ${CMAKE_SOURCE_DIR}/src/security/include
)

target_link_libraries(threatone_tests
    PRIVATE
        doctest
        threatone_core
        threatone_database
        threatone_utils
        threatone_scanner
        threatone_edr
        threatone_monitor
        threatone_firewall
        threatone_network
        threatone_ai
        threatone_analytics
        threatone_threat_intel
        threatone_security
        spdlog
        nlohmann_json
        sqlite3
        Threads::Threads
)

# Register with CTest
add_test(NAME threatone_tests COMMAND threatone_tests)
