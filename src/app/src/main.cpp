// ThreatOne Enterprise Cybersecurity Platform - Main Entry Point
// Parses command-line arguments, initializes all subsystems, and starts the event loop.

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

#include "core/Application.h"
#include "core/Logger.h"
#include "core/Config.h"
#include "core/ServiceLocator.h"
#include "core/EventBus.h"
#include "core/Types.h"
#include "app/AppController.h"

#ifdef ENABLE_QT_BUILD
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QUrl>
#include <QtQml>
#include "app/viewmodels/DashboardViewModel.h"
#include "app/viewmodels/ScannerViewModel.h"
#include "app/viewmodels/FirewallViewModel.h"
#include "app/viewmodels/EDRViewModel.h"
#include "app/viewmodels/IncidentViewModel.h"
#include "app/viewmodels/AssetViewModel.h"
#include "app/viewmodels/ThreatIntelViewModel.h"
#include "app/viewmodels/ReportViewModel.h"
#include "app/viewmodels/SettingsViewModel.h"
#include "app/viewmodels/UsersViewModel.h"
#endif

namespace {

struct CommandLineArgs {
    std::string configFile = "config.json";
    std::string logLevel = "info";
    bool showVersion = false;
    bool showHelp = false;
};

CommandLineArgs parseArgs(int argc, char** argv) {
    CommandLineArgs args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--version" || arg == "-v") {
            args.showVersion = true;
        } else if (arg == "--help" || arg == "-h") {
            args.showHelp = true;
        } else if (arg == "--config" || arg == "-c") {
            if (i + 1 < argc) {
                args.configFile = argv[++i];
            }
        } else if (arg == "--log-level" || arg == "-l") {
            if (i + 1 < argc) {
                args.logLevel = argv[++i];
            }
        }
    }
    return args;
}

void printHelp() {
    std::cout << "ThreatOne Enterprise Cybersecurity Platform\n"
              << "\n"
              << "Usage: threatone [OPTIONS]\n"
              << "\n"
              << "Options:\n"
              << "  -c, --config <file>     Configuration file path (default: config.json)\n"
              << "  -l, --log-level <level>  Log level: trace, debug, info, warn, error, critical (default: info)\n"
              << "  -v, --version           Show version information\n"
              << "  -h, --help              Show this help message\n"
              << std::endl;
}

void printVersion() {
    std::cout << "ThreatOne Enterprise Cybersecurity Platform v1.0.0\n"
              << "Build: C++20, "
#ifdef ENABLE_QT_BUILD
              << "Qt6 enabled"
#else
              << "Console mode (Qt disabled)"
#endif
              << std::endl;
}

ThreatOne::Core::LogLevel parseLogLevel(const std::string& level) {
    if (level == "trace") return ThreatOne::Core::LogLevel::Trace;
    if (level == "debug") return ThreatOne::Core::LogLevel::Debug;
    if (level == "info") return ThreatOne::Core::LogLevel::Info;
    if (level == "warn") return ThreatOne::Core::LogLevel::Warn;
    if (level == "error") return ThreatOne::Core::LogLevel::Error;
    if (level == "critical") return ThreatOne::Core::LogLevel::Critical;
    return ThreatOne::Core::LogLevel::Info;
}

} // anonymous namespace

int main(int argc, char** argv) {
    // Parse command-line arguments
    auto args = parseArgs(argc, argv);

    if (args.showHelp) {
        printHelp();
        return 0;
    }

    if (args.showVersion) {
        printVersion();
        return 0;
    }

    // Initialize the logging system
    ThreatOne::Core::LogConfig logConfig;
    logConfig.consoleLevel = parseLogLevel(args.logLevel);
    ThreatOne::Core::Logger::instance().initialize(logConfig);

    auto logger = ThreatOne::Core::Logger::instance().getModuleLogger("Main");
    logger.info("ThreatOne Enterprise Cybersecurity Platform starting...");
    logger.info("Configuration file: {}", args.configFile);
    logger.info("Log level: {}", args.logLevel);

    // Load configuration
    auto& config = ThreatOne::Core::Config::instance();
    auto configResult = config.loadFromFile(args.configFile);
    if (!configResult) {
        logger.warn("Could not load config file '{}', using defaults", args.configFile);
    }

    // Initialize the application
    ThreatOne::Core::AppConfig appConfig;
    appConfig.configFile = args.configFile;
    auto& app = ThreatOne::Core::Application::instance();
    auto initResult = app.initialize(appConfig);
    if (!initResult) {
        logger.critical("Application initialization failed: {}", initResult.error().message());
        return 1;
    }

    // Create and initialize the AppController (manages all subsystem lifecycles)
    auto appController = std::make_shared<ThreatOne::App::AppController>();
    auto ctrlResult = appController->initialize();
    if (!ctrlResult) {
        logger.critical("AppController initialization failed: {}", ctrlResult.error().message());
        return 1;
    }

    // Register AppController in the ServiceLocator
    ThreatOne::Core::ServiceLocator::instance().registerService(appController);

    logger.info("All subsystems initialized successfully");

#ifdef ENABLE_QT_BUILD
    // Qt6 GUI application initialization
    QGuiApplication qtApp(argc, argv);
    qtApp.setOrganizationName("ThreatOne");
    qtApp.setApplicationName("ThreatOne Enterprise");
    qtApp.setApplicationVersion("1.0.0");

    // Register ViewModel types for QML access
    qmlRegisterType<ThreatOne::App::DashboardViewModel>(
        "ThreatOne.ViewModels", 1, 0, "DashboardViewModel");
    qmlRegisterType<ThreatOne::App::ScannerViewModel>(
        "ThreatOne.ViewModels", 1, 0, "ScannerViewModel");
    qmlRegisterType<ThreatOne::App::FirewallViewModel>(
        "ThreatOne.ViewModels", 1, 0, "FirewallViewModel");
    qmlRegisterType<ThreatOne::App::EDRViewModel>(
        "ThreatOne.ViewModels", 1, 0, "EDRViewModel");
    qmlRegisterType<ThreatOne::App::IncidentViewModel>(
        "ThreatOne.ViewModels", 1, 0, "IncidentViewModel");
    qmlRegisterType<ThreatOne::App::AssetViewModel>(
        "ThreatOne.ViewModels", 1, 0, "AssetViewModel");
    qmlRegisterType<ThreatOne::App::ThreatIntelViewModel>(
        "ThreatOne.ViewModels", 1, 0, "ThreatIntelViewModel");
    qmlRegisterType<ThreatOne::App::ReportViewModel>(
        "ThreatOne.ViewModels", 1, 0, "ReportViewModel");
    qmlRegisterType<ThreatOne::App::SettingsViewModel>(
        "ThreatOne.ViewModels", 1, 0, "SettingsViewModel");
    qmlRegisterType<ThreatOne::App::UsersViewModel>(
        "ThreatOne.ViewModels", 1, 0, "UsersViewModel");

    // Create and load QML engine
    QQmlApplicationEngine engine;
    const QUrl url(QStringLiteral("qrc:/qml/main.qml"));
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
                     &qtApp, [url](QObject* obj, const QUrl& objUrl) {
        if (!obj && url == objUrl)
            QCoreApplication::exit(-1);
    }, Qt::QueuedConnection);
    engine.load(url);

    return qtApp.exec();
#else
    // Simple event loop for non-Qt builds.
    // The Application's signal handler (installed during app.initialize()) sets
    // Application state to ShuttingDown on SIGINT/SIGTERM.
    logger.info("Entering main event loop (console mode)");
    while (app.isRunning()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    logger.info("Shutdown signal received");
#endif

    // Graceful shutdown
    appController->shutdown();
    app.shutdown();
    ThreatOne::Core::Logger::instance().shutdown();

    return 0;
}
