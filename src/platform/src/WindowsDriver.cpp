// ThreatOne Platform - WindowsDriver implementation
// Uses ReadDirectoryChangesW for file monitoring, WFP API for network filtering,
// and ToolHelp32 for process enumeration.

#ifdef _WIN32

#include "WindowsDriver.h"

#include <tlhelp32.h>
#include <psapi.h>
#include <fwpmu.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Fwpuclnt.lib")

namespace ThreatOne::Platform {

WindowsDriver::WindowsDriver()
    : logger_(Core::Logger::instance().getModuleLogger("Platform.Windows")) {
    logger_.info("Windows platform driver initialized");
}

WindowsDriver::~WindowsDriver() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [path, handle] : monitors_) {
        if (handle && handle->running.load()) {
            handle->running.store(false);
            CancelIoEx(handle->dirHandle, nullptr);
            if (handle->watchThread.joinable()) {
                handle->watchThread.join();
            }
            CloseHandle(handle->dirHandle);
        }
    }
    monitors_.clear();
}

Core::Result<void, Core::Error> WindowsDriver::startFileMonitoring(
    const std::string& path, FileEventCallback callback) {

    if (path.empty()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Path cannot be empty", Core::ErrorCategory::Validation));
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (monitors_.count(path) > 0) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Already monitoring path: " + path, Core::ErrorCategory::Internal));
    }

    // Open directory handle with FILE_LIST_DIRECTORY access
    HANDLE dirHandle = CreateFileA(
        path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    );

    if (dirHandle == INVALID_HANDLE_VALUE) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to open directory for monitoring: " + path +
                       " (error=" + std::to_string(GetLastError()) + ")",
                       Core::ErrorCategory::IO));
    }

    auto handle = std::make_unique<MonitorHandle>();
    handle->dirHandle = dirHandle;
    handle->running.store(true);
    handle->callback = std::move(callback);

    MonitorHandle* rawHandle = handle.get();
    handle->watchThread = std::thread(&WindowsDriver::watchDirectory, this, rawHandle, path);

    monitors_[path] = std::move(handle);
    logger_.info("Started file monitoring on: {}", path);

    return Core::Result<void, Core::Error>::ok();
}

void WindowsDriver::watchDirectory(MonitorHandle* handle, const std::string& path) {
    constexpr DWORD bufferSize = 65536;
    std::vector<BYTE> buffer(bufferSize);
    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    while (handle->running.load()) {
        DWORD bytesReturned = 0;
        BOOL success = ReadDirectoryChangesW(
            handle->dirHandle,
            buffer.data(),
            bufferSize,
            TRUE, // watch subtree
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_CREATION,
            &bytesReturned,
            &overlapped,
            nullptr
        );

        if (!success) break;

        DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 1000);
        if (waitResult != WAIT_OBJECT_0) continue;

        if (!GetOverlappedResult(handle->dirHandle, &overlapped, &bytesReturned, FALSE)) {
            continue;
        }

        // Parse FILE_NOTIFY_INFORMATION records
        BYTE* ptr = buffer.data();
        while (ptr < buffer.data() + bytesReturned) {
            auto* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(ptr);

            std::wstring wFileName(info->FileName, info->FileNameLength / sizeof(WCHAR));
            std::string fileName(wFileName.begin(), wFileName.end());

            FileEvent event;
            event.path = path + "\\" + fileName;

            switch (info->Action) {
                case FILE_ACTION_ADDED:
                    event.type = FileEventType::Created;
                    break;
                case FILE_ACTION_REMOVED:
                    event.type = FileEventType::Deleted;
                    break;
                case FILE_ACTION_MODIFIED:
                    event.type = FileEventType::Modified;
                    break;
                case FILE_ACTION_RENAMED_OLD_NAME:
                    event.type = FileEventType::Renamed;
                    event.oldPath = event.path;
                    break;
                case FILE_ACTION_RENAMED_NEW_NAME:
                    event.type = FileEventType::Renamed;
                    break;
                default:
                    event.type = FileEventType::Modified;
                    break;
            }

            if (handle->callback) {
                handle->callback(event);
            }

            if (info->NextEntryOffset == 0) break;
            ptr += info->NextEntryOffset;
        }

        ResetEvent(overlapped.hEvent);
    }

    CloseHandle(overlapped.hEvent);
}

Core::Result<void, Core::Error> WindowsDriver::stopFileMonitoring(
    const std::string& path) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = monitors_.find(path);
    if (it == monitors_.end()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Not monitoring path: " + path, Core::ErrorCategory::Internal));
    }

    auto& handle = it->second;
    handle->running.store(false);
    CancelIoEx(handle->dirHandle, nullptr);

    if (handle->watchThread.joinable()) {
        handle->watchThread.join();
    }

    CloseHandle(handle->dirHandle);
    monitors_.erase(it);

    logger_.info("Stopped file monitoring on: {}", path);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> WindowsDriver::addNetworkRule(const NetworkRule& rule) {
    if (rule.name.empty()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Rule name cannot be empty", Core::ErrorCategory::Validation));
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Store the rule for local tracking
    rules_.push_back(rule);

    // WFP engine interaction: open engine, add filter
    HANDLE engineHandle = nullptr;
    DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, nullptr, &engineHandle);
    if (result != ERROR_SUCCESS) {
        logger_.warn("WFP engine open failed (error={}), rule stored locally only", result);
        return Core::Result<void, Core::Error>::ok();
    }

    // Build FWPM_FILTER0 structure for the rule
    FWPM_FILTER0 filter = {};
    filter.displayData.name = const_cast<wchar_t*>(L"ThreatOne Network Rule");
    filter.layerKey = (rule.direction == NetworkRule::Direction::Inbound) ?
                       FWPM_LAYER_INBOUND_TRANSPORT_V4 :
                       FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.action.type = (rule.action == NetworkRule::Action::Block) ?
                          FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = static_cast<UINT8>(rule.priority & 0xFF);

    UINT64 filterId = 0;
    result = FwpmFilterAdd0(engineHandle, &filter, nullptr, &filterId);
    if (result != ERROR_SUCCESS) {
        logger_.warn("WFP filter add failed (error={})", result);
    }

    FwpmEngineClose0(engineHandle);
    logger_.info("Added network rule: {}", rule.name);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<void, Core::Error> WindowsDriver::removeNetworkRule(const std::string& ruleName) {
    if (ruleName.empty()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Rule name cannot be empty", Core::ErrorCategory::Validation));
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = std::remove_if(rules_.begin(), rules_.end(),
        [&ruleName](const NetworkRule& r) { return r.name == ruleName; });

    if (it == rules_.end()) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Rule not found: " + ruleName, Core::ErrorCategory::Internal));
    }

    rules_.erase(it, rules_.end());
    logger_.info("Removed network rule: {}", ruleName);
    return Core::Result<void, Core::Error>::ok();
}

Core::Result<std::vector<NetworkRule>, Core::Error> WindowsDriver::listNetworkRules() {
    std::lock_guard<std::mutex> lock(mutex_);
    return Core::Result<std::vector<NetworkRule>, Core::Error>::ok(rules_);
}

Core::Result<std::vector<ProcessInfo>, Core::Error> WindowsDriver::listProcesses() {
    std::vector<ProcessInfo> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return Core::Result<std::vector<ProcessInfo>, Core::Error>::err(
            Core::Error("Failed to create process snapshot (error=" +
                       std::to_string(GetLastError()) + ")", Core::ErrorCategory::Internal));
    }

    PROCESSENTRY32 entry = {};
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &entry)) {
        do {
            ProcessInfo info;
            info.pid = entry.th32ProcessID;
            info.parentPid = entry.th32ParentProcessID;
            info.name = entry.szExeFile;

            // Get additional info from process handle
            HANDLE procHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
            if (procHandle != nullptr) {
                char exePath[MAX_PATH] = {};
                DWORD pathLen = MAX_PATH;
                if (QueryFullProcessImageNameA(procHandle, 0, exePath, &pathLen)) {
                    info.executablePath = exePath;
                }

                PROCESS_MEMORY_COUNTERS_EX memInfo = {};
                memInfo.cb = sizeof(memInfo);
                if (GetProcessMemoryInfo(procHandle,
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memInfo), sizeof(memInfo))) {
                    info.memoryUsageBytes = memInfo.WorkingSetSize;
                }

                CloseHandle(procHandle);
            }

            processes.push_back(std::move(info));
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return Core::Result<std::vector<ProcessInfo>, Core::Error>::ok(std::move(processes));
}

Core::Result<ProcessInfo, Core::Error> WindowsDriver::getProcessInfo(uint32_t pid) {
    if (pid == 0) {
        return Core::Result<ProcessInfo, Core::Error>::err(
            Core::Error("Invalid PID: 0", Core::ErrorCategory::Validation));
    }

    HANDLE procHandle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (procHandle == nullptr) {
        return Core::Result<ProcessInfo, Core::Error>::err(
            Core::Error("Cannot open process " + std::to_string(pid) +
                       " (error=" + std::to_string(GetLastError()) + ")",
                       Core::ErrorCategory::Internal));
    }

    ProcessInfo info;
    info.pid = pid;

    char exePath[MAX_PATH] = {};
    DWORD pathLen = MAX_PATH;
    if (QueryFullProcessImageNameA(procHandle, 0, exePath, &pathLen)) {
        info.executablePath = exePath;
        // Extract name from path
        std::string path(exePath);
        auto lastSlash = path.find_last_of("\\/");
        info.name = (lastSlash != std::string::npos) ? path.substr(lastSlash + 1) : path;
    }

    PROCESS_MEMORY_COUNTERS_EX memInfo = {};
    memInfo.cb = sizeof(memInfo);
    if (GetProcessMemoryInfo(procHandle,
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memInfo), sizeof(memInfo))) {
        info.memoryUsageBytes = memInfo.WorkingSetSize;
    }

    CloseHandle(procHandle);
    return Core::Result<ProcessInfo, Core::Error>::ok(std::move(info));
}

Core::Result<void, Core::Error> WindowsDriver::terminateProcess(uint32_t pid) {
    if (pid == 0) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Cannot terminate system idle process (PID 0)",
                       Core::ErrorCategory::Validation));
    }

    HANDLE procHandle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (procHandle == nullptr) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Cannot open process for termination: " + std::to_string(pid) +
                       " (error=" + std::to_string(GetLastError()) + ")",
                       Core::ErrorCategory::Internal));
    }

    BOOL terminated = TerminateProcess(procHandle, 1);
    CloseHandle(procHandle);

    if (!terminated) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("Failed to terminate process: " + std::to_string(pid) +
                       " (error=" + std::to_string(GetLastError()) + ")",
                       Core::ErrorCategory::Internal));
    }

    logger_.info("Terminated process: {}", pid);
    return Core::Result<void, Core::Error>::ok();
}

std::string WindowsDriver::platformName() const {
    return "Windows";
}

bool WindowsDriver::isSupported() const {
    return true;
}

} // namespace ThreatOne::Platform

#endif // _WIN32
