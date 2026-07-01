#pragma once

// ThreatOne Database - Connection Manager
// Manages database connection pooling for SQLite and PostgreSQL backends.
// Provides RAII connection wrapper and thread-safe pool management.

#include <string>
#include <memory>
#include <vector>
#include <queue>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <functional>
#include <chrono>
#include <atomic>

#include <core/Error.h>

struct sqlite3;

namespace ThreatOne::Database {

// Supported database backends
enum class Backend {
    SQLite,
    PostgreSQL
};

// Database connection configuration
struct ConnectionConfig {
    Backend backend = Backend::SQLite;

    // SQLite-specific
    std::string databasePath = "threatone.db";

    // PostgreSQL-specific
    std::string host = "localhost";
    int port = 5432;
    std::string dbname = "threatone";
    std::string username;
    std::string password;

    // Pool configuration
    std::size_t poolSize = 5;
    std::chrono::seconds connectionTimeout{30};
    std::chrono::seconds idleTimeout{300};

    // Options
    bool enableWAL = true;         // SQLite WAL mode
    bool enableForeignKeys = true; // Enforce foreign key constraints
    bool readOnly = false;
};

// Query result row - maps column name to string value
struct Row {
    std::vector<std::pair<std::string, std::string>> columns;

    [[nodiscard]] std::string get(const std::string& columnName) const;
    [[nodiscard]] int getInt(const std::string& columnName) const;
    [[nodiscard]] int64_t getInt64(const std::string& columnName) const;
    [[nodiscard]] double getDouble(const std::string& columnName) const;
    [[nodiscard]] bool getBool(const std::string& columnName) const;
    [[nodiscard]] bool hasColumn(const std::string& columnName) const;
};

// Query result set
struct QueryResult {
    std::vector<Row> rows;
    std::vector<std::string> columnNames;
    int affectedRows = 0;
    int64_t lastInsertId = 0;

    [[nodiscard]] bool empty() const { return rows.empty(); }
    [[nodiscard]] std::size_t size() const { return rows.size(); }
};

// Bound parameter value for prepared statements
struct BoundParam {
    enum class Type { Null, Integer, Real, Text, Blob };

    Type type = Type::Null;
    int64_t intValue = 0;
    double realValue = 0.0;
    std::string textValue;
    std::vector<uint8_t> blobValue;

    static BoundParam null() { return BoundParam{Type::Null, 0, 0.0, {}, {}}; }
    static BoundParam integer(int64_t v) { return BoundParam{Type::Integer, v, 0.0, {}, {}}; }
    static BoundParam real(double v) { return BoundParam{Type::Real, 0, v, {}, {}}; }
    static BoundParam text(std::string v) { return BoundParam{Type::Text, 0, 0.0, std::move(v), {}}; }
    static BoundParam blob(std::vector<uint8_t> v) { return BoundParam{Type::Blob, 0, 0.0, {}, std::move(v)}; }
};

// Abstract database connection interface
class IConnection {
public:
    virtual ~IConnection() = default;

    // Execute SQL without returning results
    [[nodiscard]] virtual Core::Result<void, Core::Error> execute(
        const std::string& sql,
        const std::vector<BoundParam>& params = {}
    ) = 0;

    // Execute SQL and return result set
    [[nodiscard]] virtual Core::Result<QueryResult, Core::Error> query(
        const std::string& sql,
        const std::vector<BoundParam>& params = {}
    ) = 0;

    // Transaction control
    [[nodiscard]] virtual Core::Result<void, Core::Error> beginTransaction() = 0;
    [[nodiscard]] virtual Core::Result<void, Core::Error> commit() = 0;
    [[nodiscard]] virtual Core::Result<void, Core::Error> rollback() = 0;

    // Connection state
    [[nodiscard]] virtual bool isOpen() const = 0;
    [[nodiscard]] virtual bool isInTransaction() const = 0;

    // Health check
    [[nodiscard]] virtual Core::Result<void, Core::Error> ping() = 0;
};

// RAII scoped connection - automatically returns to pool on destruction
class ScopedConnection {
public:
    ScopedConnection() = default;
    ScopedConnection(std::shared_ptr<IConnection> conn, std::function<void(std::shared_ptr<IConnection>)> releaser);
    ~ScopedConnection();

    // Move-only
    ScopedConnection(ScopedConnection&& other) noexcept;
    ScopedConnection& operator=(ScopedConnection&& other) noexcept;
    ScopedConnection(const ScopedConnection&) = delete;
    ScopedConnection& operator=(const ScopedConnection&) = delete;

    IConnection* operator->() const { return connection_.get(); }
    IConnection& operator*() const { return *connection_; }
    explicit operator bool() const { return connection_ != nullptr; }

    [[nodiscard]] IConnection* get() const { return connection_.get(); }

private:
    std::shared_ptr<IConnection> connection_;
    std::function<void(std::shared_ptr<IConnection>)> releaser_;
};

// Transaction RAII guard
class Transaction {
public:
    explicit Transaction(IConnection& conn);
    ~Transaction();

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    [[nodiscard]] Core::Result<void, Core::Error> commit();
    [[nodiscard]] Core::Result<void, Core::Error> rollback();

private:
    IConnection& connection_;
    bool committed_ = false;
    bool rolledBack_ = false;
};

// Connection pool and manager
class ConnectionManager {
public:
    ConnectionManager();
    ~ConnectionManager();

    // Non-copyable, non-movable
    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;

    // Initialize the connection pool
    [[nodiscard]] Core::Result<void, Core::Error> initialize(const ConnectionConfig& config);

    // Shutdown all connections
    void shutdown();

    // Get a connection from the pool (blocks until available or timeout)
    [[nodiscard]] Core::Result<ScopedConnection, Core::Error> getConnection();

    // Pool statistics
    [[nodiscard]] std::size_t activeConnections() const;
    [[nodiscard]] std::size_t availableConnections() const;
    [[nodiscard]] std::size_t poolSize() const;

    // Health check
    [[nodiscard]] Core::Result<void, Core::Error> healthCheck();

    // Access config
    [[nodiscard]] const ConnectionConfig& config() const { return config_; }

private:
    // Create a new raw connection
    [[nodiscard]] Core::Result<std::shared_ptr<IConnection>, Core::Error> createConnection();

    // Return connection to pool
    void releaseConnection(std::shared_ptr<IConnection> conn);

    ConnectionConfig config_;
    std::queue<std::shared_ptr<IConnection>> pool_;
    mutable std::mutex mutex_;
    std::condition_variable available_;
    std::atomic<std::size_t> activeCount_{0};
    std::atomic<std::size_t> totalCreated_{0};
    bool initialized_ = false;
};

} // namespace ThreatOne::Database
