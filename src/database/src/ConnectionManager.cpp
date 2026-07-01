// ThreatOne Database - Connection Manager Implementation
// Provides SQLite connection pooling with thread-safe access.

#include <database/ConnectionManager.h>
#include <sqlite3.h>
#include <stdexcept>
#include <algorithm>

namespace ThreatOne::Database {

// ===== Row Implementation =====

std::string Row::get(const std::string& columnName) const {
    for (const auto& [name, value] : columns) {
        if (name == columnName) {
            return value;
        }
    }
    return "";
}

int Row::getInt(const std::string& columnName) const {
    auto val = get(columnName);
    if (val.empty()) return 0;
    try {
        return std::stoi(val);
    } catch (...) {
        return 0;
    }
}

int64_t Row::getInt64(const std::string& columnName) const {
    auto val = get(columnName);
    if (val.empty()) return 0;
    try {
        return std::stoll(val);
    } catch (...) {
        return 0;
    }
}

double Row::getDouble(const std::string& columnName) const {
    auto val = get(columnName);
    if (val.empty()) return 0.0;
    try {
        return std::stod(val);
    } catch (...) {
        return 0.0;
    }
}

bool Row::getBool(const std::string& columnName) const {
    auto val = get(columnName);
    return val == "1" || val == "true" || val == "TRUE";
}

bool Row::hasColumn(const std::string& columnName) const {
    for (const auto& [name, value] : columns) {
        if (name == columnName) {
            return true;
        }
    }
    return false;
}

// ===== SQLite Connection Implementation =====

class SQLiteConnection : public IConnection {
public:
    SQLiteConnection() = default;
    ~SQLiteConnection() override {
        close();
    }

    Core::Result<void, Core::Error> open(const ConnectionConfig& config) {
        int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
        if (config.readOnly) {
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX;
        }

        int rc = sqlite3_open_v2(config.databasePath.c_str(), &db_, flags, nullptr);
        if (rc != SQLITE_OK) {
            std::string err = db_ ? sqlite3_errmsg(db_) : "Failed to open database";
            return Core::Result<void, Core::Error>::err(
                Core::Error(err, Core::ErrorCategory::Database));
        }

        // Enable WAL mode if configured
        if (config.enableWAL) {
            char* errMsg = nullptr;
            sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &errMsg);
            if (errMsg) sqlite3_free(errMsg);
        }

        // Enable foreign keys if configured
        if (config.enableForeignKeys) {
            char* errMsg = nullptr;
            sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, &errMsg);
            if (errMsg) sqlite3_free(errMsg);
        }

        open_ = true;
        return Core::Result<void, Core::Error>::ok();
    }

    void close() {
        if (db_) {
            sqlite3_close_v2(db_);
            db_ = nullptr;
        }
        open_ = false;
    }

    Core::Result<void, Core::Error> execute(
        const std::string& sql,
        const std::vector<BoundParam>& params = {}
    ) override {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            return Core::Result<void, Core::Error>::err(
                Core::Error(sqlite3_errmsg(db_), Core::ErrorCategory::Database));
        }

        auto bindResult = bindParams(stmt, params);
        if (bindResult.isErr()) {
            sqlite3_finalize(stmt);
            return bindResult;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
            return Core::Result<void, Core::Error>::err(
                Core::Error(sqlite3_errmsg(db_), Core::ErrorCategory::Database));
        }

        return Core::Result<void, Core::Error>::ok();
    }

    Core::Result<QueryResult, Core::Error> query(
        const std::string& sql,
        const std::vector<BoundParam>& params = {}
    ) override {
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            return Core::Result<QueryResult, Core::Error>::err(
                Core::Error(sqlite3_errmsg(db_), Core::ErrorCategory::Database));
        }

        auto bindResult = bindParams(stmt, params);
        if (bindResult.isErr()) {
            sqlite3_finalize(stmt);
            return Core::Result<QueryResult, Core::Error>::err(bindResult.error());
        }

        QueryResult result;

        // Get column names
        int colCount = sqlite3_column_count(stmt);
        result.columnNames.reserve(static_cast<std::size_t>(colCount));
        for (int i = 0; i < colCount; ++i) {
            const char* name = sqlite3_column_name(stmt, i);
            result.columnNames.emplace_back(name ? name : "");
        }

        // Fetch rows
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            Row row;
            row.columns.reserve(static_cast<std::size_t>(colCount));
            for (int i = 0; i < colCount; ++i) {
                std::string value;
                int colType = sqlite3_column_type(stmt, i);
                if (colType != SQLITE_NULL) {
                    const unsigned char* text = sqlite3_column_text(stmt, i);
                    if (text) {
                        value = reinterpret_cast<const char*>(text);
                    }
                }
                row.columns.emplace_back(result.columnNames[static_cast<std::size_t>(i)], std::move(value));
            }
            result.rows.push_back(std::move(row));
        }

        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            return Core::Result<QueryResult, Core::Error>::err(
                Core::Error(sqlite3_errmsg(db_), Core::ErrorCategory::Database));
        }

        result.lastInsertId = sqlite3_last_insert_rowid(db_);
        result.affectedRows = sqlite3_changes(db_);

        return Core::Result<QueryResult, Core::Error>::ok(std::move(result));
    }

    Core::Result<void, Core::Error> beginTransaction() override {
        auto result = execute("BEGIN TRANSACTION");
        if (result.isOk()) {
            inTransaction_ = true;
        }
        return result;
    }

    Core::Result<void, Core::Error> commit() override {
        auto result = execute("COMMIT");
        if (result.isOk()) {
            inTransaction_ = false;
        }
        return result;
    }

    Core::Result<void, Core::Error> rollback() override {
        auto result = execute("ROLLBACK");
        if (result.isOk()) {
            inTransaction_ = false;
        }
        return result;
    }

    [[nodiscard]] bool isOpen() const override {
        return open_;
    }

    [[nodiscard]] bool isInTransaction() const override {
        return inTransaction_;
    }

    Core::Result<void, Core::Error> ping() override {
        if (!db_ || !open_) {
            return Core::Result<void, Core::Error>::err(
                Core::Error("Connection is not open", Core::ErrorCategory::Database));
        }
        return execute("SELECT 1");
    }

private:
    Core::Result<void, Core::Error> bindParams(sqlite3_stmt* stmt, const std::vector<BoundParam>& params) {
        for (std::size_t i = 0; i < params.size(); ++i) {
            int idx = static_cast<int>(i) + 1;
            int rc = SQLITE_OK;

            switch (params[i].type) {
                case BoundParam::Type::Null:
                    rc = sqlite3_bind_null(stmt, idx);
                    break;
                case BoundParam::Type::Integer:
                    rc = sqlite3_bind_int64(stmt, idx, params[i].intValue);
                    break;
                case BoundParam::Type::Real:
                    rc = sqlite3_bind_double(stmt, idx, params[i].realValue);
                    break;
                case BoundParam::Type::Text:
                    rc = sqlite3_bind_text(stmt, idx, params[i].textValue.c_str(),
                        static_cast<int>(params[i].textValue.size()), SQLITE_TRANSIENT);
                    break;
                case BoundParam::Type::Blob:
                    rc = sqlite3_bind_blob(stmt, idx, params[i].blobValue.data(),
                        static_cast<int>(params[i].blobValue.size()), SQLITE_TRANSIENT);
                    break;
            }

            if (rc != SQLITE_OK) {
                return Core::Result<void, Core::Error>::err(
                    Core::Error("Failed to bind parameter " + std::to_string(i),
                                Core::ErrorCategory::Database));
            }
        }
        return Core::Result<void, Core::Error>::ok();
    }

    sqlite3* db_ = nullptr;
    bool open_ = false;
    bool inTransaction_ = false;
};

// ===== ScopedConnection Implementation =====

ScopedConnection::ScopedConnection(
    std::shared_ptr<IConnection> conn,
    std::function<void(std::shared_ptr<IConnection>)> releaser
) : connection_(std::move(conn)), releaser_(std::move(releaser)) {}

ScopedConnection::~ScopedConnection() {
    if (connection_ && releaser_) {
        releaser_(std::move(connection_));
    }
}

ScopedConnection::ScopedConnection(ScopedConnection&& other) noexcept
    : connection_(std::move(other.connection_))
    , releaser_(std::move(other.releaser_))
{
    other.connection_ = nullptr;
    other.releaser_ = nullptr;
}

ScopedConnection& ScopedConnection::operator=(ScopedConnection&& other) noexcept {
    if (this != &other) {
        if (connection_ && releaser_) {
            releaser_(std::move(connection_));
        }
        connection_ = std::move(other.connection_);
        releaser_ = std::move(other.releaser_);
        other.connection_ = nullptr;
        other.releaser_ = nullptr;
    }
    return *this;
}

// ===== Transaction Implementation =====

Transaction::Transaction(IConnection& conn) : connection_(conn) {
    auto result = connection_.beginTransaction();
    if (result.isErr()) {
        throw Core::DatabaseException("Failed to begin transaction: " + result.error().message());
    }
}

Transaction::~Transaction() {
    if (!committed_ && !rolledBack_) {
        // Auto-rollback on destruction if not explicitly committed
        [[maybe_unused]] auto _ = connection_.rollback();
    }
}

Core::Result<void, Core::Error> Transaction::commit() {
    auto result = connection_.commit();
    if (result.isOk()) {
        committed_ = true;
    }
    return result;
}

Core::Result<void, Core::Error> Transaction::rollback() {
    auto result = connection_.rollback();
    if (result.isOk()) {
        rolledBack_ = true;
    }
    return result;
}

// ===== ConnectionManager Implementation =====

ConnectionManager::ConnectionManager() = default;

ConnectionManager::~ConnectionManager() {
    shutdown();
}

Core::Result<void, Core::Error> ConnectionManager::initialize(const ConnectionConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (initialized_) {
        return Core::Result<void, Core::Error>::err(
            Core::Error("ConnectionManager already initialized", Core::ErrorCategory::Database));
    }

    config_ = config;

    // Pre-create connections for the pool
    for (std::size_t i = 0; i < config_.poolSize; ++i) {
        auto connResult = createConnection();
        if (connResult.isErr()) {
            return Core::Result<void, Core::Error>::err(connResult.error());
        }
        pool_.push(connResult.value());
    }

    initialized_ = true;
    return Core::Result<void, Core::Error>::ok();
}

void ConnectionManager::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    while (!pool_.empty()) {
        pool_.pop();
    }
    initialized_ = false;
    activeCount_ = 0;
    totalCreated_ = 0;
}

Core::Result<ScopedConnection, Core::Error> ConnectionManager::getConnection() {
    std::unique_lock<std::mutex> lock(mutex_);

    if (!initialized_) {
        return Core::Result<ScopedConnection, Core::Error>::err(
            Core::Error("ConnectionManager not initialized", Core::ErrorCategory::Database));
    }

    // Wait for an available connection
    auto deadline = std::chrono::steady_clock::now() + config_.connectionTimeout;
    while (pool_.empty()) {
        if (available_.wait_until(lock, deadline) == std::cv_status::timeout) {
            return Core::Result<ScopedConnection, Core::Error>::err(
                Core::Error("Connection pool timeout", Core::ErrorCategory::Database));
        }
    }

    auto conn = pool_.front();
    pool_.pop();
    activeCount_++;

    // Create a scoped connection that returns to pool on destruction
    auto releaser = [this](std::shared_ptr<IConnection> c) {
        releaseConnection(std::move(c));
    };

    return Core::Result<ScopedConnection, Core::Error>::ok(
        ScopedConnection(std::move(conn), std::move(releaser)));
}

std::size_t ConnectionManager::activeConnections() const {
    return activeCount_.load();
}

std::size_t ConnectionManager::availableConnections() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pool_.size();
}

std::size_t ConnectionManager::poolSize() const {
    return config_.poolSize;
}

Core::Result<void, Core::Error> ConnectionManager::healthCheck() {
    auto connResult = getConnection();
    if (connResult.isErr()) {
        return Core::Result<void, Core::Error>::err(connResult.error());
    }
    return connResult.value()->ping();
}

Core::Result<std::shared_ptr<IConnection>, Core::Error> ConnectionManager::createConnection() {
    if (config_.backend == Backend::SQLite) {
        auto conn = std::make_shared<SQLiteConnection>();
        auto result = conn->open(config_);
        if (result.isErr()) {
            return Core::Result<std::shared_ptr<IConnection>, Core::Error>::err(result.error());
        }
        totalCreated_++;
        return Core::Result<std::shared_ptr<IConnection>, Core::Error>::ok(std::move(conn));
    }

    // PostgreSQL backend requires the enterprise license and libpq.
    // Contact sales@threatone.io for enterprise database connectivity.
    return Core::Result<std::shared_ptr<IConnection>, Core::Error>::err(
        Core::Error("PostgreSQL backend requires enterprise license (contact sales@threatone.io)",
                    Core::ErrorCategory::Database));
}

void ConnectionManager::releaseConnection(std::shared_ptr<IConnection> conn) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (conn && conn->isOpen()) {
        // Rollback any uncommitted transaction before returning to pool
        if (conn->isInTransaction()) {
            [[maybe_unused]] auto _ = conn->rollback();
        }
        pool_.push(std::move(conn));
    }
    activeCount_--;
    available_.notify_one();
}

} // namespace ThreatOne::Database
