#pragma once

// ThreatOne Database - Base Model Template (CRTP)
// Provides CRUD operations, field mapping, and JSON serialization
// for database entities using the Curiously Recurring Template Pattern.

#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <chrono>
#include <type_traits>

#include <core/Error.h>
#include <nlohmann/json.hpp>
#include "ConnectionManager.h"
#include "QueryBuilder.h"
#include <cstdint>
#include <utility>

namespace ThreatOne::Database {

// Field type descriptor for model metadata
enum class FieldType {
    Integer,
    Text,
    Real,
    Boolean,
    Timestamp,
    UUID,
    JSON,
    Blob
};

// Field metadata for a single model column
struct FieldMeta {
    std::string name;
    FieldType type = FieldType::Text;
    bool nullable = false;
    bool primaryKey = false;
};

// Base model class using CRTP
// Derived classes must provide:
//   static constexpr const char* tableName() - the database table name
//   static std::vector<FieldMeta> fields() - field metadata
//   void fromRow(const Row& row) - populate from a database row
//   std::vector<std::pair<std::string, BoundParam>> toParams() const - serialize for insert/update
//   nlohmann::json toJson() const - serialize to JSON
//   void fromJson(const nlohmann::json& j) - deserialize from JSON
template<typename Derived>
class Model {
public:
    virtual ~Model() = default;

    // Primary key accessor
    [[nodiscard]] int64_t id() const { return id_; }
    void setId(int64_t id) { id_ = id; }

    // CRUD: Create a new record
    [[nodiscard]] static Core::Result<Derived, Core::Error> create(
        IConnection& conn, const Derived& model
    ) {
        auto params = model.toParams();
        std::vector<std::string> cols;
        std::vector<BoundParam> vals;
        cols.reserve(params.size());
        vals.reserve(params.size());

        for (auto& [col, val] : params) {
            cols.push_back(col);
            vals.push_back(std::move(val));
        }

        auto builder = QueryBuilder::insert(Derived::tableName());
        builder.columns(cols, vals);
        auto query = builder.build();

        auto result = conn.execute(query.sql, query.params);
        if (result.isErr()) {
            return Core::Result<Derived, Core::Error>::err(result.error());
        }

        // Retrieve the created record with the new ID
        auto queryResult = conn.query(
            "SELECT last_insert_rowid() as id", {});
        if (queryResult.isErr()) {
            return Core::Result<Derived, Core::Error>::err(queryResult.error());
        }

        Derived created = model;
        if (!queryResult.value().rows.empty()) {
            created.setId(queryResult.value().rows[0].getInt64("id"));
        }
        return Core::Result<Derived, Core::Error>::ok(std::move(created));
    }

    // CRUD: Find by primary key
    [[nodiscard]] static Core::Result<std::optional<Derived>, Core::Error> findById(
        IConnection& conn, int64_t id
    ) {
        auto query = QueryBuilder::select(Derived::tableName())
            .where("id", BoundParam::integer(id))
            .limit(1)
            .build();

        auto result = conn.query(query.sql, query.params);
        if (result.isErr()) {
            return Core::Result<std::optional<Derived>, Core::Error>::err(result.error());
        }

        if (result.value().rows.empty()) {
            return Core::Result<std::optional<Derived>, Core::Error>::ok(std::nullopt);
        }

        Derived model;
        model.fromRow(result.value().rows[0]);
        return Core::Result<std::optional<Derived>, Core::Error>::ok(std::move(model));
    }

    // CRUD: Find all records
    [[nodiscard]] static Core::Result<std::vector<Derived>, Core::Error> findAll(
        IConnection& conn,
        int limit = -1,
        int offset = 0
    ) {
        auto builder = QueryBuilder::select(Derived::tableName());
        if (limit > 0) {
            builder.limit(limit);
        }
        if (offset > 0) {
            builder.offset(offset);
        }
        auto query = builder.build();

        auto result = conn.query(query.sql, query.params);
        if (result.isErr()) {
            return Core::Result<std::vector<Derived>, Core::Error>::err(result.error());
        }

        std::vector<Derived> models;
        models.reserve(result.value().rows.size());
        for (const auto& row : result.value().rows) {
            Derived model;
            model.fromRow(row);
            models.push_back(std::move(model));
        }
        return Core::Result<std::vector<Derived>, Core::Error>::ok(std::move(models));
    }

    // CRUD: Update an existing record
    [[nodiscard]] Core::Result<void, Core::Error> update(IConnection& conn) const {
        auto params = static_cast<const Derived*>(this)->toParams();
        auto builder = QueryBuilder::update(Derived::tableName());

        for (auto& [col, val] : params) {
            builder.set(col, std::move(val));
        }
        builder.where("id", BoundParam::integer(id_));

        auto query = builder.build();
        return conn.execute(query.sql, query.params);
    }

    // CRUD: Delete this record
    [[nodiscard]] Core::Result<void, Core::Error> destroy(IConnection& conn) const {
        auto query = QueryBuilder::remove(Derived::tableName())
            .where("id", BoundParam::integer(id_))
            .build();
        return conn.execute(query.sql, query.params);
    }

    // CRUD: Delete by ID
    [[nodiscard]] static Core::Result<void, Core::Error> destroyById(
        IConnection& conn, int64_t id
    ) {
        auto query = QueryBuilder::remove(Derived::tableName())
            .where("id", BoundParam::integer(id))
            .build();
        return conn.execute(query.sql, query.params);
    }

    // Find with custom query builder
    [[nodiscard]] static Core::Result<std::vector<Derived>, Core::Error> findWhere(
        IConnection& conn,
        const std::string& column,
        BoundParam value
    ) {
        auto query = QueryBuilder::select(Derived::tableName())
            .where(column, std::move(value))
            .build();

        auto result = conn.query(query.sql, query.params);
        if (result.isErr()) {
            return Core::Result<std::vector<Derived>, Core::Error>::err(result.error());
        }

        std::vector<Derived> models;
        models.reserve(result.value().rows.size());
        for (const auto& row : result.value().rows) {
            Derived model;
            model.fromRow(row);
            models.push_back(std::move(model));
        }
        return Core::Result<std::vector<Derived>, Core::Error>::ok(std::move(models));
    }

    // Count records in table
    [[nodiscard]] static Core::Result<int64_t, Core::Error> count(IConnection& conn) {
        std::string sql = "SELECT COUNT(*) as cnt FROM " + std::string(Derived::tableName());
        auto result = conn.query(sql, {});
        if (result.isErr()) {
            return Core::Result<int64_t, Core::Error>::err(result.error());
        }
        if (result.value().rows.empty()) {
            return Core::Result<int64_t, Core::Error>::ok(0);
        }
        return Core::Result<int64_t, Core::Error>::ok(result.value().rows[0].getInt64("cnt"));
    }

    // Check if record exists
    [[nodiscard]] static Core::Result<bool, Core::Error> exists(IConnection& conn, int64_t id) {
        std::string sql = "SELECT 1 FROM " + std::string(Derived::tableName()) + " WHERE id = ? LIMIT 1";
        auto result = conn.query(sql, {BoundParam::integer(id)});
        if (result.isErr()) {
            return Core::Result<bool, Core::Error>::err(result.error());
        }
        return Core::Result<bool, Core::Error>::ok(!result.value().rows.empty());
    }

protected:
    int64_t id_ = 0;
};

} // namespace ThreatOne::Database
