// ThreatOne Database - Schema DSL Implementation
// Generates CREATE TABLE and related DDL SQL statements.

#include <database/Schema.h>
#include <sstream>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace ThreatOne::Database {

// ===== TableBuilder =====

TableBuilder::TableBuilder(std::string tableName) : tableName_(std::move(tableName)) {}

ColumnBuilder& TableBuilder::column(const std::string& name, ColumnType type) {
    ColumnDef def;
    def.name = name;
    def.type = type;
    columns_.push_back(std::move(def));
    columnBuilders_.emplace_back(columns_.back());
    return columnBuilders_.back();
}

ColumnBuilder& TableBuilder::integer(const std::string& name) {
    return column(name, ColumnType::Integer);
}

ColumnBuilder& TableBuilder::text(const std::string& name) {
    return column(name, ColumnType::Text);
}

ColumnBuilder& TableBuilder::real(const std::string& name) {
    return column(name, ColumnType::Real);
}

ColumnBuilder& TableBuilder::blob(const std::string& name) {
    return column(name, ColumnType::Blob);
}

ColumnBuilder& TableBuilder::boolean(const std::string& name) {
    return column(name, ColumnType::Boolean);
}

ColumnBuilder& TableBuilder::timestamp(const std::string& name) {
    return column(name, ColumnType::Timestamp);
}

ColumnBuilder& TableBuilder::uuid(const std::string& name) {
    return column(name, ColumnType::UUID);
}

TableBuilder& TableBuilder::id() {
    column("id", ColumnType::Integer).primaryKey().autoIncrement().notNull();
    return *this;
}

TableBuilder& TableBuilder::foreignKey(
    const std::string& columnName,
    const std::string& referenceTable,
    const std::string& referenceColumn,
    const std::string& onDelete,
    const std::string& onUpdate
) {
    foreignKeys_.push_back({columnName, referenceTable, referenceColumn, onDelete, onUpdate});
    return *this;
}

TableBuilder& TableBuilder::index(const std::string& name, std::vector<std::string> columns) {
    indices_.push_back({name, std::move(columns), false});
    return *this;
}

TableBuilder& TableBuilder::uniqueIndex(const std::string& name, std::vector<std::string> columns) {
    indices_.push_back({name, std::move(columns), true});
    return *this;
}

TableBuilder& TableBuilder::timestamps() {
    column("created_at", ColumnType::Timestamp).notNull().defaultValue("CURRENT_TIMESTAMP");
    column("updated_at", ColumnType::Timestamp).notNull().defaultValue("CURRENT_TIMESTAMP");
    return *this;
}

std::string TableBuilder::toSQL() const {
    std::ostringstream sql;
    sql << "CREATE TABLE " << tableName_ << " (\n";

    for (std::size_t i = 0; i < columns_.size(); ++i) {
        const auto& col = columns_[i];
        sql << "  " << col.name << " " << columnTypeToSQL(col.type);

        if (col.constraints.primaryKey) {
            sql << " PRIMARY KEY";
            if (col.constraints.autoIncrement) {
                sql << " AUTOINCREMENT";
            }
        }
        if (col.constraints.notNull && !col.constraints.primaryKey) {
            sql << " NOT NULL";
        }
        if (col.constraints.unique) {
            sql << " UNIQUE";
        }
        if (col.constraints.defaultValue) {
            sql << " DEFAULT " << *col.constraints.defaultValue;
        }
        if (col.constraints.checkExpr) {
            sql << " CHECK(" << *col.constraints.checkExpr << ")";
        }

        bool hasMore = (i < columns_.size() - 1) || !foreignKeys_.empty();
        if (hasMore) {
            sql << ",";
        }
        sql << "\n";
    }

    // Foreign keys
    for (std::size_t i = 0; i < foreignKeys_.size(); ++i) {
        const auto& fk = foreignKeys_[i];
        sql << "  FOREIGN KEY (" << fk.columnName << ") REFERENCES "
            << fk.referenceTable << "(" << fk.referenceColumn << ")"
            << " ON DELETE " << fk.onDelete
            << " ON UPDATE " << fk.onUpdate;
        if (i < foreignKeys_.size() - 1) {
            sql << ",";
        }
        sql << "\n";
    }

    sql << ")";
    return sql.str();
}

std::string TableBuilder::toDropSQL() const {
    return "DROP TABLE IF EXISTS " + tableName_;
}

std::vector<std::string> TableBuilder::toIndexSQL() const {
    std::vector<std::string> statements;
    for (const auto& idx : indices_) {
        std::ostringstream sql;
        sql << "CREATE ";
        if (idx.unique) sql << "UNIQUE ";
        sql << "INDEX " << idx.name << " ON " << tableName_ << " (";
        for (std::size_t i = 0; i < idx.columns.size(); ++i) {
            if (i > 0) sql << ", ";
            sql << idx.columns[i];
        }
        sql << ")";
        statements.push_back(sql.str());
    }
    return statements;
}

std::string TableBuilder::columnTypeToSQL(ColumnType type) const {
    switch (type) {
        case ColumnType::Integer:   return "INTEGER";
        case ColumnType::Text:      return "TEXT";
        case ColumnType::Real:      return "REAL";
        case ColumnType::Blob:      return "BLOB";
        case ColumnType::Boolean:   return "INTEGER";  // SQLite uses INTEGER for booleans
        case ColumnType::Timestamp: return "TEXT";     // SQLite stores timestamps as TEXT
        case ColumnType::UUID:      return "TEXT";     // UUIDs stored as TEXT in SQLite
    }
    return "TEXT";
}

// ===== Schema Utility =====

TableBuilder Schema::create(const std::string& tableName) {
    return TableBuilder(tableName);
}

std::string Schema::createIfNotExists(const TableBuilder& builder) {
    std::string sql = builder.toSQL();
    // Replace "CREATE TABLE" with "CREATE TABLE IF NOT EXISTS"
    auto pos = sql.find("CREATE TABLE ");
    if (pos != std::string::npos) {
        sql.replace(pos, 13, "CREATE TABLE IF NOT EXISTS ");
    }
    return sql;
}

std::string Schema::drop(const std::string& tableName) {
    return "DROP TABLE " + tableName;
}

std::string Schema::dropIfExists(const std::string& tableName) {
    return "DROP TABLE IF EXISTS " + tableName;
}

} // namespace ThreatOne::Database
