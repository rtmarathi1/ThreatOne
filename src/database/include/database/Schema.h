#pragma once

// ThreatOne Database - Schema Definition DSL
// Provides a fluent API for defining table schemas programmatically.
// Generates CREATE TABLE SQL statements with proper constraints.

#include <string>
#include <vector>
#include <optional>
#include <sstream>

namespace ThreatOne::Database {

// Supported column types
enum class ColumnType {
    Integer,
    Text,
    Real,
    Blob,
    Boolean,
    Timestamp,
    UUID
};

// Column constraint definitions
struct ColumnConstraint {
    bool primaryKey = false;
    bool autoIncrement = false;
    bool notNull = false;
    bool unique = false;
    std::optional<std::string> defaultValue;
    std::optional<std::string> checkExpr;
};

// Foreign key reference
struct ForeignKey {
    std::string columnName;
    std::string referenceTable;
    std::string referenceColumn;
    std::string onDelete = "CASCADE";
    std::string onUpdate = "CASCADE";
};

// Index definition
struct IndexDef {
    std::string name;
    std::vector<std::string> columns;
    bool unique = false;
};

// Single column definition
struct ColumnDef {
    std::string name;
    ColumnType type = ColumnType::Text;
    ColumnConstraint constraints;
};

// Column builder for fluent API
class ColumnBuilder {
public:
    explicit ColumnBuilder(ColumnDef& def) : def_(def) {}

    ColumnBuilder& primaryKey() { def_.constraints.primaryKey = true; return *this; }
    ColumnBuilder& autoIncrement() { def_.constraints.autoIncrement = true; return *this; }
    ColumnBuilder& notNull() { def_.constraints.notNull = true; return *this; }
    ColumnBuilder& nullable() { def_.constraints.notNull = false; return *this; }
    ColumnBuilder& unique() { def_.constraints.unique = true; return *this; }
    ColumnBuilder& defaultValue(const std::string& val) { def_.constraints.defaultValue = val; return *this; }
    ColumnBuilder& check(const std::string& expr) { def_.constraints.checkExpr = expr; return *this; }

private:
    ColumnDef& def_;
};

// Table builder - main DSL for schema definition
class TableBuilder {
public:
    explicit TableBuilder(std::string tableName);

    // Add columns by type
    ColumnBuilder& column(const std::string& name, ColumnType type);

    // Convenience column methods
    ColumnBuilder& integer(const std::string& name);
    ColumnBuilder& text(const std::string& name);
    ColumnBuilder& real(const std::string& name);
    ColumnBuilder& blob(const std::string& name);
    ColumnBuilder& boolean(const std::string& name);
    ColumnBuilder& timestamp(const std::string& name);
    ColumnBuilder& uuid(const std::string& name);

    // Primary key shorthand (id INTEGER PRIMARY KEY AUTOINCREMENT)
    TableBuilder& id();

    // Foreign key constraint
    TableBuilder& foreignKey(const std::string& column,
                             const std::string& referenceTable,
                             const std::string& referenceColumn = "id",
                             const std::string& onDelete = "CASCADE",
                             const std::string& onUpdate = "CASCADE");

    // Index definitions
    TableBuilder& index(const std::string& name, std::vector<std::string> columns);
    TableBuilder& uniqueIndex(const std::string& name, std::vector<std::string> columns);

    // Timestamps shorthand (adds created_at and updated_at)
    TableBuilder& timestamps();

    // Generate CREATE TABLE SQL
    [[nodiscard]] std::string toSQL() const;

    // Generate DROP TABLE SQL
    [[nodiscard]] std::string toDropSQL() const;

    // Generate CREATE INDEX statements
    [[nodiscard]] std::vector<std::string> toIndexSQL() const;

    // Table name accessor
    [[nodiscard]] const std::string& tableName() const { return tableName_; }

    // Column access for inspection
    [[nodiscard]] const std::vector<ColumnDef>& columns() const { return columns_; }

private:
    [[nodiscard]] std::string columnTypeToSQL(ColumnType type) const;

    std::string tableName_;
    std::vector<ColumnDef> columns_;
    std::vector<ColumnBuilder> columnBuilders_;
    std::vector<ForeignKey> foreignKeys_;
    std::vector<IndexDef> indices_;
};

// Schema utility - provides table creation / drop convenience
class Schema {
public:
    // Create a table definition
    static TableBuilder create(const std::string& tableName);

    // Generate IF NOT EXISTS variant
    static std::string createIfNotExists(const TableBuilder& builder);

    // Drop table
    static std::string drop(const std::string& tableName);
    static std::string dropIfExists(const std::string& tableName);
};

} // namespace ThreatOne::Database
