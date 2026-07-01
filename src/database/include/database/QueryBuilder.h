#pragma once

// ThreatOne Database - Fluent Query Builder
// Provides a type-safe, SQL-injection-resistant query construction API.
// Supports SELECT, INSERT, UPDATE, DELETE with parameterized queries.

#include <string>
#include <vector>
#include <optional>
#include <sstream>
#include <utility>

#include "ConnectionManager.h"

namespace ThreatOne::Database {

// Direction for ORDER BY
enum class SortOrder {
    Ascending,
    Descending
};

// Join types
enum class JoinType {
    Inner,
    Left,
    Right,
    Cross
};

// Where clause condition
struct WhereClause {
    std::string column;
    std::string op;        // =, !=, <, >, <=, >=, LIKE, IN, IS NULL, IS NOT NULL, BETWEEN
    BoundParam value;
    std::optional<BoundParam> value2; // For BETWEEN
    bool isRaw = false;
    std::string rawSQL;    // For raw expressions
};

// Join specification
struct JoinClause {
    JoinType type = JoinType::Inner;
    std::string table;
    std::string onCondition;
};

// Order by specification
struct OrderByClause {
    std::string column;
    SortOrder order = SortOrder::Ascending;
};

// Result of building a query
struct BuiltQuery {
    std::string sql;
    std::vector<BoundParam> params;
};

// Query builder for SELECT statements
class SelectBuilder {
public:
    explicit SelectBuilder(std::string table);

    // Column selection
    SelectBuilder& columns(std::vector<std::string> cols);
    SelectBuilder& column(std::string col);
    SelectBuilder& distinct();

    // Where conditions
    SelectBuilder& where(const std::string& col, const std::string& op, BoundParam value);
    SelectBuilder& where(const std::string& col, BoundParam value); // Defaults to =
    SelectBuilder& whereNull(const std::string& col);
    SelectBuilder& whereNotNull(const std::string& col);
    SelectBuilder& whereBetween(const std::string& col, BoundParam low, BoundParam high);
    SelectBuilder& whereIn(const std::string& col, std::vector<BoundParam> values);
    SelectBuilder& whereRaw(const std::string& rawCondition);
    SelectBuilder& orWhere(const std::string& col, const std::string& op, BoundParam value);

    // Joins
    SelectBuilder& join(const std::string& table, const std::string& onCondition, JoinType type = JoinType::Inner);
    SelectBuilder& leftJoin(const std::string& table, const std::string& onCondition);
    SelectBuilder& rightJoin(const std::string& table, const std::string& onCondition);

    // Grouping and having
    SelectBuilder& groupBy(std::vector<std::string> cols);
    SelectBuilder& groupBy(const std::string& col);
    SelectBuilder& having(const std::string& condition);

    // Ordering
    SelectBuilder& orderBy(const std::string& col, SortOrder order = SortOrder::Ascending);

    // Pagination
    SelectBuilder& limit(int count);
    SelectBuilder& offset(int count);

    // Subquery support
    SelectBuilder& whereSubquery(const std::string& col, const std::string& op, const SelectBuilder& subquery);

    // Build the final query
    [[nodiscard]] BuiltQuery build() const;

private:
    std::string table_;
    std::vector<std::string> columns_;
    bool distinct_ = false;
    std::vector<WhereClause> whereClauses_;
    std::vector<std::string> orWhereClauses_;
    std::vector<BoundParam> orWhereParams_;
    std::vector<JoinClause> joins_;
    std::vector<std::string> groupByCols_;
    std::string havingClause_;
    std::vector<OrderByClause> orderByClauses_;
    std::optional<int> limit_;
    std::optional<int> offset_;
    // Store subqueries for WHERE IN / WHERE op (subquery)
    std::vector<std::pair<std::string, BuiltQuery>> subqueries_;
};

// Query builder for INSERT statements
class InsertBuilder {
public:
    explicit InsertBuilder(std::string table);

    InsertBuilder& column(const std::string& col, BoundParam value);
    InsertBuilder& columns(const std::vector<std::string>& cols, const std::vector<BoundParam>& values);

    // Build the final query
    [[nodiscard]] BuiltQuery build() const;

private:
    std::string table_;
    std::vector<std::string> columnNames_;
    std::vector<BoundParam> values_;
};

// Query builder for UPDATE statements
class UpdateBuilder {
public:
    explicit UpdateBuilder(std::string table);

    UpdateBuilder& set(const std::string& col, BoundParam value);

    // Where conditions (same pattern as SelectBuilder)
    UpdateBuilder& where(const std::string& col, const std::string& op, BoundParam value);
    UpdateBuilder& where(const std::string& col, BoundParam value);
    UpdateBuilder& whereNull(const std::string& col);
    UpdateBuilder& whereNotNull(const std::string& col);

    // Build the final query
    [[nodiscard]] BuiltQuery build() const;

private:
    std::string table_;
    std::vector<std::string> setCols_;
    std::vector<BoundParam> setValues_;
    std::vector<WhereClause> whereClauses_;
};

// Query builder for DELETE statements
class DeleteBuilder {
public:
    explicit DeleteBuilder(std::string table);

    // Where conditions
    DeleteBuilder& where(const std::string& col, const std::string& op, BoundParam value);
    DeleteBuilder& where(const std::string& col, BoundParam value);
    DeleteBuilder& whereNull(const std::string& col);
    DeleteBuilder& whereNotNull(const std::string& col);

    // Build the final query
    [[nodiscard]] BuiltQuery build() const;

private:
    std::string table_;
    std::vector<WhereClause> whereClauses_;
};

// Main query builder facade
class QueryBuilder {
public:
    // Factory methods for different query types
    static SelectBuilder select(const std::string& table);
    static InsertBuilder insert(const std::string& table);
    static UpdateBuilder update(const std::string& table);
    static DeleteBuilder remove(const std::string& table);

    // Raw query
    static BuiltQuery raw(const std::string& sql, std::vector<BoundParam> params = {});
};

} // namespace ThreatOne::Database
