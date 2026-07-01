// ThreatOne Database - Query Builder Implementation
// Generates parameterized SQL from fluent builder API.

#include <database/QueryBuilder.h>
#include <sstream>
#include <stdexcept>

namespace ThreatOne::Database {

// ===== SelectBuilder =====

SelectBuilder::SelectBuilder(std::string table) : table_(std::move(table)) {}

SelectBuilder& SelectBuilder::columns(std::vector<std::string> cols) {
    columns_ = std::move(cols);
    return *this;
}

SelectBuilder& SelectBuilder::column(std::string col) {
    columns_.push_back(std::move(col));
    return *this;
}

SelectBuilder& SelectBuilder::distinct() {
    distinct_ = true;
    return *this;
}

SelectBuilder& SelectBuilder::where(const std::string& col, const std::string& op, BoundParam value) {
    whereClauses_.push_back({col, op, std::move(value), std::nullopt, false, {}});
    return *this;
}

SelectBuilder& SelectBuilder::where(const std::string& col, BoundParam value) {
    return where(col, "=", std::move(value));
}

SelectBuilder& SelectBuilder::whereNull(const std::string& col) {
    whereClauses_.push_back({col, "IS NULL", BoundParam::null(), std::nullopt, true, col + " IS NULL"});
    return *this;
}

SelectBuilder& SelectBuilder::whereNotNull(const std::string& col) {
    whereClauses_.push_back({col, "IS NOT NULL", BoundParam::null(), std::nullopt, true, col + " IS NOT NULL"});
    return *this;
}

SelectBuilder& SelectBuilder::whereBetween(const std::string& col, BoundParam low, BoundParam high) {
    whereClauses_.push_back({col, "BETWEEN", std::move(low), std::move(high), false, {}});
    return *this;
}

SelectBuilder& SelectBuilder::whereIn(const std::string& col, std::vector<BoundParam> values) {
    // Build raw SQL for IN clause with parameter markers
    std::string raw = col + " IN (";
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) raw += ", ";
        raw += "?";
    }
    raw += ")";
    // Store as raw with multiple params - we use a special handling
    WhereClause clause;
    clause.column = col;
    clause.op = "IN";
    clause.isRaw = true;
    clause.rawSQL = raw;
    // Store the first value; additional params handled via subqueries vector
    if (!values.empty()) {
        clause.value = values[0];
    }
    whereClauses_.push_back(std::move(clause));

    // Store additional IN params in the subqueries field repurposed for this
    BuiltQuery inQuery;
    inQuery.sql = raw;
    inQuery.params = std::move(values);
    subqueries_.emplace_back("__in_" + col, std::move(inQuery));
    return *this;
}

SelectBuilder& SelectBuilder::whereRaw(const std::string& rawCondition) {
    whereClauses_.push_back({"", "", BoundParam::null(), std::nullopt, true, rawCondition});
    return *this;
}

SelectBuilder& SelectBuilder::orWhere(const std::string& col, const std::string& op, BoundParam value) {
    orWhereClauses_.push_back(col + " " + op + " ?");
    orWhereParams_.push_back(std::move(value));
    return *this;
}

SelectBuilder& SelectBuilder::join(const std::string& table, const std::string& onCondition, JoinType type) {
    joins_.push_back({type, table, onCondition});
    return *this;
}

SelectBuilder& SelectBuilder::leftJoin(const std::string& table, const std::string& onCondition) {
    return join(table, onCondition, JoinType::Left);
}

SelectBuilder& SelectBuilder::rightJoin(const std::string& table, const std::string& onCondition) {
    return join(table, onCondition, JoinType::Right);
}

SelectBuilder& SelectBuilder::groupBy(std::vector<std::string> cols) {
    groupByCols_ = std::move(cols);
    return *this;
}

SelectBuilder& SelectBuilder::groupBy(const std::string& col) {
    groupByCols_.push_back(col);
    return *this;
}

SelectBuilder& SelectBuilder::having(const std::string& condition) {
    havingClause_ = condition;
    return *this;
}

SelectBuilder& SelectBuilder::orderBy(const std::string& col, SortOrder order) {
    orderByClauses_.push_back({col, order});
    return *this;
}

SelectBuilder& SelectBuilder::limit(int count) {
    limit_ = count;
    return *this;
}

SelectBuilder& SelectBuilder::offset(int count) {
    offset_ = count;
    return *this;
}

SelectBuilder& SelectBuilder::whereSubquery(const std::string& col, const std::string& op, const SelectBuilder& subquery) {
    auto built = subquery.build();
    std::string raw = col + " " + op + " (" + built.sql + ")";
    whereClauses_.push_back({"", "", BoundParam::null(), std::nullopt, true, raw});
    subqueries_.emplace_back(col, std::move(built));
    return *this;
}

BuiltQuery SelectBuilder::build() const {
    BuiltQuery result;
    std::ostringstream sql;
    std::vector<BoundParam> params;

    // SELECT
    sql << "SELECT ";
    if (distinct_) sql << "DISTINCT ";

    if (columns_.empty()) {
        sql << "*";
    } else {
        for (std::size_t i = 0; i < columns_.size(); ++i) {
            if (i > 0) sql << ", ";
            sql << columns_[i];
        }
    }

    // FROM
    sql << " FROM " << table_;

    // JOIN
    for (const auto& j : joins_) {
        switch (j.type) {
            case JoinType::Inner: sql << " INNER JOIN "; break;
            case JoinType::Left:  sql << " LEFT JOIN "; break;
            case JoinType::Right: sql << " RIGHT JOIN "; break;
            case JoinType::Cross: sql << " CROSS JOIN "; break;
        }
        sql << j.table << " ON " << j.onCondition;
    }

    // WHERE
    if (!whereClauses_.empty() || !orWhereClauses_.empty()) {
        sql << " WHERE ";
        bool first = true;

        for (const auto& clause : whereClauses_) {
            if (!first) sql << " AND ";
            first = false;

            if (clause.isRaw) {
                // Check if this is an IN clause with stored params
                bool isInClause = false;
                for (const auto& [key, subQ] : subqueries_) {
                    if (key == "__in_" + clause.column) {
                        sql << clause.rawSQL;
                        for (const auto& p : subQ.params) {
                            params.push_back(p);
                        }
                        isInClause = true;
                        break;
                    }
                }
                if (!isInClause) {
                    sql << clause.rawSQL;
                    // Check for subquery params
                    for (const auto& [key, subQ] : subqueries_) {
                        if (key == clause.column || key.empty()) {
                            for (const auto& p : subQ.params) {
                                params.push_back(p);
                            }
                            break;
                        }
                    }
                }
            } else if (clause.op == "BETWEEN") {
                sql << clause.column << " BETWEEN ? AND ?";
                params.push_back(clause.value);
                if (clause.value2) {
                    params.push_back(*clause.value2);
                }
            } else {
                sql << clause.column << " " << clause.op << " ?";
                params.push_back(clause.value);
            }
        }

        for (const auto& orClause : orWhereClauses_) {
            sql << " OR " << orClause;
        }
        for (const auto& p : orWhereParams_) {
            params.push_back(p);
        }
    }

    // GROUP BY
    if (!groupByCols_.empty()) {
        sql << " GROUP BY ";
        for (std::size_t i = 0; i < groupByCols_.size(); ++i) {
            if (i > 0) sql << ", ";
            sql << groupByCols_[i];
        }
    }

    // HAVING
    if (!havingClause_.empty()) {
        sql << " HAVING " << havingClause_;
    }

    // ORDER BY
    if (!orderByClauses_.empty()) {
        sql << " ORDER BY ";
        for (std::size_t i = 0; i < orderByClauses_.size(); ++i) {
            if (i > 0) sql << ", ";
            sql << orderByClauses_[i].column;
            sql << (orderByClauses_[i].order == SortOrder::Ascending ? " ASC" : " DESC");
        }
    }

    // LIMIT
    if (limit_) {
        sql << " LIMIT " << *limit_;
    }

    // OFFSET
    if (offset_) {
        sql << " OFFSET " << *offset_;
    }

    result.sql = sql.str();
    result.params = std::move(params);
    return result;
}

// ===== InsertBuilder =====

InsertBuilder::InsertBuilder(std::string table) : table_(std::move(table)) {}

InsertBuilder& InsertBuilder::column(const std::string& col, BoundParam value) {
    columnNames_.push_back(col);
    values_.push_back(std::move(value));
    return *this;
}

InsertBuilder& InsertBuilder::columns(const std::vector<std::string>& cols, const std::vector<BoundParam>& values) {
    columnNames_.insert(columnNames_.end(), cols.begin(), cols.end());
    values_.insert(values_.end(), values.begin(), values.end());
    return *this;
}

BuiltQuery InsertBuilder::build() const {
    BuiltQuery result;
    std::ostringstream sql;

    sql << "INSERT INTO " << table_ << " (";
    for (std::size_t i = 0; i < columnNames_.size(); ++i) {
        if (i > 0) sql << ", ";
        sql << columnNames_[i];
    }
    sql << ") VALUES (";
    for (std::size_t i = 0; i < values_.size(); ++i) {
        if (i > 0) sql << ", ";
        sql << "?";
    }
    sql << ")";

    result.sql = sql.str();
    result.params = values_;
    return result;
}

// ===== UpdateBuilder =====

UpdateBuilder::UpdateBuilder(std::string table) : table_(std::move(table)) {}

UpdateBuilder& UpdateBuilder::set(const std::string& col, BoundParam value) {
    setCols_.push_back(col);
    setValues_.push_back(std::move(value));
    return *this;
}

UpdateBuilder& UpdateBuilder::where(const std::string& col, const std::string& op, BoundParam value) {
    whereClauses_.push_back({col, op, std::move(value), std::nullopt, false, {}});
    return *this;
}

UpdateBuilder& UpdateBuilder::where(const std::string& col, BoundParam value) {
    return where(col, "=", std::move(value));
}

UpdateBuilder& UpdateBuilder::whereNull(const std::string& col) {
    whereClauses_.push_back({col, "IS NULL", BoundParam::null(), std::nullopt, true, col + " IS NULL"});
    return *this;
}

UpdateBuilder& UpdateBuilder::whereNotNull(const std::string& col) {
    whereClauses_.push_back({col, "IS NOT NULL", BoundParam::null(), std::nullopt, true, col + " IS NOT NULL"});
    return *this;
}

BuiltQuery UpdateBuilder::build() const {
    BuiltQuery result;
    std::ostringstream sql;
    std::vector<BoundParam> params;

    sql << "UPDATE " << table_ << " SET ";
    for (std::size_t i = 0; i < setCols_.size(); ++i) {
        if (i > 0) sql << ", ";
        sql << setCols_[i] << " = ?";
        params.push_back(setValues_[i]);
    }

    if (!whereClauses_.empty()) {
        sql << " WHERE ";
        bool first = true;
        for (const auto& clause : whereClauses_) {
            if (!first) sql << " AND ";
            first = false;

            if (clause.isRaw) {
                sql << clause.rawSQL;
            } else {
                sql << clause.column << " " << clause.op << " ?";
                params.push_back(clause.value);
            }
        }
    }

    result.sql = sql.str();
    result.params = std::move(params);
    return result;
}

// ===== DeleteBuilder =====

DeleteBuilder::DeleteBuilder(std::string table) : table_(std::move(table)) {}

DeleteBuilder& DeleteBuilder::where(const std::string& col, const std::string& op, BoundParam value) {
    whereClauses_.push_back({col, op, std::move(value), std::nullopt, false, {}});
    return *this;
}

DeleteBuilder& DeleteBuilder::where(const std::string& col, BoundParam value) {
    return where(col, "=", std::move(value));
}

DeleteBuilder& DeleteBuilder::whereNull(const std::string& col) {
    whereClauses_.push_back({col, "IS NULL", BoundParam::null(), std::nullopt, true, col + " IS NULL"});
    return *this;
}

DeleteBuilder& DeleteBuilder::whereNotNull(const std::string& col) {
    whereClauses_.push_back({col, "IS NOT NULL", BoundParam::null(), std::nullopt, true, col + " IS NOT NULL"});
    return *this;
}

BuiltQuery DeleteBuilder::build() const {
    BuiltQuery result;
    std::ostringstream sql;
    std::vector<BoundParam> params;

    sql << "DELETE FROM " << table_;

    if (!whereClauses_.empty()) {
        sql << " WHERE ";
        bool first = true;
        for (const auto& clause : whereClauses_) {
            if (!first) sql << " AND ";
            first = false;

            if (clause.isRaw) {
                sql << clause.rawSQL;
            } else {
                sql << clause.column << " " << clause.op << " ?";
                params.push_back(clause.value);
            }
        }
    }

    result.sql = sql.str();
    result.params = std::move(params);
    return result;
}

// ===== QueryBuilder Facade =====

SelectBuilder QueryBuilder::select(const std::string& table) {
    return SelectBuilder(table);
}

InsertBuilder QueryBuilder::insert(const std::string& table) {
    return InsertBuilder(table);
}

UpdateBuilder QueryBuilder::update(const std::string& table) {
    return UpdateBuilder(table);
}

DeleteBuilder QueryBuilder::remove(const std::string& table) {
    return DeleteBuilder(table);
}

BuiltQuery QueryBuilder::raw(const std::string& sql, std::vector<BoundParam> params) {
    return BuiltQuery{sql, std::move(params)};
}

} // namespace ThreatOne::Database
