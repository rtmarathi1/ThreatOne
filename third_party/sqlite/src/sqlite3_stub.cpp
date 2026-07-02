// ThreatOne Embedded SQL Database Engine
// A functional implementation of the sqlite3 C API for the ThreatOne platform.
// Provides in-memory SQL storage with file persistence, transactions,
// prepared statements, parameter binding, and thread-safety.

#include "sqlite3.h"

#ifdef _WIN32
#include <string.h>
#ifndef strcasecmp
#define strcasecmp _stricmp
#endif
#endif

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

// ============================================================================
// Internal Types
// ============================================================================

namespace {

// Value types stored in the database
enum class ValueType { Null, Integer, Real, Text, Blob };

struct Value {
    ValueType type = ValueType::Null;
    long long intVal = 0;
    double realVal = 0.0;
    std::string textVal;
    std::vector<unsigned char> blobVal;

    Value() = default;
    static Value makeNull() { return Value{}; }
    static Value makeInt(long long v) { Value val; val.type = ValueType::Integer; val.intVal = v; return val; }
    static Value makeReal(double v) { Value val; val.type = ValueType::Real; val.realVal = v; return val; }
    static Value makeText(const std::string& v) { Value val; val.type = ValueType::Text; val.textVal = v; return val; }
    static Value makeBlob(const std::vector<unsigned char>& v) { Value val; val.type = ValueType::Blob; val.blobVal = v; return val; }

    std::string asText() const {
        switch (type) {
            case ValueType::Null: return "";
            case ValueType::Integer: return std::to_string(intVal);
            case ValueType::Real: {
                std::ostringstream oss;
                oss << realVal;
                return oss.str();
            }
            case ValueType::Text: return textVal;
            case ValueType::Blob: return std::string(blobVal.begin(), blobVal.end());
        }
        return "";
    }

    long long asInt() const {
        switch (type) {
            case ValueType::Null: return 0;
            case ValueType::Integer: return intVal;
            case ValueType::Real: return static_cast<long long>(realVal);
            case ValueType::Text: {
                try { return std::stoll(textVal); } catch (...) { return 0; }
            }
            case ValueType::Blob: return 0;
        }
        return 0;
    }

    double asReal() const {
        switch (type) {
            case ValueType::Null: return 0.0;
            case ValueType::Integer: return static_cast<double>(intVal);
            case ValueType::Real: return realVal;
            case ValueType::Text: {
                try { return std::stod(textVal); } catch (...) { return 0.0; }
            }
            case ValueType::Blob: return 0.0;
        }
        return 0.0;
    }

    int sqliteType() const {
        switch (type) {
            case ValueType::Null: return SQLITE_NULL;
            case ValueType::Integer: return SQLITE_INTEGER;
            case ValueType::Real: return SQLITE_FLOAT;
            case ValueType::Text: return SQLITE_TEXT;
            case ValueType::Blob: return SQLITE_BLOB;
        }
        return SQLITE_NULL;
    }

    // Comparison for ordering
    bool operator<(const Value& other) const {
        if (type == ValueType::Null && other.type != ValueType::Null) return true;
        if (type != ValueType::Null && other.type == ValueType::Null) return false;
        if (type == ValueType::Null && other.type == ValueType::Null) return false;

        double lhs = 0, rhs = 0;
        bool numericCmp = false;
        if ((type == ValueType::Integer || type == ValueType::Real) &&
            (other.type == ValueType::Integer || other.type == ValueType::Real)) {
            lhs = asReal();
            rhs = other.asReal();
            numericCmp = true;
        }
        if (numericCmp) return lhs < rhs;
        return asText() < other.asText();
    }

    bool operator>(const Value& other) const { return other < *this; }
    bool operator<=(const Value& other) const { return !(other < *this); }
    bool operator>=(const Value& other) const { return !(*this < other); }
    bool operator==(const Value& other) const {
        if (type == ValueType::Null || other.type == ValueType::Null) return false;
        double lhs = 0, rhs = 0;
        bool numericCmp = false;
        if ((type == ValueType::Integer || type == ValueType::Real) &&
            (other.type == ValueType::Integer || other.type == ValueType::Real)) {
            lhs = asReal();
            rhs = other.asReal();
            numericCmp = true;
        }
        if (numericCmp) return lhs == rhs;
        return asText() == other.asText();
    }
    bool operator!=(const Value& other) const {
        if (type == ValueType::Null || other.type == ValueType::Null) return false;
        return !(*this == other);
    }
};

// Row is a vector of values
using Row = std::vector<Value>;

// Column definition
struct ColumnDef {
    std::string name;
    std::string typeName; // INTEGER, TEXT, REAL, BLOB
    bool primaryKey = false;
    bool notNull = false;
    bool autoIncrement = false;
};

// Table definition
struct Table {
    std::string name;
    std::vector<ColumnDef> columns;
    std::vector<Row> rows;
    long long nextRowId = 1;

    int findColumn(const std::string& colName) const {
        for (int i = 0; i < static_cast<int>(columns.size()); ++i) {
            if (strcasecmp(columns[static_cast<size_t>(i)].name.c_str(), colName.c_str()) == 0) {
                return i;
            }
        }
        return -1;
    }
};

// ============================================================================
// SQL Tokenizer
// ============================================================================

enum class TokenType {
    Keyword, Identifier, IntLiteral, RealLiteral, StringLiteral,
    Operator, Comma, Semicolon, LParen, RParen, Star, Dot,
    Parameter, EndOfInput, Unknown
};

struct Token {
    TokenType type;
    std::string value;
    int paramIndex = 0; // for ? parameters
};

static std::string toUpper(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return r;
}

static bool isKeyword(const std::string& s) {
    static const char* keywords[] = {
        "SELECT", "FROM", "WHERE", "INSERT", "INTO", "VALUES", "UPDATE", "SET",
        "DELETE", "CREATE", "TABLE", "DROP", "ALTER", "INDEX", "AND", "OR", "NOT",
        "NULL", "IS", "IN", "LIKE", "BETWEEN", "ORDER", "BY", "ASC", "DESC",
        "LIMIT", "OFFSET", "BEGIN", "COMMIT", "ROLLBACK", "TRANSACTION",
        "IF", "EXISTS", "PRIMARY", "KEY", "AUTOINCREMENT", "INTEGER", "TEXT",
        "REAL", "BLOB", "PRAGMA", "AS", "DISTINCT", "GROUP", "HAVING",
        "INNER", "LEFT", "RIGHT", "OUTER", "JOIN", "ON", "UNIQUE",
        "DEFAULT", "CHECK", "FOREIGN", "REFERENCES", "CASCADE",
        "REPLACE", "IGNORE", "ABORT", "FAIL", "CONFLICT",
        "TEMP", "TEMPORARY", "VIEW", "TRIGGER", "VACUUM", "EXPLAIN",
        "CASE", "WHEN", "THEN", "ELSE", "END", "CAST", "COLLATE",
        "CROSS", "NATURAL", "USING", "UNION", "ALL", "EXCEPT", "INTERSECT",
        "GLOB", "REGEXP", "MATCH", "ESCAPE", "ISNULL", "NOTNULL",
        nullptr
    };
    std::string upper = toUpper(s);
    for (int i = 0; keywords[i] != nullptr; ++i) {
        if (upper == keywords[i]) return true;
    }
    return false;
}

static std::vector<Token> tokenize(const std::string& sql) {
    std::vector<Token> tokens;
    size_t i = 0;
    int paramCount = 0;

    while (i < sql.size()) {
        // Skip whitespace
        while (i < sql.size() && isspace(static_cast<unsigned char>(sql[i]))) ++i;
        if (i >= sql.size()) break;

        char c = sql[i];

        // Single-character tokens
        if (c == '(') { tokens.push_back({TokenType::LParen, "(", 0}); ++i; continue; }
        if (c == ')') { tokens.push_back({TokenType::RParen, ")", 0}); ++i; continue; }
        if (c == ',') { tokens.push_back({TokenType::Comma, ",", 0}); ++i; continue; }
        if (c == ';') { tokens.push_back({TokenType::Semicolon, ";", 0}); ++i; continue; }
        if (c == '*') { tokens.push_back({TokenType::Star, "*", 0}); ++i; continue; }
        if (c == '.') { tokens.push_back({TokenType::Dot, ".", 0}); ++i; continue; }
        if (c == '?') { ++paramCount; tokens.push_back({TokenType::Parameter, "?", paramCount}); ++i; continue; }

        // Operators
        if (c == '=' && (i + 1 >= sql.size() || sql[i + 1] != '=')) {
            tokens.push_back({TokenType::Operator, "=", 0}); ++i; continue;
        }
        if (c == '!' && i + 1 < sql.size() && sql[i + 1] == '=') {
            tokens.push_back({TokenType::Operator, "!=", 0}); i += 2; continue;
        }
        if (c == '<') {
            if (i + 1 < sql.size() && sql[i + 1] == '=') {
                tokens.push_back({TokenType::Operator, "<=", 0}); i += 2;
            } else if (i + 1 < sql.size() && sql[i + 1] == '>') {
                tokens.push_back({TokenType::Operator, "!=", 0}); i += 2;
            } else {
                tokens.push_back({TokenType::Operator, "<", 0}); ++i;
            }
            continue;
        }
        if (c == '>') {
            if (i + 1 < sql.size() && sql[i + 1] == '=') {
                tokens.push_back({TokenType::Operator, ">=", 0}); i += 2;
            } else {
                tokens.push_back({TokenType::Operator, ">", 0}); ++i;
            }
            continue;
        }
        if (c == '|' && i + 1 < sql.size() && sql[i + 1] == '|') {
            tokens.push_back({TokenType::Operator, "||", 0}); i += 2; continue;
        }
        if (c == '+') { tokens.push_back({TokenType::Operator, "+", 0}); ++i; continue; }
        if (c == '-') {
            // Check if it's a negative number
            if (i + 1 < sql.size() && isdigit(static_cast<unsigned char>(sql[i + 1])) &&
                (tokens.empty() || tokens.back().type == TokenType::Operator ||
                 tokens.back().type == TokenType::LParen || tokens.back().type == TokenType::Comma ||
                 (tokens.back().type == TokenType::Keyword))) {
                // Parse as negative number
                std::string num = "-";
                ++i;
                bool hasDot = false;
                while (i < sql.size() && (isdigit(static_cast<unsigned char>(sql[i])) || sql[i] == '.')) {
                    if (sql[i] == '.') hasDot = true;
                    num += sql[i]; ++i;
                }
                if (hasDot) tokens.push_back({TokenType::RealLiteral, num, 0});
                else tokens.push_back({TokenType::IntLiteral, num, 0});
                continue;
            }
            tokens.push_back({TokenType::Operator, "-", 0}); ++i; continue;
        }
        if (c == '/') { tokens.push_back({TokenType::Operator, "/", 0}); ++i; continue; }
        if (c == '%') { tokens.push_back({TokenType::Operator, "%", 0}); ++i; continue; }

        // String literals
        if (c == '\'') {
            ++i;
            std::string str;
            while (i < sql.size()) {
                if (sql[i] == '\'') {
                    if (i + 1 < sql.size() && sql[i + 1] == '\'') {
                        str += '\''; i += 2;
                    } else {
                        ++i; break;
                    }
                } else {
                    str += sql[i]; ++i;
                }
            }
            tokens.push_back({TokenType::StringLiteral, str, 0});
            continue;
        }

        // Double-quoted identifiers
        if (c == '"') {
            ++i;
            std::string str;
            while (i < sql.size() && sql[i] != '"') { str += sql[i]; ++i; }
            if (i < sql.size()) ++i;
            tokens.push_back({TokenType::Identifier, str, 0});
            continue;
        }

        // Square-bracket identifiers [name]
        if (c == '[') {
            ++i;
            std::string str;
            while (i < sql.size() && sql[i] != ']') { str += sql[i]; ++i; }
            if (i < sql.size()) ++i;
            tokens.push_back({TokenType::Identifier, str, 0});
            continue;
        }

        // Numbers
        if (isdigit(static_cast<unsigned char>(c))) {
            std::string num;
            bool hasDot = false;
            while (i < sql.size() && (isdigit(static_cast<unsigned char>(sql[i])) || sql[i] == '.')) {
                if (sql[i] == '.') hasDot = true;
                num += sql[i]; ++i;
            }
            if (hasDot) tokens.push_back({TokenType::RealLiteral, num, 0});
            else tokens.push_back({TokenType::IntLiteral, num, 0});
            continue;
        }

        // Identifiers and keywords
        if (isalpha(static_cast<unsigned char>(c)) || c == '_') {
            std::string id;
            while (i < sql.size() && (isalnum(static_cast<unsigned char>(sql[i])) || sql[i] == '_')) {
                id += sql[i]; ++i;
            }
            if (isKeyword(id)) {
                tokens.push_back({TokenType::Keyword, toUpper(id), 0});
            } else {
                tokens.push_back({TokenType::Identifier, id, 0});
            }
            continue;
        }

        // Skip unknown character
        tokens.push_back({TokenType::Unknown, std::string(1, c), 0});
        ++i;
    }

    tokens.push_back({TokenType::EndOfInput, "", 0});
    return tokens;
}

// ============================================================================
// SQL Parser - AST Nodes
// ============================================================================

enum class ExprType {
    Literal, ColumnRef, Parameter, BinaryOp, UnaryOp, FunctionCall, IsNull, IsNotNull, Like, Between, InList
};

struct Expr;
using ExprPtr = std::shared_ptr<Expr>;

struct Expr {
    ExprType type;
    Value literalValue;
    std::string columnName;
    std::string tableName; // for table.column references
    int paramIndex = 0;
    std::string op;
    ExprPtr left, right;
    std::string funcName;
    std::vector<ExprPtr> args;
    ExprPtr lower, upper; // for BETWEEN

    static ExprPtr makeLiteral(const Value& v) {
        auto e = std::make_shared<Expr>();
        e->type = ExprType::Literal;
        e->literalValue = v;
        return e;
    }
    static ExprPtr makeColumn(const std::string& name, const std::string& table = "") {
        auto e = std::make_shared<Expr>();
        e->type = ExprType::ColumnRef;
        e->columnName = name;
        e->tableName = table;
        return e;
    }
    static ExprPtr makeParam(int idx) {
        auto e = std::make_shared<Expr>();
        e->type = ExprType::Parameter;
        e->paramIndex = idx;
        return e;
    }
    static ExprPtr makeBinary(const std::string& oper, ExprPtr l, ExprPtr r) {
        auto e = std::make_shared<Expr>();
        e->type = ExprType::BinaryOp;
        e->op = oper;
        e->left = std::move(l);
        e->right = std::move(r);
        return e;
    }
    static ExprPtr makeUnary(const std::string& oper, ExprPtr operand) {
        auto e = std::make_shared<Expr>();
        e->type = ExprType::UnaryOp;
        e->op = oper;
        e->left = std::move(operand);
        return e;
    }
    static ExprPtr makeIsNull(ExprPtr operand) {
        auto e = std::make_shared<Expr>();
        e->type = ExprType::IsNull;
        e->left = std::move(operand);
        return e;
    }
    static ExprPtr makeIsNotNull(ExprPtr operand) {
        auto e = std::make_shared<Expr>();
        e->type = ExprType::IsNotNull;
        e->left = std::move(operand);
        return e;
    }
    static ExprPtr makeLike(ExprPtr l, ExprPtr pattern) {
        auto e = std::make_shared<Expr>();
        e->type = ExprType::Like;
        e->left = std::move(l);
        e->right = std::move(pattern);
        return e;
    }
    static ExprPtr makeFunc(const std::string& name, std::vector<ExprPtr> arguments) {
        auto e = std::make_shared<Expr>();
        e->type = ExprType::FunctionCall;
        e->funcName = toUpper(name);
        e->args = std::move(arguments);
        return e;
    }
};

struct OrderByClause {
    ExprPtr expr;
    bool ascending = true;
};

enum class StmtType {
    Select, Insert, Update, Delete, CreateTable, DropTable,
    Begin, Commit, Rollback, Pragma, Unknown
};

struct SelectStmt {
    std::vector<ExprPtr> columns; // empty = select *
    bool selectAll = false;
    bool distinct = false;
    std::string tableName;
    std::string tableAlias;
    ExprPtr whereClause;
    std::vector<OrderByClause> orderBy;
    int limit = -1;
    int offset = 0;
    std::vector<ExprPtr> groupBy;
};

struct InsertStmt {
    std::string tableName;
    std::vector<std::string> columnNames;
    std::vector<std::vector<ExprPtr>> valueRows;
};

struct UpdateStmt {
    std::string tableName;
    std::vector<std::pair<std::string, ExprPtr>> assignments;
    ExprPtr whereClause;
};

struct DeleteStmt {
    std::string tableName;
    ExprPtr whereClause;
};

struct CreateTableStmt {
    std::string tableName;
    std::vector<ColumnDef> columns;
    bool ifNotExists = false;
};

struct DropTableStmt {
    std::string tableName;
    bool ifExists = false;
};

struct PragmaStmt {
    std::string name;
    std::string value;
};

struct ParsedStmt {
    StmtType type = StmtType::Unknown;
    SelectStmt select;
    InsertStmt insert;
    UpdateStmt update;
    DeleteStmt del;
    CreateTableStmt createTable;
    DropTableStmt dropTable;
    PragmaStmt pragma;
    std::string errorMsg;
};

// ============================================================================
// SQL Parser
// ============================================================================

class Parser {
public:
    explicit Parser(const std::vector<Token>& tokens) : tokens_(tokens), pos_(0) {}

    ParsedStmt parse() {
        ParsedStmt stmt;
        if (pos_ >= tokens_.size() || tokens_[pos_].type == TokenType::EndOfInput) {
            stmt.type = StmtType::Unknown;
            return stmt;
        }

        if (match("SELECT")) return parseSelect();
        if (match("INSERT") || match("REPLACE")) return parseInsert();
        if (match("UPDATE")) return parseUpdate();
        if (match("DELETE")) return parseDelete();
        if (match("CREATE")) return parseCreate();
        if (match("DROP")) return parseDrop();
        if (match("BEGIN")) return parseBegin();
        if (match("COMMIT") || match("END")) return parseCommit();
        if (match("ROLLBACK")) return parseRollback();
        if (match("PRAGMA")) return parsePragma();

        // Unknown statement - just accept it
        stmt.type = StmtType::Unknown;
        return stmt;
    }

private:
    const std::vector<Token>& tokens_;
    size_t pos_;

    bool atEnd() const { return pos_ >= tokens_.size() || tokens_[pos_].type == TokenType::EndOfInput; }

    const Token& current() const {
        static Token eof{TokenType::EndOfInput, "", 0};
        if (pos_ >= tokens_.size()) return eof;
        return tokens_[pos_];
    }

    const Token& peek(size_t ahead = 0) const {
        static Token eof{TokenType::EndOfInput, "", 0};
        size_t idx = pos_ + ahead;
        if (idx >= tokens_.size()) return eof;
        return tokens_[idx];
    }

    bool match(const std::string& keyword) {
        if (!atEnd() && current().type == TokenType::Keyword && current().value == keyword) {
            ++pos_;
            return true;
        }
        return false;
    }

    bool matchAny(const std::vector<std::string>& keywords) {
        for (const auto& kw : keywords) {
            if (match(kw)) return true;
        }
        return false;
    }

    void advance() { if (!atEnd()) ++pos_; }

    std::string consumeIdentifier() {
        if (!atEnd() && (current().type == TokenType::Identifier || current().type == TokenType::Keyword)) {
            std::string val = current().value;
            ++pos_;
            return val;
        }
        return "";
    }

    bool expect(TokenType t) {
        if (!atEnd() && current().type == t) { ++pos_; return true; }
        return false;
    }

    // Expression parsing with operator precedence
    ExprPtr parseExpr() { return parseOr(); }

    ExprPtr parseOr() {
        auto left = parseAnd();
        while (match("OR")) {
            auto right = parseAnd();
            left = Expr::makeBinary("OR", left, right);
        }
        return left;
    }

    ExprPtr parseAnd() {
        auto left = parseNot();
        while (match("AND")) {
            auto right = parseNot();
            left = Expr::makeBinary("AND", left, right);
        }
        return left;
    }

    ExprPtr parseNot() {
        if (match("NOT")) {
            auto operand = parseNot();
            return Expr::makeUnary("NOT", operand);
        }
        return parseComparison();
    }

    ExprPtr parseComparison() {
        auto left = parseAddition();

        // IS NULL / IS NOT NULL
        if (match("IS")) {
            if (match("NOT")) {
                if (match("NULL")) return Expr::makeIsNotNull(left);
            } else if (match("NULL")) {
                return Expr::makeIsNull(left);
            }
        }

        // LIKE
        if (match("LIKE")) {
            auto pattern = parseAddition();
            return Expr::makeLike(left, pattern);
        }

        // NOT LIKE
        if (!atEnd() && current().type == TokenType::Keyword && current().value == "NOT") {
            if (pos_ + 1 < tokens_.size() && tokens_[pos_ + 1].type == TokenType::Keyword && tokens_[pos_ + 1].value == "LIKE") {
                pos_ += 2;
                auto pattern = parseAddition();
                return Expr::makeUnary("NOT", Expr::makeLike(left, pattern));
            }
        }

        // BETWEEN
        if (match("BETWEEN")) {
            auto low = parseAddition();
            match("AND");
            auto high = parseAddition();
            auto geExpr = Expr::makeBinary(">=", left, low);
            auto leExpr = Expr::makeBinary("<=", left, high);
            return Expr::makeBinary("AND", geExpr, leExpr);
        }

        // IN (...)
        if (match("IN")) {
            if (expect(TokenType::LParen)) {
                std::vector<ExprPtr> vals;
                if (current().type != TokenType::RParen) {
                    vals.push_back(parseExpr());
                    while (!atEnd() && current().type == TokenType::Comma) {
                        advance();
                        vals.push_back(parseExpr());
                    }
                }
                expect(TokenType::RParen);
                // Convert IN to series of OR comparisons
                if (vals.empty()) return Expr::makeLiteral(Value::makeInt(0));
                auto result = Expr::makeBinary("=", left, vals[0]);
                for (size_t i = 1; i < vals.size(); ++i) {
                    auto cmp = Expr::makeBinary("=", left, vals[i]);
                    result = Expr::makeBinary("OR", result, cmp);
                }
                return result;
            }
        }

        // Standard comparison operators
        if (!atEnd() && current().type == TokenType::Operator) {
            std::string op = current().value;
            if (op == "=" || op == "!=" || op == "<" || op == ">" || op == "<=" || op == ">=") {
                advance();
                auto right = parseAddition();
                return Expr::makeBinary(op, left, right);
            }
        }

        return left;
    }

    ExprPtr parseAddition() {
        auto left = parseMultiplication();
        while (!atEnd() && current().type == TokenType::Operator &&
               (current().value == "+" || current().value == "-" || current().value == "||")) {
            std::string op = current().value;
            advance();
            auto right = parseMultiplication();
            left = Expr::makeBinary(op, left, right);
        }
        return left;
    }

    ExprPtr parseMultiplication() {
        auto left = parseUnary();
        while (!atEnd() && current().type == TokenType::Operator &&
               (current().value == "*" || current().value == "/" || current().value == "%")) {
            std::string op = current().value;
            advance();
            auto right = parseUnary();
            left = Expr::makeBinary(op, left, right);
        }
        return left;
    }

    ExprPtr parseUnary() {
        if (!atEnd() && current().type == TokenType::Operator && current().value == "-") {
            advance();
            auto operand = parsePrimary();
            return Expr::makeUnary("-", operand);
        }
        return parsePrimary();
    }

    ExprPtr parsePrimary() {
        if (atEnd()) return Expr::makeLiteral(Value::makeNull());

        // Parameter ?
        if (current().type == TokenType::Parameter) {
            int idx = current().paramIndex;
            advance();
            return Expr::makeParam(idx);
        }

        // NULL
        if (current().type == TokenType::Keyword && current().value == "NULL") {
            advance();
            return Expr::makeLiteral(Value::makeNull());
        }

        // Integer literal
        if (current().type == TokenType::IntLiteral) {
            long long val = 0;
            try { val = std::stoll(current().value); } catch (...) {}
            advance();
            return Expr::makeLiteral(Value::makeInt(val));
        }

        // Real literal
        if (current().type == TokenType::RealLiteral) {
            double val = 0;
            try { val = std::stod(current().value); } catch (...) {}
            advance();
            return Expr::makeLiteral(Value::makeReal(val));
        }

        // String literal
        if (current().type == TokenType::StringLiteral) {
            std::string val = current().value;
            advance();
            return Expr::makeLiteral(Value::makeText(val));
        }

        // Parenthesized expression
        if (current().type == TokenType::LParen) {
            advance();
            auto expr = parseExpr();
            expect(TokenType::RParen);
            return expr;
        }

        // Star (for COUNT(*) etc)
        if (current().type == TokenType::Star) {
            advance();
            return Expr::makeColumn("*");
        }

        // CASE expression
        if (current().type == TokenType::Keyword && current().value == "CASE") {
            advance();
            // Skip through CASE ... END, return NULL as simplification
            int depth = 1;
            while (!atEnd() && depth > 0) {
                if (current().type == TokenType::Keyword && current().value == "CASE") ++depth;
                if (current().type == TokenType::Keyword && current().value == "END") --depth;
                advance();
            }
            return Expr::makeLiteral(Value::makeNull());
        }

        // CAST expression
        if (current().type == TokenType::Keyword && current().value == "CAST") {
            advance();
            expect(TokenType::LParen);
            auto expr = parseExpr();
            // Skip AS type
            if (match("AS")) consumeIdentifier();
            expect(TokenType::RParen);
            return expr;
        }

        // Identifier (column or function call)
        if (current().type == TokenType::Identifier || current().type == TokenType::Keyword) {
            std::string name = current().value;
            advance();

            // Check for function call
            if (!atEnd() && current().type == TokenType::LParen) {
                advance();
                std::vector<ExprPtr> arguments;
                if (current().type != TokenType::RParen) {
                    // handle DISTINCT in aggregate
                    matchAny({"DISTINCT", "ALL"});
                    if (current().type == TokenType::Star) {
                        arguments.push_back(Expr::makeColumn("*"));
                        advance();
                    } else {
                        arguments.push_back(parseExpr());
                        while (!atEnd() && current().type == TokenType::Comma) {
                            advance();
                            arguments.push_back(parseExpr());
                        }
                    }
                }
                expect(TokenType::RParen);
                return Expr::makeFunc(name, arguments);
            }

            // Check for table.column
            if (!atEnd() && current().type == TokenType::Dot) {
                advance();
                std::string colName;
                if (!atEnd() && current().type == TokenType::Star) {
                    colName = "*";
                    advance();
                } else {
                    colName = consumeIdentifier();
                }
                return Expr::makeColumn(colName, name);
            }

            return Expr::makeColumn(name);
        }

        // Skip unknown
        advance();
        return Expr::makeLiteral(Value::makeNull());
    }

    // Statement parsers
    ParsedStmt parseSelect() {
        ParsedStmt stmt;
        stmt.type = StmtType::Select;
        auto& sel = stmt.select;

        // DISTINCT
        if (match("DISTINCT")) sel.distinct = true;
        if (match("ALL")) {} // ignore ALL

        // Column list
        if (!atEnd() && current().type == TokenType::Star) {
            sel.selectAll = true;
            advance();
        } else {
            sel.selectAll = false;
            sel.columns.push_back(parseExpr());
            // Handle alias
            if (match("AS")) consumeIdentifier();
            else if (!atEnd() && current().type == TokenType::Identifier &&
                     current().value != "FROM" && toUpper(current().value) != "FROM") {
                // implicit alias - skip
            }
            while (!atEnd() && current().type == TokenType::Comma) {
                advance();
                sel.columns.push_back(parseExpr());
                if (match("AS")) consumeIdentifier();
            }
        }

        // FROM
        if (match("FROM")) {
            sel.tableName = consumeIdentifier();
            // Alias
            if (match("AS")) sel.tableAlias = consumeIdentifier();
            else if (!atEnd() && current().type == TokenType::Identifier &&
                     !isKeyword(current().value)) {
                sel.tableAlias = consumeIdentifier();
            }

            // Skip JOINs (simplified - just consume until WHERE/ORDER/LIMIT/GROUP/END)
            while (!atEnd() && (match("INNER") || match("LEFT") || match("RIGHT") ||
                   match("OUTER") || match("CROSS") || match("NATURAL"))) {
                match("OUTER");
                if (match("JOIN")) {
                    consumeIdentifier(); // table name
                    if (match("AS")) consumeIdentifier();
                    else if (!atEnd() && current().type == TokenType::Identifier &&
                             !isKeyword(current().value)) consumeIdentifier();
                    if (match("ON")) {
                        parseExpr(); // skip ON condition
                    }
                }
            }
            if (match("JOIN")) {
                consumeIdentifier();
                if (match("AS")) consumeIdentifier();
                else if (!atEnd() && current().type == TokenType::Identifier &&
                         !isKeyword(current().value)) consumeIdentifier();
                if (match("ON")) {
                    parseExpr();
                }
            }
        }

        // WHERE
        if (match("WHERE")) {
            sel.whereClause = parseExpr();
        }

        // GROUP BY
        if (match("GROUP")) {
            match("BY");
            sel.groupBy.push_back(parseExpr());
            while (!atEnd() && current().type == TokenType::Comma) {
                advance();
                sel.groupBy.push_back(parseExpr());
            }
            // HAVING
            if (match("HAVING")) {
                parseExpr(); // skip for now
            }
        }

        // ORDER BY
        if (match("ORDER")) {
            match("BY");
            OrderByClause obc;
            obc.expr = parseExpr();
            obc.ascending = true;
            if (match("DESC")) obc.ascending = false;
            else match("ASC");
            sel.orderBy.push_back(obc);

            while (!atEnd() && current().type == TokenType::Comma) {
                advance();
                OrderByClause obc2;
                obc2.expr = parseExpr();
                obc2.ascending = true;
                if (match("DESC")) obc2.ascending = false;
                else match("ASC");
                sel.orderBy.push_back(obc2);
            }
        }

        // LIMIT
        if (match("LIMIT")) {
            if (!atEnd() && current().type == TokenType::IntLiteral) {
                sel.limit = std::stoi(current().value);
                advance();
            } else if (!atEnd() && current().type == TokenType::Parameter) {
                sel.limit = -1; // dynamic limit not supported, treat as no limit
                advance();
            }

            // OFFSET
            if (match("OFFSET")) {
                if (!atEnd() && current().type == TokenType::IntLiteral) {
                    sel.offset = std::stoi(current().value);
                    advance();
                } else if (!atEnd() && current().type == TokenType::Parameter) {
                    advance();
                }
            }
            // alternate syntax: LIMIT x, y
            if (!atEnd() && current().type == TokenType::Comma) {
                advance();
                if (!atEnd() && current().type == TokenType::IntLiteral) {
                    sel.offset = sel.limit;
                    sel.limit = std::stoi(current().value);
                    advance();
                }
            }
        }

        return stmt;
    }

    ParsedStmt parseInsert() {
        ParsedStmt stmt;
        stmt.type = StmtType::Insert;
        auto& ins = stmt.insert;

        // OR REPLACE/IGNORE/ABORT
        if (match("OR")) {
            matchAny({"REPLACE", "IGNORE", "ABORT", "FAIL", "ROLLBACK"});
        }

        match("INTO");
        ins.tableName = consumeIdentifier();

        // Column names (optional)
        if (!atEnd() && current().type == TokenType::LParen) {
            advance();
            if (current().type != TokenType::RParen) {
                ins.columnNames.push_back(consumeIdentifier());
                while (!atEnd() && current().type == TokenType::Comma) {
                    advance();
                    ins.columnNames.push_back(consumeIdentifier());
                }
            }
            expect(TokenType::RParen);
        }

        // VALUES
        if (match("VALUES")) {
            do {
                expect(TokenType::LParen);
                std::vector<ExprPtr> row;
                if (current().type != TokenType::RParen) {
                    row.push_back(parseExpr());
                    while (!atEnd() && current().type == TokenType::Comma) {
                        advance();
                        row.push_back(parseExpr());
                    }
                }
                expect(TokenType::RParen);
                ins.valueRows.push_back(std::move(row));
            } while (!atEnd() && current().type == TokenType::Comma && (advance(), true));
        }
        // DEFAULT VALUES
        else if (match("DEFAULT")) {
            match("VALUES");
            ins.valueRows.push_back({});
        }

        return stmt;
    }

    ParsedStmt parseUpdate() {
        ParsedStmt stmt;
        stmt.type = StmtType::Update;
        auto& upd = stmt.update;

        // OR REPLACE/IGNORE
        if (match("OR")) {
            matchAny({"REPLACE", "IGNORE", "ABORT", "FAIL", "ROLLBACK"});
        }

        upd.tableName = consumeIdentifier();

        match("SET");

        // assignments
        {
            std::string col = consumeIdentifier();
            expect(TokenType::Operator); // =
            auto val = parseExpr();
            upd.assignments.emplace_back(col, val);
        }
        while (!atEnd() && current().type == TokenType::Comma) {
            advance();
            std::string col = consumeIdentifier();
            expect(TokenType::Operator); // =
            auto val = parseExpr();
            upd.assignments.emplace_back(col, val);
        }

        if (match("WHERE")) {
            upd.whereClause = parseExpr();
        }

        return stmt;
    }

    ParsedStmt parseDelete() {
        ParsedStmt stmt;
        stmt.type = StmtType::Delete;
        auto& del = stmt.del;

        match("FROM");
        del.tableName = consumeIdentifier();

        if (match("WHERE")) {
            del.whereClause = parseExpr();
        }

        return stmt;
    }

    ParsedStmt parseCreate() {
        ParsedStmt stmt;

        // CREATE TABLE, CREATE INDEX, etc.
        if (match("TABLE")) {
            stmt.type = StmtType::CreateTable;
            auto& ct = stmt.createTable;

            if (match("IF")) { match("NOT"); match("EXISTS"); ct.ifNotExists = true; }

            ct.tableName = consumeIdentifier();

            if (!atEnd() && current().type == TokenType::LParen) {
                advance();
                parseColumnDefs(ct.columns);
                expect(TokenType::RParen);
            }

            // WITHOUT ROWID or other trailing stuff
            while (!atEnd() && current().type != TokenType::Semicolon &&
                   current().type != TokenType::EndOfInput) advance();

            return stmt;
        }

        // Skip other CREATE statements (INDEX, VIEW, etc.)
        stmt.type = StmtType::Unknown;
        while (!atEnd() && current().type != TokenType::Semicolon &&
               current().type != TokenType::EndOfInput) advance();
        return stmt;
    }

    void parseColumnDefs(std::vector<ColumnDef>& columns) {
        while (!atEnd() && current().type != TokenType::RParen) {
            // Check for table constraints
            if (current().type == TokenType::Keyword &&
                (current().value == "PRIMARY" || current().value == "UNIQUE" ||
                 current().value == "CHECK" || current().value == "FOREIGN" ||
                 current().value == "CONSTRAINT")) {
                // Skip table constraint
                int depth = 0;
                while (!atEnd()) {
                    if (current().type == TokenType::LParen) ++depth;
                    if (current().type == TokenType::RParen) {
                        if (depth == 0) break;
                        --depth;
                    }
                    if (current().type == TokenType::Comma && depth == 0) break;
                    advance();
                }
                if (!atEnd() && current().type == TokenType::Comma) { advance(); continue; }
                break;
            }

            ColumnDef col;
            col.name = consumeIdentifier();
            if (col.name.empty()) { advance(); continue; }

            // Type name (optional)
            if (!atEnd() && (current().type == TokenType::Identifier || current().type == TokenType::Keyword) &&
                current().value != "PRIMARY" && current().value != "NOT" &&
                current().value != "UNIQUE" && current().value != "CHECK" &&
                current().value != "DEFAULT" && current().value != "REFERENCES" &&
                current().value != "CONSTRAINT" && current().value != "COLLATE") {
                col.typeName = toUpper(consumeIdentifier());
                // Handle multi-word types like VARCHAR(n)
                if (!atEnd() && current().type == TokenType::LParen) {
                    advance();
                    while (!atEnd() && current().type != TokenType::RParen) advance();
                    expect(TokenType::RParen);
                }
                // Additional type words (e.g., "VARYING", "PRECISION")
                while (!atEnd() && (current().type == TokenType::Identifier || current().type == TokenType::Keyword) &&
                       current().value != "PRIMARY" && current().value != "NOT" &&
                       current().value != "UNIQUE" && current().value != "CHECK" &&
                       current().value != "DEFAULT" && current().value != "REFERENCES" &&
                       current().value != "NULL" && current().value != "CONSTRAINT" &&
                       current().value != "COLLATE" && current().value != "AUTOINCREMENT") {
                    consumeIdentifier();
                    if (!atEnd() && current().type == TokenType::LParen) {
                        advance();
                        while (!atEnd() && current().type != TokenType::RParen) advance();
                        expect(TokenType::RParen);
                    }
                }
            }

            // Column constraints
            while (!atEnd() && current().type != TokenType::Comma && current().type != TokenType::RParen) {
                if (match("PRIMARY")) {
                    match("KEY");
                    col.primaryKey = true;
                    if (match("AUTOINCREMENT")) col.autoIncrement = true;
                    // ASC/DESC
                    matchAny({"ASC", "DESC"});
                } else if (match("NOT")) {
                    match("NULL");
                    col.notNull = true;
                } else if (match("NULL")) {
                    // explicitly nullable
                } else if (match("UNIQUE")) {
                    // skip
                } else if (match("DEFAULT")) {
                    // skip default value expression
                    if (!atEnd() && current().type == TokenType::LParen) {
                        int depth = 1; advance();
                        while (!atEnd() && depth > 0) {
                            if (current().type == TokenType::LParen) ++depth;
                            if (current().type == TokenType::RParen) --depth;
                            advance();
                        }
                    } else {
                        advance(); // skip default value
                    }
                } else if (match("CHECK")) {
                    if (!atEnd() && current().type == TokenType::LParen) {
                        int depth = 1; advance();
                        while (!atEnd() && depth > 0) {
                            if (current().type == TokenType::LParen) ++depth;
                            if (current().type == TokenType::RParen) --depth;
                            advance();
                        }
                    }
                } else if (match("REFERENCES")) {
                    consumeIdentifier();
                    if (!atEnd() && current().type == TokenType::LParen) {
                        advance();
                        while (!atEnd() && current().type != TokenType::RParen) advance();
                        expect(TokenType::RParen);
                    }
                    // ON DELETE/UPDATE
                    while (match("ON")) {
                        matchAny({"DELETE", "UPDATE"});
                        matchAny({"CASCADE", "RESTRICT", "SET"});
                        match("NULL");
                        match("DEFAULT");
                    }
                } else if (match("COLLATE")) {
                    consumeIdentifier();
                } else if (match("AUTOINCREMENT")) {
                    col.autoIncrement = true;
                } else if (match("CONSTRAINT")) {
                    consumeIdentifier(); // constraint name
                } else {
                    break;
                }
            }

            columns.push_back(col);
            if (!atEnd() && current().type == TokenType::Comma) { advance(); }
            else break;
        }
    }

    ParsedStmt parseDrop() {
        ParsedStmt stmt;
        if (match("TABLE")) {
            stmt.type = StmtType::DropTable;
            if (match("IF")) { match("EXISTS"); stmt.dropTable.ifExists = true; }
            stmt.dropTable.tableName = consumeIdentifier();
        } else {
            stmt.type = StmtType::Unknown;
            while (!atEnd() && current().type != TokenType::Semicolon &&
                   current().type != TokenType::EndOfInput) advance();
        }
        return stmt;
    }

    ParsedStmt parseBegin() {
        ParsedStmt stmt;
        stmt.type = StmtType::Begin;
        // Skip DEFERRED/IMMEDIATE/EXCLUSIVE TRANSACTION
        matchAny({"DEFERRED", "IMMEDIATE", "EXCLUSIVE"});
        match("TRANSACTION");
        return stmt;
    }

    ParsedStmt parseCommit() {
        ParsedStmt stmt;
        stmt.type = StmtType::Commit;
        match("TRANSACTION");
        return stmt;
    }

    ParsedStmt parseRollback() {
        ParsedStmt stmt;
        stmt.type = StmtType::Rollback;
        match("TRANSACTION");
        // TO SAVEPOINT
        if (match("TO")) { match("SAVEPOINT"); consumeIdentifier(); }
        return stmt;
    }

    ParsedStmt parsePragma() {
        ParsedStmt stmt;
        stmt.type = StmtType::Pragma;
        stmt.pragma.name = consumeIdentifier();

        // PRAGMA name = value or PRAGMA name(value)
        if (!atEnd() && current().type == TokenType::Operator && current().value == "=") {
            advance();
            if (!atEnd()) {
                stmt.pragma.value = current().value;
                advance();
            }
        } else if (!atEnd() && current().type == TokenType::LParen) {
            advance();
            if (!atEnd() && current().type != TokenType::RParen) {
                stmt.pragma.value = current().value;
                advance();
            }
            expect(TokenType::RParen);
        }

        return stmt;
    }
};

// ============================================================================
// Database Engine (internal struct definitions)
// ============================================================================

} // end anonymous namespace

struct sqlite3 {
    std::mutex mutex;
    std::map<std::string, Table> tables; // key is lowercase table name
    std::string lastError;
    int lastErrCode = SQLITE_OK;
    long long lastInsertRowid = 0;
    int changes = 0;
    bool isOpen = true;
    std::string filePath;
    bool inTransaction = false;
    bool foreignKeysEnabled = false;

    // Transaction snapshot for rollback
    std::map<std::string, Table> snapshot;

    std::string getTableKey(const std::string& name) const {
        std::string lower = name;
        for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        return lower;
    }

    Table* findTable(const std::string& name) {
        auto it = tables.find(getTableKey(name));
        if (it != tables.end()) return &it->second;
        return nullptr;
    }
};

struct sqlite3_stmt {
    sqlite3* db = nullptr;
    ParsedStmt parsed;
    std::string sql;
    std::vector<Value> params;
    int paramCount = 0;

    // Result state
    std::vector<std::vector<Value>> resultRows;
    std::vector<std::string> resultColumns;
    int currentRow = -1;
    bool executed = false;
    bool done = false;
};

namespace {

// ============================================================================
// Expression Evaluator
// ============================================================================

static bool likeMatch(const std::string& pattern, const std::string& str) {
    size_t pi = 0, si = 0;
    size_t starP = std::string::npos, starS = 0;

    while (si < str.size()) {
        if (pi < pattern.size() && (pattern[pi] == '_' ||
            tolower(static_cast<unsigned char>(pattern[pi])) == tolower(static_cast<unsigned char>(str[si])))) {
            ++pi; ++si;
        } else if (pi < pattern.size() && pattern[pi] == '%') {
            starP = pi; starS = si;
            ++pi;
        } else if (starP != std::string::npos) {
            pi = starP + 1;
            ++starS;
            si = starS;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '%') ++pi;
    return pi == pattern.size();
}

static Value evaluateExpr(const ExprPtr& expr, const Row& row, const std::vector<ColumnDef>& cols,
                          const std::vector<Value>& params) {
    if (!expr) return Value::makeNull();

    switch (expr->type) {
        case ExprType::Literal:
            return expr->literalValue;

        case ExprType::Parameter: {
            int idx = expr->paramIndex - 1;
            if (idx >= 0 && idx < static_cast<int>(params.size())) return params[static_cast<size_t>(idx)];
            return Value::makeNull();
        }

        case ExprType::ColumnRef: {
            if (expr->columnName == "*") return Value::makeNull();
            for (size_t i = 0; i < cols.size(); ++i) {
                if (strcasecmp(cols[i].name.c_str(), expr->columnName.c_str()) == 0) {
                    if (i < row.size()) return row[i];
                }
            }
            // Try without table prefix
            return Value::makeNull();
        }

        case ExprType::BinaryOp: {
            if (expr->op == "AND") {
                auto l = evaluateExpr(expr->left, row, cols, params);
                if (l.type == ValueType::Integer && l.intVal == 0) return Value::makeInt(0);
                if (l.type == ValueType::Null) return Value::makeInt(0);
                auto r = evaluateExpr(expr->right, row, cols, params);
                if (r.type == ValueType::Null) return Value::makeInt(0);
                return Value::makeInt((l.asInt() != 0 && r.asInt() != 0) ? 1 : 0);
            }
            if (expr->op == "OR") {
                auto l = evaluateExpr(expr->left, row, cols, params);
                if (l.type == ValueType::Integer && l.intVal != 0) return Value::makeInt(1);
                auto r = evaluateExpr(expr->right, row, cols, params);
                return Value::makeInt((l.asInt() != 0 || r.asInt() != 0) ? 1 : 0);
            }

            auto l = evaluateExpr(expr->left, row, cols, params);
            auto r = evaluateExpr(expr->right, row, cols, params);

            if (expr->op == "||") {
                return Value::makeText(l.asText() + r.asText());
            }
            if (expr->op == "+") {
                if (l.type == ValueType::Real || r.type == ValueType::Real)
                    return Value::makeReal(l.asReal() + r.asReal());
                return Value::makeInt(l.asInt() + r.asInt());
            }
            if (expr->op == "-") {
                if (l.type == ValueType::Real || r.type == ValueType::Real)
                    return Value::makeReal(l.asReal() - r.asReal());
                return Value::makeInt(l.asInt() - r.asInt());
            }
            if (expr->op == "*") {
                if (l.type == ValueType::Real || r.type == ValueType::Real)
                    return Value::makeReal(l.asReal() * r.asReal());
                return Value::makeInt(l.asInt() * r.asInt());
            }
            if (expr->op == "/") {
                if (r.asReal() == 0.0) return Value::makeNull();
                if (l.type == ValueType::Real || r.type == ValueType::Real)
                    return Value::makeReal(l.asReal() / r.asReal());
                if (r.asInt() == 0) return Value::makeNull();
                return Value::makeInt(l.asInt() / r.asInt());
            }
            if (expr->op == "%") {
                if (r.asInt() == 0) return Value::makeNull();
                return Value::makeInt(l.asInt() % r.asInt());
            }

            // Comparison
            if (expr->op == "=") return Value::makeInt((l == r) ? 1 : 0);
            if (expr->op == "!=") return Value::makeInt((l != r) ? 1 : 0);
            if (expr->op == "<") return Value::makeInt((l < r) ? 1 : 0);
            if (expr->op == ">") return Value::makeInt((l > r) ? 1 : 0);
            if (expr->op == "<=") return Value::makeInt((l <= r) ? 1 : 0);
            if (expr->op == ">=") return Value::makeInt((l >= r) ? 1 : 0);

            return Value::makeNull();
        }

        case ExprType::UnaryOp: {
            auto operand = evaluateExpr(expr->left, row, cols, params);
            if (expr->op == "-") {
                if (operand.type == ValueType::Real) return Value::makeReal(-operand.asReal());
                return Value::makeInt(-operand.asInt());
            }
            if (expr->op == "NOT") {
                return Value::makeInt(operand.asInt() == 0 ? 1 : 0);
            }
            return Value::makeNull();
        }

        case ExprType::IsNull: {
            auto operand = evaluateExpr(expr->left, row, cols, params);
            return Value::makeInt(operand.type == ValueType::Null ? 1 : 0);
        }

        case ExprType::IsNotNull: {
            auto operand = evaluateExpr(expr->left, row, cols, params);
            return Value::makeInt(operand.type != ValueType::Null ? 1 : 0);
        }

        case ExprType::Like: {
            auto val = evaluateExpr(expr->left, row, cols, params);
            auto pat = evaluateExpr(expr->right, row, cols, params);
            if (val.type == ValueType::Null || pat.type == ValueType::Null) return Value::makeInt(0);
            return Value::makeInt(likeMatch(pat.asText(), val.asText()) ? 1 : 0);
        }

        case ExprType::FunctionCall: {
            // Handle common functions
            if (expr->funcName == "COUNT" || expr->funcName == "SUM" ||
                expr->funcName == "AVG" || expr->funcName == "MIN" ||
                expr->funcName == "MAX") {
                // Aggregates handled elsewhere
                return Value::makeNull();
            }
            if (expr->funcName == "COALESCE" || expr->funcName == "IFNULL") {
                for (const auto& arg : expr->args) {
                    auto v = evaluateExpr(arg, row, cols, params);
                    if (v.type != ValueType::Null) return v;
                }
                return Value::makeNull();
            }
            if (expr->funcName == "NULLIF") {
                if (expr->args.size() >= 2) {
                    auto a = evaluateExpr(expr->args[0], row, cols, params);
                    auto b = evaluateExpr(expr->args[1], row, cols, params);
                    if (a == b) return Value::makeNull();
                    return a;
                }
                return Value::makeNull();
            }
            if (expr->funcName == "LENGTH" || expr->funcName == "LEN") {
                if (!expr->args.empty()) {
                    auto v = evaluateExpr(expr->args[0], row, cols, params);
                    return Value::makeInt(static_cast<long long>(v.asText().size()));
                }
                return Value::makeNull();
            }
            if (expr->funcName == "UPPER") {
                if (!expr->args.empty()) {
                    auto v = evaluateExpr(expr->args[0], row, cols, params);
                    return Value::makeText(toUpper(v.asText()));
                }
                return Value::makeNull();
            }
            if (expr->funcName == "LOWER") {
                if (!expr->args.empty()) {
                    auto v = evaluateExpr(expr->args[0], row, cols, params);
                    std::string s = v.asText();
                    for (auto& ch : s) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
                    return Value::makeText(s);
                }
                return Value::makeNull();
            }
            if (expr->funcName == "TYPEOF") {
                if (!expr->args.empty()) {
                    auto v = evaluateExpr(expr->args[0], row, cols, params);
                    switch (v.type) {
                        case ValueType::Null: return Value::makeText("null");
                        case ValueType::Integer: return Value::makeText("integer");
                        case ValueType::Real: return Value::makeText("real");
                        case ValueType::Text: return Value::makeText("text");
                        case ValueType::Blob: return Value::makeText("blob");
                    }
                }
                return Value::makeText("null");
            }
            if (expr->funcName == "ABS") {
                if (!expr->args.empty()) {
                    auto v = evaluateExpr(expr->args[0], row, cols, params);
                    if (v.type == ValueType::Real) return Value::makeReal(v.asReal() < 0 ? -v.asReal() : v.asReal());
                    return Value::makeInt(v.asInt() < 0 ? -v.asInt() : v.asInt());
                }
                return Value::makeNull();
            }
            if (expr->funcName == "TRIM" || expr->funcName == "LTRIM" || expr->funcName == "RTRIM") {
                if (!expr->args.empty()) {
                    auto v = evaluateExpr(expr->args[0], row, cols, params);
                    std::string s = v.asText();
                    if (expr->funcName == "TRIM" || expr->funcName == "LTRIM") {
                        auto start = s.find_first_not_of(" \t\r\n");
                        if (start != std::string::npos) s = s.substr(start);
                        else s = "";
                    }
                    if (expr->funcName == "TRIM" || expr->funcName == "RTRIM") {
                        auto end = s.find_last_not_of(" \t\r\n");
                        if (end != std::string::npos) s = s.substr(0, end + 1);
                        else s = "";
                    }
                    return Value::makeText(s);
                }
                return Value::makeNull();
            }
            if (expr->funcName == "SUBSTR" || expr->funcName == "SUBSTRING") {
                if (expr->args.size() >= 2) {
                    auto v = evaluateExpr(expr->args[0], row, cols, params);
                    auto start = evaluateExpr(expr->args[1], row, cols, params);
                    std::string s = v.asText();
                    int startIdx = static_cast<int>(start.asInt()) - 1; // 1-based
                    if (startIdx < 0) startIdx = 0;
                    int len = static_cast<int>(s.size()) - startIdx;
                    if (expr->args.size() >= 3) {
                        auto lenVal = evaluateExpr(expr->args[2], row, cols, params);
                        len = static_cast<int>(lenVal.asInt());
                    }
                    if (startIdx >= static_cast<int>(s.size())) return Value::makeText("");
                    return Value::makeText(s.substr(static_cast<size_t>(startIdx), static_cast<size_t>(len)));
                }
                return Value::makeNull();
            }
            if (expr->funcName == "REPLACE") {
                if (expr->args.size() >= 3) {
                    auto v = evaluateExpr(expr->args[0], row, cols, params);
                    auto from = evaluateExpr(expr->args[1], row, cols, params);
                    auto to = evaluateExpr(expr->args[2], row, cols, params);
                    std::string s = v.asText();
                    std::string f = from.asText();
                    std::string t = to.asText();
                    if (!f.empty()) {
                        size_t pos = 0;
                        while ((pos = s.find(f, pos)) != std::string::npos) {
                            s.replace(pos, f.size(), t);
                            pos += t.size();
                        }
                    }
                    return Value::makeText(s);
                }
                return Value::makeNull();
            }
            if (expr->funcName == "HEX") {
                if (!expr->args.empty()) {
                    auto v = evaluateExpr(expr->args[0], row, cols, params);
                    std::string s = v.asText();
                    std::string hex;
                    for (unsigned char ch : s) {
                        char buf[3];
                        snprintf(buf, sizeof(buf), "%02X", ch);
                        hex += buf;
                    }
                    return Value::makeText(hex);
                }
                return Value::makeNull();
            }
            if (expr->funcName == "RANDOM") {
                return Value::makeInt(static_cast<long long>(rand()));
            }
            if (expr->funcName == "LAST_INSERT_ROWID") {
                return Value::makeNull(); // Would need db access
            }
            if (expr->funcName == "CHANGES") {
                return Value::makeNull();
            }
            if (expr->funcName == "TOTAL_CHANGES") {
                return Value::makeNull();
            }
            if (expr->funcName == "INSTR") {
                if (expr->args.size() >= 2) {
                    auto v = evaluateExpr(expr->args[0], row, cols, params);
                    auto sub = evaluateExpr(expr->args[1], row, cols, params);
                    auto pos = v.asText().find(sub.asText());
                    if (pos == std::string::npos) return Value::makeInt(0);
                    return Value::makeInt(static_cast<long long>(pos) + 1);
                }
                return Value::makeNull();
            }
            // Default: return null for unknown functions
            return Value::makeNull();
        }

        case ExprType::Between:
        case ExprType::InList:
            return Value::makeNull();
    }
    return Value::makeNull();
}

static bool evaluateWhere(const ExprPtr& where, const Row& row,
                          const std::vector<ColumnDef>& cols, const std::vector<Value>& params) {
    if (!where) return true;
    auto result = evaluateExpr(where, row, cols, params);
    return result.asInt() != 0;
}

// ============================================================================
// Query Executor
// ============================================================================

static int executeSelect(sqlite3* db, sqlite3_stmt* stmt) {
    auto& sel = stmt->parsed.select;
    Table* table = db->findTable(sel.tableName);

    stmt->resultColumns.clear();
    stmt->resultRows.clear();

    if (!table) {
        // Special case: "SELECT 1" with no table
        if (sel.tableName.empty()) {
            stmt->resultColumns.clear();
            std::vector<Value> row;
            for (size_t i = 0; i < sel.columns.size(); ++i) {
                auto val = evaluateExpr(sel.columns[i], {}, {}, stmt->params);
                row.push_back(val);
                // Column name
                if (sel.columns[i]->type == ExprType::Literal) {
                    stmt->resultColumns.push_back(sel.columns[i]->literalValue.asText());
                } else {
                    stmt->resultColumns.push_back(std::to_string(i));
                }
            }
            stmt->resultRows.push_back(row);
            return SQLITE_OK;
        }
        db->lastError = "no such table: " + sel.tableName;
        db->lastErrCode = SQLITE_ERROR;
        return SQLITE_ERROR;
    }

    // Determine result columns
    if (sel.selectAll || sel.columns.empty()) {
        for (const auto& col : table->columns) {
            stmt->resultColumns.push_back(col.name);
        }
    } else {
        for (const auto& colExpr : sel.columns) {
            if (colExpr->type == ExprType::ColumnRef) {
                if (colExpr->columnName == "*") {
                    for (const auto& col : table->columns) {
                        stmt->resultColumns.push_back(col.name);
                    }
                } else {
                    stmt->resultColumns.push_back(colExpr->columnName);
                }
            } else if (colExpr->type == ExprType::FunctionCall) {
                stmt->resultColumns.push_back(colExpr->funcName + "(...)");
            } else {
                stmt->resultColumns.push_back("expr");
            }
        }
    }

    // Check for aggregate functions
    bool hasAggregate = false;
    if (!sel.selectAll && !sel.columns.empty()) {
        for (const auto& col : sel.columns) {
            if (col->type == ExprType::FunctionCall) {
                std::string fn = col->funcName;
                if (fn == "COUNT" || fn == "SUM" || fn == "AVG" || fn == "MIN" || fn == "MAX" ||
                    fn == "TOTAL" || fn == "GROUP_CONCAT") {
                    hasAggregate = true;
                    break;
                }
            }
        }
    }

    // Filter rows
    std::vector<const Row*> matchingRows;
    for (const auto& row : table->rows) {
        if (evaluateWhere(sel.whereClause, row, table->columns, stmt->params)) {
            matchingRows.push_back(&row);
        }
    }

    // Handle aggregates
    if (hasAggregate && sel.groupBy.empty()) {
        // Single aggregate over all matching rows
        std::vector<Value> resultRow;
        for (const auto& colExpr : sel.columns) {
            if (colExpr->type == ExprType::FunctionCall) {
                std::string fn = colExpr->funcName;
                if (fn == "COUNT") {
                    if (!colExpr->args.empty() && colExpr->args[0]->type == ExprType::ColumnRef &&
                        colExpr->args[0]->columnName == "*") {
                        resultRow.push_back(Value::makeInt(static_cast<long long>(matchingRows.size())));
                    } else if (!colExpr->args.empty()) {
                        long long count = 0;
                        for (const auto* row : matchingRows) {
                            auto v = evaluateExpr(colExpr->args[0], *row, table->columns, stmt->params);
                            if (v.type != ValueType::Null) ++count;
                        }
                        resultRow.push_back(Value::makeInt(count));
                    } else {
                        resultRow.push_back(Value::makeInt(static_cast<long long>(matchingRows.size())));
                    }
                } else if (fn == "SUM" || fn == "TOTAL") {
                    double sum = 0;
                    bool hasValue = false;
                    for (const auto* row : matchingRows) {
                        if (!colExpr->args.empty()) {
                            auto v = evaluateExpr(colExpr->args[0], *row, table->columns, stmt->params);
                            if (v.type != ValueType::Null) { sum += v.asReal(); hasValue = true; }
                        }
                    }
                    if (fn == "TOTAL" || hasValue) resultRow.push_back(Value::makeReal(sum));
                    else resultRow.push_back(Value::makeNull());
                } else if (fn == "AVG") {
                    double sum = 0;
                    long long count = 0;
                    for (const auto* row : matchingRows) {
                        if (!colExpr->args.empty()) {
                            auto v = evaluateExpr(colExpr->args[0], *row, table->columns, stmt->params);
                            if (v.type != ValueType::Null) { sum += v.asReal(); ++count; }
                        }
                    }
                    if (count > 0) resultRow.push_back(Value::makeReal(sum / static_cast<double>(count)));
                    else resultRow.push_back(Value::makeNull());
                } else if (fn == "MIN") {
                    Value minVal = Value::makeNull();
                    for (const auto* row : matchingRows) {
                        if (!colExpr->args.empty()) {
                            auto v = evaluateExpr(colExpr->args[0], *row, table->columns, stmt->params);
                            if (v.type != ValueType::Null && (minVal.type == ValueType::Null || v < minVal))
                                minVal = v;
                        }
                    }
                    resultRow.push_back(minVal);
                } else if (fn == "MAX") {
                    Value maxVal = Value::makeNull();
                    for (const auto* row : matchingRows) {
                        if (!colExpr->args.empty()) {
                            auto v = evaluateExpr(colExpr->args[0], *row, table->columns, stmt->params);
                            if (v.type != ValueType::Null && (maxVal.type == ValueType::Null || v > maxVal))
                                maxVal = v;
                        }
                    }
                    resultRow.push_back(maxVal);
                } else {
                    resultRow.push_back(Value::makeNull());
                }
            } else {
                // Non-aggregate column in aggregate query - use first row
                if (!matchingRows.empty()) {
                    resultRow.push_back(evaluateExpr(colExpr, *matchingRows[0], table->columns, stmt->params));
                } else {
                    resultRow.push_back(Value::makeNull());
                }
            }
        }
        stmt->resultRows.push_back(resultRow);
        return SQLITE_OK;
    }

    // ORDER BY
    if (!sel.orderBy.empty()) {
        std::sort(matchingRows.begin(), matchingRows.end(),
            [&](const Row* a, const Row* b) {
                for (const auto& ob : sel.orderBy) {
                    auto va = evaluateExpr(ob.expr, *a, table->columns, stmt->params);
                    auto vb = evaluateExpr(ob.expr, *b, table->columns, stmt->params);
                    if (ob.ascending) {
                        if (va < vb) return true;
                        if (vb < va) return false;
                    } else {
                        if (vb < va) return true;
                        if (va < vb) return false;
                    }
                }
                return false;
            });
    }

    // OFFSET and LIMIT
    size_t start = (sel.offset > 0) ? static_cast<size_t>(sel.offset) : 0;
    size_t count = matchingRows.size();
    if (sel.limit >= 0) {
        count = static_cast<size_t>(sel.limit);
    }

    // Build result rows
    for (size_t i = start; i < matchingRows.size() && (i - start) < count; ++i) {
        const auto& srcRow = *matchingRows[i];

        if (sel.selectAll || sel.columns.empty()) {
            stmt->resultRows.push_back(srcRow);
        } else {
            std::vector<Value> resultRow;
            for (const auto& colExpr : sel.columns) {
                if (colExpr->type == ExprType::ColumnRef && colExpr->columnName == "*") {
                    for (const auto& v : srcRow) resultRow.push_back(v);
                } else {
                    resultRow.push_back(evaluateExpr(colExpr, srcRow, table->columns, stmt->params));
                }
            }
            stmt->resultRows.push_back(resultRow);
        }
    }

    return SQLITE_OK;
}

static int executeInsert(sqlite3* db, sqlite3_stmt* stmt) {
    auto& ins = stmt->parsed.insert;
    Table* table = db->findTable(ins.tableName);
    if (!table) {
        db->lastError = "no such table: " + ins.tableName;
        db->lastErrCode = SQLITE_ERROR;
        return SQLITE_ERROR;
    }

    db->changes = 0;

    for (const auto& valueRow : ins.valueRows) {
        Row newRow(table->columns.size(), Value::makeNull());

        // Determine column mapping
        std::vector<int> colMapping;
        if (!ins.columnNames.empty()) {
            for (const auto& name : ins.columnNames) {
                int idx = table->findColumn(name);
                if (idx < 0) {
                    db->lastError = "table " + ins.tableName + " has no column named " + name;
                    db->lastErrCode = SQLITE_ERROR;
                    return SQLITE_ERROR;
                }
                colMapping.push_back(idx);
            }
        } else {
            for (int i = 0; i < static_cast<int>(table->columns.size()); ++i) {
                colMapping.push_back(i);
            }
        }

        // Evaluate and assign values
        for (size_t i = 0; i < valueRow.size() && i < colMapping.size(); ++i) {
            auto val = evaluateExpr(valueRow[i], {}, table->columns, stmt->params);
            newRow[static_cast<size_t>(colMapping[i])] = val;
        }

        // Handle auto-increment / INTEGER PRIMARY KEY
        int pkIdx = -1;
        for (int i = 0; i < static_cast<int>(table->columns.size()); ++i) {
            if (table->columns[static_cast<size_t>(i)].primaryKey) {
                pkIdx = i;
                break;
            }
        }

        if (pkIdx >= 0) {
            auto& pkVal = newRow[static_cast<size_t>(pkIdx)];
            const auto& pkCol = table->columns[static_cast<size_t>(pkIdx)];

            // Auto-assign rowid for INTEGER PRIMARY KEY if null
            if (pkVal.type == ValueType::Null &&
                (pkCol.typeName == "INTEGER" || pkCol.typeName == "INT")) {
                pkVal = Value::makeInt(table->nextRowId);
                table->nextRowId++;
            } else if (pkVal.type != ValueType::Null) {
                // Update nextRowId if needed
                long long pkIntVal = pkVal.asInt();
                if (pkIntVal >= table->nextRowId) {
                    table->nextRowId = pkIntVal + 1;
                }
                // Check for duplicate primary key
                for (const auto& existing : table->rows) {
                    if (static_cast<size_t>(pkIdx) < existing.size() &&
                        existing[static_cast<size_t>(pkIdx)].type != ValueType::Null &&
                        existing[static_cast<size_t>(pkIdx)].asInt() == pkIntVal) {
                        db->lastError = "UNIQUE constraint failed: " + table->columns[static_cast<size_t>(pkIdx)].name;
                        db->lastErrCode = SQLITE_CONSTRAINT;
                        return SQLITE_CONSTRAINT;
                    }
                }
            }
            db->lastInsertRowid = newRow[static_cast<size_t>(pkIdx)].asInt();
        } else {
            db->lastInsertRowid = table->nextRowId;
            table->nextRowId++;
        }

        // Check NOT NULL constraints
        for (size_t i = 0; i < table->columns.size(); ++i) {
            if (table->columns[i].notNull && !table->columns[i].primaryKey &&
                newRow[i].type == ValueType::Null) {
                db->lastError = "NOT NULL constraint failed: " + table->columns[i].name;
                db->lastErrCode = SQLITE_CONSTRAINT;
                return SQLITE_CONSTRAINT;
            }
        }

        table->rows.push_back(std::move(newRow));
        db->changes++;
    }

    return SQLITE_OK;
}

static int executeUpdate(sqlite3* db, sqlite3_stmt* stmt) {
    auto& upd = stmt->parsed.update;
    Table* table = db->findTable(upd.tableName);
    if (!table) {
        db->lastError = "no such table: " + upd.tableName;
        db->lastErrCode = SQLITE_ERROR;
        return SQLITE_ERROR;
    }

    db->changes = 0;

    for (auto& row : table->rows) {
        if (evaluateWhere(upd.whereClause, row, table->columns, stmt->params)) {
            for (const auto& [colName, expr] : upd.assignments) {
                int colIdx = table->findColumn(colName);
                if (colIdx >= 0) {
                    auto val = evaluateExpr(expr, row, table->columns, stmt->params);
                    // Check NOT NULL
                    if (table->columns[static_cast<size_t>(colIdx)].notNull && val.type == ValueType::Null) {
                        db->lastError = "NOT NULL constraint failed: " + colName;
                        db->lastErrCode = SQLITE_CONSTRAINT;
                        return SQLITE_CONSTRAINT;
                    }
                    row[static_cast<size_t>(colIdx)] = val;
                }
            }
            db->changes++;
        }
    }

    return SQLITE_OK;
}

static int executeDelete(sqlite3* db, sqlite3_stmt* stmt) {
    auto& del = stmt->parsed.del;
    Table* table = db->findTable(del.tableName);
    if (!table) {
        db->lastError = "no such table: " + del.tableName;
        db->lastErrCode = SQLITE_ERROR;
        return SQLITE_ERROR;
    }

    db->changes = 0;

    auto it = table->rows.begin();
    while (it != table->rows.end()) {
        if (evaluateWhere(del.whereClause, *it, table->columns, stmt->params)) {
            it = table->rows.erase(it);
            db->changes++;
        } else {
            ++it;
        }
    }

    return SQLITE_OK;
}

static int executeCreateTable(sqlite3* db, sqlite3_stmt* stmt) {
    auto& ct = stmt->parsed.createTable;
    std::string key = db->getTableKey(ct.tableName);

    if (db->tables.find(key) != db->tables.end()) {
        if (ct.ifNotExists) return SQLITE_OK;
        db->lastError = "table " + ct.tableName + " already exists";
        db->lastErrCode = SQLITE_ERROR;
        return SQLITE_ERROR;
    }

    Table table;
    table.name = ct.tableName;
    table.columns = ct.columns;

    // If there is an INTEGER PRIMARY KEY, ensure it's set up for autoincrement
    for (auto& col : table.columns) {
        if (col.primaryKey && (col.typeName == "INTEGER" || col.typeName == "INT")) {
            col.notNull = true; // PRIMARY KEY implies NOT NULL for INTEGER
        }
    }

    db->tables[key] = std::move(table);
    return SQLITE_OK;
}

static int executeDropTable(sqlite3* db, sqlite3_stmt* stmt) {
    auto& dt = stmt->parsed.dropTable;
    std::string key = db->getTableKey(dt.tableName);

    auto it = db->tables.find(key);
    if (it == db->tables.end()) {
        if (dt.ifExists) return SQLITE_OK;
        db->lastError = "no such table: " + dt.tableName;
        db->lastErrCode = SQLITE_ERROR;
        return SQLITE_ERROR;
    }

    db->tables.erase(it);
    return SQLITE_OK;
}

static int executePragma(sqlite3* db, sqlite3_stmt* stmt) {
    auto& pragma = stmt->parsed.pragma;
    std::string name = toUpper(pragma.name);

    // journal_mode - accept but no-op
    if (name == "JOURNAL_MODE") {
        // Return the mode as a result
        stmt->resultColumns = {"journal_mode"};
        std::string mode = pragma.value.empty() ? "wal" : pragma.value;
        for (auto& c : mode) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        stmt->resultRows.push_back({Value::makeText(mode)});
        return SQLITE_OK;
    }

    // foreign_keys
    if (name == "FOREIGN_KEYS") {
        if (!pragma.value.empty()) {
            db->foreignKeysEnabled = (pragma.value == "1" || toUpper(pragma.value) == "ON" || toUpper(pragma.value) == "TRUE");
        } else {
            stmt->resultColumns = {"foreign_keys"};
            stmt->resultRows.push_back({Value::makeInt(db->foreignKeysEnabled ? 1 : 0)});
        }
        return SQLITE_OK;
    }

    // table_info(tablename)
    if (name == "TABLE_INFO") {
        Table* table = db->findTable(pragma.value);
        if (table) {
            stmt->resultColumns = {"cid", "name", "type", "notnull", "dflt_value", "pk"};
            for (int i = 0; i < static_cast<int>(table->columns.size()); ++i) {
                const auto& col = table->columns[static_cast<size_t>(i)];
                std::vector<Value> row;
                row.push_back(Value::makeInt(i));
                row.push_back(Value::makeText(col.name));
                row.push_back(Value::makeText(col.typeName));
                row.push_back(Value::makeInt(col.notNull ? 1 : 0));
                row.push_back(Value::makeNull());
                row.push_back(Value::makeInt(col.primaryKey ? 1 : 0));
                stmt->resultRows.push_back(row);
            }
        }
        return SQLITE_OK;
    }

    // Other pragmas - accept silently
    return SQLITE_OK;
}

static int executeStmt(sqlite3* db, sqlite3_stmt* stmt) {
    switch (stmt->parsed.type) {
        case StmtType::Select:
            return executeSelect(db, stmt);
        case StmtType::Insert:
            return executeInsert(db, stmt);
        case StmtType::Update:
            return executeUpdate(db, stmt);
        case StmtType::Delete:
            return executeDelete(db, stmt);
        case StmtType::CreateTable:
            return executeCreateTable(db, stmt);
        case StmtType::DropTable:
            return executeDropTable(db, stmt);
        case StmtType::Pragma:
            return executePragma(db, stmt);
        case StmtType::Begin:
            if (!db->inTransaction) {
                db->inTransaction = true;
                db->snapshot = db->tables;
            }
            return SQLITE_OK;
        case StmtType::Commit:
            db->inTransaction = false;
            db->snapshot.clear();
            return SQLITE_OK;
        case StmtType::Rollback:
            if (db->inTransaction) {
                db->tables = db->snapshot;
                db->inTransaction = false;
                db->snapshot.clear();
            }
            return SQLITE_OK;
        case StmtType::Unknown:
            return SQLITE_OK;
    }
    return SQLITE_OK;
}

// ============================================================================
// File Persistence
// ============================================================================

static const char MAGIC[] = "TODB0001";

static void saveToFile(sqlite3* db) {
    if (db->filePath.empty() || db->filePath == ":memory:") return;

    std::ofstream out(db->filePath, std::ios::binary);
    if (!out.is_open()) return;

    // Write magic
    out.write(MAGIC, 8);

    // Write number of tables
    auto tableCount = static_cast<uint32_t>(db->tables.size());
    out.write(reinterpret_cast<const char*>(&tableCount), 4);

    for (const auto& [key, table] : db->tables) {
        // Table name
        auto nameLen = static_cast<uint32_t>(table.name.size());
        out.write(reinterpret_cast<const char*>(&nameLen), 4);
        out.write(table.name.c_str(), static_cast<std::streamsize>(nameLen));

        // Next rowid
        out.write(reinterpret_cast<const char*>(&table.nextRowId), 8);

        // Column count
        auto colCount = static_cast<uint32_t>(table.columns.size());
        out.write(reinterpret_cast<const char*>(&colCount), 4);

        for (const auto& col : table.columns) {
            // Column name
            auto cnLen = static_cast<uint32_t>(col.name.size());
            out.write(reinterpret_cast<const char*>(&cnLen), 4);
            out.write(col.name.c_str(), static_cast<std::streamsize>(cnLen));
            // Type name
            auto tnLen = static_cast<uint32_t>(col.typeName.size());
            out.write(reinterpret_cast<const char*>(&tnLen), 4);
            out.write(col.typeName.c_str(), static_cast<std::streamsize>(tnLen));
            // Flags
            uint8_t flags = 0;
            if (col.primaryKey) flags |= 1;
            if (col.notNull) flags |= 2;
            if (col.autoIncrement) flags |= 4;
            out.write(reinterpret_cast<const char*>(&flags), 1);
        }

        // Row count
        auto rowCount = static_cast<uint32_t>(table.rows.size());
        out.write(reinterpret_cast<const char*>(&rowCount), 4);

        for (const auto& row : table.rows) {
            for (size_t i = 0; i < table.columns.size(); ++i) {
                const Value& val = (i < row.size()) ? row[i] : Value{};
                auto vtype = static_cast<uint8_t>(val.type);
                out.write(reinterpret_cast<const char*>(&vtype), 1);

                switch (val.type) {
                    case ValueType::Null: break;
                    case ValueType::Integer:
                        out.write(reinterpret_cast<const char*>(&val.intVal), 8);
                        break;
                    case ValueType::Real:
                        out.write(reinterpret_cast<const char*>(&val.realVal), 8);
                        break;
                    case ValueType::Text: {
                        auto tLen = static_cast<uint32_t>(val.textVal.size());
                        out.write(reinterpret_cast<const char*>(&tLen), 4);
                        out.write(val.textVal.c_str(), static_cast<std::streamsize>(tLen));
                        break;
                    }
                    case ValueType::Blob: {
                        auto bLen = static_cast<uint32_t>(val.blobVal.size());
                        out.write(reinterpret_cast<const char*>(&bLen), 4);
                        out.write(reinterpret_cast<const char*>(val.blobVal.data()), static_cast<std::streamsize>(bLen));
                        break;
                    }
                }
            }
        }
    }
}

static void loadFromFile(sqlite3* db) {
    if (db->filePath.empty() || db->filePath == ":memory:") return;

    std::ifstream in(db->filePath, std::ios::binary);
    if (!in.is_open()) return;

    // Read and check magic
    char magic[8];
    in.read(magic, 8);
    if (!in.good() || memcmp(magic, MAGIC, 8) != 0) return;

    uint32_t tableCount = 0;
    in.read(reinterpret_cast<char*>(&tableCount), 4);
    if (!in.good()) return;

    for (uint32_t t = 0; t < tableCount && in.good(); ++t) {
        Table table;

        // Table name
        uint32_t nameLen = 0;
        in.read(reinterpret_cast<char*>(&nameLen), 4);
        if (!in.good() || nameLen > 10000) return;
        table.name.resize(nameLen);
        in.read(&table.name[0], static_cast<std::streamsize>(nameLen));

        // Next rowid
        in.read(reinterpret_cast<char*>(&table.nextRowId), 8);

        // Column count
        uint32_t colCount = 0;
        in.read(reinterpret_cast<char*>(&colCount), 4);
        if (!in.good() || colCount > 10000) return;

        for (uint32_t c = 0; c < colCount && in.good(); ++c) {
            ColumnDef col;
            uint32_t cnLen = 0;
            in.read(reinterpret_cast<char*>(&cnLen), 4);
            if (!in.good() || cnLen > 10000) return;
            col.name.resize(cnLen);
            in.read(&col.name[0], static_cast<std::streamsize>(cnLen));

            uint32_t tnLen = 0;
            in.read(reinterpret_cast<char*>(&tnLen), 4);
            if (!in.good() || tnLen > 10000) return;
            col.typeName.resize(tnLen);
            in.read(&col.typeName[0], static_cast<std::streamsize>(tnLen));

            uint8_t flags = 0;
            in.read(reinterpret_cast<char*>(&flags), 1);
            col.primaryKey = (flags & 1) != 0;
            col.notNull = (flags & 2) != 0;
            col.autoIncrement = (flags & 4) != 0;

            table.columns.push_back(col);
        }

        // Row count
        uint32_t rowCount = 0;
        in.read(reinterpret_cast<char*>(&rowCount), 4);
        if (!in.good()) return;

        for (uint32_t r = 0; r < rowCount && in.good(); ++r) {
            Row row;
            row.reserve(colCount);
            for (uint32_t c = 0; c < colCount && in.good(); ++c) {
                uint8_t vtype = 0;
                in.read(reinterpret_cast<char*>(&vtype), 1);
                Value val;
                val.type = static_cast<ValueType>(vtype);

                switch (val.type) {
                    case ValueType::Null: break;
                    case ValueType::Integer:
                        in.read(reinterpret_cast<char*>(&val.intVal), 8);
                        break;
                    case ValueType::Real:
                        in.read(reinterpret_cast<char*>(&val.realVal), 8);
                        break;
                    case ValueType::Text: {
                        uint32_t tLen = 0;
                        in.read(reinterpret_cast<char*>(&tLen), 4);
                        if (!in.good() || tLen > 100000000) return;
                        val.textVal.resize(tLen);
                        in.read(&val.textVal[0], static_cast<std::streamsize>(tLen));
                        break;
                    }
                    case ValueType::Blob: {
                        uint32_t bLen = 0;
                        in.read(reinterpret_cast<char*>(&bLen), 4);
                        if (!in.good() || bLen > 100000000) return;
                        val.blobVal.resize(bLen);
                        in.read(reinterpret_cast<char*>(val.blobVal.data()), static_cast<std::streamsize>(bLen));
                        break;
                    }
                }
                row.push_back(val);
            }
            table.rows.push_back(std::move(row));
        }

        std::string key = db->getTableKey(table.name);
        db->tables[key] = std::move(table);
    }
}

// Count parameters in SQL
static int countParams(const std::string& sql) {
    int count = 0;
    bool inString = false;
    for (size_t i = 0; i < sql.size(); ++i) {
        if (sql[i] == '\'') {
            inString = !inString;
            if (inString && i + 1 < sql.size() && sql[i + 1] == '\'') {
                ++i; // escaped quote
                inString = !inString;
            }
        } else if (!inString && sql[i] == '?') {
            ++count;
        }
    }
    return count;
}

} // end anonymous namespace

// ============================================================================
// Public C API Implementation
// ============================================================================

extern "C" {

int sqlite3_open(const char* filename, sqlite3** ppDb) {
    return sqlite3_open_v2(filename, ppDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
}

int sqlite3_open_v2(const char* filename, sqlite3** ppDb, int /*flags*/, const char* /*zVfs*/) {
    if (!ppDb) return SQLITE_MISUSE;

    auto* db = new (std::nothrow) sqlite3;
    if (!db) {
        *ppDb = nullptr;
        return SQLITE_NOMEM;
    }

    db->filePath = filename ? filename : "";
    db->isOpen = true;
    db->lastError = "";
    db->lastErrCode = SQLITE_OK;

    // Load existing data from file
    loadFromFile(db);

    *ppDb = db;
    return SQLITE_OK;
}

int sqlite3_close(sqlite3* db) {
    return sqlite3_close_v2(db);
}

int sqlite3_close_v2(sqlite3* db) {
    if (!db) return SQLITE_OK;

    {
        std::lock_guard<std::mutex> lock(db->mutex);
        saveToFile(db);
        db->isOpen = false;
    }

    delete db;
    return SQLITE_OK;
}

const char* sqlite3_errmsg(sqlite3* db) {
    if (!db) return "not an error";
    // No lock needed for read of atomic-like string in single-threaded error context
    if (db->lastError.empty()) return "not an error";
    return db->lastError.c_str();
}

int sqlite3_errcode(sqlite3* db) {
    if (!db) return SQLITE_OK;
    return db->lastErrCode;
}

int sqlite3_extended_errcode(sqlite3* db) {
    if (!db) return SQLITE_OK;
    return db->lastErrCode;
}

int sqlite3_exec(
    sqlite3* db,
    const char* sql,
    sqlite3_callback callback,
    void* callbackArg,
    char** errmsg
) {
    if (errmsg) *errmsg = nullptr;
    if (!db || !sql) return SQLITE_MISUSE;

    std::lock_guard<std::mutex> lock(db->mutex);
    db->lastErrCode = SQLITE_OK;
    db->lastError = "";

    // Handle multiple statements separated by semicolons
    std::string sqlStr(sql);
    size_t pos = 0;

    while (pos < sqlStr.size()) {
        // Skip whitespace and semicolons
        while (pos < sqlStr.size() && (isspace(static_cast<unsigned char>(sqlStr[pos])) || sqlStr[pos] == ';')) ++pos;
        if (pos >= sqlStr.size()) break;

        // Find end of statement
        size_t end = pos;
        bool inStr = false;
        while (end < sqlStr.size()) {
            if (sqlStr[end] == '\'') inStr = !inStr;
            else if (!inStr && sqlStr[end] == ';') break;
            ++end;
        }

        std::string stmtStr = sqlStr.substr(pos, end - pos);
        pos = end + 1;

        if (stmtStr.empty()) continue;

        // Tokenize and parse
        auto tokens = tokenize(stmtStr);
        Parser parser(tokens);
        auto parsed = parser.parse();

        // Create a temporary stmt for execution
        sqlite3_stmt tempStmt;
        tempStmt.db = db;
        tempStmt.parsed = parsed;
        tempStmt.sql = stmtStr;

        int rc = executeStmt(db, &tempStmt);
        if (rc != SQLITE_OK) {
            if (errmsg) {
                *errmsg = static_cast<char*>(malloc(db->lastError.size() + 1));
                if (*errmsg) {
                    strcpy(*errmsg, db->lastError.c_str());
                }
            }
            return rc;
        }

        // Call callback for SELECT results
        if (callback && !tempStmt.resultRows.empty()) {
            int colCount = static_cast<int>(tempStmt.resultColumns.size());
            for (const auto& row : tempStmt.resultRows) {
                std::vector<char*> values(static_cast<size_t>(colCount), nullptr);
                std::vector<char*> names(static_cast<size_t>(colCount), nullptr);
                std::vector<std::string> valStrs(static_cast<size_t>(colCount));
                std::vector<std::string> nameStrs(static_cast<size_t>(colCount));

                for (int i = 0; i < colCount; ++i) {
                    nameStrs[static_cast<size_t>(i)] = tempStmt.resultColumns[static_cast<size_t>(i)];
                    names[static_cast<size_t>(i)] = &nameStrs[static_cast<size_t>(i)][0];
                    if (static_cast<size_t>(i) < row.size() && row[static_cast<size_t>(i)].type != ValueType::Null) {
                        valStrs[static_cast<size_t>(i)] = row[static_cast<size_t>(i)].asText();
                        values[static_cast<size_t>(i)] = &valStrs[static_cast<size_t>(i)][0];
                    }
                }

                int cbRc = callback(callbackArg, colCount, values.data(), names.data());
                if (cbRc != 0) {
                    db->lastError = "callback requested abort";
                    db->lastErrCode = SQLITE_ABORT;
                    return SQLITE_ABORT;
                }
            }
        }
    }

    return SQLITE_OK;
}

int sqlite3_prepare_v2(
    sqlite3* db,
    const char* zSql,
    int nByte,
    sqlite3_stmt** ppStmt,
    const char** pzTail
) {
    if (!db || !ppStmt) return SQLITE_MISUSE;
    *ppStmt = nullptr;
    if (pzTail) *pzTail = nullptr;

    if (!zSql) return SQLITE_OK;

    std::string sql;
    if (nByte < 0) {
        sql = zSql;
    } else {
        sql.assign(zSql, static_cast<size_t>(nByte));
    }

    // Remove trailing whitespace and semicolons for tail tracking
    // Find first statement
    size_t endPos = 0;
    bool inStr = false;
    for (size_t i = 0; i < sql.size(); ++i) {
        if (sql[i] == '\'') inStr = !inStr;
        else if (!inStr && sql[i] == ';') { endPos = i + 1; break; }
    }
    if (endPos == 0) endPos = sql.size();

    std::string firstStmt = sql.substr(0, endPos);

    // Set tail pointer
    if (pzTail) {
        if (endPos < sql.size()) {
            *pzTail = zSql + endPos;
        } else {
            *pzTail = zSql + sql.size();
        }
    }

    // Skip empty statements
    bool allSpace = true;
    for (char c : firstStmt) {
        if (!isspace(static_cast<unsigned char>(c)) && c != ';') { allSpace = false; break; }
    }
    if (allSpace) return SQLITE_OK;

    std::lock_guard<std::mutex> lock(db->mutex);

    auto tokens = tokenize(firstStmt);
    Parser parser(tokens);
    auto parsed = parser.parse();

    auto* stmt = new (std::nothrow) sqlite3_stmt;
    if (!stmt) return SQLITE_NOMEM;

    stmt->db = db;
    stmt->parsed = parsed;
    stmt->sql = firstStmt;
    stmt->paramCount = countParams(firstStmt);
    stmt->params.resize(static_cast<size_t>(stmt->paramCount), Value::makeNull());
    stmt->currentRow = -1;
    stmt->executed = false;
    stmt->done = false;

    *ppStmt = stmt;
    return SQLITE_OK;
}

int sqlite3_step(sqlite3_stmt* stmt) {
    if (!stmt || !stmt->db) return SQLITE_MISUSE;

    std::lock_guard<std::mutex> lock(stmt->db->mutex);

    if (stmt->done) return SQLITE_DONE;

    if (!stmt->executed) {
        stmt->db->lastErrCode = SQLITE_OK;
        stmt->db->lastError = "";
        stmt->db->changes = 0;
        stmt->resultRows.clear();
        stmt->resultColumns.clear();

        int rc = executeStmt(stmt->db, stmt);
        if (rc != SQLITE_OK) {
            stmt->done = true;
            return rc;
        }
        stmt->executed = true;
        stmt->currentRow = -1;
    }

    // For SELECT/PRAGMA with results, return one row at a time
    if (!stmt->resultRows.empty()) {
        stmt->currentRow++;
        if (stmt->currentRow < static_cast<int>(stmt->resultRows.size())) {
            return SQLITE_ROW;
        }
        stmt->done = true;
        return SQLITE_DONE;
    }

    stmt->done = true;
    return SQLITE_DONE;
}

int sqlite3_reset(sqlite3_stmt* stmt) {
    if (!stmt) return SQLITE_MISUSE;
    stmt->currentRow = -1;
    stmt->executed = false;
    stmt->done = false;
    stmt->resultRows.clear();
    stmt->resultColumns.clear();
    return SQLITE_OK;
}

int sqlite3_finalize(sqlite3_stmt* stmt) {
    if (!stmt) return SQLITE_OK;
    delete stmt;
    return SQLITE_OK;
}

// ============================================================================
// Binding Functions
// ============================================================================

int sqlite3_bind_int(sqlite3_stmt* stmt, int index, int value) {
    if (!stmt || index < 1 || index > stmt->paramCount) return SQLITE_RANGE;
    stmt->params[static_cast<size_t>(index - 1)] = Value::makeInt(value);
    return SQLITE_OK;
}

int sqlite3_bind_int64(sqlite3_stmt* stmt, int index, sqlite3_int64 value) {
    if (!stmt || index < 1 || index > stmt->paramCount) return SQLITE_RANGE;
    stmt->params[static_cast<size_t>(index - 1)] = Value::makeInt(value);
    return SQLITE_OK;
}

int sqlite3_bind_double(sqlite3_stmt* stmt, int index, double value) {
    if (!stmt || index < 1 || index > stmt->paramCount) return SQLITE_RANGE;
    stmt->params[static_cast<size_t>(index - 1)] = Value::makeReal(value);
    return SQLITE_OK;
}

int sqlite3_bind_text(sqlite3_stmt* stmt, int index, const char* value, int nBytes, void(*destructor)(void*)) {
    if (!stmt || index < 1 || index > stmt->paramCount) return SQLITE_RANGE;
    if (!value) {
        stmt->params[static_cast<size_t>(index - 1)] = Value::makeNull();
    } else {
        std::string text;
        if (nBytes < 0) text = value;
        else text.assign(value, static_cast<size_t>(nBytes));
        stmt->params[static_cast<size_t>(index - 1)] = Value::makeText(text);
    }
    // If SQLITE_TRANSIENT, we already copied. If a real destructor, call it.
    if (destructor && destructor != reinterpret_cast<void(*)(void*)>(-1) &&
        destructor != reinterpret_cast<void(*)(void*)>(0) && value) {
        destructor(const_cast<void*>(static_cast<const void*>(value)));
    }
    return SQLITE_OK;
}

int sqlite3_bind_blob(sqlite3_stmt* stmt, int index, const void* value, int nBytes, void(*destructor)(void*)) {
    if (!stmt || index < 1 || index > stmt->paramCount) return SQLITE_RANGE;
    if (!value || nBytes <= 0) {
        stmt->params[static_cast<size_t>(index - 1)] = Value::makeNull();
    } else {
        auto* bytes = static_cast<const unsigned char*>(value);
        std::vector<unsigned char> blob(bytes, bytes + nBytes);
        stmt->params[static_cast<size_t>(index - 1)] = Value::makeBlob(blob);
    }
    if (destructor && destructor != reinterpret_cast<void(*)(void*)>(-1) &&
        destructor != reinterpret_cast<void(*)(void*)>(0) && value) {
        destructor(const_cast<void*>(value));
    }
    return SQLITE_OK;
}

int sqlite3_bind_null(sqlite3_stmt* stmt, int index) {
    if (!stmt || index < 1 || index > stmt->paramCount) return SQLITE_RANGE;
    stmt->params[static_cast<size_t>(index - 1)] = Value::makeNull();
    return SQLITE_OK;
}

int sqlite3_bind_parameter_count(sqlite3_stmt* stmt) {
    if (!stmt) return 0;
    return stmt->paramCount;
}

// ============================================================================
// Column Value Extraction
// ============================================================================

int sqlite3_column_count(sqlite3_stmt* stmt) {
    if (!stmt) return 0;
    return static_cast<int>(stmt->resultColumns.size());
}

int sqlite3_column_type(sqlite3_stmt* stmt, int col) {
    if (!stmt || stmt->currentRow < 0 ||
        stmt->currentRow >= static_cast<int>(stmt->resultRows.size())) return SQLITE_NULL;
    const auto& row = stmt->resultRows[static_cast<size_t>(stmt->currentRow)];
    if (col < 0 || static_cast<size_t>(col) >= row.size()) return SQLITE_NULL;
    return row[static_cast<size_t>(col)].sqliteType();
}

int sqlite3_column_int(sqlite3_stmt* stmt, int col) {
    if (!stmt || stmt->currentRow < 0 ||
        stmt->currentRow >= static_cast<int>(stmt->resultRows.size())) return 0;
    const auto& row = stmt->resultRows[static_cast<size_t>(stmt->currentRow)];
    if (col < 0 || static_cast<size_t>(col) >= row.size()) return 0;
    return static_cast<int>(row[static_cast<size_t>(col)].asInt());
}

sqlite3_int64 sqlite3_column_int64(sqlite3_stmt* stmt, int col) {
    if (!stmt || stmt->currentRow < 0 ||
        stmt->currentRow >= static_cast<int>(stmt->resultRows.size())) return 0;
    const auto& row = stmt->resultRows[static_cast<size_t>(stmt->currentRow)];
    if (col < 0 || static_cast<size_t>(col) >= row.size()) return 0;
    return row[static_cast<size_t>(col)].asInt();
}

double sqlite3_column_double(sqlite3_stmt* stmt, int col) {
    if (!stmt || stmt->currentRow < 0 ||
        stmt->currentRow >= static_cast<int>(stmt->resultRows.size())) return 0.0;
    const auto& row = stmt->resultRows[static_cast<size_t>(stmt->currentRow)];
    if (col < 0 || static_cast<size_t>(col) >= row.size()) return 0.0;
    return row[static_cast<size_t>(col)].asReal();
}

const unsigned char* sqlite3_column_text(sqlite3_stmt* stmt, int col) {
    if (!stmt || stmt->currentRow < 0 ||
        stmt->currentRow >= static_cast<int>(stmt->resultRows.size()))
        return reinterpret_cast<const unsigned char*>("");
    auto& row = stmt->resultRows[static_cast<size_t>(stmt->currentRow)];
    if (col < 0 || static_cast<size_t>(col) >= row.size())
        return reinterpret_cast<const unsigned char*>("");
    auto& val = row[static_cast<size_t>(col)];
    if (val.type == ValueType::Null) return nullptr;
    // Ensure textVal is populated for non-text types
    if (val.type != ValueType::Text && val.type != ValueType::Blob) {
        val.textVal = val.asText();
    }
    return reinterpret_cast<const unsigned char*>(val.textVal.c_str());
}

const void* sqlite3_column_blob(sqlite3_stmt* stmt, int col) {
    if (!stmt || stmt->currentRow < 0 ||
        stmt->currentRow >= static_cast<int>(stmt->resultRows.size())) return nullptr;
    const auto& row = stmt->resultRows[static_cast<size_t>(stmt->currentRow)];
    if (col < 0 || static_cast<size_t>(col) >= row.size()) return nullptr;
    const auto& val = row[static_cast<size_t>(col)];
    if (val.type == ValueType::Null) return nullptr;
    if (val.type == ValueType::Blob) {
        if (val.blobVal.empty()) return nullptr;
        return val.blobVal.data();
    }
    // For other types, return text representation as blob
    return val.textVal.c_str();
}

int sqlite3_column_bytes(sqlite3_stmt* stmt, int col) {
    if (!stmt || stmt->currentRow < 0 ||
        stmt->currentRow >= static_cast<int>(stmt->resultRows.size())) return 0;
    const auto& row = stmt->resultRows[static_cast<size_t>(stmt->currentRow)];
    if (col < 0 || static_cast<size_t>(col) >= row.size()) return 0;
    const auto& val = row[static_cast<size_t>(col)];
    if (val.type == ValueType::Blob) return static_cast<int>(val.blobVal.size());
    if (val.type == ValueType::Text) return static_cast<int>(val.textVal.size());
    if (val.type == ValueType::Null) return 0;
    return static_cast<int>(val.asText().size());
}

const char* sqlite3_column_name(sqlite3_stmt* stmt, int col) {
    if (!stmt || col < 0 || static_cast<size_t>(col) >= stmt->resultColumns.size()) return "";
    return stmt->resultColumns[static_cast<size_t>(col)].c_str();
}

// ============================================================================
// Utility Functions
// ============================================================================

sqlite3_int64 sqlite3_last_insert_rowid(sqlite3* db) {
    if (!db) return 0;
    return db->lastInsertRowid;
}

int sqlite3_changes(sqlite3* db) {
    if (!db) return 0;
    return db->changes;
}

void sqlite3_free(void* ptr) {
    free(ptr);
}

} // extern "C"
