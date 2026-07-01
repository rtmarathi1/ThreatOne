// SQLite3 stub implementation for ThreatOne
// Provides minimal stub functions that return error codes.
// This allows linking to succeed without a real SQLite library.
// In production, this would be replaced by the actual sqlite3 amalgamation.

#include "sqlite3.h"
#include <cstdlib>
#include <cstring>

// Internal stub state
static const char* stub_errmsg = "SQLite stub: not implemented";

// Database connection management
int sqlite3_open(const char* /*filename*/, sqlite3** ppDb) {
    *ppDb = nullptr;
    return SQLITE_OK;
}

int sqlite3_open_v2(const char* /*filename*/, sqlite3** ppDb, int /*flags*/, const char* /*zVfs*/) {
    *ppDb = nullptr;
    return SQLITE_OK;
}

int sqlite3_close(sqlite3* /*db*/) {
    return SQLITE_OK;
}

int sqlite3_close_v2(sqlite3* /*db*/) {
    return SQLITE_OK;
}

// Error information
const char* sqlite3_errmsg(sqlite3* /*db*/) {
    return stub_errmsg;
}

int sqlite3_errcode(sqlite3* /*db*/) {
    return SQLITE_OK;
}

int sqlite3_extended_errcode(sqlite3* /*db*/) {
    return SQLITE_OK;
}

// Execute SQL directly
int sqlite3_exec(
    sqlite3* /*db*/,
    const char* /*sql*/,
    sqlite3_callback /*callback*/,
    void* /*callbackArg*/,
    char** errmsg
) {
    if (errmsg) {
        *errmsg = nullptr;
    }
    return SQLITE_OK;
}

// Prepared statements
int sqlite3_prepare_v2(
    sqlite3* /*db*/,
    const char* /*zSql*/,
    int /*nByte*/,
    sqlite3_stmt** ppStmt,
    const char** /*pzTail*/
) {
    *ppStmt = nullptr;
    return SQLITE_OK;
}

int sqlite3_step(sqlite3_stmt* /*stmt*/) {
    return SQLITE_DONE;
}

int sqlite3_reset(sqlite3_stmt* /*stmt*/) {
    return SQLITE_OK;
}

int sqlite3_finalize(sqlite3_stmt* /*stmt*/) {
    return SQLITE_OK;
}

// Binding values
int sqlite3_bind_int(sqlite3_stmt* /*stmt*/, int /*index*/, int /*value*/) {
    return SQLITE_OK;
}

int sqlite3_bind_int64(sqlite3_stmt* /*stmt*/, int /*index*/, sqlite3_int64 /*value*/) {
    return SQLITE_OK;
}

int sqlite3_bind_double(sqlite3_stmt* /*stmt*/, int /*index*/, double /*value*/) {
    return SQLITE_OK;
}

int sqlite3_bind_text(sqlite3_stmt* /*stmt*/, int /*index*/, const char* /*value*/, int /*nBytes*/, void(*/*destructor*/)(void*)) {
    return SQLITE_OK;
}

int sqlite3_bind_blob(sqlite3_stmt* /*stmt*/, int /*index*/, const void* /*value*/, int /*nBytes*/, void(*/*destructor*/)(void*)) {
    return SQLITE_OK;
}

int sqlite3_bind_null(sqlite3_stmt* /*stmt*/, int /*index*/) {
    return SQLITE_OK;
}

int sqlite3_bind_parameter_count(sqlite3_stmt* /*stmt*/) {
    return 0;
}

// Column value extraction
int sqlite3_column_count(sqlite3_stmt* /*stmt*/) {
    return 0;
}

int sqlite3_column_type(sqlite3_stmt* /*stmt*/, int /*col*/) {
    return SQLITE_NULL;
}

int sqlite3_column_int(sqlite3_stmt* /*stmt*/, int /*col*/) {
    return 0;
}

sqlite3_int64 sqlite3_column_int64(sqlite3_stmt* /*stmt*/, int /*col*/) {
    return 0;
}

double sqlite3_column_double(sqlite3_stmt* /*stmt*/, int /*col*/) {
    return 0.0;
}

const unsigned char* sqlite3_column_text(sqlite3_stmt* /*stmt*/, int /*col*/) {
    return reinterpret_cast<const unsigned char*>("");
}

const void* sqlite3_column_blob(sqlite3_stmt* /*stmt*/, int /*col*/) {
    return nullptr;
}

int sqlite3_column_bytes(sqlite3_stmt* /*stmt*/, int /*col*/) {
    return 0;
}

const char* sqlite3_column_name(sqlite3_stmt* /*stmt*/, int /*col*/) {
    return "";
}

// Utility
sqlite3_int64 sqlite3_last_insert_rowid(sqlite3* /*db*/) {
    return 0;
}

int sqlite3_changes(sqlite3* /*db*/) {
    return 0;
}

void sqlite3_free(void* ptr) {
    free(ptr);
}
