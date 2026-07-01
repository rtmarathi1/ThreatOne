#pragma once

// SQLite3 stub header for ThreatOne compilation
// Provides type definitions and function declarations without implementation.
// This allows the database layer to compile against the SQLite API.

#ifdef __cplusplus
extern "C" {
#endif

// Opaque types
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef struct sqlite3_value sqlite3_value;

// Result codes
#define SQLITE_OK           0   // Successful result
#define SQLITE_ERROR        1   // Generic error
#define SQLITE_INTERNAL     2   // Internal logic error
#define SQLITE_PERM         3   // Access permission denied
#define SQLITE_ABORT        4   // Callback routine requested abort
#define SQLITE_BUSY         5   // Database file is locked
#define SQLITE_LOCKED       6   // Table in the database is locked
#define SQLITE_NOMEM        7   // malloc() failed
#define SQLITE_READONLY     8   // Attempt to write a readonly database
#define SQLITE_INTERRUPT    9   // Operation terminated by interrupt
#define SQLITE_IOERR       10   // Some kind of disk I/O error
#define SQLITE_CORRUPT     11   // Database disk image is malformed
#define SQLITE_NOTFOUND    12   // Unknown opcode
#define SQLITE_FULL        13   // Insertion failed because database is full
#define SQLITE_CANTOPEN    14   // Unable to open database file
#define SQLITE_PROTOCOL    15   // Database lock protocol error
#define SQLITE_EMPTY       16   // Internal use only
#define SQLITE_SCHEMA      17   // Database schema changed
#define SQLITE_TOOBIG      18   // String or BLOB exceeds size limit
#define SQLITE_CONSTRAINT  19   // Abort due to constraint violation
#define SQLITE_MISMATCH    20   // Data type mismatch
#define SQLITE_MISUSE      21   // Library used incorrectly
#define SQLITE_NOLFS       22   // Uses OS features not supported on host
#define SQLITE_AUTH        23   // Authorization denied
#define SQLITE_FORMAT      24   // Not used
#define SQLITE_RANGE       25   // 2nd parameter to sqlite3_bind out of range
#define SQLITE_NOTADB      26   // File opened that is not a database file
#define SQLITE_ROW        100   // sqlite3_step() has another row ready
#define SQLITE_DONE       101   // sqlite3_step() has finished executing

// Column types
#define SQLITE_INTEGER  1
#define SQLITE_FLOAT    2
#define SQLITE_BLOB     4
#define SQLITE_NULL     5
#define SQLITE_TEXT     3

// Fundamental datatypes
typedef long long int sqlite3_int64;
typedef unsigned long long int sqlite3_uint64;

// Callback type for sqlite3_exec
typedef int (*sqlite3_callback)(void*, int, char**, char**);

// Database connection management
int sqlite3_open(const char* filename, sqlite3** ppDb);
int sqlite3_open_v2(const char* filename, sqlite3** ppDb, int flags, const char* zVfs);
int sqlite3_close(sqlite3* db);
int sqlite3_close_v2(sqlite3* db);

// Error information
const char* sqlite3_errmsg(sqlite3* db);
int sqlite3_errcode(sqlite3* db);
int sqlite3_extended_errcode(sqlite3* db);

// Execute SQL directly
int sqlite3_exec(
    sqlite3* db,
    const char* sql,
    sqlite3_callback callback,
    void* callbackArg,
    char** errmsg
);

// Prepared statements
int sqlite3_prepare_v2(
    sqlite3* db,
    const char* zSql,
    int nByte,
    sqlite3_stmt** ppStmt,
    const char** pzTail
);

int sqlite3_step(sqlite3_stmt* stmt);
int sqlite3_reset(sqlite3_stmt* stmt);
int sqlite3_finalize(sqlite3_stmt* stmt);

// Binding values to prepared statements
int sqlite3_bind_int(sqlite3_stmt* stmt, int index, int value);
int sqlite3_bind_int64(sqlite3_stmt* stmt, int index, sqlite3_int64 value);
int sqlite3_bind_double(sqlite3_stmt* stmt, int index, double value);
int sqlite3_bind_text(sqlite3_stmt* stmt, int index, const char* value, int nBytes, void(*destructor)(void*));
int sqlite3_bind_blob(sqlite3_stmt* stmt, int index, const void* value, int nBytes, void(*destructor)(void*));
int sqlite3_bind_null(sqlite3_stmt* stmt, int index);
int sqlite3_bind_parameter_count(sqlite3_stmt* stmt);

// Extracting column values from results
int sqlite3_column_count(sqlite3_stmt* stmt);
int sqlite3_column_type(sqlite3_stmt* stmt, int col);
int sqlite3_column_int(sqlite3_stmt* stmt, int col);
sqlite3_int64 sqlite3_column_int64(sqlite3_stmt* stmt, int col);
double sqlite3_column_double(sqlite3_stmt* stmt, int col);
const unsigned char* sqlite3_column_text(sqlite3_stmt* stmt, int col);
const void* sqlite3_column_blob(sqlite3_stmt* stmt, int col);
int sqlite3_column_bytes(sqlite3_stmt* stmt, int col);
const char* sqlite3_column_name(sqlite3_stmt* stmt, int col);

// Utility
sqlite3_int64 sqlite3_last_insert_rowid(sqlite3* db);
int sqlite3_changes(sqlite3* db);
void sqlite3_free(void* ptr);

// Memory management constants for bind functions
#define SQLITE_STATIC      ((void(*)(void*))0)
#define SQLITE_TRANSIENT   ((void(*)(void*))-1)

// Open flags
#define SQLITE_OPEN_READONLY         0x00000001
#define SQLITE_OPEN_READWRITE        0x00000002
#define SQLITE_OPEN_CREATE           0x00000004
#define SQLITE_OPEN_NOMUTEX          0x00008000
#define SQLITE_OPEN_FULLMUTEX        0x00010000
#define SQLITE_OPEN_SHAREDCACHE      0x00020000
#define SQLITE_OPEN_PRIVATECACHE     0x00040000
#define SQLITE_OPEN_URI              0x00000040

#ifdef __cplusplus
} // extern "C"
#endif
