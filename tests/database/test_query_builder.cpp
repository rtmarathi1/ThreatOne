#include <doctest/doctest.h>
#include <database/QueryBuilder.h>
#include <string>
#include <vector>

using namespace ThreatOne::Database;

TEST_CASE("QueryBuilder SELECT") {
    SUBCASE("Simple select all columns") {
        auto query = QueryBuilder::select("users").build();
        CHECK(query.sql == "SELECT * FROM users");
        CHECK(query.params.empty());
    }

    SUBCASE("Select specific columns") {
        auto query = QueryBuilder::select("users")
            .columns({"id", "name", "email"})
            .build();
        CHECK(query.sql == "SELECT id, name, email FROM users");
    }

    SUBCASE("Select with single column") {
        auto query = QueryBuilder::select("users")
            .column("name")
            .build();
        CHECK(query.sql == "SELECT name FROM users");
    }

    SUBCASE("Select distinct") {
        auto query = QueryBuilder::select("users")
            .column("status")
            .distinct()
            .build();
        CHECK(query.sql == "SELECT DISTINCT status FROM users");
    }

    SUBCASE("Select with WHERE clause") {
        auto query = QueryBuilder::select("users")
            .where("id", BoundParam::integer(1))
            .build();
        CHECK(query.sql == "SELECT * FROM users WHERE id = ?");
        REQUIRE(query.params.size() == 1);
        CHECK(query.params[0].intValue == 1);
    }

    SUBCASE("Select with WHERE and operator") {
        auto query = QueryBuilder::select("products")
            .where("price", ">", BoundParam::real(9.99))
            .build();
        CHECK(query.sql == "SELECT * FROM products WHERE price > ?");
        REQUIRE(query.params.size() == 1);
        CHECK(query.params[0].realValue == doctest::Approx(9.99));
    }

    SUBCASE("Select with multiple WHERE (AND)") {
        auto query = QueryBuilder::select("users")
            .where("status", BoundParam::text("active"))
            .where("role", BoundParam::text("admin"))
            .build();
        CHECK(query.sql == "SELECT * FROM users WHERE status = ? AND role = ?");
        REQUIRE(query.params.size() == 2);
        CHECK(query.params[0].textValue == "active");
        CHECK(query.params[1].textValue == "admin");
    }

    SUBCASE("Select with ORDER BY ascending") {
        auto query = QueryBuilder::select("users")
            .orderBy("name", SortOrder::Ascending)
            .build();
        CHECK(query.sql == "SELECT * FROM users ORDER BY name ASC");
    }

    SUBCASE("Select with ORDER BY descending") {
        auto query = QueryBuilder::select("events")
            .orderBy("created_at", SortOrder::Descending)
            .build();
        CHECK(query.sql == "SELECT * FROM events ORDER BY created_at DESC");
    }

    SUBCASE("Select with multiple ORDER BY") {
        auto query = QueryBuilder::select("users")
            .orderBy("last_name", SortOrder::Ascending)
            .orderBy("first_name", SortOrder::Ascending)
            .build();
        CHECK(query.sql == "SELECT * FROM users ORDER BY last_name ASC, first_name ASC");
    }

    SUBCASE("Select with LIMIT") {
        auto query = QueryBuilder::select("logs")
            .limit(10)
            .build();
        CHECK(query.sql == "SELECT * FROM logs LIMIT 10");
    }

    SUBCASE("Select with LIMIT and OFFSET") {
        auto query = QueryBuilder::select("logs")
            .limit(25)
            .offset(50)
            .build();
        CHECK(query.sql == "SELECT * FROM logs LIMIT 25 OFFSET 50");
    }

    SUBCASE("Select with WHERE NULL") {
        auto query = QueryBuilder::select("users")
            .whereNull("deleted_at")
            .build();
        CHECK(query.sql == "SELECT * FROM users WHERE deleted_at IS NULL");
    }

    SUBCASE("Select with WHERE NOT NULL") {
        auto query = QueryBuilder::select("users")
            .whereNotNull("email")
            .build();
        CHECK(query.sql == "SELECT * FROM users WHERE email IS NOT NULL");
    }

    SUBCASE("Select with BETWEEN") {
        auto query = QueryBuilder::select("products")
            .whereBetween("price", BoundParam::real(10.0), BoundParam::real(50.0))
            .build();
        CHECK(query.sql == "SELECT * FROM products WHERE price BETWEEN ? AND ?");
        REQUIRE(query.params.size() == 2);
        CHECK(query.params[0].realValue == doctest::Approx(10.0));
        CHECK(query.params[1].realValue == doctest::Approx(50.0));
    }

    SUBCASE("Select with GROUP BY") {
        auto query = QueryBuilder::select("orders")
            .column("status")
            .groupBy("status")
            .build();
        CHECK(query.sql == "SELECT status FROM orders GROUP BY status");
    }

    SUBCASE("Complex select with all clauses") {
        auto query = QueryBuilder::select("threats")
            .columns({"id", "name", "severity"})
            .where("severity", ">=", BoundParam::integer(3))
            .where("status", BoundParam::text("active"))
            .orderBy("severity", SortOrder::Descending)
            .limit(100)
            .offset(0)
            .build();

        CHECK(query.sql == "SELECT id, name, severity FROM threats WHERE severity >= ? AND status = ? ORDER BY severity DESC LIMIT 100 OFFSET 0");
        CHECK(query.params.size() == 2);
    }
}

TEST_CASE("QueryBuilder SELECT with JOIN") {
    SUBCASE("INNER JOIN") {
        auto query = QueryBuilder::select("users")
            .columns({"users.name", "orders.total"})
            .join("orders", "users.id = orders.user_id")
            .build();
        CHECK(query.sql == "SELECT users.name, orders.total FROM users INNER JOIN orders ON users.id = orders.user_id");
    }

    SUBCASE("LEFT JOIN") {
        auto query = QueryBuilder::select("users")
            .leftJoin("profiles", "users.id = profiles.user_id")
            .build();
        CHECK(query.sql == "SELECT * FROM users LEFT JOIN profiles ON users.id = profiles.user_id");
    }

    SUBCASE("RIGHT JOIN") {
        auto query = QueryBuilder::select("orders")
            .rightJoin("users", "orders.user_id = users.id")
            .build();
        CHECK(query.sql == "SELECT * FROM orders RIGHT JOIN users ON orders.user_id = users.id");
    }

    SUBCASE("Multiple JOINs") {
        auto query = QueryBuilder::select("users")
            .join("orders", "users.id = orders.user_id")
            .leftJoin("profiles", "users.id = profiles.user_id")
            .build();
        CHECK(query.sql == "SELECT * FROM users INNER JOIN orders ON users.id = orders.user_id LEFT JOIN profiles ON users.id = profiles.user_id");
    }
}

TEST_CASE("QueryBuilder INSERT") {
    SUBCASE("Insert single row") {
        auto query = QueryBuilder::insert("users")
            .column("name", BoundParam::text("Alice"))
            .column("email", BoundParam::text("alice@example.com"))
            .column("age", BoundParam::integer(30))
            .build();
        CHECK(query.sql == "INSERT INTO users (name, email, age) VALUES (?, ?, ?)");
        REQUIRE(query.params.size() == 3);
        CHECK(query.params[0].textValue == "Alice");
        CHECK(query.params[1].textValue == "alice@example.com");
        CHECK(query.params[2].intValue == 30);
    }

    SUBCASE("Insert with columns vector") {
        std::vector<std::string> cols = {"a", "b"};
        std::vector<BoundParam> vals = {BoundParam::integer(1), BoundParam::text("two")};

        auto query = QueryBuilder::insert("data")
            .columns(cols, vals)
            .build();
        CHECK(query.sql == "INSERT INTO data (a, b) VALUES (?, ?)");
        CHECK(query.params.size() == 2);
    }

    SUBCASE("Insert with null value") {
        auto query = QueryBuilder::insert("users")
            .column("name", BoundParam::text("Bob"))
            .column("deleted_at", BoundParam::null())
            .build();
        CHECK(query.sql == "INSERT INTO users (name, deleted_at) VALUES (?, ?)");
        REQUIRE(query.params.size() == 2);
        CHECK(query.params[1].type == BoundParam::Type::Null);
    }
}

TEST_CASE("QueryBuilder UPDATE") {
    SUBCASE("Update with WHERE") {
        auto query = QueryBuilder::update("users")
            .set("name", BoundParam::text("Updated"))
            .set("email", BoundParam::text("new@example.com"))
            .where("id", BoundParam::integer(5))
            .build();
        CHECK(query.sql == "UPDATE users SET name = ?, email = ? WHERE id = ?");
        REQUIRE(query.params.size() == 3);
        CHECK(query.params[0].textValue == "Updated");
        CHECK(query.params[1].textValue == "new@example.com");
        CHECK(query.params[2].intValue == 5);
    }

    SUBCASE("Update without WHERE (update all)") {
        auto query = QueryBuilder::update("settings")
            .set("value", BoundParam::text("default"))
            .build();
        CHECK(query.sql == "UPDATE settings SET value = ?");
        CHECK(query.params.size() == 1);
    }

    SUBCASE("Update with multiple WHERE conditions") {
        auto query = QueryBuilder::update("alerts")
            .set("status", BoundParam::text("resolved"))
            .where("severity", ">=", BoundParam::integer(3))
            .where("status", BoundParam::text("active"))
            .build();
        CHECK(query.sql == "UPDATE alerts SET status = ? WHERE severity >= ? AND status = ?");
        CHECK(query.params.size() == 3);
    }
}

TEST_CASE("QueryBuilder DELETE") {
    SUBCASE("Delete with WHERE") {
        auto query = QueryBuilder::remove("sessions")
            .where("expired_at", "<", BoundParam::text("2024-01-01"))
            .build();
        CHECK(query.sql == "DELETE FROM sessions WHERE expired_at < ?");
        REQUIRE(query.params.size() == 1);
        CHECK(query.params[0].textValue == "2024-01-01");
    }

    SUBCASE("Delete with equality WHERE") {
        auto query = QueryBuilder::remove("users")
            .where("id", BoundParam::integer(42))
            .build();
        CHECK(query.sql == "DELETE FROM users WHERE id = ?");
        CHECK(query.params.size() == 1);
    }

    SUBCASE("Delete with NULL check") {
        auto query = QueryBuilder::remove("logs")
            .whereNotNull("archived_at")
            .build();
        CHECK(query.sql == "DELETE FROM logs WHERE archived_at IS NOT NULL");
        CHECK(query.params.empty());
    }

    SUBCASE("Delete without WHERE (delete all)") {
        auto query = QueryBuilder::remove("temp_data").build();
        CHECK(query.sql == "DELETE FROM temp_data");
        CHECK(query.params.empty());
    }
}

TEST_CASE("QueryBuilder raw query") {
    SUBCASE("Raw SQL without params") {
        auto query = QueryBuilder::raw("PRAGMA table_info(users)");
        CHECK(query.sql == "PRAGMA table_info(users)");
        CHECK(query.params.empty());
    }

    SUBCASE("Raw SQL with params") {
        auto query = QueryBuilder::raw(
            "SELECT * FROM users WHERE name LIKE ?",
            {BoundParam::text("%admin%")}
        );
        CHECK(query.sql == "SELECT * FROM users WHERE name LIKE ?");
        REQUIRE(query.params.size() == 1);
        CHECK(query.params[0].textValue == "%admin%");
    }
}

TEST_CASE("BoundParam types") {
    SUBCASE("Null param") {
        auto p = BoundParam::null();
        CHECK(p.type == BoundParam::Type::Null);
    }

    SUBCASE("Integer param") {
        auto p = BoundParam::integer(123);
        CHECK(p.type == BoundParam::Type::Integer);
        CHECK(p.intValue == 123);
    }

    SUBCASE("Real param") {
        auto p = BoundParam::real(3.14);
        CHECK(p.type == BoundParam::Type::Real);
        CHECK(p.realValue == doctest::Approx(3.14));
    }

    SUBCASE("Text param") {
        auto p = BoundParam::text("hello");
        CHECK(p.type == BoundParam::Type::Text);
        CHECK(p.textValue == "hello");
    }

    SUBCASE("Blob param") {
        auto p = BoundParam::blob({0x01, 0x02, 0x03});
        CHECK(p.type == BoundParam::Type::Blob);
        CHECK(p.blobValue.size() == 3);
        CHECK(p.blobValue[0] == 0x01);
    }
}
