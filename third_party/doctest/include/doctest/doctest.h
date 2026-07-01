#pragma once

// Simplified doctest-compatible test framework
// This is a minimal vendored implementation for ThreatOne
// Supports: TEST_CASE, SUBCASE, CHECK, REQUIRE,
//           CHECK_EQ, CHECK_NE, CHECK_FALSE, CHECK_THROWS_AS, Approx

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <sstream>
#include <cstdlib>
#include <cmath>
#include <type_traits>

namespace doctest {

struct TestCase {
    std::string name;
    std::string file;
    int line;
    std::function<void()> func;
};

struct SubcaseSignature {
    std::string name;
    std::string file;
    int line;
};

class Context {
public:
    int run() {
        int failures = 0;
        int total = 0;
        auto& tests = get_tests();

        std::cout << "[doctest] Running " << tests.size() << " test case(s)...\n";

        for (auto& tc : tests) {
            ++total;
            current_test_failed() = false;
            try {
                tc.func();
            } catch (const std::exception& e) {
                current_test_failed() = true;
                std::cerr << tc.file << ":" << tc.line << ": FAILED:\n"
                          << "  exception: " << e.what() << "\n"
                          << "  in test case: " << tc.name << "\n\n";
            } catch (...) {
                current_test_failed() = true;
                std::cerr << tc.file << ":" << tc.line << ": FAILED:\n"
                          << "  unknown exception\n"
                          << "  in test case: " << tc.name << "\n\n";
            }
            if (current_test_failed()) ++failures;
        }

        std::cout << "[doctest] " << total << " test case(s) | "
                  << (total - failures) << " passed | "
                  << failures << " failed\n";

        return failures;
    }

    static std::vector<TestCase>& get_tests() {
        static std::vector<TestCase> tests;
        return tests;
    }

    static bool& current_test_failed() {
        static bool failed = false;
        return failed;
    }
};

struct TestRegistrar {
    TestRegistrar(const char* name, const char* file, int line, std::function<void()> func) {
        Context::get_tests().push_back({name, file, line, std::move(func)});
    }
};

// Subcase tracking
inline std::vector<SubcaseSignature>& get_subcases_entered() {
    static std::vector<SubcaseSignature> subcases;
    return subcases;
}

struct Subcase {
    bool entered = true;

    Subcase(const char* /*name*/, const char* /*file*/, int /*line*/) {
        // Simplified: always enter subcases
    }

    ~Subcase() = default;

    operator bool() const { return entered; }
};

// Approx class for floating-point comparison
class Approx {
public:
    explicit Approx(double value)
        : value_(value), epsilon_(1e-6) {}

    Approx& epsilon(double eps) { epsilon_ = eps; return *this; }

    friend bool operator==(double lhs, const Approx& rhs) {
        return std::fabs(lhs - rhs.value_) <= rhs.epsilon_ * (1.0 + std::fabs(rhs.value_));
    }

    friend bool operator==(const Approx& lhs, double rhs) {
        return rhs == lhs;
    }

    friend bool operator!=(double lhs, const Approx& rhs) {
        return !(lhs == rhs);
    }

    friend bool operator!=(const Approx& lhs, double rhs) {
        return !(rhs == lhs);
    }

    friend std::ostream& operator<<(std::ostream& os, const Approx& a) {
        os << "Approx(" << a.value_ << ")";
        return os;
    }

private:
    double value_;
    double epsilon_;
};

namespace detail {

inline void check_impl(bool result, const char* expr, const char* file, int line, bool is_require) {
    if (!result) {
        Context::current_test_failed() = true;
        std::cerr << file << ":" << line << ": FAILED:\n"
                  << "  " << (is_require ? "REQUIRE" : "CHECK") << "( " << expr << " )\n\n";
        if (is_require) {
            throw std::runtime_error(std::string("REQUIRE failed: ") + expr);
        }
    }
}

template<typename L, typename R>
inline void check_eq_impl(const L& lhs, const R& rhs, const char* lhs_expr, const char* rhs_expr,
                           const char* file, int line, bool is_require) {
    if (!(lhs == rhs)) {
        Context::current_test_failed() = true;
        std::ostringstream oss;
        oss << file << ":" << line << ": FAILED:\n"
            << "  " << (is_require ? "REQUIRE_EQ" : "CHECK_EQ")
            << "( " << lhs_expr << ", " << rhs_expr << " )\n"
            << "  values: " << lhs << " != " << rhs << "\n\n";
        std::cerr << oss.str();
        if (is_require) {
            throw std::runtime_error("REQUIRE_EQ failed");
        }
    }
}

template<typename L, typename R>
inline void check_ne_impl(const L& lhs, const R& rhs, const char* lhs_expr, const char* rhs_expr,
                           const char* file, int line, bool is_require) {
    if (!(lhs != rhs)) {
        Context::current_test_failed() = true;
        std::ostringstream oss;
        oss << file << ":" << line << ": FAILED:\n"
            << "  " << (is_require ? "REQUIRE_NE" : "CHECK_NE")
            << "( " << lhs_expr << ", " << rhs_expr << " )\n"
            << "  values: both equal\n\n";
        std::cerr << oss.str();
        if (is_require) {
            throw std::runtime_error("REQUIRE_NE failed");
        }
    }
}

template<typename ExceptionType, typename F>
inline bool check_throws_as_impl(F&& func) {
    try {
        func();
        return false;
    } catch (const ExceptionType&) {
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace detail

} // namespace doctest

// Macros

#define DOCTEST_UNIQUE_NAME_LINE2(name, line) name##line
#define DOCTEST_UNIQUE_NAME_LINE(name, line) DOCTEST_UNIQUE_NAME_LINE2(name, line)
#define DOCTEST_UNIQUE_NAME(name) DOCTEST_UNIQUE_NAME_LINE(name, __LINE__)

#define TEST_CASE(name)                                                          \
    static void DOCTEST_UNIQUE_NAME(doctest_test_func_)();                       \
    static doctest::TestRegistrar DOCTEST_UNIQUE_NAME(doctest_registrar_)(       \
        name, __FILE__, __LINE__, DOCTEST_UNIQUE_NAME(doctest_test_func_));       \
    static void DOCTEST_UNIQUE_NAME(doctest_test_func_)()

#define SUBCASE(name) if (doctest::Subcase DOCTEST_UNIQUE_NAME(doctest_subcase_) = \
    doctest::Subcase(name, __FILE__, __LINE__))

// TEST_CASE_FIXTURE: inherits from the fixture so that the test body
// has direct access to its members. The fixture ctor/dtor provide
// setup/teardown.
#define TEST_CASE_FIXTURE(fixture, name)                                                      \
    class DOCTEST_UNIQUE_NAME(doctest_fixture_test_) : public fixture {                       \
    public:                                                                                   \
        void doctest_test_body();                                                             \
    };                                                                                        \
    static void DOCTEST_UNIQUE_NAME(doctest_fixture_wrapper_)() {                             \
        DOCTEST_UNIQUE_NAME(doctest_fixture_test_) instance;                                  \
        instance.doctest_test_body();                                                         \
    }                                                                                         \
    static doctest::TestRegistrar DOCTEST_UNIQUE_NAME(doctest_registrar_)(                    \
        name, __FILE__, __LINE__, DOCTEST_UNIQUE_NAME(doctest_fixture_wrapper_));              \
    void DOCTEST_UNIQUE_NAME(doctest_fixture_test_)::doctest_test_body()

#define CHECK(expr) \
    doctest::detail::check_impl(static_cast<bool>(expr), #expr, __FILE__, __LINE__, false)

#define CHECK_EQ(lhs, rhs) \
    doctest::detail::check_eq_impl((lhs), (rhs), #lhs, #rhs, __FILE__, __LINE__, false)

#define CHECK_NE(lhs, rhs) \
    doctest::detail::check_ne_impl((lhs), (rhs), #lhs, #rhs, __FILE__, __LINE__, false)

#define CHECK_FALSE(expr) \
    doctest::detail::check_impl(!static_cast<bool>(expr), "!(" #expr ")", __FILE__, __LINE__, false)

#define CHECK_THROWS_AS(expr, exception_type)                                    \
    doctest::detail::check_impl(                                                 \
        doctest::detail::check_throws_as_impl<exception_type>([&]() { expr; }),  \
        #expr " throws " #exception_type,                                        \
        __FILE__, __LINE__, false)

#define REQUIRE(expr) \
    doctest::detail::check_impl(static_cast<bool>(expr), #expr, __FILE__, __LINE__, true)

#define REQUIRE_EQ(lhs, rhs) \
    doctest::detail::check_eq_impl((lhs), (rhs), #lhs, #rhs, __FILE__, __LINE__, true)

#define REQUIRE_NE(lhs, rhs) \
    doctest::detail::check_ne_impl((lhs), (rhs), #lhs, #rhs, __FILE__, __LINE__, true)

#define REQUIRE_FALSE(expr) \
    doctest::detail::check_impl(!static_cast<bool>(expr), "!(" #expr ")", __FILE__, __LINE__, true)

#define REQUIRE_THROWS_AS(expr, exception_type)                                  \
    doctest::detail::check_impl(                                                 \
        doctest::detail::check_throws_as_impl<exception_type>([&]() { expr; }),  \
        #expr " throws " #exception_type,                                        \
        __FILE__, __LINE__, true)

// Main implementation macro
#ifdef DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
int main(int /*argc*/, char** /*argv*/) {
    doctest::Context ctx;
    return ctx.run();
}
#endif
