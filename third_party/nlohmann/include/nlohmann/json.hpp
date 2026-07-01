#pragma once

// ============================================================================
// SIMPLIFIED nlohmann/json-COMPATIBLE JSON LIBRARY (Phase 1 Stub)
//
// This is a minimal reimplementation of the nlohmann/json API for ThreatOne Phase 1.
// It is NOT the real nlohmann/json library and diverges from the real API in several ways:
//
// Known divergences from real nlohmann/json:
//   - Initializer-list constructor uses a heuristic to distinguish arrays from
//     objects that may not match the real library's behavior (e.g., json{{"key", value}})
//   - json::parse() error modes may differ (no parse error callbacks)
//   - json::items() iteration may have different semantics
//   - No SAX parser, JSON Pointer, JSON Patch, or CBOR/MessagePack support
//   - No custom allocator support
//   - Type conversions (to_type/from_type) are simplified
//
// When migrating to the real nlohmann/json library:
//   1. Replace this header with the real nlohmann/json.hpp single-header
//   2. Update CMakeLists.txt if needed
//   3. Test initializer-list constructions (most likely source of breakage)
//   4. Verify parse error handling paths
// ============================================================================

#include <string>
#include <map>
#include <vector>
#include <variant>
#include <stdexcept>
#include <sstream>
#include <initializer_list>
#include <iostream>
#include <cstdint>
#include <cassert>
#include <algorithm>
#include <type_traits>

namespace nlohmann {

class json {
public:
    enum class value_t {
        null,
        object,
        array,
        string,
        number_integer,
        number_float,
        boolean
    };

    using object_t = std::map<std::string, json>;
    using array_t = std::vector<json>;
    using string_t = std::string;
    using number_integer_t = int64_t;
    using number_float_t = double;
    using boolean_t = bool;

private:
    value_t type_ = value_t::null;
    object_t object_val_;
    array_t array_val_;
    string_t string_val_;
    number_integer_t int_val_ = 0;
    number_float_t float_val_ = 0.0;
    boolean_t bool_val_ = false;

public:
    // Constructors
    json() : type_(value_t::null) {}
    json(std::nullptr_t) : type_(value_t::null) {}
    json(bool val) : type_(value_t::boolean), bool_val_(val) {}
    json(int val) : type_(value_t::number_integer), int_val_(val) {}
    json(int64_t val) : type_(value_t::number_integer), int_val_(val) {}
    json(unsigned int val) : type_(value_t::number_integer), int_val_(static_cast<int64_t>(val)) {}
    json(uint64_t val) : type_(value_t::number_integer), int_val_(static_cast<int64_t>(val)) {}
    json(double val) : type_(value_t::number_float), float_val_(val) {}
    json(const std::string& val) : type_(value_t::string), string_val_(val) {}
    json(const char* val) : type_(value_t::string), string_val_(val) {}
    json(const object_t& val) : type_(value_t::object), object_val_(val) {}
    json(const array_t& val) : type_(value_t::array), array_val_(val) {}

    // Initializer list constructor for objects
    json(std::initializer_list<json> init) {
        // Determine if this is an object (all elements are arrays of size 2 with string first element)
        bool is_object = true;
        for (const auto& element : init) {
            if (element.type_ != value_t::array || element.array_val_.size() != 2 ||
                element.array_val_[0].type_ != value_t::string) {
                is_object = false;
                break;
            }
        }

        if (is_object && init.size() > 0) {
            type_ = value_t::object;
            for (const auto& element : init) {
                object_val_[element.array_val_[0].string_val_] = element.array_val_[1];
            }
        } else {
            type_ = value_t::array;
            array_val_ = array_t(init.begin(), init.end());
        }
    }

    // Static constructors
    static json object() {
        json j;
        j.type_ = value_t::object;
        return j;
    }

    static json array() {
        json j;
        j.type_ = value_t::array;
        return j;
    }

    // Type checks
    bool is_null() const { return type_ == value_t::null; }
    bool is_object() const { return type_ == value_t::object; }
    bool is_array() const { return type_ == value_t::array; }
    bool is_string() const { return type_ == value_t::string; }
    bool is_number() const { return type_ == value_t::number_integer || type_ == value_t::number_float; }
    bool is_number_integer() const { return type_ == value_t::number_integer; }
    bool is_number_float() const { return type_ == value_t::number_float; }
    bool is_boolean() const { return type_ == value_t::boolean; }

    value_t type() const { return type_; }

    // Value access
    template<typename T>
    T get() const {
        if constexpr (std::is_same_v<T, std::string>) {
            if (type_ != value_t::string) throw std::runtime_error("json: not a string");
            return string_val_;
        } else if constexpr (std::is_same_v<T, int> || std::is_same_v<T, int64_t>) {
            if (type_ != value_t::number_integer) throw std::runtime_error("json: not an integer");
            return static_cast<T>(int_val_);
        } else if constexpr (std::is_same_v<T, double> || std::is_same_v<T, float>) {
            if (type_ == value_t::number_float) return static_cast<T>(float_val_);
            if (type_ == value_t::number_integer) return static_cast<T>(int_val_);
            throw std::runtime_error("json: not a number");
        } else if constexpr (std::is_same_v<T, bool>) {
            if (type_ != value_t::boolean) throw std::runtime_error("json: not a boolean");
            return bool_val_;
        } else {
            throw std::runtime_error("json: unsupported type");
        }
    }

    // value() with default
    template<typename T>
    T value(const std::string& key, const T& default_val) const {
        if (type_ != value_t::object) return default_val;
        auto it = object_val_.find(key);
        if (it == object_val_.end()) return default_val;
        try {
            return it->second.get<T>();
        } catch (...) {
            return default_val;
        }
    }

    // Special overload for string literals
    std::string value(const std::string& key, const char* default_val) const {
        return value<std::string>(key, std::string(default_val));
    }

    // Operator[] for objects
    json& operator[](const std::string& key) {
        if (type_ == value_t::null) type_ = value_t::object;
        if (type_ != value_t::object) throw std::runtime_error("json: not an object");
        return object_val_[key];
    }

    const json& operator[](const std::string& key) const {
        if (type_ != value_t::object) throw std::runtime_error("json: not an object");
        auto it = object_val_.find(key);
        if (it == object_val_.end()) {
            static const json null_json;
            return null_json;
        }
        return it->second;
    }

    // Operator[] for arrays
    json& operator[](size_t idx) {
        if (type_ != value_t::array) throw std::runtime_error("json: not an array");
        return array_val_[idx];
    }

    const json& operator[](size_t idx) const {
        if (type_ != value_t::array) throw std::runtime_error("json: not an array");
        return array_val_[idx];
    }

    // Size
    size_t size() const {
        switch (type_) {
            case value_t::object: return object_val_.size();
            case value_t::array: return array_val_.size();
            default: return 0;
        }
    }

    bool empty() const { return size() == 0; }

    // Contains (for objects)
    bool contains(const std::string& key) const {
        if (type_ != value_t::object) return false;
        return object_val_.find(key) != object_val_.end();
    }

    // Push back (for arrays)
    void push_back(const json& val) {
        if (type_ == value_t::null) type_ = value_t::array;
        if (type_ != value_t::array) throw std::runtime_error("json: not an array");
        array_val_.push_back(val);
    }

    // Iteration
    using iterator = object_t::iterator;
    using const_iterator = object_t::const_iterator;

    // Object iterators
    auto begin() { return type_ == value_t::object ? object_val_.begin() : object_val_.begin(); }
    auto end() { return type_ == value_t::object ? object_val_.end() : object_val_.end(); }
    auto begin() const { return type_ == value_t::object ? object_val_.begin() : object_val_.begin(); }
    auto end() const { return type_ == value_t::object ? object_val_.end() : object_val_.end(); }

    // Array iterators for range-for support
    array_t::iterator array_begin() { return array_val_.begin(); }
    array_t::iterator array_end() { return array_val_.end(); }
    array_t::const_iterator array_begin() const { return array_val_.begin(); }
    array_t::const_iterator array_end() const { return array_val_.end(); }

    // Return the underlying array (for iteration)
    const array_t& get_array() const {
        if (type_ != value_t::array) {
            static const array_t empty;
            return empty;
        }
        return array_val_;
    }

    array_t& get_array() {
        if (type_ == value_t::null) type_ = value_t::array;
        if (type_ != value_t::array) {
            throw std::runtime_error("json: not an array");
        }
        return array_val_;
    }

    // items() for object iteration
    const object_t& items() const {
        if (type_ != value_t::object) {
            static const object_t empty;
            return empty;
        }
        return object_val_;
    }

    // Dump to string
    std::string dump(int indent = -1) const {
        std::ostringstream oss;
        dump_impl(oss, indent, 0);
        return oss.str();
    }

    // Parse from string
    static json parse(const std::string& str) {
        size_t pos = 0;
        return parse_impl(str, pos);
    }

    // Comparison
    bool operator==(const json& other) const {
        if (type_ != other.type_) return false;
        switch (type_) {
            case value_t::null: return true;
            case value_t::boolean: return bool_val_ == other.bool_val_;
            case value_t::number_integer: return int_val_ == other.int_val_;
            case value_t::number_float: return float_val_ == other.float_val_;
            case value_t::string: return string_val_ == other.string_val_;
            case value_t::object: return object_val_ == other.object_val_;
            case value_t::array: return array_val_ == other.array_val_;
        }
        return false;
    }

    bool operator!=(const json& other) const { return !(*this == other); }

    // Stream output
    friend std::ostream& operator<<(std::ostream& os, const json& j) {
        os << j.dump();
        return os;
    }

private:
    void dump_impl(std::ostringstream& oss, int indent, int current_indent) const {
        std::string indent_str = (indent > 0) ? std::string(static_cast<size_t>(current_indent), ' ') : "";
        std::string child_indent_str = (indent > 0) ? std::string(static_cast<size_t>(current_indent + indent), ' ') : "";
        std::string newline = (indent > 0) ? "\n" : "";
        std::string space = (indent > 0) ? " " : "";

        switch (type_) {
            case value_t::null:
                oss << "null";
                break;
            case value_t::boolean:
                oss << (bool_val_ ? "true" : "false");
                break;
            case value_t::number_integer:
                oss << int_val_;
                break;
            case value_t::number_float:
                oss << float_val_;
                break;
            case value_t::string:
                oss << "\"" << escape_string(string_val_) << "\"";
                break;
            case value_t::object: {
                oss << "{" << newline;
                bool first = true;
                for (const auto& [key, val] : object_val_) {
                    if (!first) oss << "," << newline;
                    first = false;
                    oss << child_indent_str << "\"" << escape_string(key) << "\":" << space;
                    val.dump_impl(oss, indent, current_indent + indent);
                }
                oss << newline << indent_str << "}";
                break;
            }
            case value_t::array: {
                oss << "[" << newline;
                bool first = true;
                for (const auto& val : array_val_) {
                    if (!first) oss << "," << newline;
                    first = false;
                    oss << child_indent_str;
                    val.dump_impl(oss, indent, current_indent + indent);
                }
                oss << newline << indent_str << "]";
                break;
            }
        }
    }

    static std::string escape_string(const std::string& s) {
        std::string result;
        result.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c; break;
            }
        }
        return result;
    }

    static void skip_whitespace(const std::string& str, size_t& pos) {
        while (pos < str.size() && (str[pos] == ' ' || str[pos] == '\t' || str[pos] == '\n' || str[pos] == '\r')) {
            ++pos;
        }
    }

    static json parse_impl(const std::string& str, size_t& pos) {
        skip_whitespace(str, pos);
        if (pos >= str.size()) return json();

        char c = str[pos];

        if (c == '{') return parse_object(str, pos);
        if (c == '[') return parse_array(str, pos);
        if (c == '"') return parse_string(str, pos);
        if (c == 't' || c == 'f') return parse_bool(str, pos);
        if (c == 'n') return parse_null(str, pos);
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number(str, pos);

        throw std::runtime_error("json parse error at position " + std::to_string(pos));
    }

    static json parse_object(const std::string& str, size_t& pos) {
        json result;
        result.type_ = value_t::object;
        ++pos; // skip '{'
        skip_whitespace(str, pos);
        if (pos < str.size() && str[pos] == '}') { ++pos; return result; }

        while (pos < str.size()) {
            skip_whitespace(str, pos);
            json key = parse_string(str, pos);
            skip_whitespace(str, pos);
            if (pos >= str.size() || str[pos] != ':') throw std::runtime_error("json: expected ':'");
            ++pos;
            json val = parse_impl(str, pos);
            result.object_val_[key.string_val_] = std::move(val);
            skip_whitespace(str, pos);
            if (pos < str.size() && str[pos] == ',') { ++pos; continue; }
            if (pos < str.size() && str[pos] == '}') { ++pos; return result; }
            throw std::runtime_error("json: expected ',' or '}'");
        }
        return result;
    }

    static json parse_array(const std::string& str, size_t& pos) {
        json result;
        result.type_ = value_t::array;
        ++pos; // skip '['
        skip_whitespace(str, pos);
        if (pos < str.size() && str[pos] == ']') { ++pos; return result; }

        while (pos < str.size()) {
            json val = parse_impl(str, pos);
            result.array_val_.push_back(std::move(val));
            skip_whitespace(str, pos);
            if (pos < str.size() && str[pos] == ',') { ++pos; continue; }
            if (pos < str.size() && str[pos] == ']') { ++pos; return result; }
            throw std::runtime_error("json: expected ',' or ']'");
        }
        return result;
    }

    static json parse_string(const std::string& str, size_t& pos) {
        if (pos >= str.size() || str[pos] != '"') throw std::runtime_error("json: expected '\"'");
        ++pos;
        std::string result;
        while (pos < str.size() && str[pos] != '"') {
            if (str[pos] == '\\') {
                ++pos;
                if (pos >= str.size()) throw std::runtime_error("json: unexpected end of string");
                switch (str[pos]) {
                    case '"': result += '"'; break;
                    case '\\': result += '\\'; break;
                    case '/': result += '/'; break;
                    case 'n': result += '\n'; break;
                    case 'r': result += '\r'; break;
                    case 't': result += '\t'; break;
                    default: result += str[pos]; break;
                }
            } else {
                result += str[pos];
            }
            ++pos;
        }
        if (pos >= str.size()) throw std::runtime_error("json: unterminated string");
        ++pos; // skip closing '"'
        return json(result);
    }

    static json parse_number(const std::string& str, size_t& pos) {
        size_t start = pos;
        bool is_float = false;
        if (str[pos] == '-') ++pos;
        while (pos < str.size() && str[pos] >= '0' && str[pos] <= '9') ++pos;
        if (pos < str.size() && str[pos] == '.') { is_float = true; ++pos; }
        while (pos < str.size() && str[pos] >= '0' && str[pos] <= '9') ++pos;
        if (pos < str.size() && (str[pos] == 'e' || str[pos] == 'E')) {
            is_float = true; ++pos;
            if (pos < str.size() && (str[pos] == '+' || str[pos] == '-')) ++pos;
            while (pos < str.size() && str[pos] >= '0' && str[pos] <= '9') ++pos;
        }
        std::string num_str = str.substr(start, pos - start);
        if (is_float) return json(std::stod(num_str));
        return json(static_cast<int64_t>(std::stoll(num_str)));
    }

    static json parse_bool(const std::string& str, size_t& pos) {
        if (str.substr(pos, 4) == "true") { pos += 4; return json(true); }
        if (str.substr(pos, 5) == "false") { pos += 5; return json(false); }
        throw std::runtime_error("json: invalid boolean");
    }

    static json parse_null(const std::string& str, size_t& pos) {
        if (str.substr(pos, 4) == "null") { pos += 4; return json(nullptr); }
        throw std::runtime_error("json: invalid null");
    }
};

} // namespace nlohmann
