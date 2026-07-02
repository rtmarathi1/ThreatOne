#pragma once

// ThreatOne Database Migration 001 - Create Core Tables
// Defines the initial schema for all core platform tables.

#include <database/Migration.h>
#include <database/Schema.h>
#include <string>

namespace ThreatOne::Database::Migrations {

class CreateCoreTables : public IMigration {
public:
    [[nodiscard]] int version() const override { return 1; }
    [[nodiscard]] std::string name() const override { return "create_core_tables"; }

    [[nodiscard]] Core::Result<void, Core::Error> up(IConnection& conn) override;
    [[nodiscard]] Core::Result<void, Core::Error> down(IConnection& conn) override;
};

} // namespace ThreatOne::Database::Migrations
