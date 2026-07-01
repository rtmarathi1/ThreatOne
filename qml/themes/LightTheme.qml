import QtQuick

// Comprehensive light color palette for ThreatOne
QtObject {
    // Core backgrounds
    property color background: "#f8fafc"
    property color surface: "#ffffff"
    property color surfaceVariant: "#f1f5f9"
    property color card: "#ffffff"
    property color elevated: "#ffffff"

    // Primary palette
    property color primary: "#0284c7"
    property color primaryVariant: "#0369a1"
    property color primaryMuted: "#bae6fd"
    property color secondary: "#7c3aed"
    property color secondaryVariant: "#6d28d9"
    property color accent: "#dc2626"

    // Semantic colors
    property color success: "#16a34a"
    property color successVariant: "#15803d"
    property color warning: "#d97706"
    property color warningVariant: "#b45309"
    property color error: "#dc2626"
    property color errorVariant: "#b91c1c"
    property color info: "#2563eb"
    property color infoVariant: "#1d4ed8"

    // Text hierarchy
    property color onBackground: "#1e293b"
    property color onSurface: "#1e293b"
    property color textPrimary: "#1e293b"
    property color textSecondary: "#64748b"
    property color textMuted: "#94a3b8"
    property color textDisabled: "#cbd5e1"
    property color textLink: "#0284c7"

    // Borders and dividers
    property color border: "#e2e8f0"
    property color borderStrong: "#cbd5e1"
    property color borderFocus: "#0284c7"
    property color divider: "#f1f5f9"

    // Component-specific
    property color sidebar: "#ffffff"
    property color sidebarActive: "#f1f5f9"
    property color sidebarHover: "#f8fafc"
    property color topbar: "#ffffff"
    property color statusbar: "#f1f5f9"
    property color overlay: "#1e293b"
    property real overlayOpacity: 0.5

    // Input/Form
    property color inputBackground: "#f1f5f9"
    property color inputBorder: "#e2e8f0"
    property color inputFocusBorder: "#0284c7"
    property color inputPlaceholder: "#94a3b8"

    // Table
    property color tableHeader: "#f1f5f9"
    property color tableRow: "#ffffff"
    property color tableRowAlt: "#f8fafc"
    property color tableRowHover: "#f1f5f9"
    property color tableRowSelected: "#eff6ff"

    // Badge/Tag
    property color badgeCritical: "#ef4444"
    property color badgeHigh: "#f59e0b"
    property color badgeMedium: "#3b82f6"
    property color badgeLow: "#16a34a"
    property color badgeInfo: "#64748b"

    // Chart palette
    property var chartColors: ["#0284c7", "#7c3aed", "#16a34a", "#d97706", "#dc2626", "#db2777", "#0891b2", "#9333ea"]

    // Scrollbar
    property color scrollbarTrack: "#f1f5f9"
    property color scrollbarThumb: "#cbd5e1"
    property color scrollbarThumbHover: "#94a3b8"
}
