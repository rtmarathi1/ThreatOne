import QtQuick

// Comprehensive dark color palette for ThreatOne
QtObject {
    // Core backgrounds
    property color background: "#0a0a1a"
    property color surface: "#1a1a2e"
    property color surfaceVariant: "#16213e"
    property color card: "#0f1629"
    property color elevated: "#1e2746"

    // Primary palette
    property color primary: "#00d4ff"
    property color primaryVariant: "#0099cc"
    property color primaryMuted: "#00d4ff"
    property color secondary: "#8b5cf6"
    property color secondaryVariant: "#7c3aed"
    property color accent: "#e94560"

    // Semantic colors
    property color success: "#4ade80"
    property color successVariant: "#22c55e"
    property color warning: "#f59e0b"
    property color warningVariant: "#d97706"
    property color error: "#ef4444"
    property color errorVariant: "#dc2626"
    property color info: "#3b82f6"
    property color infoVariant: "#2563eb"

    // Text hierarchy
    property color onBackground: "#ffffff"
    property color onSurface: "#ffffff"
    property color textPrimary: "#ffffff"
    property color textSecondary: "#8892b0"
    property color textMuted: "#4a5568"
    property color textDisabled: "#374151"
    property color textLink: "#00d4ff"

    // Borders and dividers
    property color border: "#2a2a4a"
    property color borderStrong: "#3a3a5a"
    property color borderFocus: "#00d4ff"
    property color divider: "#1e293b"

    // Component-specific
    property color sidebar: "#1a1a2e"
    property color sidebarActive: "#2a2a4a"
    property color sidebarHover: "#232345"
    property color topbar: "#0f3460"
    property color statusbar: "#0a0a1a"
    property color overlay: "#000000"
    property real overlayOpacity: 0.7

    // Input/Form
    property color inputBackground: "#0f1629"
    property color inputBorder: "#2a2a4a"
    property color inputFocusBorder: "#00d4ff"
    property color inputPlaceholder: "#4a5568"

    // Table
    property color tableHeader: "#16213e"
    property color tableRow: "#0f1629"
    property color tableRowAlt: "#131b30"
    property color tableRowHover: "#1a2540"
    property color tableRowSelected: "#1a3a5a"

    // Badge/Tag
    property color badgeCritical: "#ef4444"
    property color badgeHigh: "#f59e0b"
    property color badgeMedium: "#3b82f6"
    property color badgeLow: "#4ade80"
    property color badgeInfo: "#8892b0"

    // Chart palette
    property var chartColors: ["#00d4ff", "#8b5cf6", "#4ade80", "#f59e0b", "#ef4444", "#ec4899", "#06b6d4", "#a855f7"]

    // Scrollbar
    property color scrollbarTrack: "#0a0a1a"
    property color scrollbarThumb: "#2a2a4a"
    property color scrollbarThumbHover: "#3a3a5a"
}
