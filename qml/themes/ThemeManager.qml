import QtQuick

pragma Singleton

// Theme manager singleton providing comprehensive design tokens
// for colors, typography, spacing, radius, elevation, and animations.
QtObject {
    id: themeManager

    // Current theme mode
    property bool darkMode: true

    // --- Color Tokens ---
    property color backgroundColor: darkMode ? "#0a0a1a" : "#f8fafc"
    property color surfaceColor: darkMode ? "#1a1a2e" : "#ffffff"
    property color surfaceVariantColor: darkMode ? "#16213e" : "#f1f5f9"
    property color primaryColor: darkMode ? "#00d4ff" : "#0284c7"
    property color primaryVariantColor: darkMode ? "#0099cc" : "#0369a1"
    property color secondaryColor: darkMode ? "#8b5cf6" : "#7c3aed"
    property color accentColor: "#8b5cf6"
    property color successColor: "#4ade80"
    property color warningColor: "#f59e0b"
    property color errorColor: "#ef4444"

    // Text colors
    property color textPrimary: darkMode ? "#ffffff" : "#1e293b"
    property color textSecondary: darkMode ? "#8892b0" : "#64748b"
    property color textMuted: darkMode ? "#4a5568" : "#94a3b8"
    property color textOnPrimary: darkMode ? "#0a0a1a" : "#ffffff"

    // Surface/UI element colors
    property color borderColor: darkMode ? "#2a2a4a" : "#e2e8f0"
    property color dividerColor: darkMode ? "#1e293b" : "#f1f5f9"
    property color sidebarColor: darkMode ? "#1a1a2e" : "#ffffff"
    property color sidebarActiveColor: darkMode ? "#2a2a4a" : "#f1f5f9"
    property color topbarColor: darkMode ? "#0f3460" : "#ffffff"
    property color overlayColor: darkMode ? "#000000" : "#1e293b"
    property color cardColor: darkMode ? "#0f1629" : "#f8fafc"
    property color inputColor: darkMode ? "#0f1629" : "#f1f5f9"
    property color hoverColor: darkMode ? "#2a2a4a" : "#e2e8f0"

    // Chart colors (array exposed as individual properties for QML compatibility)
    property color chart0: "#00d4ff"
    property color chart1: "#8b5cf6"
    property color chart2: "#4ade80"
    property color chart3: "#f59e0b"
    property color chart4: "#ef4444"
    property color chart5: "#ec4899"
    property color chart6: "#06b6d4"
    property color chart7: "#a855f7"

    // Severity colors
    property color severityCritical: "#ef4444"
    property color severityHigh: "#f59e0b"
    property color severityMedium: "#3b82f6"
    property color severityLow: "#4ade80"
    property color severityInfo: "#8892b0"

    // --- Typography Scale ---
    property string fontFamily: "Inter"
    property string fontFamilyMono: "JetBrains Mono"

    property int fontSizeXS: 10
    property int fontSizeSmall: 11
    property int fontSizeBody: 13
    property int fontSizeNormal: 14
    property int fontSizeMedium: 16
    property int fontSizeLarge: 18
    property int fontSizeXL: 20
    property int fontSizeTitle: 24
    property int fontSizeHeading: 28
    property int fontSizeDisplay: 36
    property int fontSizeHero: 48

    property int fontWeightLight: Font.Light
    property int fontWeightNormal: Font.Normal
    property int fontWeightMedium: Font.Medium
    property int fontWeightSemiBold: Font.DemiBold
    property int fontWeightBold: Font.Bold

    property real lineHeightTight: 1.2
    property real lineHeightNormal: 1.5
    property real lineHeightRelaxed: 1.75

    // --- Spacing Scale ---
    property int spacingXXS: 2
    property int spacingXS: 4
    property int spacingSmall: 8
    property int spacingMedium: 12
    property int spacingNormal: 16
    property int spacingLarge: 20
    property int spacingXL: 24
    property int spacingXXL: 32
    property int spacingXXXL: 48
    property int spacingHuge: 64

    // --- Border Radius ---
    property int radiusNone: 0
    property int radiusXS: 2
    property int radiusSmall: 4
    property int radiusMedium: 8
    property int radiusLarge: 12
    property int radiusXL: 16
    property int radiusXXL: 20
    property int radiusFull: 9999

    // --- Elevation / Shadows ---
    property color shadowColor: darkMode ? "#000000" : "#1e293b"
    property real shadowOpacitySmall: darkMode ? 0.2 : 0.05
    property real shadowOpacityMedium: darkMode ? 0.3 : 0.08
    property real shadowOpacityLarge: darkMode ? 0.4 : 0.1

    property int elevationNone: 0
    property int elevationSmall: 2
    property int elevationMedium: 4
    property int elevationLarge: 8
    property int elevationXL: 16

    // --- Animation Durations (ms) ---
    property int animFast: 100
    property int animNormal: 200
    property int animMedium: 300
    property int animSlow: 500
    property int animVerySlow: 800

    // --- Easing ---
    property int easingType: Easing.OutCubic

    // --- Icon sizes ---
    property int iconSizeSmall: 16
    property int iconSizeMedium: 20
    property int iconSizeLarge: 24
    property int iconSizeXL: 32
    property int iconSizeXXL: 48

    // --- Component dimensions ---
    property int sidebarExpandedWidth: 260
    property int sidebarCollapsedWidth: 64
    property int topbarHeight: 64
    property int statusBarHeight: 32
    property int buttonHeight: 36
    property int buttonHeightSmall: 28
    property int buttonHeightLarge: 44
    property int inputHeight: 40
    property int tableRowHeight: 48

    // --- Theme toggle ---
    function toggleTheme() {
        darkMode = !darkMode
    }
}
