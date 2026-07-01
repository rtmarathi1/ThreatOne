import QtQuick 2.15

pragma Singleton

// Theme manager singleton that provides colors, fonts,
// and spacing for the entire application
QtObject {
    id: themeManager

    property bool darkMode: true

    // Colors
    property color backgroundColor: darkMode ? "#0a0a1a" : "#f8fafc"
    property color surfaceColor: darkMode ? "#1a1a2e" : "#ffffff"
    property color primaryColor: "#00d4ff"
    property color accentColor: "#8b5cf6"
    property color successColor: "#4ade80"
    property color warningColor: "#f59e0b"
    property color errorColor: "#ef4444"
    property color textPrimary: darkMode ? "#ffffff" : "#1e293b"
    property color textSecondary: darkMode ? "#8892b0" : "#64748b"
    property color borderColor: darkMode ? "#2a2a4a" : "#e2e8f0"

    // Fonts
    property string fontFamily: "Inter"
    property int fontSizeSmall: 11
    property int fontSizeNormal: 14
    property int fontSizeLarge: 18
    property int fontSizeTitle: 24
    property int fontSizeHeading: 28

    // Spacing
    property int spacingSmall: 8
    property int spacingMedium: 16
    property int spacingLarge: 24
    property int spacingXLarge: 32

    // Border radius
    property int radiusSmall: 4
    property int radiusMedium: 8
    property int radiusLarge: 12
    property int radiusXLarge: 16

    // Shadows
    property color shadowColor: darkMode ? "#000000" : "#1e293b"
    property real shadowOpacity: darkMode ? 0.4 : 0.1

    function toggleTheme() {
        darkMode = !darkMode
    }
}
