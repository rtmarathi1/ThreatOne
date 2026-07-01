import QtQuick 2.15
import QtQuick.Controls 2.15
import "themes"

// Root application item that wraps theme management and navigation
Item {
    id: app
    anchors.fill: parent

    // Theme provider - manages dark/light mode switching
    property bool darkMode: true
    property var theme: darkMode ? darkTheme : lightTheme

    DarkTheme {
        id: darkTheme
    }

    LightTheme {
        id: lightTheme
    }

    // Global theme manager singleton reference
    ThemeManager {
        id: themeManager
    }

    // Navigation state
    property string currentPage: "dashboard"
    property var navigationHistory: []

    function navigateTo(page) {
        navigationHistory.push(currentPage)
        currentPage = page
    }

    function navigateBack() {
        if (navigationHistory.length > 0) {
            currentPage = navigationHistory.pop()
        }
    }

    // Application state
    property bool connected: true
    property int alertCount: 0
    property double securityScore: 85.0
}
