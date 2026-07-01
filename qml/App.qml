import QtQuick
import QtQuick.Controls

// Root application state management component.
// Manages theme state, navigation with history, global alert/score bindings,
// connection status, and utility navigation functions.
Item {
    id: app
    anchors.fill: parent

    // --- Theme State ---
    property bool darkMode: true
    property var theme: darkMode ? darkTheme : lightTheme

    DarkTheme { id: darkTheme }
    LightTheme { id: lightTheme }

    // --- Navigation State ---
    property string currentPage: "dashboard"
    property var navigationHistory: []
    property int maxHistoryLength: 50

    // --- Global Application State ---
    property bool connected: true
    property int alertCount: 5
    property int criticalAlertCount: 2
    property double securityScore: 85.0
    property string securityGrade: securityScore >= 90 ? "A+" :
                                    securityScore >= 80 ? "A" :
                                    securityScore >= 70 ? "B" :
                                    securityScore >= 60 ? "C" : "D"
    property bool protectionActive: true
    property bool scanRunning: false
    property real scanProgress: 0.0
    property int threatsDetected: 0
    property int totalEndpoints: 142
    property int onlineEndpoints: 138
    property string lastScanTime: "14:32"

    // --- System Health ---
    property real cpuUsage: 0.23
    property real memoryUsage: 0.45
    property real diskUsage: 0.62
    property real networkThroughput: 0.0

    // --- User Info ---
    property string userName: "Admin"
    property string userInitials: "AD"
    property string userRole: "Security Administrator"

    // --- Navigation Functions ---
    function navigateTo(page) {
        if (page === currentPage) return
        if (navigationHistory.length >= maxHistoryLength) {
            navigationHistory.shift()
        }
        navigationHistory.push(currentPage)
        currentPage = page
    }

    function navigateBack() {
        if (navigationHistory.length > 0) {
            currentPage = navigationHistory.pop()
        }
    }

    function canNavigateBack() {
        return navigationHistory.length > 0
    }

    function clearHistory() {
        navigationHistory = []
    }

    // --- Theme Functions ---
    function toggleTheme() {
        darkMode = !darkMode
        ThemeManager.darkMode = darkMode
    }

    // --- Utility Functions ---
    function formatTimestamp(date) {
        var now = new Date()
        var diff = (now - date) / 1000
        if (diff < 60) return "Just now"
        if (diff < 3600) return Math.floor(diff / 60) + "m ago"
        if (diff < 86400) return Math.floor(diff / 3600) + "h ago"
        return Math.floor(diff / 86400) + "d ago"
    }

    function severityColor(severity) {
        switch(severity) {
            case "critical": return ThemeManager.severityCritical
            case "high": return ThemeManager.severityHigh
            case "medium": return ThemeManager.severityMedium
            case "low": return ThemeManager.severityLow
            default: return ThemeManager.severityInfo
        }
    }

    function severityWeight(severity) {
        switch(severity) {
            case "critical": return 4
            case "high": return 3
            case "medium": return 2
            case "low": return 1
            default: return 0
        }
    }
}
