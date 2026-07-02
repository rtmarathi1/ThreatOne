import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../themes"

// Enhanced navigation sidebar with icons, badges, collapsible sections,
// active state highlighting with left accent bar, and collapse/expand toggle
Rectangle {
    id: sidebar
    color: ThemeManager.sidebarColor
    width: collapsed ? ThemeManager.sidebarCollapsedWidth : ThemeManager.sidebarExpandedWidth
    clip: true

    Behavior on width { NumberAnimation { duration: ThemeManager.animNormal; easing.type: Easing.OutCubic } }

    signal pageSelected(string page)

    property int currentIndex: 0
    property bool collapsed: false

    // Section model with grouped navigation items
    property var sections: [
        {
            title: "Security",
            items: [
                { title: "Dashboard", icon: "\u2302", page: "pages/dashboard/DashboardPage.qml", badge: 0 },
                { title: "Scanner", icon: "\u2315", page: "pages/scanner/ScannerPage.qml", badge: 0 },
                { title: "Firewall", icon: "\u2616", page: "pages/firewall/FirewallPage.qml", badge: 2 },
                { title: "EDR", icon: "\u2699", page: "pages/edr/EDRPage.qml", badge: 5 }
            ]
        },
        {
            title: "Analysis",
            items: [
                { title: "Incidents", icon: "\u26A0", page: "pages/incidents/IncidentsPage.qml", badge: 3 },
                { title: "Threat Intel", icon: "\u2604", page: "pages/threat_intel/ThreatIntelPage.qml", badge: 0 },
                { title: "Reports", icon: "\u2637", page: "pages/reports/ReportsPage.qml", badge: 0 }
            ]
        },
        {
            title: "Management",
            items: [
                { title: "Assets", icon: "\u2316", page: "pages/assets/AssetsPage.qml", badge: 0 },
                { title: "Users", icon: "\u263A", page: "pages/users/UsersPage.qml", badge: 0 },
                { title: "Settings", icon: "\u2699", page: "pages/settings/SettingsPage.qml", badge: 0 }
            ]
        }
    ]

    // Flatten items for index tracking
    property var flatItems: {
        var items = []
        for (var s = 0; s < sections.length; s++) {
            for (var i = 0; i < sections[s].items.length; i++) {
                items.push(sections[s].items[i])
            }
        }
        return items
    }

    // Pre-computed section offsets for flat index lookup
    property var sectionOffsets: {
        var offsets = []
        var offset = 0
        for (var s = 0; s < sections.length; s++) {
            offsets.push(offset)
            offset += sections[s].items.length
        }
        return offsets
    }

    // Compute flat index from section index and item index
    function computeFlatIndex(sectionIndex, itemIndex) {
        return sectionOffsets[sectionIndex] + itemIndex
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Logo / Brand area
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: ThemeManager.topbarHeight
            color: ThemeManager.surfaceVariantColor

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: sidebar.collapsed ? 0 : ThemeManager.spacingNormal
                anchors.rightMargin: ThemeManager.spacingSmall
                spacing: ThemeManager.spacingSmall

                // Logo icon
                Rectangle {
                    Layout.preferredWidth: 36
                    Layout.preferredHeight: 36
                    Layout.alignment: Qt.AlignVCenter
                    Layout.leftMargin: sidebar.collapsed ? (sidebar.width - 36) / 2 : 0
                    radius: ThemeManager.radiusMedium
                    color: ThemeManager.primaryColor
                    opacity: 0.15

                    Text {
                        anchors.centerIn: parent
                        text: "\u2616"
                        font.pixelSize: 18
                        color: ThemeManager.primaryColor
                    }
                }

                // Brand text
                Text {
                    visible: !sidebar.collapsed
                    text: "ThreatOne"
                    font.pixelSize: ThemeManager.fontSizeLarge
                    font.weight: Font.Bold
                    font.family: ThemeManager.fontFamily
                    color: ThemeManager.primaryColor
                    Layout.fillWidth: true
                }
            }
        }

        // Scrollable navigation
        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            contentHeight: navColumn.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: navColumn
                width: parent.width
                spacing: 0

                // Sections
                Repeater {
                    model: sidebar.sections

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0

                        // Store section index as a named property for child access
                        property int sectionIdx: index

                        // Section header
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 32
                            Layout.topMargin: index > 0 ? ThemeManager.spacingMedium : ThemeManager.spacingSmall
                            color: "transparent"
                            visible: !sidebar.collapsed

                            Text {
                                anchors.left: parent.left
                                anchors.leftMargin: ThemeManager.spacingNormal
                                anchors.verticalCenter: parent.verticalCenter
                                text: modelData.title.toUpperCase()
                                font.pixelSize: ThemeManager.fontSizeXS
                                font.weight: Font.DemiBold
                                font.family: ThemeManager.fontFamily
                                color: ThemeManager.textMuted
                                font.letterSpacing: 1.2
                            }
                        }

                        // Section divider (collapsed mode)
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 1
                            Layout.topMargin: index > 0 ? ThemeManager.spacingSmall : 0
                            Layout.leftMargin: ThemeManager.spacingSmall
                            Layout.rightMargin: ThemeManager.spacingSmall
                            color: ThemeManager.dividerColor
                            visible: sidebar.collapsed && index > 0
                        }

                        // Navigation items
                        Repeater {
                            id: itemsRepeater
                            model: modelData.items

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 44
                                Layout.leftMargin: sidebar.collapsed ? 4 : ThemeManager.spacingSmall
                                Layout.rightMargin: sidebar.collapsed ? 4 : ThemeManager.spacingSmall
                                radius: ThemeManager.radiusMedium

                                property int itemIndex: index
                                property int sectionIndex: sectionIdx
                                property int flatIdx: sidebar.computeFlatIndex(sectionIndex, itemIndex)

                                color: sidebar.currentIndex === flatIdx ? ThemeManager.sidebarActiveColor : "transparent"

                                // Left accent bar for active item
                                Rectangle {
                                    anchors.left: parent.left
                                    anchors.top: parent.top
                                    anchors.bottom: parent.bottom
                                    anchors.topMargin: 8
                                    anchors.bottomMargin: 8
                                    width: 3
                                    radius: 2
                                    color: ThemeManager.primaryColor
                                    visible: sidebar.currentIndex === parent.flatIdx
                                }

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: sidebar.collapsed ? 0 : ThemeManager.spacingNormal
                                    anchors.rightMargin: ThemeManager.spacingSmall
                                    spacing: ThemeManager.spacingMedium

                                    // Icon
                                    Text {
                                        Layout.preferredWidth: sidebar.collapsed ? parent.width : 20
                                        Layout.alignment: Qt.AlignVCenter
                                        text: modelData.icon
                                        font.pixelSize: 18
                                        color: sidebar.currentIndex === parent.parent.flatIdx ? ThemeManager.primaryColor : ThemeManager.textSecondary
                                        horizontalAlignment: sidebar.collapsed ? Text.AlignHCenter : Text.AlignLeft
                                    }

                                    // Title text
                                    Text {
                                        visible: !sidebar.collapsed
                                        Layout.fillWidth: true
                                        text: modelData.title
                                        font.pixelSize: ThemeManager.fontSizeNormal
                                        font.weight: sidebar.currentIndex === parent.parent.flatIdx ? Font.DemiBold : Font.Normal
                                        font.family: ThemeManager.fontFamily
                                        color: sidebar.currentIndex === parent.parent.flatIdx ? ThemeManager.textPrimary : ThemeManager.textSecondary
                                    }

                                    // Badge
                                    Rectangle {
                                        visible: !sidebar.collapsed && modelData.badge > 0
                                        width: 20; height: 20; radius: 10
                                        color: ThemeManager.errorColor

                                        Text {
                                            anchors.centerIn: parent
                                            text: modelData.badge.toString()
                                            font.pixelSize: ThemeManager.fontSizeXS
                                            font.weight: Font.Bold
                                            font.family: ThemeManager.fontFamily
                                            color: "#ffffff"
                                        }
                                    }
                                }

                                // Tooltip for collapsed mode
                                ToolTip {
                                    visible: sidebar.collapsed && hoverArea.containsMouse
                                    text: modelData.title
                                    delay: 400
                                }

                                MouseArea {
                                    id: hoverArea
                                    anchors.fill: parent
                                    cursorShape: Qt.PointingHandCursor
                                    hoverEnabled: true
                                    onClicked: {
                                        sidebar.currentIndex = parent.flatIdx
                                        sidebar.pageSelected(modelData.page)
                                    }
                                    onEntered: {
                                        if (sidebar.currentIndex !== parent.flatIdx)
                                            parent.color = ThemeManager.hoverColor
                                    }
                                    onExited: {
                                        if (sidebar.currentIndex !== parent.flatIdx)
                                            parent.color = "transparent"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Collapse toggle + version footer
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 48
            color: ThemeManager.surfaceVariantColor

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: sidebar.collapsed ? 0 : ThemeManager.spacingNormal
                anchors.rightMargin: ThemeManager.spacingSmall
                spacing: ThemeManager.spacingSmall

                // Collapse/Expand button
                Rectangle {
                    Layout.preferredWidth: 32
                    Layout.preferredHeight: 32
                    Layout.alignment: Qt.AlignVCenter
                    Layout.leftMargin: sidebar.collapsed ? (sidebar.width - 32) / 2 : 0
                    radius: ThemeManager.radiusSmall
                    color: "transparent"

                    Text {
                        anchors.centerIn: parent
                        text: sidebar.collapsed ? "\u25B6" : "\u25C0"
                        font.pixelSize: 12
                        color: ThemeManager.textSecondary
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        hoverEnabled: true
                        onClicked: sidebar.collapsed = !sidebar.collapsed
                        onEntered: parent.color = ThemeManager.hoverColor
                        onExited: parent.color = "transparent"
                    }
                }

                // Version/status text
                Text {
                    visible: !sidebar.collapsed
                    Layout.fillWidth: true
                    text: "v2.0.0 \u2022 Protected"
                    font.pixelSize: ThemeManager.fontSizeXS
                    font.family: ThemeManager.fontFamily
                    color: ThemeManager.successColor
                }
            }
        }
    }

    // Right border separator
    Rectangle {
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: 1
        color: ThemeManager.borderColor
    }
}
