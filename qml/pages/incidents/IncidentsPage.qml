import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../themes"
import "../../widgets"

Rectangle {
    id: incidentsPage
    objectName: "incidents"
    color: ThemeManager.backgroundColor

    property var incidentViewModel: QtObject {
        property int totalIncidents: 24
        property int criticalCount: 3
        property int highCount: 7
        property int mediumCount: 9
        property int lowCount: 5
        property int openCount: 8
        property int investigatingCount: 6
        property int resolvedCount: 7
        property int closedCount: 3

        Behavior on totalIncidents { NumberAnimation { duration: 600 } }
        Behavior on criticalCount { NumberAnimation { duration: 600 } }
        Behavior on openCount { NumberAnimation { duration: 600 } }
        Behavior on investigatingCount { NumberAnimation { duration: 600 } }
    }

    // Real-time data update timer
    Timer {
        interval: 2500
        running: incidentsPage.visible
        repeat: true
        onTriggered: {
            incidentViewModel.totalIncidents = incidentViewModel.totalIncidents + Math.floor(Math.random() * 3) - 1
            if (incidentViewModel.totalIncidents < 20) incidentViewModel.totalIncidents = 20
            if (incidentViewModel.totalIncidents > 35) incidentViewModel.totalIncidents = 35
            incidentViewModel.criticalCount = incidentViewModel.criticalCount + Math.floor(Math.random() * 3) - 1
            if (incidentViewModel.criticalCount < 1) incidentViewModel.criticalCount = 1
            if (incidentViewModel.criticalCount > 6) incidentViewModel.criticalCount = 6
            incidentViewModel.investigatingCount = incidentViewModel.investigatingCount + Math.floor(Math.random() * 3) - 1
            if (incidentViewModel.investigatingCount < 3) incidentViewModel.investigatingCount = 3
            if (incidentViewModel.investigatingCount > 10) incidentViewModel.investigatingCount = 10
        }
    }

    property bool showDetail: false
    property int selectedIncident: -1

    ScrollView {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingXL
        clip: true
        contentWidth: availableWidth

        ColumnLayout {
            width: parent.width
            spacing: ThemeManager.spacingXL

            // Header
            RowLayout {
                Layout.fillWidth: true
                ColumnLayout {
                    spacing: ThemeManager.spacingXS
                    Text { text: "Incident Management"; font.pixelSize: ThemeManager.fontSizeHeading; font.weight: Font.Bold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary }
                    Text { text: "Track, investigate, and resolve security incidents"; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textSecondary }
                }
                Item { Layout.fillWidth: true }
                Rectangle {
                    width: newIncLabel.implicitWidth + ThemeManager.spacingXL; height: ThemeManager.buttonHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.primaryColor
                    Text { id: newIncLabel; anchors.centerIn: parent; text: "+ New Incident"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textOnPrimary; font.family: ThemeManager.fontFamily }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor }
                }
            }

            // Stats
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Total Incidents"; value: incidentViewModel.totalIncidents.toString(); icon: "\u2139"; iconColor: ThemeManager.primaryColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Critical"; value: incidentViewModel.criticalCount.toString(); icon: "\u2620"; iconColor: ThemeManager.severityCritical }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Investigating"; value: incidentViewModel.investigatingCount.toString(); icon: "\uD83D\uDD0D"; iconColor: ThemeManager.warningColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Resolved"; value: incidentViewModel.resolvedCount.toString(); trend: -15.0; icon: "\u2713"; iconColor: ThemeManager.successColor }
            }

            // Severity + Status filters
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                RowLayout {
                    spacing: ThemeManager.spacingXS
                    Text { text: "Severity:"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                    Repeater {
                        model: ["All", "Critical", "High", "Medium", "Low"]
                        Rectangle {
                            width: sfLabel.implicitWidth + 14; height: 26; radius: 13
                            color: index === 0 ? ThemeManager.primaryColor : ThemeManager.cardColor
                            border.color: index === 0 ? ThemeManager.primaryColor : ThemeManager.borderColor; border.width: 1
                            Text { id: sfLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.Medium; color: index === 0 ? ThemeManager.textOnPrimary : ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor }
                        }
                    }
                }
                Item { Layout.fillWidth: true }
                RowLayout {
                    spacing: ThemeManager.spacingXS
                    Text { text: "Status:"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                    Repeater {
                        model: ["All", "Open", "Investigating", "Resolved", "Closed"]
                        Rectangle {
                            width: stLabel.implicitWidth + 14; height: 26; radius: 13
                            color: index === 0 ? ThemeManager.secondaryColor : ThemeManager.cardColor
                            border.color: index === 0 ? ThemeManager.secondaryColor : ThemeManager.borderColor; border.width: 1
                            Text { id: stLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.Medium; color: index === 0 ? ThemeManager.textOnPrimary : ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor }
                        }
                    }
                }
            }

            // Incident list OR detail
            Loader {
                Layout.fillWidth: true
                Layout.minimumHeight: 450
                sourceComponent: incidentsPage.showDetail ? incidentDetailView : incidentListView
            }
        }
    }

    Component {
        id: incidentListView
        DataTable {
            title: "Incidents"
            columns: [
                { key: "id", label: "ID", width: 80 },
                { key: "title", label: "Title", width: 260 },
                { key: "severity", label: "Severity", width: 90 },
                { key: "status", label: "Status", width: 110 },
                { key: "assignee", label: "Assignee", width: 120 },
                { key: "created", label: "Created", width: 140 },
                { key: "updated", label: "Updated", width: 100 }
            ]
            rows: [
                { id: "INC-001", title: "Ransomware outbreak - Finance dept", severity: "Critical", status: "Investigating", assignee: "J. Smith", created: "2024-12-15 14:30", updated: "2m ago" },
                { id: "INC-002", title: "Data exfiltration via DNS tunneling", severity: "Critical", status: "Open", assignee: "A. Chen", created: "2024-12-15 12:00", updated: "15m ago" },
                { id: "INC-003", title: "Compromised admin credentials", severity: "Critical", status: "Investigating", assignee: "M. Garcia", created: "2024-12-15 10:15", updated: "1h ago" },
                { id: "INC-004", title: "Lateral movement in DMZ", severity: "High", status: "Open", assignee: "Unassigned", created: "2024-12-15 09:00", updated: "2h ago" },
                { id: "INC-005", title: "Phishing campaign targeting execs", severity: "High", status: "Investigating", assignee: "K. Patel", created: "2024-12-14 16:30", updated: "4h ago" },
                { id: "INC-006", title: "Unauthorized VPN access", severity: "High", status: "Resolved", assignee: "J. Smith", created: "2024-12-14 11:00", updated: "8h ago" },
                { id: "INC-007", title: "Cryptominer on build server", severity: "Medium", status: "Resolved", assignee: "T. Wilson", created: "2024-12-13 14:00", updated: "1d ago" },
                { id: "INC-008", title: "Suspicious scheduled tasks", severity: "Medium", status: "Open", assignee: "A. Chen", created: "2024-12-13 10:30", updated: "1d ago" },
                { id: "INC-009", title: "Policy violation - USB device", severity: "Low", status: "Closed", assignee: "K. Patel", created: "2024-12-12 09:00", updated: "3d ago" },
                { id: "INC-010", title: "Failed login brute force", severity: "Medium", status: "Resolved", assignee: "M. Garcia", created: "2024-12-11 22:00", updated: "4d ago" }
            ]
            onRowClicked: function(idx) { incidentsPage.selectedIncident = idx; incidentsPage.showDetail = true }
        }
    }

    Component {
        id: incidentDetailView
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            // Back button and incident header
            RowLayout {
                Layout.fillWidth: true
                Rectangle {
                    width: backLabel.implicitWidth + 16; height: 32; radius: ThemeManager.radiusMedium; color: ThemeManager.cardColor; border.color: ThemeManager.borderColor; border.width: 1
                    Text { id: backLabel; anchors.centerIn: parent; text: "\u2190 Back to List"; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.primaryColor; font.family: ThemeManager.fontFamily }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: incidentsPage.showDetail = false }
                }
                Item { Layout.fillWidth: true }
                Rectangle { width: 80; height: 32; radius: ThemeManager.radiusMedium; color: ThemeManager.errorColor; Text { anchors.centerIn: parent; text: "Critical"; font.pixelSize: ThemeManager.fontSizeSmall; font.weight: Font.Medium; color: "#ffffff"; font.family: ThemeManager.fontFamily } }
            }

            // Incident detail card
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 120
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor; border.width: 1

                ColumnLayout {
                    anchors.fill: parent; anchors.margins: ThemeManager.spacingLarge
                    spacing: ThemeManager.spacingSmall
                    Text { text: "INC-001: Ransomware outbreak - Finance dept"; font.pixelSize: ThemeManager.fontSizeLarge; font.weight: Font.Bold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                    RowLayout {
                        spacing: ThemeManager.spacingNormal
                        Text { text: "Status: Investigating"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.warningColor; font.family: ThemeManager.fontFamily }
                        Text { text: "Assignee: J. Smith"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        Text { text: "Created: 2024-12-15 14:30"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                    }
                    Text { text: "LockBit ransomware variant detected on 3 workstations in Finance department. Files being encrypted. Immediate containment required."; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                }
            }

            // Timeline and evidence side by side
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                TimelineView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 280
                    title: "Incident Timeline"
                    events: [
                        { time: "14:35", title: "Containment initiated", description: "Network isolation applied to affected hosts", severity: "info" },
                        { time: "14:32", title: "Encryption detected", description: "Rapid file modification on FIN-WS-003, FIN-WS-007, FIN-WS-012", severity: "critical" },
                        { time: "14:30", title: "Ransomware executed", description: "LockBit 3.0 binary executed via scheduled task", severity: "critical" },
                        { time: "14:25", title: "Lateral spread", description: "PsExec used to copy payload to 2 additional hosts", severity: "high" },
                        { time: "14:18", title: "Initial execution", description: "Malicious macro triggered from invoice_Q4.docm on FIN-WS-003", severity: "high" }
                    ]
                }

                // Remediation steps
                Rectangle {
                    Layout.preferredWidth: 320
                    Layout.preferredHeight: 280
                    radius: ThemeManager.radiusLarge
                    color: ThemeManager.surfaceColor
                    border.color: ThemeManager.borderColor; border.width: 1

                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: ThemeManager.spacingLarge
                        spacing: ThemeManager.spacingSmall
                        Text { text: "Remediation Steps"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                        Repeater {
                            model: ListModel {
                                ListElement { step: "Isolate affected endpoints from network"; done: true }
                                ListElement { step: "Kill malicious processes and services"; done: true }
                                ListElement { step: "Collect forensic evidence (memory dumps)"; done: false }
                                ListElement { step: "Restore files from backup"; done: false }
                                ListElement { step: "Reset compromised credentials"; done: false }
                                ListElement { step: "Patch vulnerability and re-image hosts"; done: false }
                                ListElement { step: "Monitor for re-infection indicators"; done: false }
                            }
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: ThemeManager.spacingSmall
                                Rectangle { width: 20; height: 20; radius: 4; color: model.done ? ThemeManager.successColor : "transparent"; border.color: model.done ? ThemeManager.successColor : ThemeManager.borderColor; border.width: 1; Text { anchors.centerIn: parent; text: model.done ? "\u2713" : ""; font.pixelSize: 12; color: "#ffffff" } }
                                Text { text: model.step; font.pixelSize: ThemeManager.fontSizeSmall; color: model.done ? ThemeManager.textMuted : ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.fillWidth: true; wrapMode: Text.WordWrap }
                            }
                        }
                    }
                }
            }
        }
    }
}
