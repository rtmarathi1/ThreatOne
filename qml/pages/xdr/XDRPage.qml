import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../themes"
import "../../widgets"

Rectangle {
    id: xdrPage
    objectName: "xdr"
    color: ThemeManager.backgroundColor

    // ViewModel binding placeholders
    property var xdrViewModel: QtObject {
        property int activeInvestigations: 14
        property int automatedResponses: 89
        property int dataSourcesConnected: 47
        property string meanTimeToRespond: "4.2m"
        property int resolvedToday: 23
        property int pendingActions: 7

        Behavior on activeInvestigations { NumberAnimation { duration: 600; easing.type: Easing.OutCubic } }
        Behavior on automatedResponses { NumberAnimation { duration: 600; easing.type: Easing.OutCubic } }
    }

    // Investigation data model
    ListModel {
        id: investigationModel
        ListElement { invId: "INV-2847"; invTitle: "Ransomware Activity Chain"; invSeverity: "Critical"; invStatus: "Active"; invAssets: "WS-2847, SRV-DB01"; invAnalyst: "J. Morrison"; invTime: "12m ago" }
        ListElement { invId: "INV-2846"; invTitle: "Lateral Movement Detection"; invSeverity: "High"; invStatus: "Active"; invAssets: "10.0.1.15, 10.0.1.22"; invAnalyst: "S. Chen"; invTime: "28m ago" }
        ListElement { invId: "INV-2845"; invTitle: "Credential Theft Attempt"; invSeverity: "High"; invStatus: "Investigating"; invAssets: "DC-01"; invAnalyst: "M. Johnson"; invTime: "45m ago" }
        ListElement { invId: "INV-2844"; invTitle: "Suspicious DNS Tunneling"; invSeverity: "Medium"; invStatus: "Contained"; invAssets: "WS-1204"; invAnalyst: "A. Patel"; invTime: "1h ago" }
        ListElement { invId: "INV-2843"; invTitle: "Phishing Campaign Detected"; invSeverity: "Medium"; invStatus: "Active"; invAssets: "Mail-GW"; invAnalyst: "J. Morrison"; invTime: "1.5h ago" }
        ListElement { invId: "INV-2842"; invTitle: "Unauthorized Access Attempt"; invSeverity: "Low"; invStatus: "Resolved"; invAssets: "VPN-GW"; invAnalyst: "S. Chen"; invTime: "2h ago" }
    }

    // Timer for real-time updates
    Timer {
        id: xdrUpdateTimer
        interval: 3000
        running: true
        repeat: true
        onTriggered: {
            xdrViewModel.activeInvestigations = 12 + Math.floor(Math.random() * 6)
            xdrViewModel.automatedResponses += Math.floor(Math.random() * 2)
            xdrViewModel.pendingActions = 5 + Math.floor(Math.random() * 5)
        }
    }

    // New investigation timer
    Timer {
        id: newInvestigationTimer
        interval: 8000
        running: true
        repeat: true
        onTriggered: {
            var severities = ["Critical", "High", "Medium", "Low"]
            var titles = ["Anomalous Process Execution", "Data Staging Detected", "Beaconing Activity", "Policy Violation", "Suspicious File Download"]
            var analysts = ["J. Morrison", "S. Chen", "M. Johnson", "A. Patel"]
            var assets = ["WS-" + Math.floor(1000 + Math.random() * 9000), "SRV-" + Math.floor(10 + Math.random() * 90)]

            var invNum = 2848 + Math.floor(Math.random() * 100)
            investigationModel.insert(0, {
                invId: "INV-" + invNum,
                invTitle: titles[Math.floor(Math.random() * titles.length)],
                invSeverity: severities[Math.floor(Math.random() * severities.length)],
                invStatus: "Active",
                invAssets: assets,
                invAnalyst: analysts[Math.floor(Math.random() * analysts.length)],
                invTime: "Just now"
            })

            if (investigationModel.count > 12) {
                investigationModel.remove(12, investigationModel.count - 12)
            }
        }
    }

    // Kill chain stages
    property var killChainStages: [
        { name: "Recon", detections: 3, color: ThemeManager.primaryColor },
        { name: "Weaponize", detections: 1, color: ThemeManager.secondaryColor },
        { name: "Delivery", detections: 5, color: ThemeManager.warningColor },
        { name: "Exploit", detections: 2, color: ThemeManager.warningColor },
        { name: "Install", detections: 4, color: ThemeManager.errorColor },
        { name: "C2", detections: 2, color: ThemeManager.errorColor },
        { name: "Actions", detections: 1, color: ThemeManager.errorColor }
    ]

    ScrollView {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingXL
        clip: true
        contentWidth: availableWidth

        ColumnLayout {
            width: parent.width
            spacing: ThemeManager.spacingXL

            // Page header
            RowLayout {
                Layout.fillWidth: true
                ColumnLayout {
                    spacing: ThemeManager.spacingXS
                    Text {
                        text: "XDR Platform"
                        font.pixelSize: ThemeManager.fontSizeHeading
                        font.weight: Font.Bold
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textPrimary
                    }
                    Text {
                        text: "Extended Detection and Response - Unified threat investigation and automated response"
                        font.pixelSize: ThemeManager.fontSizeNormal
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textSecondary
                    }
                }
                Item { Layout.fillWidth: true }
                Rectangle {
                    width: xdrStatusRow.implicitWidth + 16
                    height: 28
                    radius: ThemeManager.radiusSmall
                    color: Qt.rgba(ThemeManager.primaryColor.r, ThemeManager.primaryColor.g, ThemeManager.primaryColor.b, 0.15)
                    RowLayout {
                        id: xdrStatusRow
                        anchors.centerIn: parent
                        spacing: ThemeManager.spacingXS
                        Rectangle { width: 8; height: 8; radius: 4; color: ThemeManager.primaryColor }
                        Text {
                            text: xdrViewModel.pendingActions + " Actions Pending"
                            font.pixelSize: ThemeManager.fontSizeSmall
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.primaryColor
                            font.weight: Font.Medium
                        }
                    }
                }
            }

            // Stats row
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal

                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Active Investigations"
                    value: xdrViewModel.activeInvestigations.toString()
                    trend: 12.5
                    icon: "\u2316"
                    iconColor: ThemeManager.errorColor
                    sparklineData: [10, 12, 11, 14, 13, 15, 14]
                }
                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Automated Responses"
                    value: xdrViewModel.automatedResponses.toString()
                    trend: 24.1
                    icon: "\u26A1"
                    iconColor: ThemeManager.successColor
                    sparklineData: [72, 75, 78, 81, 84, 87, 89]
                }
                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "Data Sources"
                    value: xdrViewModel.dataSourcesConnected.toString()
                    trend: 6.3
                    icon: "\u2637"
                    iconColor: ThemeManager.primaryColor
                }
                StatCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    title: "MTTR"
                    value: xdrViewModel.meanTimeToRespond
                    trend: -18.5
                    icon: "\u231A"
                    iconColor: ThemeManager.secondaryColor
                }
            }

            // Kill Chain Visualization
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 140
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: ThemeManager.spacingLarge
                    spacing: ThemeManager.spacingMedium

                    Text {
                        text: "Kill Chain Coverage"
                        font.pixelSize: ThemeManager.fontSizeMedium
                        font.weight: Font.DemiBold
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textPrimary
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: ThemeManager.spacingSmall

                        Repeater {
                            model: xdrPage.killChainStages.length

                            RowLayout {
                                spacing: 2
                                property var stageData: xdrPage.killChainStages[index]

                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.preferredWidth: 100
                                    height: 60
                                    radius: ThemeManager.radiusMedium
                                    color: Qt.rgba(stageData.color.r, stageData.color.g, stageData.color.b, 0.15)
                                    border.color: Qt.rgba(stageData.color.r, stageData.color.g, stageData.color.b, 0.5)
                                    border.width: 1

                                    ColumnLayout {
                                        anchors.centerIn: parent
                                        spacing: 4
                                        Text {
                                            Layout.alignment: Qt.AlignHCenter
                                            text: stageData.name
                                            font.pixelSize: ThemeManager.fontSizeXS
                                            font.weight: Font.Medium
                                            font.family: ThemeManager.fontFamily
                                            color: ThemeManager.textPrimary
                                        }
                                        Rectangle {
                                            Layout.alignment: Qt.AlignHCenter
                                            width: 22; height: 22; radius: 11
                                            color: stageData.color
                                            Text {
                                                anchors.centerIn: parent
                                                text: stageData.detections.toString()
                                                font.pixelSize: 10
                                                font.weight: Font.Bold
                                                font.family: ThemeManager.fontFamily
                                                color: "#ffffff"
                                            }
                                        }
                                    }
                                }

                                // Arrow connector (not on last item)
                                Text {
                                    visible: index < xdrPage.killChainStages.length - 1
                                    text: "\u25B6"
                                    font.pixelSize: 10
                                    color: ThemeManager.textMuted
                                }
                            }
                        }
                    }
                }
            }

            // Investigation Queue
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 380
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: ThemeManager.spacingLarge
                    spacing: ThemeManager.spacingMedium

                    RowLayout {
                        Layout.fillWidth: true
                        Text {
                            text: "Investigation Queue"
                            font.pixelSize: ThemeManager.fontSizeMedium
                            font.weight: Font.DemiBold
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textPrimary
                        }
                        Item { Layout.fillWidth: true }
                        Text {
                            text: xdrViewModel.resolvedToday + " resolved today"
                            font.pixelSize: ThemeManager.fontSizeSmall
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.successColor
                        }
                    }

                    // Column headers
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: ThemeManager.spacingSmall
                        Text { Layout.preferredWidth: 70; text: "ID"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        Text { Layout.fillWidth: true; text: "INVESTIGATION"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        Text { Layout.preferredWidth: 60; text: "SEVERITY"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        Text { Layout.preferredWidth: 80; text: "STATUS"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        Text { Layout.preferredWidth: 120; text: "ASSETS"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        Text { Layout.preferredWidth: 80; text: "ANALYST"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        Text { Layout.preferredWidth: 60; text: "TIME"; font.pixelSize: ThemeManager.fontSizeXS; font.weight: Font.DemiBold; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: ThemeManager.borderColor
                    }

                    ListView {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 2
                        model: investigationModel

                        delegate: Rectangle {
                            width: ListView.view.width
                            height: 40
                            radius: ThemeManager.radiusSmall
                            color: index % 2 === 0 ? "transparent" : Qt.rgba(ThemeManager.cardColor.r, ThemeManager.cardColor.g, ThemeManager.cardColor.b, 0.5)

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: ThemeManager.spacingXS
                                anchors.rightMargin: ThemeManager.spacingXS
                                spacing: ThemeManager.spacingSmall

                                Text {
                                    Layout.preferredWidth: 70
                                    text: model.invId
                                    font.pixelSize: ThemeManager.fontSizeSmall
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.primaryColor
                                    font.weight: Font.Medium
                                }
                                Text {
                                    Layout.fillWidth: true
                                    text: model.invTitle
                                    font.pixelSize: ThemeManager.fontSizeSmall
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.textPrimary
                                    elide: Text.ElideRight
                                }
                                Rectangle {
                                    Layout.preferredWidth: 60
                                    height: 20
                                    radius: ThemeManager.radiusSmall
                                    color: model.invSeverity === "Critical" ? Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.15) :
                                           model.invSeverity === "High" ? Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.15) :
                                           model.invSeverity === "Medium" ? Qt.rgba(ThemeManager.secondaryColor.r, ThemeManager.secondaryColor.g, ThemeManager.secondaryColor.b, 0.15) :
                                           Qt.rgba(ThemeManager.successColor.r, ThemeManager.successColor.g, ThemeManager.successColor.b, 0.15)
                                    Text {
                                        anchors.centerIn: parent
                                        text: model.invSeverity
                                        font.pixelSize: 9
                                        font.weight: Font.Medium
                                        font.family: ThemeManager.fontFamily
                                        color: model.invSeverity === "Critical" ? ThemeManager.errorColor :
                                               model.invSeverity === "High" ? ThemeManager.warningColor :
                                               model.invSeverity === "Medium" ? ThemeManager.secondaryColor :
                                               ThemeManager.successColor
                                    }
                                }
                                Rectangle {
                                    Layout.preferredWidth: 80
                                    height: 20
                                    radius: ThemeManager.radiusSmall
                                    color: model.invStatus === "Active" ? Qt.rgba(ThemeManager.errorColor.r, ThemeManager.errorColor.g, ThemeManager.errorColor.b, 0.1) :
                                           model.invStatus === "Investigating" ? Qt.rgba(ThemeManager.warningColor.r, ThemeManager.warningColor.g, ThemeManager.warningColor.b, 0.1) :
                                           model.invStatus === "Contained" ? Qt.rgba(ThemeManager.primaryColor.r, ThemeManager.primaryColor.g, ThemeManager.primaryColor.b, 0.1) :
                                           Qt.rgba(ThemeManager.successColor.r, ThemeManager.successColor.g, ThemeManager.successColor.b, 0.1)
                                    Text {
                                        anchors.centerIn: parent
                                        text: model.invStatus
                                        font.pixelSize: 9
                                        font.weight: Font.Medium
                                        font.family: ThemeManager.fontFamily
                                        color: model.invStatus === "Active" ? ThemeManager.errorColor :
                                               model.invStatus === "Investigating" ? ThemeManager.warningColor :
                                               model.invStatus === "Contained" ? ThemeManager.primaryColor :
                                               ThemeManager.successColor
                                    }
                                }
                                Text {
                                    Layout.preferredWidth: 120
                                    text: model.invAssets
                                    font.pixelSize: ThemeManager.fontSizeSmall
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.textSecondary
                                    elide: Text.ElideRight
                                }
                                Text {
                                    Layout.preferredWidth: 80
                                    text: model.invAnalyst
                                    font.pixelSize: ThemeManager.fontSizeSmall
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.textSecondary
                                }
                                Text {
                                    Layout.preferredWidth: 60
                                    text: model.invTime
                                    font.pixelSize: ThemeManager.fontSizeSmall
                                    font.family: ThemeManager.fontFamily
                                    color: ThemeManager.textMuted
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
