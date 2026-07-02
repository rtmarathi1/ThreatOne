import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../themes"
import "../../widgets"

Rectangle {
    id: reportsPage
    objectName: "reports"
    color: ThemeManager.backgroundColor

    property var reportViewModel: QtObject {
        property int totalReports: 47
        property int scheduledReports: 5
        property int templatesCount: 8
        property string lastGenerated: "2024-12-15 14:00"
    }

    property int currentTab: 0
    property int wizardStep: 0

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
                    Text { text: "Report Center"; font.pixelSize: ThemeManager.fontSizeHeading; font.weight: Font.Bold; font.family: ThemeManager.fontFamily; color: ThemeManager.textPrimary }
                    Text { text: "Generate, schedule, and manage security reports"; font.pixelSize: ThemeManager.fontSizeNormal; font.family: ThemeManager.fontFamily; color: ThemeManager.textSecondary }
                }
                Item { Layout.fillWidth: true }
                Rectangle {
                    width: genLabel.implicitWidth + ThemeManager.spacingXL; height: ThemeManager.buttonHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.primaryColor
                    Text { id: genLabel; anchors.centerIn: parent; text: "+ Generate Report"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textOnPrimary; font.family: ThemeManager.fontFamily }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { reportsPage.currentTab = 0; reportsPage.wizardStep = 0 } }
                }
            }

            // Stats
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingNormal
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Total Reports"; value: reportViewModel.totalReports.toString(); icon: "\u2261"; iconColor: ThemeManager.primaryColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Scheduled"; value: reportViewModel.scheduledReports.toString(); icon: "\u23F0"; iconColor: ThemeManager.warningColor }
                StatCard { Layout.fillWidth: true; Layout.preferredHeight: 100; title: "Templates"; value: reportViewModel.templatesCount.toString(); icon: "\u2750"; iconColor: ThemeManager.secondaryColor }
            }

            // Tabs
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingXS
                Repeater {
                    model: ["Report Wizard", "Templates", "Generated Reports"]
                    Rectangle {
                        Layout.preferredHeight: 36; Layout.preferredWidth: rptTabLabel.implicitWidth + ThemeManager.spacingXL; radius: ThemeManager.radiusMedium
                        color: reportsPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.cardColor
                        border.color: reportsPage.currentTab === index ? ThemeManager.primaryColor : ThemeManager.borderColor; border.width: 1
                        Text { id: rptTabLabel; anchors.centerIn: parent; text: modelData; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; font.family: ThemeManager.fontFamily; color: reportsPage.currentTab === index ? ThemeManager.textOnPrimary : ThemeManager.textSecondary }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: reportsPage.currentTab = index }
                    }
                }
            }

            Loader {
                Layout.fillWidth: true
                Layout.minimumHeight: 450
                sourceComponent: reportsPage.currentTab === 0 ? wizardTab :
                                 reportsPage.currentTab === 1 ? templatesTab : generatedTab
            }
        }
    }

    // Report Wizard
    Component {
        id: wizardTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal

            // Step indicator
            RowLayout {
                Layout.fillWidth: true
                spacing: ThemeManager.spacingSmall
                Repeater {
                    model: ["Select Type", "Configure Scope", "Select Sections", "Generate"]
                    RowLayout {
                        spacing: ThemeManager.spacingXS
                        Rectangle {
                            width: 28; height: 28; radius: 14
                            color: reportsPage.wizardStep >= index ? ThemeManager.primaryColor : ThemeManager.cardColor
                            border.color: reportsPage.wizardStep >= index ? ThemeManager.primaryColor : ThemeManager.borderColor; border.width: 1
                            Text { anchors.centerIn: parent; text: (index + 1).toString(); font.pixelSize: ThemeManager.fontSizeSmall; font.weight: Font.Bold; color: reportsPage.wizardStep >= index ? ThemeManager.textOnPrimary : ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        }
                        Text { text: modelData; font.pixelSize: ThemeManager.fontSizeSmall; color: reportsPage.wizardStep >= index ? ThemeManager.textPrimary : ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                        Rectangle { width: 40; height: 2; color: index < 3 ? (reportsPage.wizardStep > index ? ThemeManager.primaryColor : ThemeManager.borderColor) : "transparent"; visible: index < 3 }
                    }
                }
            }

            // Wizard content
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 360
                radius: ThemeManager.radiusLarge
                color: ThemeManager.surfaceColor
                border.color: ThemeManager.borderColor; border.width: 1

                Loader {
                    anchors.fill: parent
                    anchors.margins: ThemeManager.spacingXL
                    sourceComponent: reportsPage.wizardStep === 0 ? step1 :
                                     reportsPage.wizardStep === 1 ? step2 :
                                     reportsPage.wizardStep === 2 ? step3 : step4
                }
            }

            // Navigation buttons
            RowLayout {
                Layout.fillWidth: true
                Rectangle {
                    visible: reportsPage.wizardStep > 0
                    width: 90; height: ThemeManager.buttonHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.cardColor; border.color: ThemeManager.borderColor; border.width: 1
                    Text { anchors.centerIn: parent; text: "\u2190 Back"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: reportsPage.wizardStep-- }
                }
                Item { Layout.fillWidth: true }
                Rectangle {
                    width: reportsPage.wizardStep === 3 ? 140 : 90; height: ThemeManager.buttonHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.primaryColor
                    Text { anchors.centerIn: parent; text: reportsPage.wizardStep === 3 ? "Generate Report" : "Next \u2192"; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.Medium; color: ThemeManager.textOnPrimary; font.family: ThemeManager.fontFamily }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { if (reportsPage.wizardStep < 3) reportsPage.wizardStep++ } }
                }
            }
        }
    }

    // Step 1: Select type
    Component {
        id: step1
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Select Report Type"; font.pixelSize: ThemeManager.fontSizeLarge; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            GridLayout {
                Layout.fillWidth: true; columns: 3; rowSpacing: ThemeManager.spacingNormal; columnSpacing: ThemeManager.spacingNormal
                Repeater {
                    model: ListModel {
                        ListElement { typeName: "Executive Summary"; typeDesc: "High-level security posture overview for leadership"; typeIcon: "\u2605" }
                        ListElement { typeName: "Compliance Report"; typeDesc: "Detailed compliance status against frameworks"; typeIcon: "\u2611" }
                        ListElement { typeName: "Incident Report"; typeDesc: "Comprehensive incident analysis and timeline"; typeIcon: "\u26A0" }
                        ListElement { typeName: "Vulnerability Report"; typeDesc: "Open vulnerabilities and remediation status"; typeIcon: "\u2620" }
                        ListElement { typeName: "Threat Landscape"; typeDesc: "Current threats, trends, and risk assessment"; typeIcon: "\u2616" }
                        ListElement { typeName: "Custom Report"; typeDesc: "Build a custom report with selected modules"; typeIcon: "\u2699" }
                    }
                    Rectangle {
                        Layout.fillWidth: true; height: 90; radius: ThemeManager.radiusMedium; color: ThemeManager.cardColor; border.color: ThemeManager.borderColor; border.width: 1
                        ColumnLayout {
                            anchors.fill: parent; anchors.margins: ThemeManager.spacingMedium; spacing: ThemeManager.spacingXS
                            RowLayout { Text { text: model.typeIcon; font.pixelSize: 16 } Text { text: model.typeName; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily } }
                            Text { text: model.typeDesc; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                        }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; hoverEnabled: true; onEntered: parent.border.color = ThemeManager.primaryColor; onExited: parent.border.color = ThemeManager.borderColor }
                    }
                }
            }
        }
    }

    // Step 2: Configure scope
    Component {
        id: step2
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Configure Report Scope"; font.pixelSize: ThemeManager.fontSizeLarge; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            GridLayout {
                columns: 2; rowSpacing: ThemeManager.spacingMedium; columnSpacing: ThemeManager.spacingXL; Layout.fillWidth: true
                Text { text: "Date Range:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                Rectangle { Layout.fillWidth: true; height: ThemeManager.inputHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.inputColor; border.color: ThemeManager.borderColor; border.width: 1; Text { anchors.centerIn: parent; text: "Last 30 days (Nov 15 - Dec 15, 2024)"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily } }
                Text { text: "Scope:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                Rectangle { Layout.fillWidth: true; height: ThemeManager.inputHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.inputColor; border.color: ThemeManager.borderColor; border.width: 1; Text { anchors.centerIn: parent; text: "All Assets (342 devices)"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily } }
                Text { text: "Department:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                Rectangle { Layout.fillWidth: true; height: ThemeManager.inputHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.inputColor; border.color: ThemeManager.borderColor; border.width: 1; Text { anchors.centerIn: parent; text: "All Departments"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily } }
                Text { text: "Classification:"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                Rectangle { Layout.fillWidth: true; height: ThemeManager.inputHeight; radius: ThemeManager.radiusMedium; color: ThemeManager.inputColor; border.color: ThemeManager.borderColor; border.width: 1; Text { anchors.centerIn: parent; text: "Confidential"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily } }
            }
        }
    }

    // Step 3: Select sections
    Component {
        id: step3
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Select Report Sections"; font.pixelSize: ThemeManager.fontSizeLarge; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            ListView {
                Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 4
                model: ListModel {
                    ListElement { section: "Executive Summary"; included: true }
                    ListElement { section: "Security Score & Metrics"; included: true }
                    ListElement { section: "Threat Analysis"; included: true }
                    ListElement { section: "Incident Summary"; included: true }
                    ListElement { section: "Vulnerability Assessment"; included: true }
                    ListElement { section: "Compliance Status"; included: false }
                    ListElement { section: "Asset Inventory"; included: false }
                    ListElement { section: "Network Activity"; included: true }
                    ListElement { section: "Recommendations"; included: true }
                    ListElement { section: "Appendix - Raw Data"; included: false }
                }
                delegate: Rectangle {
                    width: ListView.view.width; height: 36; radius: ThemeManager.radiusSmall; color: "transparent"
                    RowLayout {
                        anchors.fill: parent; anchors.margins: ThemeManager.spacingSmall; spacing: ThemeManager.spacingSmall
                        Rectangle { width: 20; height: 20; radius: 4; color: model.included ? ThemeManager.primaryColor : "transparent"; border.color: model.included ? ThemeManager.primaryColor : ThemeManager.borderColor; border.width: 1; Text { anchors.centerIn: parent; text: model.included ? "\u2713" : ""; font.pixelSize: 12; color: "#ffffff" } MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor } }
                        Text { text: model.section; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily; Layout.fillWidth: true }
                    }
                }
            }
        }
    }

    // Step 4: Generate/export
    Component {
        id: step4
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Export Options"; font.pixelSize: ThemeManager.fontSizeLarge; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            Text { text: "Select the output format for your report"; font.pixelSize: ThemeManager.fontSizeBody; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
            GridLayout {
                Layout.fillWidth: true; columns: 4; rowSpacing: ThemeManager.spacingNormal; columnSpacing: ThemeManager.spacingNormal
                Repeater {
                    model: ListModel {
                        ListElement { format: "PDF"; desc: "Professional document format"; icon: "\u2750"; selected: true }
                        ListElement { format: "Excel"; desc: "Spreadsheet with raw data"; icon: "\u2261"; selected: false }
                        ListElement { format: "HTML"; desc: "Interactive web report"; icon: "\u2604"; selected: false }
                        ListElement { format: "JSON"; desc: "Machine-readable data"; icon: "{ }"; selected: false }
                    }
                    Rectangle {
                        Layout.fillWidth: true; height: 100; radius: ThemeManager.radiusMedium
                        color: model.selected ? Qt.rgba(ThemeManager.primaryColor.r, ThemeManager.primaryColor.g, ThemeManager.primaryColor.b, 0.1) : ThemeManager.cardColor
                        border.color: model.selected ? ThemeManager.primaryColor : ThemeManager.borderColor; border.width: model.selected ? 2 : 1
                        ColumnLayout {
                            anchors.fill: parent; anchors.margins: ThemeManager.spacingMedium; spacing: ThemeManager.spacingXS
                            Text { text: model.icon; font.pixelSize: 24; color: model.selected ? ThemeManager.primaryColor : ThemeManager.textMuted }
                            Text { text: model.format; font.pixelSize: ThemeManager.fontSizeBody; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                            Text { text: model.desc; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily }
                        }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor }
                    }
                }
            }
        }
    }

    // Templates tab
    Component {
        id: templatesTab
        ColumnLayout {
            spacing: ThemeManager.spacingNormal
            Text { text: "Report Templates"; font.pixelSize: ThemeManager.fontSizeMedium; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
            GridLayout {
                Layout.fillWidth: true; columns: 2; rowSpacing: ThemeManager.spacingNormal; columnSpacing: ThemeManager.spacingNormal
                Repeater {
                    model: ListModel {
                        ListElement { tplName: "Executive Summary"; tplDesc: "High-level metrics, security score, top incidents, and recommendations for C-level"; tplSchedule: "Weekly, Monday 8:00 AM"; tplLastRun: "Dec 14, 2024" }
                        ListElement { tplName: "Compliance Report"; tplDesc: "Full compliance assessment against NIST, ISO 27001, SOC 2, PCI DSS frameworks"; tplSchedule: "Monthly, 1st of month"; tplLastRun: "Dec 1, 2024" }
                        ListElement { tplName: "Incident Response"; tplDesc: "Detailed incident timeline, impact analysis, containment steps, and lessons learned"; tplSchedule: "On-demand"; tplLastRun: "Dec 15, 2024" }
                        ListElement { tplName: "Vulnerability Assessment"; tplDesc: "Open CVEs, patch status, risk prioritization, and remediation timeline"; tplSchedule: "Bi-weekly"; tplLastRun: "Dec 8, 2024" }
                        ListElement { tplName: "Threat Landscape"; tplDesc: "Active threat actors, campaigns, IOC trends, and predictive analysis"; tplSchedule: "Monthly"; tplLastRun: "Dec 1, 2024" }
                        ListElement { tplName: "Board Presentation"; tplDesc: "Quarterly security briefing with charts and executive metrics"; tplSchedule: "Quarterly"; tplLastRun: "Oct 1, 2024" }
                    }
                    Rectangle {
                        Layout.fillWidth: true; height: 110; radius: ThemeManager.radiusLarge; color: ThemeManager.surfaceColor; border.color: ThemeManager.borderColor; border.width: 1
                        ColumnLayout {
                            anchors.fill: parent; anchors.margins: ThemeManager.spacingLarge; spacing: ThemeManager.spacingSmall
                            Text { text: model.tplName; font.pixelSize: ThemeManager.fontSizeNormal; font.weight: Font.DemiBold; color: ThemeManager.textPrimary; font.family: ThemeManager.fontFamily }
                            Text { text: model.tplDesc; font.pixelSize: ThemeManager.fontSizeSmall; color: ThemeManager.textSecondary; font.family: ThemeManager.fontFamily; wrapMode: Text.WordWrap; Layout.fillWidth: true; maximumLineCount: 2 }
                            RowLayout { Layout.fillWidth: true; spacing: ThemeManager.spacingNormal
                                Text { text: "Schedule: " + model.tplSchedule; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                                Item { Layout.fillWidth: true }
                                Text { text: "Last: " + model.tplLastRun; font.pixelSize: ThemeManager.fontSizeXS; color: ThemeManager.textMuted; font.family: ThemeManager.fontFamily }
                            }
                        }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; hoverEnabled: true; onEntered: parent.border.color = ThemeManager.primaryColor; onExited: parent.border.color = ThemeManager.borderColor }
                    }
                }
            }
        }
    }

    // Generated Reports tab
    Component {
        id: generatedTab
        DataTable {
            title: "Generated Reports"
            columns: [
                { key: "name", label: "Report Name", width: 260 },
                { key: "type", label: "Type", width: 140 },
                { key: "generated", label: "Generated", width: 150 },
                { key: "format", label: "Format", width: 80 },
                { key: "size", label: "Size", width: 80 },
                { key: "status", label: "Status", width: 90 }
            ]
            rows: [
                { name: "Executive Summary - Week 50", type: "Executive Summary", generated: "2024-12-15 14:00", format: "PDF", size: "2.4 MB", status: "Ready" },
                { name: "Incident Report - INC-001", type: "Incident Response", generated: "2024-12-15 12:30", format: "PDF", size: "5.1 MB", status: "Ready" },
                { name: "Vulnerability Scan Results", type: "Vulnerability", generated: "2024-12-14 23:00", format: "Excel", size: "8.7 MB", status: "Ready" },
                { name: "December Compliance Review", type: "Compliance", generated: "2024-12-01 08:00", format: "PDF", size: "12.3 MB", status: "Ready" },
                { name: "Threat Landscape Q4 2024", type: "Threat Landscape", generated: "2024-12-01 09:00", format: "HTML", size: "3.8 MB", status: "Ready" },
                { name: "Board Security Briefing Q4", type: "Board Presentation", generated: "2024-10-01 10:00", format: "PDF", size: "4.2 MB", status: "Ready" },
                { name: "Network Activity Report", type: "Custom", generated: "2024-12-13 16:00", format: "JSON", size: "1.1 MB", status: "Ready" }
            ]
        }
    }
}
