import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../themes"

// Sortable, filterable data table with column headers, row selection, pagination
Rectangle {
    id: root
    radius: ThemeManager.radiusLarge
    color: ThemeManager.surfaceColor
    border.color: ThemeManager.borderColor
    border.width: 1

    property string title: "Data Table"
    property var columns: [
        { key: "name", label: "Name", width: 200 },
        { key: "status", label: "Status", width: 100 },
        { key: "value", label: "Value", width: 120 }
    ]
    property var rows: []
    property int currentPage: 0
    property int pageSize: 10
    property int sortColumn: -1
    property bool sortAscending: true
    property int selectedRow: -1
    property string filterText: ""

    signal rowClicked(int rowIndex)
    signal sortChanged(int columnIndex, bool ascending)

    property int totalPages: Math.max(1, Math.ceil(filteredRows.length / pageSize))
    property var filteredRows: {
        if (!filterText) return rows
        var result = []
        for (var i = 0; i < rows.length; i++) {
            var match = false
            for (var j = 0; j < columns.length; j++) {
                var val = rows[i][columns[j].key]
                if (val && val.toString().toLowerCase().indexOf(filterText.toLowerCase()) >= 0) {
                    match = true
                    break
                }
            }
            if (match) result.push(rows[i])
        }
        return result
    }

    property var pagedRows: {
        var start = currentPage * pageSize
        var end = Math.min(start + pageSize, filteredRows.length)
        return filteredRows.slice(start, end)
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingLarge
        spacing: ThemeManager.spacingMedium

        // Header with title and search filter
        RowLayout {
            Layout.fillWidth: true
            spacing: ThemeManager.spacingMedium

            Text {
                text: root.title
                font.pixelSize: ThemeManager.fontSizeMedium
                font.weight: Font.DemiBold
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textPrimary
            }

            Item { Layout.fillWidth: true }

            // Filter input
            Rectangle {
                width: 220
                height: ThemeManager.inputHeight
                radius: ThemeManager.radiusMedium
                color: ThemeManager.inputColor
                border.color: filterInput.activeFocus ? ThemeManager.primaryColor : ThemeManager.borderColor
                border.width: 1

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 12
                    anchors.rightMargin: 12
                    spacing: 8

                    Text {
                        text: "\uD83D\uDD0D"
                        font.pixelSize: 12
                        color: ThemeManager.textMuted
                    }

                    TextInput {
                        id: filterInput
                        Layout.fillWidth: true
                        font.pixelSize: ThemeManager.fontSizeBody
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textPrimary
                        clip: true
                        onTextChanged: {
                            root.filterText = text
                            root.currentPage = 0
                        }

                        Text {
                            anchors.fill: parent
                            text: "Filter rows..."
                            font.pixelSize: ThemeManager.fontSizeBody
                            font.family: ThemeManager.fontFamily
                            color: ThemeManager.textMuted
                            visible: !filterInput.text && !filterInput.activeFocus
                            verticalAlignment: Text.AlignVCenter
                        }
                    }
                }
            }
        }

        // Column headers
        Rectangle {
            Layout.fillWidth: true
            height: ThemeManager.tableRowHeight
            radius: ThemeManager.radiusSmall
            color: ThemeManager.hoverColor

            Row {
                anchors.fill: parent
                anchors.leftMargin: ThemeManager.spacingMedium
                anchors.rightMargin: ThemeManager.spacingMedium

                Repeater {
                    model: root.columns
                    Rectangle {
                        width: modelData.width || 150
                        height: parent.height
                        color: "transparent"

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 8
                            spacing: 4

                            Text {
                                text: modelData.label
                                font.pixelSize: ThemeManager.fontSizeSmall
                                font.weight: Font.DemiBold
                                font.family: ThemeManager.fontFamily
                                color: ThemeManager.textSecondary
                                Layout.fillWidth: true
                            }

                            Text {
                                text: root.sortColumn === index ? (root.sortAscending ? "\u25B2" : "\u25BC") : ""
                                font.pixelSize: 8
                                color: ThemeManager.primaryColor
                            }
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                if (root.sortColumn === index) {
                                    root.sortAscending = !root.sortAscending
                                } else {
                                    root.sortColumn = index
                                    root.sortAscending = true
                                }
                                root.sortChanged(root.sortColumn, root.sortAscending)
                            }
                        }
                    }
                }
            }
        }

        // Table body
        ListView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: root.pagedRows
            spacing: 1

            delegate: Rectangle {
                width: ListView.view.width
                height: ThemeManager.tableRowHeight
                radius: ThemeManager.radiusXS
                color: root.selectedRow === (root.currentPage * root.pageSize + index)
                       ? Qt.rgba(ThemeManager.primaryColor.r, ThemeManager.primaryColor.g, ThemeManager.primaryColor.b, 0.1)
                       : (index % 2 === 0 ? "transparent" : ThemeManager.cardColor)

                Row {
                    anchors.fill: parent
                    anchors.leftMargin: ThemeManager.spacingMedium
                    anchors.rightMargin: ThemeManager.spacingMedium

                    Repeater {
                        model: root.columns
                        Rectangle {
                            width: modelData.width || 150
                            height: parent.height
                            color: "transparent"

                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.left: parent.left
                                anchors.leftMargin: 8
                                anchors.right: parent.right
                                anchors.rightMargin: 8
                                text: {
                                    var rowData = root.pagedRows[index]
                                    return rowData ? (rowData[modelData.key] || "") : ""
                                }
                                font.pixelSize: ThemeManager.fontSizeBody
                                font.family: ThemeManager.fontFamily
                                color: ThemeManager.textPrimary
                                elide: Text.ElideRight
                            }
                        }
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    hoverEnabled: true
                    onClicked: {
                        root.selectedRow = root.currentPage * root.pageSize + index
                        root.rowClicked(root.selectedRow)
                    }
                    onEntered: parent.color = ThemeManager.hoverColor
                    onExited: parent.color = root.selectedRow === (root.currentPage * root.pageSize + index)
                        ? Qt.rgba(ThemeManager.primaryColor.r, ThemeManager.primaryColor.g, ThemeManager.primaryColor.b, 0.1)
                        : (index % 2 === 0 ? "transparent" : ThemeManager.cardColor)
                }
            }
        }

        // Pagination footer
        RowLayout {
            Layout.fillWidth: true
            spacing: ThemeManager.spacingMedium

            Text {
                text: "Showing " + (root.currentPage * root.pageSize + 1) + "-" +
                      Math.min((root.currentPage + 1) * root.pageSize, root.filteredRows.length) +
                      " of " + root.filteredRows.length
                font.pixelSize: ThemeManager.fontSizeSmall
                font.family: ThemeManager.fontFamily
                color: ThemeManager.textMuted
            }

            Item { Layout.fillWidth: true }

            Row {
                spacing: 4

                // Previous button
                Rectangle {
                    width: 28; height: 28
                    radius: ThemeManager.radiusSmall
                    color: root.currentPage > 0 ? ThemeManager.hoverColor : "transparent"
                    opacity: root.currentPage > 0 ? 1.0 : 0.4

                    Text {
                        anchors.centerIn: parent
                        text: "\u25C0"
                        font.pixelSize: 10
                        color: ThemeManager.textSecondary
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: root.currentPage > 0 ? Qt.PointingHandCursor : Qt.ArrowCursor
                        onClicked: if (root.currentPage > 0) root.currentPage--
                    }
                }

                // Page indicator
                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: (root.currentPage + 1) + " / " + root.totalPages
                    font.pixelSize: ThemeManager.fontSizeSmall
                    font.family: ThemeManager.fontFamily
                    color: ThemeManager.textSecondary
                }

                // Next button
                Rectangle {
                    width: 28; height: 28
                    radius: ThemeManager.radiusSmall
                    color: root.currentPage < root.totalPages - 1 ? ThemeManager.hoverColor : "transparent"
                    opacity: root.currentPage < root.totalPages - 1 ? 1.0 : 0.4

                    Text {
                        anchors.centerIn: parent
                        text: "\u25B6"
                        font.pixelSize: 10
                        color: ThemeManager.textSecondary
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: root.currentPage < root.totalPages - 1 ? Qt.PointingHandCursor : Qt.ArrowCursor
                        onClicked: if (root.currentPage < root.totalPages - 1) root.currentPage++
                    }
                }
            }
        }
    }
}
