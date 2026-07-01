import QtQuick
import QtQuick.Layouts

// Line/Bar chart component with Canvas rendering, axis labels, gridlines
Rectangle {
    id: root
    radius: ThemeManager.radiusLarge
    color: ThemeManager.surfaceColor
    border.color: ThemeManager.borderColor
    border.width: 1

    property string title: "Threat Activity"
    property string chartType: "line" // "line" or "bar"
    property var chartData: [
        { label: "Mon", value: 12 },
        { label: "Tue", value: 28 },
        { label: "Wed", value: 18 },
        { label: "Thu", value: 45 },
        { label: "Fri", value: 32 },
        { label: "Sat", value: 15 },
        { label: "Sun", value: 22 }
    ]
    property color lineColor: ThemeManager.primaryColor
    property color fillColor: ThemeManager.primaryColor
    property bool showGrid: true
    property int gridLines: 4

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: ThemeManager.spacingLarge
        spacing: ThemeManager.spacingMedium

        // Header
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

            // Chart type toggle
            Row {
                spacing: 4

                Rectangle {
                    width: 28; height: 24; radius: 4
                    color: root.chartType === "line" ? ThemeManager.primaryColor : "transparent"
                    opacity: root.chartType === "line" ? 0.2 : 1.0
                    border.color: ThemeManager.borderColor
                    border.width: root.chartType === "line" ? 0 : 1

                    Text {
                        anchors.centerIn: parent
                        text: "\u2571"
                        font.pixelSize: 12
                        color: root.chartType === "line" ? ThemeManager.primaryColor : ThemeManager.textMuted
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.chartType = "line"
                    }
                }

                Rectangle {
                    width: 28; height: 24; radius: 4
                    color: root.chartType === "bar" ? ThemeManager.primaryColor : "transparent"
                    opacity: root.chartType === "bar" ? 0.2 : 1.0
                    border.color: ThemeManager.borderColor
                    border.width: root.chartType === "bar" ? 0 : 1

                    Text {
                        anchors.centerIn: parent
                        text: "\u2585"
                        font.pixelSize: 12
                        color: root.chartType === "bar" ? ThemeManager.primaryColor : ThemeManager.textMuted
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.chartType = "bar"
                    }
                }
            }
        }

        // Chart area
        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            Canvas {
                id: chartCanvas
                anchors.fill: parent
                anchors.leftMargin: 30
                anchors.bottomMargin: 24

                onPaint: {
                    var ctx = getContext("2d")
                    ctx.clearRect(0, 0, width, height)

                    if (!root.chartData || root.chartData.length === 0) return

                    var maxVal = 0
                    for (var i = 0; i < root.chartData.length; i++) {
                        if (root.chartData[i].value > maxVal)
                            maxVal = root.chartData[i].value
                    }
                    maxVal = Math.ceil(maxVal * 1.1)
                    if (maxVal === 0) maxVal = 1

                    var padding = 8
                    var chartWidth = width - padding * 2
                    var chartHeight = height - padding * 2

                    // Draw grid lines
                    if (root.showGrid) {
                        ctx.strokeStyle = ThemeManager.borderColor
                        ctx.lineWidth = 0.5
                        for (var g = 0; g <= root.gridLines; g++) {
                            var gy = padding + (chartHeight / root.gridLines) * g
                            ctx.beginPath()
                            ctx.moveTo(padding, gy)
                            ctx.lineTo(padding + chartWidth, gy)
                            ctx.stroke()
                        }
                    }

                    var barWidth = chartWidth / root.chartData.length
                    var points = []

                    for (var j = 0; j < root.chartData.length; j++) {
                        var x = padding + barWidth * j + barWidth / 2
                        var y = padding + chartHeight - (root.chartData[j].value / maxVal) * chartHeight

                        if (root.chartType === "bar") {
                            var bw = barWidth * 0.6
                            var bh = (root.chartData[j].value / maxVal) * chartHeight
                            ctx.fillStyle = root.fillColor
                            ctx.globalAlpha = 0.7
                            ctx.beginPath()
                            ctx.roundedRect(x - bw / 2, padding + chartHeight - bh, bw, bh, 4, 4)
                            ctx.fill()
                            ctx.globalAlpha = 1.0
                        }

                        points.push({ x: x, y: y })
                    }

                    // Line chart
                    if (root.chartType === "line" && points.length > 1) {
                        // Fill area under line
                        ctx.beginPath()
                        ctx.moveTo(points[0].x, padding + chartHeight)
                        for (var k = 0; k < points.length; k++) {
                            ctx.lineTo(points[k].x, points[k].y)
                        }
                        ctx.lineTo(points[points.length - 1].x, padding + chartHeight)
                        ctx.closePath()
                        ctx.fillStyle = root.fillColor
                        ctx.globalAlpha = 0.1
                        ctx.fill()
                        ctx.globalAlpha = 1.0

                        // Draw line
                        ctx.beginPath()
                        ctx.moveTo(points[0].x, points[0].y)
                        for (var l = 1; l < points.length; l++) {
                            ctx.lineTo(points[l].x, points[l].y)
                        }
                        ctx.strokeStyle = root.lineColor
                        ctx.lineWidth = 2.5
                        ctx.lineJoin = "round"
                        ctx.stroke()

                        // Draw dots
                        for (var m = 0; m < points.length; m++) {
                            ctx.beginPath()
                            ctx.arc(points[m].x, points[m].y, 4, 0, Math.PI * 2)
                            ctx.fillStyle = root.lineColor
                            ctx.fill()
                        }
                    }
                }

                Connections {
                    target: root
                    function onChartDataChanged() { chartCanvas.requestPaint() }
                    function onChartTypeChanged() { chartCanvas.requestPaint() }
                }

                Component.onCompleted: requestPaint()
            }

            // Y-axis labels
            Column {
                anchors.left: parent.left
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.bottomMargin: 24
                width: 28

                Repeater {
                    model: root.gridLines + 1
                    Text {
                        width: 28
                        height: (parent.height) / root.gridLines
                        text: {
                            var maxVal = 0
                            for (var i = 0; i < root.chartData.length; i++) {
                                if (root.chartData[i].value > maxVal)
                                    maxVal = root.chartData[i].value
                            }
                            return Math.round(Math.ceil(maxVal * 1.1) * (1 - index / root.gridLines)).toString()
                        }
                        font.pixelSize: ThemeManager.fontSizeXS
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textMuted
                        verticalAlignment: Text.AlignTop
                        horizontalAlignment: Text.AlignRight
                    }
                }
            }

            // X-axis labels
            Row {
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.leftMargin: 30
                height: 20

                Repeater {
                    model: root.chartData
                    Text {
                        width: (parent.width) / root.chartData.length
                        text: modelData.label
                        font.pixelSize: ThemeManager.fontSizeXS
                        font.family: ThemeManager.fontFamily
                        color: ThemeManager.textMuted
                        horizontalAlignment: Text.AlignHCenter
                    }
                }
            }
        }
    }
}
