import QtQuick
import QtQuick.Layouts
import "../themes"

// Animated circular progress indicator with percentage center text
Rectangle {
    id: root
    radius: ThemeManager.radiusLarge
    color: ThemeManager.surfaceColor
    border.color: ThemeManager.borderColor
    border.width: 1
    implicitWidth: 160
    implicitHeight: 160

    property real progress: 0.0 // 0.0 to 1.0
    property string label: "Scanning..."
    property bool running: false
    property int ringWidth: 10
    property color ringColor: ThemeManager.primaryColor
    property color trackColor: ThemeManager.borderColor

    // Animated progress
    property real animatedProgress: 0
    Behavior on animatedProgress { NumberAnimation { duration: ThemeManager.animMedium; easing.type: Easing.OutCubic } }
    onProgressChanged: animatedProgress = progress

    // Indeterminate spin animation
    property real spinAngle: 0
    NumberAnimation on spinAngle {
        from: 0
        to: 360
        duration: 1200
        loops: Animation.Infinite
        running: root.running && root.progress <= 0
    }

    // Pulsing glow for running state
    property real pulseOpacity: 0.0
    SequentialAnimation on pulseOpacity {
        loops: Animation.Infinite
        running: root.running
        NumberAnimation { from: 0.0; to: 0.4; duration: 1000; easing.type: Easing.InOutSine }
        NumberAnimation { from: 0.4; to: 0.0; duration: 1000; easing.type: Easing.InOutSine }
    }

    // Traveling dot angle offset (runs ahead of progress)
    property real dotAngle: 0
    NumberAnimation on dotAngle {
        from: 0
        to: 360
        duration: 2000
        loops: Animation.Infinite
        running: root.running
    }

    Canvas {
        id: ringCanvas
        anchors.centerIn: parent
        width: Math.min(parent.width, parent.height) - ThemeManager.spacingLarge * 2
        height: width

        onPaint: {
            var ctx = getContext("2d")
            ctx.clearRect(0, 0, width, height)

            var cx = width / 2
            var cy = height / 2
            var radius = (width - root.ringWidth) / 2 - 4

            // Glowing halo behind progress arc
            if (root.running && root.animatedProgress > 0) {
                var haloStartAngle = -Math.PI / 2
                var haloEndAngle = haloStartAngle + Math.PI * 2 * root.animatedProgress
                ctx.beginPath()
                ctx.arc(cx, cy, radius, haloStartAngle, haloEndAngle)
                ctx.strokeStyle = root.ringColor
                ctx.lineWidth = root.ringWidth + 8
                ctx.lineCap = "round"
                ctx.globalAlpha = root.pulseOpacity
                ctx.stroke()
                ctx.globalAlpha = 1.0
            }

            // Track circle
            ctx.beginPath()
            ctx.arc(cx, cy, radius, 0, Math.PI * 2)
            ctx.strokeStyle = root.trackColor
            ctx.lineWidth = root.ringWidth
            ctx.lineCap = "round"
            ctx.stroke()

            // Progress arc
            var startAngle = -Math.PI / 2
            if (root.running && root.progress <= 0) {
                // Indeterminate mode
                var offset = root.spinAngle * Math.PI / 180
                ctx.beginPath()
                ctx.arc(cx, cy, radius, offset, offset + Math.PI * 0.7)
                ctx.strokeStyle = root.ringColor
                ctx.lineWidth = root.ringWidth
                ctx.lineCap = "round"
                ctx.stroke()
            } else if (root.animatedProgress > 0) {
                var endAngle = startAngle + Math.PI * 2 * root.animatedProgress
                ctx.beginPath()
                ctx.arc(cx, cy, radius, startAngle, endAngle)
                ctx.strokeStyle = root.ringColor
                ctx.lineWidth = root.ringWidth
                ctx.lineCap = "round"
                ctx.stroke()

                // Traveling dot ahead of progress
                if (root.running) {
                    var dotOffset = root.dotAngle * Math.PI / 180
                    var dotPos = startAngle + Math.PI * 2 * Math.min(root.animatedProgress + 0.05, 1.0)
                    var effectiveDotAngle = startAngle + ((dotOffset) % (Math.PI * 2 * root.animatedProgress))
                    var dotX = cx + radius * Math.cos(effectiveDotAngle)
                    var dotY = cy + radius * Math.sin(effectiveDotAngle)

                    // Dot glow
                    ctx.beginPath()
                    ctx.arc(dotX, dotY, 6, 0, Math.PI * 2)
                    ctx.fillStyle = root.ringColor
                    ctx.globalAlpha = 0.3
                    ctx.fill()
                    ctx.globalAlpha = 1.0

                    // Dot
                    ctx.beginPath()
                    ctx.arc(dotX, dotY, 3, 0, Math.PI * 2)
                    ctx.fillStyle = root.ringColor
                    ctx.fill()
                }
            }
        }

        Connections {
            target: root
            function onAnimatedProgressChanged() { ringCanvas.requestPaint() }
            function onSpinAngleChanged() { ringCanvas.requestPaint() }
            function onPulseOpacityChanged() { ringCanvas.requestPaint() }
            function onDotAngleChanged() { ringCanvas.requestPaint() }
        }

        Component.onCompleted: requestPaint()
    }

    // Center text
    ColumnLayout {
        anchors.centerIn: parent
        spacing: 2

        Text {
            Layout.alignment: Qt.AlignHCenter
            text: root.progress > 0 ? Math.round(root.animatedProgress * 100) + "%" : (root.running ? "..." : "0%")
            font.pixelSize: ThemeManager.fontSizeXL
            font.weight: Font.Bold
            font.family: ThemeManager.fontFamily
            color: ThemeManager.textPrimary
        }

        Text {
            Layout.alignment: Qt.AlignHCenter
            text: root.label
            font.pixelSize: ThemeManager.fontSizeXS
            font.family: ThemeManager.fontFamily
            color: ThemeManager.textSecondary
            visible: root.label !== ""
        }
    }
}
