import QtQuick
import QtQuick.Layouts
import "../themes"

// Reusable glassmorphism card widget with semi-transparent background,
// subtle inner gradient, softened border, and top highlight line
Rectangle {
    id: root
    radius: ThemeManager.radiusLarge
    color: ThemeManager.glassBackground
    border.color: showBorder ? ThemeManager.glassBorder : "transparent"
    border.width: showBorder ? 1 : 0

    // Public properties
    property string title: ""
    property bool showBorder: true
    default property alias contentItem: contentContainer.data

    // Subtle inner gradient overlay (from transparent to very faint white)
    Rectangle {
        anchors.fill: parent
        radius: parent.radius
        gradient: Gradient {
            GradientStop { position: 0.0; color: "transparent" }
            GradientStop { position: 1.0; color: ThemeManager.darkMode ? Qt.rgba(1.0, 1.0, 1.0, 0.02) : Qt.rgba(1.0, 1.0, 1.0, 0.03) }
        }
    }

    // Top highlight line (1px across the top with low-opacity white)
    Rectangle {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 1
        anchors.leftMargin: parent.radius
        anchors.rightMargin: parent.radius
        height: 1
        gradient: Gradient {
            orientation: Gradient.Horizontal
            GradientStop { position: 0.0; color: "transparent" }
            GradientStop { position: 0.3; color: Qt.rgba(1.0, 1.0, 1.0, 0.05) }
            GradientStop { position: 0.5; color: Qt.rgba(1.0, 1.0, 1.0, 0.08) }
            GradientStop { position: 0.7; color: Qt.rgba(1.0, 1.0, 1.0, 0.05) }
            GradientStop { position: 1.0; color: "transparent" }
        }
    }

    // Optional title header
    Text {
        id: titleText
        visible: root.title !== ""
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: ThemeManager.spacingLarge
        anchors.leftMargin: ThemeManager.spacingLarge
        anchors.rightMargin: ThemeManager.spacingLarge
        text: root.title
        font.pixelSize: ThemeManager.fontSizeMedium
        font.weight: Font.DemiBold
        font.family: ThemeManager.fontFamily
        color: ThemeManager.textPrimary
    }

    // Content container for children
    Item {
        id: contentContainer
        anchors.top: titleText.visible ? titleText.bottom : parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.topMargin: titleText.visible ? ThemeManager.spacingMedium : 0
        anchors.leftMargin: ThemeManager.spacingLarge
        anchors.rightMargin: ThemeManager.spacingLarge
        anchors.bottomMargin: ThemeManager.spacingLarge
    }
}
