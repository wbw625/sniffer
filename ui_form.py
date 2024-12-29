# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'form.ui'
##
## Created by: Qt User Interface Compiler version 6.8.1
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QComboBox, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QPlainTextEdit,
    QPushButton, QRadioButton, QSizePolicy, QSpacerItem,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(1500, 1200)
        self.centralWidget = QWidget(MainWindow)
        self.centralWidget.setObjectName(u"centralWidget")
        self.verticalLayout = QVBoxLayout(self.centralWidget)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.networkInterfaceHorizontalLayout = QHBoxLayout()
        self.networkInterfaceHorizontalLayout.setObjectName(u"networkInterfaceHorizontalLayout")
        self.networkInterfaceLabel = QLabel(self.centralWidget)
        self.networkInterfaceLabel.setObjectName(u"networkInterfaceLabel")

        self.networkInterfaceHorizontalLayout.addWidget(self.networkInterfaceLabel)

        self.networkInterfacesComboBox = QComboBox(self.centralWidget)
        self.networkInterfacesComboBox.setObjectName(u"networkInterfacesComboBox")
        sizePolicy = QSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.networkInterfacesComboBox.sizePolicy().hasHeightForWidth())
        self.networkInterfacesComboBox.setSizePolicy(sizePolicy)

        self.networkInterfaceHorizontalLayout.addWidget(self.networkInterfacesComboBox)


        self.verticalLayout.addLayout(self.networkInterfaceHorizontalLayout)

        self.filterHorizontalLayout = QHBoxLayout()
        self.filterHorizontalLayout.setObjectName(u"filterHorizontalLayout")
        self.protocolLineEdit = QLineEdit(self.centralWidget)
        self.protocolLineEdit.setObjectName(u"protocolLineEdit")

        self.filterHorizontalLayout.addWidget(self.protocolLineEdit)

        self.sourceLineEdit = QLineEdit(self.centralWidget)
        self.sourceLineEdit.setObjectName(u"sourceLineEdit")

        self.filterHorizontalLayout.addWidget(self.sourceLineEdit)

        self.destinationLineEdit = QLineEdit(self.centralWidget)
        self.destinationLineEdit.setObjectName(u"destinationLineEdit")

        self.filterHorizontalLayout.addWidget(self.destinationLineEdit)

        self.filterButton = QPushButton(self.centralWidget)
        self.filterButton.setObjectName(u"filterButton")

        self.filterHorizontalLayout.addWidget(self.filterButton)


        self.verticalLayout.addLayout(self.filterHorizontalLayout)

        self.reassembleHorizontalLayout = QHBoxLayout()
        self.reassembleHorizontalLayout.setObjectName(u"reassembleHorizontalLayout")
        self.reassembleLabel = QLabel(self.centralWidget)
        self.reassembleLabel.setObjectName(u"reassembleLabel")

        self.reassembleHorizontalLayout.addWidget(self.reassembleLabel)

        self.yesReassembleRadioButton = QRadioButton(self.centralWidget)
        self.yesReassembleRadioButton.setObjectName(u"yesReassembleRadioButton")
        self.yesReassembleRadioButton.setChecked(True)

        self.reassembleHorizontalLayout.addWidget(self.yesReassembleRadioButton)

        self.noReassembleRadioButton = QRadioButton(self.centralWidget)
        self.noReassembleRadioButton.setObjectName(u"noReassembleRadioButton")
        self.noReassembleRadioButton.setChecked(False)

        self.reassembleHorizontalLayout.addWidget(self.noReassembleRadioButton)

        self.reassembleHorizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.reassembleHorizontalLayout.addItem(self.reassembleHorizontalSpacer)


        self.verticalLayout.addLayout(self.reassembleHorizontalLayout)

        self.startStopHorizontalLayout = QHBoxLayout()
        self.startStopHorizontalLayout.setObjectName(u"startStopHorizontalLayout")
        self.startButton = QPushButton(self.centralWidget)
        self.startButton.setObjectName(u"startButton")

        self.startStopHorizontalLayout.addWidget(self.startButton)

        self.stopButton = QPushButton(self.centralWidget)
        self.stopButton.setObjectName(u"stopButton")

        self.startStopHorizontalLayout.addWidget(self.stopButton)


        self.verticalLayout.addLayout(self.startStopHorizontalLayout)

        self.packetListhorizontalLayout = QHBoxLayout()
        self.packetListhorizontalLayout.setObjectName(u"packetListhorizontalLayout")
        self.packetListLabel = QLabel(self.centralWidget)
        self.packetListLabel.setObjectName(u"packetListLabel")

        self.packetListhorizontalLayout.addWidget(self.packetListLabel)

        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.packetListhorizontalLayout.addItem(self.horizontalSpacer)

        self.clearButton = QPushButton(self.centralWidget)
        self.clearButton.setObjectName(u"clearButton")

        self.packetListhorizontalLayout.addWidget(self.clearButton)


        self.verticalLayout.addLayout(self.packetListhorizontalLayout)

        self.packetTableWidget = QTableWidget(self.centralWidget)
        self.packetTableWidget.setObjectName(u"packetTableWidget")
        self.packetTableWidget.horizontalHeader().setDefaultSectionSize(250)

        self.verticalLayout.addWidget(self.packetTableWidget)

        self.packetDetailsLabel = QLabel(self.centralWidget)
        self.packetDetailsLabel.setObjectName(u"packetDetailsLabel")

        self.verticalLayout.addWidget(self.packetDetailsLabel)

        self.packetDetailsTextEdit = QPlainTextEdit(self.centralWidget)
        self.packetDetailsTextEdit.setObjectName(u"packetDetailsTextEdit")
        self.packetDetailsTextEdit.setReadOnly(True)

        self.verticalLayout.addWidget(self.packetDetailsTextEdit)

        self.saveLoadHorizontalLayout = QHBoxLayout()
        self.saveLoadHorizontalLayout.setObjectName(u"saveLoadHorizontalLayout")
        self.saveButton = QPushButton(self.centralWidget)
        self.saveButton.setObjectName(u"saveButton")

        self.saveLoadHorizontalLayout.addWidget(self.saveButton)

        self.loadButton = QPushButton(self.centralWidget)
        self.loadButton.setObjectName(u"loadButton")

        self.saveLoadHorizontalLayout.addWidget(self.loadButton)


        self.verticalLayout.addLayout(self.saveLoadHorizontalLayout)

        MainWindow.setCentralWidget(self.centralWidget)

        self.retranslateUi(MainWindow)

        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"Network Sniffer", None))
        self.networkInterfaceLabel.setText(QCoreApplication.translate("MainWindow", u"Network Interface: ", None))
        self.protocolLineEdit.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Protocol (e.g. TCP)", None))
        self.sourceLineEdit.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Source IP (e.g. 192.168.1.1)", None))
        self.destinationLineEdit.setPlaceholderText(QCoreApplication.translate("MainWindow", u"Destination IP (e.g. 192.168.1.2)", None))
        self.filterButton.setText(QCoreApplication.translate("MainWindow", u"Filter", None))
        self.reassembleLabel.setText(QCoreApplication.translate("MainWindow", u"Reassemble IP Fragments:", None))
        self.yesReassembleRadioButton.setText(QCoreApplication.translate("MainWindow", u"Yes", None))
        self.noReassembleRadioButton.setText(QCoreApplication.translate("MainWindow", u"No", None))
        self.startButton.setText(QCoreApplication.translate("MainWindow", u"Start", None))
        self.stopButton.setText(QCoreApplication.translate("MainWindow", u"Stop", None))
        self.packetListLabel.setText(QCoreApplication.translate("MainWindow", u"Packet List:", None))
        self.clearButton.setText(QCoreApplication.translate("MainWindow", u"Clear", None))
        self.packetDetailsLabel.setText(QCoreApplication.translate("MainWindow", u"Packet Details:", None))
        self.saveButton.setText(QCoreApplication.translate("MainWindow", u"Save", None))
        self.loadButton.setText(QCoreApplication.translate("MainWindow", u"Load", None))
    # retranslateUi

