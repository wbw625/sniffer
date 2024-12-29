import sys
import pickle
import datetime
import urllib.parse
import socket
import re
import urllib.parse

from scapy.all import sniff, conf, wrpcap, rdpcap

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTableWidgetItem, QMessageBox, QFileDialog
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QColor

from ui import Ui_MainWindow  # 确保 ui.py 文件存在并包含 Ui_MainWindow 类


class CaptureThread(QThread):
    packet_received = pyqtSignal(object)  # 信号用于发射捕获的数据包

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.is_running = True

    def run(self):
        sniff(
            iface=self.interface,
            prn=self.on_packet,
            store=False,
            stop_filter=lambda pkt: not self.is_running
        )

    def on_packet(self, packet):
        self.packet_received.emit(packet)

    def stop_capture(self):
        self.is_running = False
        self.wait(3000)


class SnifferApp(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()

        self.setupUi(self)

        # 初始化接口和数据包存储
        self.interfaces_list = []
        self.interface_names = []
        self.packets_dict = {}

        self.current_protocol_filter = ""
        self.current_src_filter = ""
        self.current_dst_filter = ""

        self.resolved_src_ips = []
        self.resolved_dst_ips = []

        self.ip_reassembly_enabled = self.yesReassembleRadioButton.isChecked()

        # 定义协议颜色映射
        self.protocol_color_mapping = {
            # bright
            # 'TCP': QColor(255, 228, 196),
            # 'UDP': QColor(217, 217, 243),
            # 'DNS': QColor(204, 255, 204),
            # 'ICMP': QColor(255, 204, 204),
            # 'Other': QColor(255, 255, 204)

            # dark
            'TCP': QColor(127, 114, 98),
            'UDP': QColor(108, 108, 121),
            'DNS': QColor(102, 127, 102),
            'ICMP': QColor(127, 102, 102),
            'Other': QColor(127, 127, 102)
        }

        # 连接 UI 按钮到方法
        self.startButton.clicked.connect(self.begin_sniffing)
        self.stopButton.clicked.connect(self.end_sniffing)
        self.filterButton.clicked.connect(self.apply_filters)
        self.clearButton.clicked.connect(self.clear_packets)
        self.saveButton.clicked.connect(self.export_packets)
        self.loadButton.clicked.connect(self.import_packets)

        self.yesReassembleRadioButton.toggled.connect(self.toggle_ip_reassembly)
        self.noReassembleRadioButton.toggled.connect(self.toggle_ip_reassembly)

        self.stopButton.setEnabled(False)

        # 填充网络接口
        for iface_key, iface_value in conf.ifaces.items():
            self.interfaces_list.append(iface_key)
            self.interface_names.append(f"{iface_key} ({iface_value.name})")
            self.packets_dict[iface_key] = []

        self.networkInterfacesComboBox.addItems(self.interface_names)
        self.networkInterfacesComboBox.currentIndexChanged.connect(self.change_interface)

        # 设置数据包表格
        self.packetTableWidget.setColumnCount(5)
        self.packetTableWidget.setHorizontalHeaderLabels(["Time", "Protocol", "Source", "Destination", "Length"])
        self.packetTableWidget.setColumnWidth(1, 100)  # 调整协议列宽度以适应内容
        self.packetTableWidget.setColumnWidth(4, 80)
        self.packetTableWidget.itemClicked.connect(self.display_packet_info)

        # 默认选择第一个接口
        if self.interfaces_list:
            self.change_interface(0)

    def is_url(self, text):
        """
        判断输入的文本是否为 URL。支持域名（如 baidu.com）和完整的 URL（如 https://www.baidu.com）。
        但排除 IP 地址（如 1.1.1.1）。
        """
        # 去除前后的空格
        text = text.strip()
        
        # 检查是否是有效的 IP 地址（简单检查，排除 IP）
        ip_regex = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_regex, text):
            return False

        # 域名的正则表达式（包括带协议和不带协议的域名）
        domain_regex = r"^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,6}$"
        
        # 如果是域名（没有协议），返回 True
        if re.match(domain_regex, text):
            return True
        
        # 如果是完整的 URL（带协议），使用 urlparse 解析并检查协议部分
        parsed = urllib.parse.urlparse(text)
        return parsed.scheme in ('http', 'https') and parsed.netloc



    def extract_hostname(self, url):
        """
        从 URL 中提取主机名。如果没有协议（即不完整 URL），假设它是一个域名。
        """
        # 如果没有协议，则加上 http:// 作为默认协议来处理
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc


    def resolve_hostname(self, hostname):
        """
        将主机名解析为 IP 地址列表。
        """
        try:
            resolved_ips = socket.gethostbyname_ex(hostname)[2]
            if not resolved_ips:
                raise socket.gaierror
            return resolved_ips
        except socket.gaierror:
            QMessageBox.warning(self, "Invalid URL", f"无法解析主机名: {hostname}")
            return []


    def apply_filters(self):
        """
        应用过滤条件，包括协议、源、目的地（支持 IP 和 URL）。
        """
        self.current_protocol_filter = self.protocolLineEdit.text().strip()
        self.current_src_filter = self.sourceLineEdit.text().strip()
        self.current_dst_filter = self.destinationLineEdit.text().strip()

        self.resolved_src_ips = []
        self.resolved_dst_ips = []

        # 解析源过滤器
        if self.current_src_filter:
            if self.is_url(self.current_src_filter):
                hostname = self.extract_hostname(self.current_src_filter)
                self.resolved_src_ips = self.resolve_hostname(hostname)
            else:
                # 假设是 IP 地址
                self.resolved_src_ips = [self.current_src_filter]

        # 解析目的地过滤器
        if self.current_dst_filter:
            if self.is_url(self.current_dst_filter):
                hostname = self.extract_hostname(self.current_dst_filter)
                self.resolved_dst_ips = self.resolve_hostname(hostname)
            else:
                # 假设是 IP 地址
                self.resolved_dst_ips = [self.current_dst_filter]

        # 刷新数据包显示
        current_index = self.networkInterfacesComboBox.currentIndex()
        self.change_interface(current_index)



    def change_interface(self, index):
        """
        更改当前选择的网络接口，刷新数据包表格。
        """
        if index < 0 or index >= len(self.interfaces_list):
            return

        selected_iface = self.interfaces_list[index]
        self.packetDetailsTextEdit.clear()

        # 刷新数据包表格
        self.packetTableWidget.clearContents()
        self.packetTableWidget.setRowCount(0)

        # 显示选定接口的现有数据包
        for pkt in self.packets_dict[selected_iface]:
            self.display_filtered_packet(pkt)

    def clear_packets(self):
        """
        清除当前接口的所有捕获数据包。
        """
        current_index = self.networkInterfacesComboBox.currentIndex()
        if current_index < 0 or current_index >= len(self.interfaces_list):
            return

        current_iface = self.interfaces_list[current_index]
        self.packets_dict[current_iface].clear()
        self.packetTableWidget.clearContents()
        self.packetTableWidget.setRowCount(0)
        self.packetDetailsTextEdit.clear()

    def begin_sniffing(self):
        """
        开始抓包，启动捕获线程。
        """
        current_index = self.networkInterfacesComboBox.currentIndex()
        if current_index < 0 or current_index >= len(self.interfaces_list):
            QMessageBox.warning(self, "Warning", "请选择一个有效的网络接口进行抓包。")
            return

        iface = self.interfaces_list[current_index]
        self.capture_thread = CaptureThread(iface)
        self.capture_thread.packet_received.connect(self.handle_packet)
        self.capture_thread.start()

        # 更新 UI 状态
        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)
        self.networkInterfacesComboBox.setEnabled(False)
        self.yesReassembleRadioButton.setEnabled(False)
        self.noReassembleRadioButton.setEnabled(False)

    def end_sniffing(self):
        """
        停止抓包，终止捕获线程。
        """
        if hasattr(self, 'capture_thread') and self.capture_thread.isRunning():
            self.capture_thread.stop_capture()

            if self.capture_thread.isRunning():
                response = QMessageBox.warning(
                    self,
                    "警告",
                    "无法停止抓包。是否强制终止？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if response == QMessageBox.StandardButton.Yes:
                    self.capture_thread.terminate()
                    self.capture_thread.wait(3000)
                    if self.capture_thread.isRunning():
                        QMessageBox.warning(self, "警告", "无法终止抓包线程！")
                        return
                else:
                    return

        # 恢复 UI 状态
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)
        self.networkInterfacesComboBox.setEnabled(True)
        self.yesReassembleRadioButton.setEnabled(True)
        self.noReassembleRadioButton.setEnabled(True)

    def handle_packet(self, packet):
        """
        处理捕获到的数据包，存储并根据过滤条件显示。
        """
        current_index = self.networkInterfacesComboBox.currentIndex()
        if current_index < 0 or current_index >= len(self.interfaces_list):
            return

        current_iface = self.interfaces_list[current_index]
        self.packets_dict[current_iface].append(packet)
        self.display_filtered_packet(packet)

    def determine_protocol(self, packet):
        """
        确定数据包的协议类型。
        """
        if packet.haslayer('TCP'):
            return 'TCP'
        elif packet.haslayer('UDP'):
            return 'UDP'
        elif packet.haslayer('ICMP'):
            return 'ICMP'
        elif packet.haslayer('DNS'):
            return 'DNS'
        else:
            return 'Other'

    def display_filtered_packet(self, packet):
        """
        根据当前的过滤条件，决定是否显示数据包。
        """
        protocol = self.determine_protocol(packet)

        # 提取源和目的地址
        if packet.haslayer('IP'):
            src = packet['IP'].src
            dst = packet['IP'].dst
        elif packet.haslayer('IPv6'):
            src = packet['IPv6'].src
            dst = packet['IPv6'].dst
        else:
            src = packet.src if hasattr(packet, 'src') else 'N/A'
            dst = packet.dst if hasattr(packet, 'dst') else 'N/A'

        # 应用协议过滤
        if self.current_protocol_filter and self.current_protocol_filter.lower() not in protocol.lower():
            return

        # 应用源过滤
        if self.resolved_src_ips:
            if src not in self.resolved_src_ips:
                return
        elif self.current_src_filter and self.current_src_filter != src:
            return

        # 应用目的地过滤
        if self.resolved_dst_ips:
            if dst not in self.resolved_dst_ips:
                return
        elif self.current_dst_filter and self.current_dst_filter != dst:
            return

        self.add_packet_to_table(packet)

    def add_packet_to_table(self, packet):
        """
        将符合过滤条件的数据包信息添加到表格中。
        """
        timestamp = float(packet.time)
        formatted_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        protocol = self.determine_protocol(packet)

        # 提取源和目的地址
        if packet.haslayer('IP'):
            src = packet['IP'].src
            dst = packet['IP'].dst
        elif packet.haslayer('IPv6'):
            src = packet['IPv6'].src
            dst = packet['IPv6'].dst
        else:
            src = packet.src if hasattr(packet, 'src') else 'N/A'
            dst = packet.dst if hasattr(packet, 'dst') else 'N/A'

        pkt_length = len(packet)

        # 将数据包信息插入表格
        row_idx = self.packetTableWidget.rowCount()
        self.packetTableWidget.insertRow(row_idx)

        # 根据协议设置行颜色
        row_color = self.protocol_color_mapping.get(protocol, self.protocol_color_mapping['Other'])
        packet_info = [formatted_time, protocol, src, dst, str(pkt_length)]

        for col, info in enumerate(packet_info):
            table_item = QTableWidgetItem(info)
            table_item.setBackground(row_color)
            table_item.setFlags(table_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.packetTableWidget.setItem(row_idx, col, table_item)

    def display_packet_info(self, item):
        """
        显示选中数据包的详细信息。
        """
        row = item.row()
        current_index = self.networkInterfacesComboBox.currentIndex()
        if current_index < 0 or current_index >= len(self.interfaces_list):
            self.packetDetailsTextEdit.setPlainText("无效的接口选择。")
            return

        current_iface = self.interfaces_list[current_index]

        try:
            packet = self.packets_dict[current_iface][row]
            # 使用 Scapy 的 show() 方法获取详细信息
            packet_details = packet.show(dump=True)
            self.packetDetailsTextEdit.setPlainText(packet_details)
        except IndexError:
            self.packetDetailsTextEdit.setPlainText("此数据包暂无详细信息。")

    def toggle_ip_reassembly(self, checked):
        """
        切换 IP 重组功能。
        """
        sender = self.sender()
        if sender == self.yesReassembleRadioButton and checked:
            self.ip_reassembly_enabled = True
        elif sender == self.noReassembleRadioButton and checked:
            self.ip_reassembly_enabled = False

    def export_packets(self):
        """
        导出当前接口的捕获数据包到 PCAP 文件。
        """
        options = QFileDialog.Option.DontUseNativeDialog
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存捕获的数据包",
            "",
            "PCAP 文件 (*.pcap);;所有文件 (*)",
            options=options
        )

        if file_path:
            current_index = self.networkInterfacesComboBox.currentIndex()
            if current_index < 0 or current_index >= len(self.interfaces_list):
                QMessageBox.warning(self, "警告", "请选择一个有效的网络接口进行保存。")
                return

            current_iface = self.interfaces_list[current_index]
            try:
                wrpcap(file_path, self.packets_dict[current_iface])
                QMessageBox.information(self, "成功", f"数据包已成功保存到 {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"保存数据包失败:\n{e}")

    def import_packets(self):
        """
        从 PCAP 文件导入数据包并显示。
        """
        try:
            options = QFileDialog.Option.DontUseNativeDialog
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "加载数据包捕获",
                "",
                "PCAP 文件 (*.pcap);;所有文件 (*)",
                options=options
            )

            if file_path:
                loaded_packets = rdpcap(file_path)
                current_index = self.networkInterfacesComboBox.currentIndex()
                if current_index < 0 or current_index >= len(self.interfaces_list):
                    QMessageBox.warning(self, "警告", "请选择一个有效的网络接口进行导入。")
                    return

                current_iface = self.interfaces_list[current_index]
                for pkt in loaded_packets:
                    self.packets_dict[current_iface].append(pkt)
                    self.display_filtered_packet(pkt)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载 PCAP 文件失败:\n{e}")


def main():
    app = QApplication(sys.argv)
    window = SnifferApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
