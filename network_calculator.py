"""
网络计算器 - Windows 版本
完全基于 macOS 源码实现的功能一致版本
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import ipaddress
import json
import math
from pathlib import Path
from datetime import datetime
import re


class NetworkCalculator:
    """IPv4 网络计算器核心类"""
    
    @staticmethod
    def ip_to_binary(ip):
        """IP地址转二进制"""
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return ""
            return '.'.join(format(octet, '08b') for octet in octets)
        except:
            return ""
    
    @staticmethod
    def cidr_to_mask(cidr):
        """CIDR转子网掩码"""
        try:
            cidr = int(cidr)
            if not 0 <= cidr <= 32:
                return None
            
            # 生成二进制掩码
            binary_mask = '1' * cidr + '0' * (32 - cidr)
            
            # 转换为点分十进制
            octets = []
            for i in range(0, 32, 8):
                octet = binary_mask[i:i+8]
                octets.append(str(int(octet, 2)))
            
            mask = '.'.join(octets)
            binary_display = '.'.join([binary_mask[i:i+8] for i in range(0, 32, 8)])
            
            return {'mask': mask, 'binary': binary_display}
        except:
            return None
    
    @staticmethod
    def mask_to_cidr(mask):
        """子网掩码转CIDR"""
        try:
            # 处理 /24 格式
            if mask.startswith('/'):
                cidr = int(mask[1:])
                if 0 <= cidr <= 32:
                    binary = '1' * cidr + '0' * (32 - cidr)
                    binary_display = '.'.join([binary[i:i+8] for i in range(0, 32, 8)])
                    return {'cidr': cidr, 'binary': binary_display}
                return None
            
            # 处理点分十进制格式
            octets = [int(x) for x in mask.split('.')]
            if len(octets) != 4:
                return None
            
            # 转为二进制
            binary = ''.join(format(octet, '08b') for octet in octets)
            
            # 验证是否为有效掩码（连续的1后面是连续的0）
            if '01' in binary:
                return None
            
            cidr = binary.count('1')
            binary_display = '.'.join([binary[i:i+8] for i in range(0, 32, 8)])
            
            return {'cidr': cidr, 'binary': binary_display}
        except:
            return None
    
    @staticmethod
    def calculate_mask_from_hosts(host_count):
        """根据主机数计算掩码"""
        try:
            host_count = int(host_count)
            if host_count <= 0:
                return None
            
            # 计算需要的主机位数
            needed_bits = math.ceil(math.log2(host_count + 2))
            if needed_bits > 30:
                return None
            
            cidr = 32 - needed_bits
            usable_hosts = (2 ** needed_bits) - 2
            
            mask_result = NetworkCalculator.cidr_to_mask(cidr)
            if not mask_result:
                return None
            
            return {
                'mask': mask_result['mask'],
                'cidr': cidr,
                'max_hosts': usable_hosts
            }
        except:
            return None
    
    @staticmethod
    def is_valid_ip(ip):
        """验证IP地址"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if not 0 <= num <= 255:
                    return False
            return True
        except:
            return False
    
    @staticmethod
    def get_ip_class(first_octet):
        """获取IP类别"""
        if 0 <= first_octet <= 127:
            return "A"
        elif 128 <= first_octet <= 191:
            return "B"
        elif 192 <= first_octet <= 223:
            return "C"
        elif 224 <= first_octet <= 239:
            return "D (组播)"
        elif 240 <= first_octet <= 255:
            return "E (保留)"
        else:
            return "未知"
    
    @staticmethod
    def calculate_network_info(ip, mask):
        """计算网络信息"""
        try:
            if not NetworkCalculator.is_valid_ip(ip):
                return None
            
            # 获取掩码信息
            mask_info = NetworkCalculator.mask_to_cidr(mask)
            if not mask_info:
                return None
            
            # 如果输入是CIDR格式，获取点分十进制掩码
            if mask.startswith('/'):
                cidr_value = int(mask[1:])
                mask_result = NetworkCalculator.cidr_to_mask(cidr_value)
                if not mask_result:
                    return None
                mask_decimal = mask_result['mask']
            else:
                mask_decimal = mask
            
            # 使用 ipaddress 库进行计算
            network = ipaddress.IPv4Network(f"{ip}/{mask_info['cidr']}", strict=False)
            
            # 计算各种地址
            network_address = str(network.network_address)
            broadcast_address = str(network.broadcast_address)
            
            # 计算主机范围
            hosts = list(network.hosts())
            if hosts:
                first_host = str(hosts[0])
                last_host = str(hosts[-1])
            else:
                first_host = network_address
                last_host = broadcast_address
            
            # 计算通配符掩码
            mask_octets = [int(x) for x in mask_decimal.split('.')]
            wildcard_mask = '.'.join(str(255 - x) for x in mask_octets)
            
            # 获取IP类别
            ip_octets = [int(x) for x in ip.split('.')]
            ip_class = NetworkCalculator.get_ip_class(ip_octets[0])
            
            return {
                'ip_address': ip,
                'subnet_mask': mask_decimal,
                'network_address': network_address,
                'broadcast_address': broadcast_address,
                'first_host': first_host,
                'last_host': last_host,
                'total_hosts': network.num_addresses,
                'usable_hosts': max(network.num_addresses - 2, 0) if network.num_addresses > 2 else 0,
                'cidr': mask_info['cidr'],
                'ip_class': ip_class,
                'ip_binary': NetworkCalculator.ip_to_binary(ip),
                'mask_binary': mask_info['binary'],
                'wildcard_mask': wildcard_mask
            }
        except Exception as e:
            print(f"计算错误: {e}")
            return None


class IPv6Calculator:
    """IPv6 计算器核心类"""
    
    @staticmethod
    def is_valid_ipv6(ip):
        """验证IPv6地址"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except:
            return False
    
    @staticmethod
    def expand_ipv6(ip):
        """展开IPv6地址"""
        try:
            addr = ipaddress.IPv6Address(ip)
            return addr.exploded
        except:
            return None
    
    @staticmethod
    def compress_ipv6(ip):
        """压缩IPv6地址"""
        try:
            addr = ipaddress.IPv6Address(ip)
            return addr.compressed
        except:
            return None
    
    @staticmethod
    def calculate_ipv6_info(ip, prefix):
        """计算IPv6网络信息"""
        try:
            prefix = int(prefix)
            if not 0 <= prefix <= 128:
                return None
            
            network = ipaddress.IPv6Network(f"{ip}/{prefix}", strict=False)
            
            # 计算地址数量
            total_addresses = 2 ** (128 - prefix)
            
            # 格式化大数字
            if total_addresses > 10**15:
                total_str = f"{total_addresses:.2e}"
            else:
                total_str = f"{total_addresses:,}"
            
            # 判断地址类型
            addr = ipaddress.IPv6Address(ip)
            if addr.is_loopback:
                addr_type = "环回地址"
            elif addr.is_link_local:
                addr_type = "链路本地地址"
            elif addr.is_site_local:
                addr_type = "站点本地地址"
            elif addr.is_multicast:
                addr_type = "组播地址"
            elif addr.is_global:
                addr_type = "全局单播地址"
            else:
                addr_type = "未指定地址"
            
            return {
                'ip_address': ip,
                'prefix': prefix,
                'network_address': str(network.network_address),
                'first_address': str(network.network_address),
                'last_address': str(network.broadcast_address),
                'total_addresses': total_str,
                'address_type': addr_type,
                'expanded': IPv6Calculator.expand_ipv6(ip),
                'compressed': IPv6Calculator.compress_ipv6(ip)
            }
        except:
            return None


class MACAddressConverter:
    """MAC地址转换器"""
    
    @staticmethod
    def normalize_mac(mac):
        """标准化MAC地址"""
        # 移除所有分隔符
        mac = re.sub(r'[:\-\.]', '', mac)
        mac = mac.upper()
        
        if len(mac) != 12:
            return None
        
        # 验证是否为有效十六进制
        try:
            int(mac, 16)
        except:
            return None
        
        return mac
    
    @staticmethod
    def convert_mac(mac, format_type):
        """转换MAC地址格式"""
        normalized = MACAddressConverter.normalize_mac(mac)
        if not normalized:
            return None
        
        if format_type == "colon":
            # AA:BB:CC:DD:EE:FF
            return ':'.join(normalized[i:i+2] for i in range(0, 12, 2))
        elif format_type == "hyphen":
            # AA-BB-CC-DD-EE-FF
            return '-'.join(normalized[i:i+2] for i in range(0, 12, 2))
        elif format_type == "dot":
            # AABB.CCDD.EEFF
            return '.'.join(normalized[i:i+4] for i in range(0, 12, 4))
        elif format_type == "none":
            # AABBCCDDEEFF
            return normalized
        else:
            return None
    
    @staticmethod
    def get_vendor_info(mac):
        """获取厂商信息（简化版）"""
        normalized = MACAddressConverter.normalize_mac(mac)
        if not normalized:
            return "无效的MAC地址"
        
        oui = normalized[:6]
        
        # 简化的OUI数据库（可以扩展）
        oui_database = {
            '000000': 'Xerox Corporation',
            '00005E': 'IANA (Internet Assigned Numbers Authority)',
            '0000FF': 'Reserved',
            '001122': 'Cisco Systems',
            '001B63': 'Apple Inc.',
            '00D0C9': 'Intel Corporation',
            '00E04C': 'Realtek Semiconductor',
            '08002B': 'Digital Equipment Corporation',
            '080027': 'Oracle VirtualBox',
            '525400': 'QEMU/KVM Virtual NIC',
        }
        
        vendor = oui_database.get(oui, f"未知厂商 (OUI: {oui})")
        return vendor


class HistoryManager:
    """历史记录管理器"""
    
    def __init__(self):
        self.history_file = Path.home() / ".network_calculator_history.json"
        self.history = self.load_history()
    
    def load_history(self):
        """加载历史记录"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def save_history(self):
        """保存历史记录"""
        try:
            # 只保留最近100条记录
            self.history = self.history[-100:]
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"保存历史记录失败: {e}")
    
    def add_record(self, calc_type, input_data, result_summary):
        """添加历史记录"""
        record = {
            'type': calc_type,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'input': input_data,
            'result': result_summary
        }
        self.history.append(record)
        self.save_history()
    
    def clear_history(self):
        """清空历史记录"""
        self.history = []
        self.save_history()


class IPCalculatorTab(ttk.Frame):
    """IP计算器标签页"""
    
    def __init__(self, parent, history_manager):
        super().__init__(parent)
        self.history_manager = history_manager
        
        # 创建输入区域
        input_frame = ttk.LabelFrame(self, text="输入", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="IP地址:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip_entry = ttk.Entry(input_frame, width=30)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        self.ip_entry.insert(0, "192.168.1.1")
        
        ttk.Label(input_frame, text="子网掩码/CIDR:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.mask_entry = ttk.Entry(input_frame, width=30)
        self.mask_entry.grid(row=1, column=1, padx=5, pady=5)
        self.mask_entry.insert(0, "255.255.255.0")
        
        ttk.Button(input_frame, text="计算", command=self.calculate).grid(row=2, column=0, columnspan=2, pady=10)
        
        # 创建结果区域
        result_frame = ttk.LabelFrame(self, text="计算结果", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=20, width=70)
        self.result_text.pack(fill=tk.BOTH, expand=True)
    
    def calculate(self):
        """执行计算"""
        ip = self.ip_entry.get().strip()
        mask = self.mask_entry.get().strip()
        
        result = NetworkCalculator.calculate_network_info(ip, mask)
        
        if result:
            output = f"""
IP地址: {result['ip_address']}
子网掩码: {result['subnet_mask']}
CIDR: /{result['cidr']}
IP类别: {result['ip_class']}

网络地址: {result['network_address']}
广播地址: {result['broadcast_address']}
第一个可用主机: {result['first_host']}
最后一个可用主机: {result['last_host']}

通配符掩码: {result['wildcard_mask']}
总主机数: {result['total_hosts']}
可用主机数: {result['usable_hosts']}

IP地址 (二进制): {result['ip_binary']}
子网掩码 (二进制): {result['mask_binary']}
"""
            
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', output)
            
            # 保存到历史记录
            self.history_manager.add_record(
                "IPv4 计算",
                f"{ip} / {mask}",
                f"网络: {result['network_address']}/{result['cidr']}"
            )
        else:
            messagebox.showerror("错误", "无效的IP地址或子网掩码")


class SubnetMaskTab(ttk.Frame):
    """子网掩码标签页"""
    
    def __init__(self, parent, history_manager):
        super().__init__(parent)
        self.history_manager = history_manager
        
        # 创建输入区域
        input_frame = ttk.LabelFrame(self, text="输入", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="CIDR (0-32):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.cidr_entry = ttk.Entry(input_frame, width=30)
        self.cidr_entry.grid(row=0, column=1, padx=5, pady=5)
        self.cidr_entry.insert(0, "24")
        
        ttk.Button(input_frame, text="计算子网掩码", command=self.calculate_mask).grid(row=1, column=0, columnspan=2, pady=10)
        
        # 分隔线
        ttk.Separator(input_frame, orient=tk.HORIZONTAL).grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=10)
        
        ttk.Label(input_frame, text="子网掩码:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.mask_entry = ttk.Entry(input_frame, width=30)
        self.mask_entry.grid(row=3, column=1, padx=5, pady=5)
        self.mask_entry.insert(0, "255.255.255.0")
        
        ttk.Button(input_frame, text="计算CIDR", command=self.calculate_cidr).grid(row=4, column=0, columnspan=2, pady=10)
        
        # 创建结果区域
        result_frame = ttk.LabelFrame(self, text="计算结果", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=15, width=70)
        self.result_text.pack(fill=tk.BOTH, expand=True)
    
    def calculate_mask(self):
        """CIDR转子网掩码"""
        cidr = self.cidr_entry.get().strip()
        result = NetworkCalculator.cidr_to_mask(cidr)
        
        if result:
            output = f"""
CIDR: /{cidr}
子网掩码: {result['mask']}
二进制: {result['binary']}
"""
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', output)
            
            self.history_manager.add_record(
                "子网掩码计算",
                f"CIDR: /{cidr}",
                f"掩码: {result['mask']}"
            )
        else:
            messagebox.showerror("错误", "无效的CIDR值")
    
    def calculate_cidr(self):
        """子网掩码转CIDR"""
        mask = self.mask_entry.get().strip()
        result = NetworkCalculator.mask_to_cidr(mask)
        
        if result:
            output = f"""
子网掩码: {mask}
CIDR: /{result['cidr']}
二进制: {result['binary']}
"""
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', output)
            
            self.history_manager.add_record(
                "子网掩码计算",
                f"掩码: {mask}",
                f"CIDR: /{result['cidr']}"
            )
        else:
            messagebox.showerror("错误", "无效的子网掩码")


class HostCalculatorTab(ttk.Frame):
    """主机数计算标签页"""
    
    def __init__(self, parent, history_manager):
        super().__init__(parent)
        self.history_manager = history_manager
        
        # 创建输入区域
        input_frame = ttk.LabelFrame(self, text="输入", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="需要的主机数:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.hosts_entry = ttk.Entry(input_frame, width=30)
        self.hosts_entry.grid(row=0, column=1, padx=5, pady=5)
        self.hosts_entry.insert(0, "100")
        
        ttk.Button(input_frame, text="计算子网掩码", command=self.calculate).grid(row=1, column=0, columnspan=2, pady=10)
        
        # 创建结果区域
        result_frame = ttk.LabelFrame(self, text="计算结果", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=15, width=70)
        self.result_text.pack(fill=tk.BOTH, expand=True)
    
    def calculate(self):
        """执行计算"""
        hosts = self.hosts_entry.get().strip()
        result = NetworkCalculator.calculate_mask_from_hosts(hosts)
        
        if result:
            output = f"""
需要的主机数: {hosts}

推荐配置:
CIDR: /{result['cidr']}
子网掩码: {result['mask']}
最大可用主机数: {result['max_hosts']}
"""
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', output)
            
            self.history_manager.add_record(
                "主机数计算",
                f"需要 {hosts} 个主机",
                f"推荐 /{result['cidr']}, 可容纳 {result['max_hosts']} 个主机"
            )
        else:
            messagebox.showerror("错误", "无效的主机数")


class IPv6CalculatorTab(ttk.Frame):
    """IPv6计算器标签页"""
    
    def __init__(self, parent, history_manager):
        super().__init__(parent)
        self.history_manager = history_manager
        
        # 创建输入区域
        input_frame = ttk.LabelFrame(self, text="输入", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="IPv6地址:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ipv6_entry = ttk.Entry(input_frame, width=40)
        self.ipv6_entry.grid(row=0, column=1, padx=5, pady=5)
        self.ipv6_entry.insert(0, "2001:db8::1")
        
        ttk.Label(input_frame, text="前缀长度:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.prefix_entry = ttk.Entry(input_frame, width=40)
        self.prefix_entry.grid(row=1, column=1, padx=5, pady=5)
        self.prefix_entry.insert(0, "64")
        
        ttk.Button(input_frame, text="计算", command=self.calculate).grid(row=2, column=0, columnspan=2, pady=10)
        
        # 创建结果区域
        result_frame = ttk.LabelFrame(self, text="计算结果", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=15, width=70)
        self.result_text.pack(fill=tk.BOTH, expand=True)
    
    def calculate(self):
        """执行计算"""
        ipv6 = self.ipv6_entry.get().strip()
        prefix = self.prefix_entry.get().strip()
        
        result = IPv6Calculator.calculate_ipv6_info(ipv6, prefix)
        
        if result:
            output = f"""
IPv6地址: {result['ip_address']}
前缀长度: /{result['prefix']}
地址类型: {result['address_type']}

网络地址: {result['network_address']}
第一个地址: {result['first_address']}
最后一个地址: {result['last_address']}
总地址数: {result['total_addresses']}

完整格式: {result['expanded']}
压缩格式: {result['compressed']}
"""
            self.result_text.delete('1.0', tk.END)
            self.result_text.insert('1.0', output)
            
            self.history_manager.add_record(
                "IPv6 计算",
                f"{ipv6}/{prefix}",
                f"网络: {result['network_address']}"
            )
        else:
            messagebox.showerror("错误", "无效的IPv6地址或前缀")


class MACAddressTab(ttk.Frame):
    """MAC地址转换标签页"""
    
    def __init__(self, parent, history_manager):
        super().__init__(parent)
        self.history_manager = history_manager
        
        # 创建输入区域
        input_frame = ttk.LabelFrame(self, text="输入", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text="MAC地址:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.mac_entry = ttk.Entry(input_frame, width=40)
        self.mac_entry.grid(row=0, column=1, padx=5, pady=5)
        self.mac_entry.insert(0, "00:1B:63:84:45:E6")
        
        ttk.Button(input_frame, text="转换并查询", command=self.convert).grid(row=1, column=0, columnspan=2, pady=10)
        
        # 创建结果区域
        result_frame = ttk.LabelFrame(self, text="转换结果", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, height=15, width=70)
        self.result_text.pack(fill=tk.BOTH, expand=True)
    
    def convert(self):
        """执行转换"""
        mac = self.mac_entry.get().strip()
        
        # 转换为各种格式
        formats = {
            'colon': ('冒号分隔', MACAddressConverter.convert_mac(mac, 'colon')),
            'hyphen': ('连字符分隔', MACAddressConverter.convert_mac(mac, 'hyphen')),
            'dot': ('点分隔 (Cisco)', MACAddressConverter.convert_mac(mac, 'dot')),
            'none': ('无分隔符', MACAddressConverter.convert_mac(mac, 'none'))
        }
        
        if all(result is None for _, result in formats.values()):
            messagebox.showerror("错误", "无效的MAC地址")
            return
        
        output = "MAC地址格式转换:\n\n"
        for name, result in formats.values():
            if result:
                output += f"{name}: {result}\n"
        
        # 获取厂商信息
        vendor = MACAddressConverter.get_vendor_info(mac)
        output += f"\n厂商信息: {vendor}\n"
        
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert('1.0', output)
        
        self.history_manager.add_record(
            "MAC地址转换",
            mac,
            vendor
        )


class HistoryTab(ttk.Frame):
    """历史记录标签页"""
    
    def __init__(self, parent, history_manager):
        super().__init__(parent)
        self.history_manager = history_manager
        
        # 创建工具栏
        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(toolbar, text="刷新", command=self.refresh).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="清空历史", command=self.clear_history).pack(side=tk.LEFT, padx=5)
        
        # 创建历史记录列表
        list_frame = ttk.LabelFrame(self, text="历史记录", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 创建树形视图
        columns = ('时间', '类型', '输入', '结果')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 初始加载
        self.refresh()
    
    def refresh(self):
        """刷新历史记录"""
        # 清空现有项
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 重新加载
        self.history_manager.history = self.history_manager.load_history()
        
        # 逆序显示（最新的在前）
        for record in reversed(self.history_manager.history):
            self.tree.insert('', tk.END, values=(
                record.get('timestamp', ''),
                record.get('type', ''),
                record.get('input', ''),
                record.get('result', '')
            ))
    
    def clear_history(self):
        """清空历史记录"""
        if messagebox.askyesno("确认", "确定要清空所有历史记录吗？"):
            self.history_manager.clear_history()
            self.refresh()


class NetworkCalculatorApp:
    """网络计算器主应用"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("网络计算器")
        self.root.geometry("900x700")
        
        # 创建历史管理器
        self.history_manager = HistoryManager()
        
        # 创建标签页
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 添加各个标签页
        self.ip_calc_tab = IPCalculatorTab(self.notebook, self.history_manager)
        self.notebook.add(self.ip_calc_tab, text="IP计算器")
        
        self.subnet_tab = SubnetMaskTab(self.notebook, self.history_manager)
        self.notebook.add(self.subnet_tab, text="子网掩码")
        
        self.host_tab = HostCalculatorTab(self.notebook, self.history_manager)
        self.notebook.add(self.host_tab, text="主机数计算")
        
        self.ipv6_tab = IPv6CalculatorTab(self.notebook, self.history_manager)
        self.notebook.add(self.ipv6_tab, text="IPv6计算器")
        
        self.mac_tab = MACAddressTab(self.notebook, self.history_manager)
        self.notebook.add(self.mac_tab, text="MAC地址转换")
        
        self.history_tab = HistoryTab(self.notebook, self.history_manager)
        self.notebook.add(self.history_tab, text="历史记录")
        
        # 创建菜单栏
        self.create_menu()
    
    def create_menu(self):
        """创建菜单栏"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="退出", command=self.root.quit)
        
        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self.show_about)
    
    def show_about(self):
        """显示关于对话框"""
        about_text = """
网络计算器 v1.0

功能特性:
• IPv4 网络计算
• IPv6 网络计算
• 子网掩码转换
• 主机数计算
• MAC 地址转换
• 历史记录管理

基于 macOS 版本开发
"""
        messagebox.showinfo("关于", about_text)
    
    def run(self):
        """运行应用"""
        self.root.mainloop()


if __name__ == "__main__":
    app = NetworkCalculatorApp()
    app.run()
