"""
网络计算器 - Windows 版本
界面完全对照 macOS SwiftUI 版本重建
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ipaddress
import json
import re
import math
from datetime import datetime
from pathlib import Path

# ══════════════════════════════════════════════
#  颜色 & 字体常量（对照 macOS 系统设计规范）
# ══════════════════════════════════════════════
BLUE         = "#007AFF"
BLUE_DARK    = "#0062CC"
BLUE_LIGHT   = "#EBF4FF"
GREEN_LIGHT  = "#EBFBF1"
ORANGE_LIGHT = "#FFF6EB"
GRAY_BG      = "#F5F5F7"
CARD_BG      = "#FFFFFF"
WIN_BG       = "#F2F2F7"
TEXT_PRI     = "#1C1C1E"
TEXT_SEC     = "#636366"
BORDER       = "#C7C7CC"
BIT_ON       = "#3B82F6"   # 二进制 1 的颜色（blue）
BIT_OFF      = "#D1D1D6"   # 二进制 0 的颜色（gray）

def F(size=13, bold=False, mono=False):
    """跨平台字体"""
    family = "Courier New" if mono else "Microsoft YaHei UI"
    weight = "bold" if bold else "normal"
    return (family, size, weight)

# ══════════════════════════════════════════════
#  可复用 UI 组件
# ══════════════════════════════════════════════

class ScrollFrame(tk.Frame):
    """带滚动条的可滚动容器（对标 SwiftUI ScrollView）"""
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=WIN_BG)
        canvas = tk.Canvas(self, bg=WIN_BG, highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self.inner = tk.Frame(canvas, bg=WIN_BG)
        win_id = canvas.create_window((0, 0), window=self.inner, anchor="nw")

        def _on_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def _on_canvas_configure(e):
            canvas.itemconfig(win_id, width=e.width)

        self.inner.bind("<Configure>", _on_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        # 鼠标滚轮
        def _on_mousewheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)


class Card(tk.Frame):
    """卡片容器（对标 SwiftUI 的 .background + .cornerRadius）"""
    def __init__(self, parent, bg=CARD_BG, padding=16, **kw):
        super().__init__(parent, bg=bg, relief="flat", bd=0,
                         highlightbackground=BORDER, highlightthickness=1)
        self.inner = tk.Frame(self, bg=bg, padx=padding, pady=padding)
        self.inner.pack(fill="both", expand=True)


class SectionTitle(tk.Label):
    """卡片标题（对标 SwiftUI .font(.headline)）"""
    def __init__(self, parent, text, bg=CARD_BG, **kw):
        super().__init__(parent, text=text, font=F(14, bold=True), bg=bg,
                         fg=TEXT_PRI, anchor="w")


class InfoRow(tk.Frame):
    """结果行：标签 + 等宽值 + 复制按钮（对标 SwiftUI InfoRow）"""
    def __init__(self, parent, label, value, bg=CARD_BG, copyable=True, root=None):
        super().__init__(parent, bg=bg)
        self._root = root
        self._value = value

        lbl = tk.Label(self, text=label, font=F(12, bold=True), bg=bg,
                       fg=TEXT_PRI, width=14, anchor="w")
        lbl.pack(side="left")

        val = tk.Label(self, text=value, font=F(12, mono=True), bg=bg,
                       fg=TEXT_PRI, anchor="w")
        val.pack(side="left", fill="x", expand=True)

        if copyable and root:
            btn = tk.Button(self, text="复制", font=F(11), relief="flat",
                            bg=BLUE_LIGHT, fg=BLUE, cursor="hand2",
                            padx=6, pady=2,
                            command=self._copy)
            btn.pack(side="right")

    def _copy(self):
        if self._root:
            self._root.clipboard_clear()
            self._root.clipboard_append(self._value)


class SegmentedControl(tk.Frame):
    """分段选择器（对标 SwiftUI SegmentedPickerStyle）"""
    def __init__(self, parent, options, variable, command=None, bg=CARD_BG):
        super().__init__(parent, bg=BORDER, bd=1)
        self._var = variable
        self._btns = {}
        self._cmd = command

        for i, opt in enumerate(options):
            btn = tk.Button(self, text=opt, font=F(11), relief="flat", bd=0,
                            cursor="hand2", padx=12, pady=4,
                            command=lambda o=opt: self._select(o))
            btn.pack(side="left")
            self._btns[opt] = btn

        self._update()
        variable.trace_add("write", lambda *a: self._update())

    def _select(self, opt):
        self._var.set(opt)
        if self._cmd:
            self._cmd()

    def _update(self):
        val = self._var.get()
        for opt, btn in self._btns.items():
            if opt == val:
                btn.configure(bg=BLUE, fg="white")
            else:
                btn.configure(bg="#E5E5EA", fg=TEXT_PRI)


class CopyButton(tk.Button):
    def __init__(self, parent, get_text, root, **kw):
        super().__init__(parent, text="复制", font=F(11), relief="flat",
                         bg=BLUE_LIGHT, fg=BLUE, cursor="hand2",
                         padx=6, pady=2,
                         command=lambda: self._copy(get_text(), root), **kw)

    def _copy(self, text, root):
        root.clipboard_clear()
        root.clipboard_append(text)


# ══════════════════════════════════════════════
#  核心计算逻辑
# ══════════════════════════════════════════════

class NetworkCalculator:
    @staticmethod
    def is_valid_ip(ip):
        try:
            parts = [int(x) for x in ip.split(".")]
            return len(parts) == 4 and all(0 <= p <= 255 for p in parts)
        except:
            return False

    @staticmethod
    def cidr_to_mask(cidr):
        cidr = int(cidr)
        if not 0 <= cidr <= 32:
            return None
        binary = "1" * cidr + "0" * (32 - cidr)
        octets = [int(binary[i:i+8], 2) for i in range(0, 32, 8)]
        mask = ".".join(map(str, octets))
        binary_display = ".".join([binary[i:i+8] for i in range(0, 32, 8)])
        return {"mask": mask, "binary": binary_display}

    @staticmethod
    def mask_to_cidr(mask):
        octets = mask.split(".")
        if len(octets) != 4:
            return None
        try:
            ints = [int(o) for o in octets]
        except:
            return None
        if not all(0 <= o <= 255 for o in ints):
            return None
        binary = "".join(f"{o:08b}" for o in ints)
        if "01" in binary:
            return None
        cidr = binary.count("1")
        binary_display = ".".join([binary[i:i+8] for i in range(0, 32, 8)])
        return {"cidr": cidr, "binary": binary_display}

    @staticmethod
    def get_ip_class(ip):
        first = int(ip.split(".")[0])
        if first < 128: return "A 类"
        if first < 192: return "B 类"
        if first < 224: return "C 类"
        if first < 240: return "D 类（组播）"
        return "E 类（保留）"

    @staticmethod
    def calculate_network_info(ip, mask_str):
        try:
            if mask_str.startswith("/"):
                cidr = int(mask_str[1:])
                net = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
            elif mask_str.count(".") == 3:
                net = ipaddress.IPv4Network(f"{ip}/{mask_str}", strict=False)
            else:
                cidr = int(mask_str)
                net = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)

            hosts = list(net.hosts())
            wildcard_parts = [str(255 - int(o)) for o in str(net.netmask).split(".")]
            wildcard = ".".join(wildcard_parts)

            return {
                "ip_address": ip,
                "subnet_mask": str(net.netmask),
                "cidr": net.prefixlen,
                "ip_class": NetworkCalculator.get_ip_class(ip),
                "wildcard_mask": wildcard,
                "network_address": str(net.network_address),
                "broadcast_address": str(net.broadcast_address),
                "first_host": str(hosts[0]) if hosts else str(net.network_address),
                "last_host": str(hosts[-1]) if hosts else str(net.broadcast_address),
                "total_hosts": net.num_addresses,
                "usable_hosts": max(net.num_addresses - 2, 0),
            }
        except Exception as e:
            return None

    @staticmethod
    def calculate_mask_from_hosts(host_count):
        if host_count <= 0:
            return None
        host_bits = math.ceil(math.log2(host_count + 2))
        cidr = 32 - host_bits
        if cidr < 0 or cidr > 32:
            return None
        result = NetworkCalculator.cidr_to_mask(cidr)
        if not result:
            return None
        return {
            "mask": result["mask"],
            "cidr": cidr,
            "max_hosts": 2**host_bits - 2,
        }


class IPv6Calculator:
    @staticmethod
    def expand(addr):
        try:
            return str(ipaddress.IPv6Address(addr).exploded)
        except:
            return None

    @staticmethod
    def compress(addr):
        try:
            return str(ipaddress.IPv6Address(addr).compressed)
        except:
            return None

    @staticmethod
    def calculate(ip, prefix):
        try:
            net = ipaddress.IPv6Network(f"{ip}/{prefix}", strict=False)
            addr = ipaddress.IPv6Address(ip)
            total = net.num_addresses

            # 地址类型
            if addr.is_loopback:
                atype = "环回地址"
            elif addr.is_link_local:
                atype = "链路本地地址"
            elif addr.is_multicast:
                atype = "组播地址"
            elif addr.is_global:
                atype = "全球单播地址"
            else:
                atype = "特殊地址"

            return {
                "ip": str(addr),
                "ip_expanded": addr.exploded,
                "ip_compressed": addr.compressed,
                "prefix": prefix,
                "network_address": str(net.network_address),
                "network_compressed": ipaddress.IPv6Address(net.network_address).compressed,
                "range_start": str(net.network_address),
                "range_end": str(net.broadcast_address),
                "range_start_c": ipaddress.IPv6Address(net.network_address).compressed,
                "range_end_c": ipaddress.IPv6Address(net.broadcast_address).compressed,
                "total": total,
                "address_type": atype,
                "is_64": prefix == 64,
            }
        except Exception as e:
            return None

    @staticmethod
    def subnetting(ip, prefix, new_prefix, count=8):
        try:
            net = ipaddress.IPv6Network(f"{ip}/{prefix}", strict=False)
            subnets = list(net.subnets(new_prefix=new_prefix))
            total_subnets = len(subnets)
            addrs_per = subnets[0].num_addresses if subnets else 0
            preview = subnets[:count]
            return {
                "subnet_count": total_subnets,
                "addrs_per": addrs_per,
                "preview": [{"start": ipaddress.IPv6Address(s.network_address).compressed,
                              "end": ipaddress.IPv6Address(s.broadcast_address).compressed}
                             for s in preview],
            }
        except:
            return None

    @staticmethod
    def slaac(network_ip, prefix, mac):
        try:
            if prefix != 64:
                return None
            mac_clean = re.sub(r"[^0-9a-fA-F]", "", mac)
            if len(mac_clean) != 12:
                return None
            b = [int(mac_clean[i:i+2], 16) for i in range(0, 12, 2)]
            b[0] ^= 0x02
            eui64 = f"{b[0]:02x}{b[1]:02x}:{b[2]:02x}ff:fe{b[3]:02x}:{b[4]:02x}{b[5]:02x}"
            net = ipaddress.IPv6Network(f"{network_ip}/{prefix}", strict=False)
            prefix_hex = net.network_address.exploded[:19]
            slaac_addr = ipaddress.IPv6Address(prefix_hex + eui64.replace(":", "")).compressed

            # Solicited-node
            sn_suffix = slaac_addr[-7:].replace(":", "")
            sol_node = f"ff02::1:ff{sn_suffix[-6:-4]}:{sn_suffix[-4:-2]}{sn_suffix[-2:]}"

            # Multicast MAC
            sn_bytes = bytes.fromhex(sn_suffix[-6:])
            mc_mac = f"33:33:FF:{sn_bytes[0]:02X}:{sn_bytes[1]:02X}:{sn_bytes[2]:02X}"

            return {
                "iid": eui64,
                "slaac_address": slaac_addr,
                "solicited_node": sol_node,
                "multicast_mac": mc_mac,
            }
        except:
            return None


class MACConverter:
    FORMATS = ["大写（冒号）", "小写（冒号）", "大写（短横线）",
               "小写（短横线）", "无分隔符（大写）", "无分隔符（小写）"]

    @staticmethod
    def is_valid(mac):
        patterns = [
            r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$',
            r'^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$',
            r'^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$',
            r'^[0-9A-Fa-f]{12}$',
        ]
        return any(re.match(p, mac) for p in patterns)

    @staticmethod
    def normalize(mac):
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(clean) != 12:
            return mac
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))

    @staticmethod
    def convert(mac, fmt):
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(clean) != 12:
            return ""
        pairs = [clean[i:i+2] for i in range(0, 12, 2)]
        upper_colon = ":".join(pairs)
        if fmt == "大写（冒号）":
            return upper_colon
        if fmt == "小写（冒号）":
            return upper_colon.lower()
        if fmt == "大写（短横线）":
            return "-".join(pairs)
        if fmt == "小写（短横线）":
            return "-".join(pairs).lower()
        if fmt == "无分隔符（大写）":
            return clean
        if fmt == "无分隔符（小写）":
            return clean.lower()
        return upper_colon

    @staticmethod
    def all_formats(mac):
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        pairs = [clean[i:i+2] for i in range(0, 12, 2)]
        colon_u = ":".join(pairs)
        colon_l = colon_u.lower()
        hyphen_u = "-".join(pairs)
        hyphen_l = hyphen_u.lower()
        plain_u = clean
        plain_l = clean.lower()
        group_u = f"{clean[:4]}-{clean[4:8]}-{clean[8:]}"
        group_l = group_u.lower()
        return [colon_u, colon_l, hyphen_u, hyphen_l, plain_u, plain_l, group_u, group_l]

    @staticmethod
    def get_info(mac):
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(clean) != 12:
            return None
        first = int(clean[:2], 16)
        is_multicast = bool(first & 0x01)
        is_local = bool(first & 0x02)
        if is_multicast:
            type_text = "组播地址"
        elif is_local:
            type_text = "本地管理地址"
        else:
            type_text = "全球唯一地址"
        return {
            "normalized": MACConverter.normalize(mac),
            "oui": clean[:6],
            "is_local": is_local,
            "is_multicast": is_multicast,
            "type_text": type_text,
            "all_formats": MACConverter.all_formats(mac),
        }


class HistoryManager:
    def __init__(self):
        self.path = Path.home() / ".network_calculator_history.json"
        self.records = []
        self._load()

    def _load(self):
        try:
            if self.path.exists():
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # 过滤掉缺少必要字段的旧记录，避免 KeyError
                self.records = [
                    r for r in data
                    if isinstance(r, dict) and "type" in r and "summary" in r
                ]
                # 补全缺失字段
                for r in self.records:
                    r.setdefault("time", "")
                    r.setdefault("payload", {})
        except:
            self.records = []

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.records[-200:], f, ensure_ascii=False, indent=2)
        except:
            pass

    def add(self, type_, summary, payload):
        self.records.append({
            "type": type_,
            "summary": summary,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "payload": payload,
        })
        self._save()

    def clear(self):
        self.records = []
        self._save()


history_mgr = HistoryManager()


# ══════════════════════════════════════════════
#  标签页：IP 计算器
# ══════════════════════════════════════════════

class IPCalculatorTab(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=WIN_BG)
        self._root = root
        self._mask_fmt = tk.StringVar(value="CIDR (/xx)")
        self._ip_var = tk.StringVar(value="192.168.1.1")
        self._mask_var = tk.StringVar(value="24")
        self._result = None

        sf = ScrollFrame(self)
        sf.pack(fill="both", expand=True)
        body = sf.inner
        body.columnconfigure(0, weight=1)

        # 标题
        tk.Label(body, text="IP地址计算器", font=F(20, bold=True),
                 bg=WIN_BG, fg=TEXT_PRI).pack(pady=(20, 12))

        # 输入区 Card
        input_card = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        input_card.pack(fill="x", padx=24, pady=6)
        ic = tk.Frame(input_card, bg=CARD_BG, padx=18, pady=16)
        ic.pack(fill="both")
        ic.columnconfigure(1, weight=1)

        # IP 地址
        tk.Label(ic, text="IP地址", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        self._ip_entry = ttk.Entry(ic, textvariable=self._ip_var, font=F(13, mono=True))
        self._ip_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        self._ip_entry.bind("<Return>", lambda e: self._calculate())

        # 子网掩码标题 + 分段选择
        hdr = tk.Frame(ic, bg=CARD_BG)
        hdr.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        tk.Label(hdr, text="子网掩码", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI).pack(side="left")
        SegmentedControl(hdr, ["CIDR (/xx)", "点分十进制"], self._mask_fmt,
                         command=self._on_fmt_change, bg=CARD_BG).pack(side="right")

        # 掩码输入
        self._mask_entry = ttk.Entry(ic, textvariable=self._mask_var, font=F(13, mono=True))
        self._mask_entry.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        self._mask_entry.bind("<Return>", lambda e: self._calculate())

        # 提示
        self._hint_lbl = tk.Label(ic, text="输入 0–32 的数字，如 24 表示 /24",
                                  font=F(11), bg=CARD_BG, fg=TEXT_SEC, anchor="w")
        self._hint_lbl.grid(row=4, column=0, columnspan=2, sticky="w", pady=(0, 10))

        # 计算按钮（蓝底白字全宽）
        btn_frame = tk.Frame(ic, bg=BLUE, cursor="hand2")
        btn_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        calc_btn = tk.Label(btn_frame, text="  🌐  计算网络信息  ",
                            font=F(13, bold=True), bg=BLUE, fg="white",
                            padx=12, pady=10, cursor="hand2")
        calc_btn.pack(fill="x")
        calc_btn.bind("<Button-1>", lambda e: self._calculate())
        btn_frame.bind("<Button-1>", lambda e: self._calculate())

        # 结果区
        self._result_frame = tk.Frame(body, bg=WIN_BG)
        self._result_frame.pack(fill="x", padx=24, pady=10)

        # 初始计算
        self.after(200, self._calculate)

    def _on_fmt_change(self):
        fmt = self._mask_fmt.get()
        if fmt == "CIDR (/xx)":
            self._mask_var.set("24")
            self._hint_lbl.config(text="输入 0–32 的数字，如 24 表示 /24")
        else:
            self._mask_var.set("255.255.255.0")
            self._hint_lbl.config(text="输入点分十进制格式，如 255.255.255.0")

    def _calculate(self):
        ip = self._ip_var.get().strip()
        mask_raw = self._mask_var.get().strip()
        fmt = self._mask_fmt.get()

        if not NetworkCalculator.is_valid_ip(ip):
            messagebox.showerror("错误", "请输入有效的IP地址（格式: 192.168.1.1）")
            return

        if fmt == "CIDR (/xx)":
            try:
                cidr = int(mask_raw)
                assert 0 <= cidr <= 32
                mask_str = f"/{cidr}"
            except:
                messagebox.showerror("错误", "CIDR 值无效，请输入 0–32 之间的数字")
                return
        else:
            result = NetworkCalculator.mask_to_cidr(mask_raw)
            if not result:
                messagebox.showerror("错误", "子网掩码格式错误，请检查输入")
                return
            mask_str = mask_raw

        info = NetworkCalculator.calculate_network_info(ip, mask_str)
        if not info:
            messagebox.showerror("错误", "计算失败，请检查输入参数")
            return

        self._result = info
        history_mgr.add("IPv4 计算",
                         f"{ip} / {mask_str}",
                         {"ip": ip, "mask": mask_str})
        self._render_result(info)

    def _render_result(self, info):
        for w in self._result_frame.winfo_children():
            w.destroy()

        r = self._root

        tk.Label(self._result_frame, text="计算结果", font=F(16, bold=True),
                 bg=WIN_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))

        # 基本信息卡（蓝色背景）
        self._make_result_card(
            self._result_frame, "基本信息", BLUE_LIGHT,
            [
                ("IP地址",    info["ip_address"],   True),
                ("子网掩码",  info["subnet_mask"],   True),
                ("CIDR表示",  f"/{info['cidr']}",    True),
                ("IP类别",    info["ip_class"],      False),
                ("通配符掩码",info["wildcard_mask"], True),
            ], r
        )

        # 网络地址卡（绿色背景）
        self._make_result_card(
            self._result_frame, "网络地址", GREEN_LIGHT,
            [
                ("网络地址",         info["network_address"],   True),
                ("广播地址",         info["broadcast_address"], True),
                ("第一个可用主机",   info["first_host"],        True),
                ("最后一个可用主机", info["last_host"],         True),
            ], r
        )

        # 统计信息卡（橙色背景）
        range_str = f"{info['first_host']} - {info['last_host']}"
        self._make_result_card(
            self._result_frame, "统计信息", ORANGE_LIGHT,
            [
                ("总主机数",   str(info["total_hosts"]),  False),
                ("可用主机数", str(info["usable_hosts"]), False),
                ("IP地址范围", range_str,                 True),
            ], r
        )

    def _make_result_card(self, parent, title, bg, rows, root):
        card = tk.Frame(parent, bg=bg, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", pady=6)
        inner = tk.Frame(card, bg=bg, padx=16, pady=12)
        inner.pack(fill="both")

        tk.Label(inner, text=title, font=F(13, bold=True), bg=bg, fg=TEXT_PRI, anchor="w").pack(
            fill="x", pady=(0, 8))

        for label, value, copyable in rows:
            row_f = tk.Frame(inner, bg=bg)
            row_f.pack(fill="x", pady=2)
            tk.Label(row_f, text=label, font=F(12, bold=True), bg=bg, fg=TEXT_PRI,
                     width=16, anchor="w").pack(side="left")
            tk.Label(row_f, text=value, font=F(12, mono=True), bg=bg, fg=TEXT_PRI,
                     anchor="w").pack(side="left", fill="x", expand=True)
            if copyable:
                v = value
                btn = tk.Button(row_f, text="复制", font=F(10), relief="flat",
                                bg=CARD_BG, fg=BLUE, cursor="hand2", padx=6, pady=1,
                                command=lambda t=v: (root.clipboard_clear(), root.clipboard_append(t)))
                btn.pack(side="right")

    def restore(self, payload):
        ip = payload.get("ip", "")
        mask = payload.get("mask", "")
        self._ip_var.set(ip)
        if mask.startswith("/"):
            self._mask_fmt.set("CIDR (/xx)")
            self._mask_var.set(mask[1:])
        elif "." in mask:
            self._mask_fmt.set("点分十进制")
            self._mask_var.set(mask)
        else:
            self._mask_fmt.set("CIDR (/xx)")
            self._mask_var.set(mask)
        self._calculate()


# ══════════════════════════════════════════════
#  标签页：子网掩码计算器
# ══════════════════════════════════════════════

class SubnetMaskTab(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=WIN_BG)
        self._root = root
        self._cidr_var = tk.IntVar(value=24)
        self._mask_input = tk.StringVar()

        sf = ScrollFrame(self)
        sf.pack(fill="both", expand=True)
        body = sf.inner
        body.columnconfigure(0, weight=1)

        tk.Label(body, text="子网掩码计算器", font=F(20, bold=True),
                 bg=WIN_BG, fg=TEXT_PRI).pack(pady=(20, 12))

        # ── Section 1: CIDR → 掩码 ──
        c1 = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c1.pack(fill="x", padx=24, pady=6)
        i1 = tk.Frame(c1, bg=CARD_BG, padx=18, pady=14)
        i1.pack(fill="both")

        tk.Label(i1, text="掩码位元数 → 子网掩码", font=F(13, bold=True), bg=CARD_BG,
                 fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 10))

        ctrl_f = tk.Frame(i1, bg=CARD_BG)
        ctrl_f.pack(fill="x")
        tk.Label(ctrl_f, text="CIDR:", font=F(13), bg=CARD_BG, fg=TEXT_PRI).pack(side="left")
        tk.Label(ctrl_f, textvariable=self._cidr_var, font=F(13, bold=True, mono=True),
                 bg=CARD_BG, fg=BLUE, width=4).pack(side="left", padx=4)
        ttk.Button(ctrl_f, text="▲",
                   command=lambda: self._cidr_var.set(min(32, self._cidr_var.get()+1))).pack(side="left")
        ttk.Button(ctrl_f, text="▼",
                   command=lambda: self._cidr_var.set(max(0, self._cidr_var.get()-1))).pack(side="left", padx=(0, 12))
        ttk.Button(ctrl_f, text="计算掩码", command=self._calc_cidr_to_mask).pack(side="left")

        self._result1_frame = tk.Frame(i1, bg=CARD_BG)
        self._result1_frame.pack(fill="x", pady=(10, 0))

        # ── Section 2: 掩码 → CIDR ──
        c2 = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c2.pack(fill="x", padx=24, pady=6)
        i2 = tk.Frame(c2, bg=CARD_BG, padx=18, pady=14)
        i2.pack(fill="both")

        tk.Label(i2, text="子网掩码 → 掩码位元数", font=F(13, bold=True), bg=CARD_BG,
                 fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 10))

        ctrl2 = tk.Frame(i2, bg=CARD_BG)
        ctrl2.pack(fill="x")
        tk.Label(ctrl2, text="子网掩码:", font=F(13), bg=CARD_BG, fg=TEXT_PRI).pack(side="left")
        self._mask_entry = ttk.Entry(ctrl2, textvariable=self._mask_input,
                                      font=F(13, mono=True), width=20)
        self._mask_entry.pack(side="left", padx=(6, 12))
        self._mask_entry.bind("<Return>", lambda e: self._calc_mask_to_cidr())
        ttk.Button(ctrl2, text="计算CIDR", command=self._calc_mask_to_cidr).pack(side="left")

        self._result2_frame = tk.Frame(i2, bg=CARD_BG)
        self._result2_frame.pack(fill="x", pady=(10, 0))

        # ── Section 3: 功能说明 ──
        c3 = tk.Frame(body, bg=GRAY_BG, highlightbackground=BORDER, highlightthickness=1)
        c3.pack(fill="x", padx=24, pady=6)
        i3 = tk.Frame(c3, bg=GRAY_BG, padx=18, pady=14)
        i3.pack(fill="both")
        tk.Label(i3, text="功能说明", font=F(13, bold=True), bg=GRAY_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w")
        for line in ["• CIDR → 子网掩码: 输入掩码位元数，计算对应的子网掩码",
                     "• 子网掩码 → CIDR: 输入子网掩码，计算对应的掩码位元数",
                     "• 通配符掩码: 显示与子网掩码对应的通配符掩码"]:
            tk.Label(i3, text=line, font=F(11), bg=GRAY_BG, fg=TEXT_SEC, anchor="w").pack(anchor="w")

    def _calc_cidr_to_mask(self):
        cidr = self._cidr_var.get()
        result = NetworkCalculator.cidr_to_mask(cidr)
        if not result:
            messagebox.showerror("错误", "CIDR值无效")
            return

        wildcard_octets = [str(255 - int(o)) for o in result["mask"].split(".")]
        wildcard = ".".join(wildcard_octets)

        for w in self._result1_frame.winfo_children():
            w.destroy()

        bg = BLUE_LIGHT
        f = tk.Frame(self._result1_frame, bg=bg, padx=12, pady=8,
                     highlightbackground=BORDER, highlightthickness=1)
        f.pack(fill="x")
        for label, value in [
            ("子网掩码", result["mask"]),
            ("二进制", result["binary"]),
            ("通配符掩码", wildcard),
        ]:
            r = tk.Frame(f, bg=bg)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=label, font=F(12, bold=True), bg=bg, width=10, anchor="w").pack(side="left")
            tk.Label(r, text=value, font=F(12, mono=True), bg=bg, fg=TEXT_PRI, anchor="w").pack(side="left", fill="x", expand=True)
            v = value
            tk.Button(r, text="复制", font=F(10), relief="flat", bg=CARD_BG, fg=BLUE,
                      cursor="hand2", padx=6, pady=1,
                      command=lambda t=v: (self._root.clipboard_clear(), self._root.clipboard_append(t))).pack(side="right")

        history_mgr.add("子网掩码计算", f"CIDR /{cidr} → {result['mask']}", {})

    def _calc_mask_to_cidr(self):
        mask = self._mask_input.get().strip()
        result = NetworkCalculator.mask_to_cidr(mask)
        if not result:
            messagebox.showerror("错误", "子网掩码格式错误，请检查输入（如 255.255.255.0）")
            return

        wildcard_octets = [str(255 - int(o)) for o in mask.split(".")]
        wildcard = ".".join(wildcard_octets)

        for w in self._result2_frame.winfo_children():
            w.destroy()

        bg = GREEN_LIGHT
        f = tk.Frame(self._result2_frame, bg=bg, padx=12, pady=8,
                     highlightbackground=BORDER, highlightthickness=1)
        f.pack(fill="x")
        for label, value in [
            ("CIDR表示", f"/{result['cidr']}"),
            ("位元数", f"{result['cidr']} 位"),
            ("二进制", result["binary"]),
            ("通配符掩码", wildcard),
        ]:
            r = tk.Frame(f, bg=bg)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=label, font=F(12, bold=True), bg=bg, width=10, anchor="w").pack(side="left")
            tk.Label(r, text=value, font=F(12, mono=True), bg=bg, fg=TEXT_PRI, anchor="w").pack(side="left", fill="x", expand=True)


# ══════════════════════════════════════════════
#  标签页：主机数计算
# ══════════════════════════════════════════════

class HostCalculatorTab(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=WIN_BG)
        self._root = root
        self._host_var = tk.StringVar(value="254")

        sf = ScrollFrame(self)
        sf.pack(fill="both", expand=True)
        body = sf.inner
        body.columnconfigure(0, weight=1)

        tk.Label(body, text="根据主机数计算掩码", font=F(20, bold=True),
                 bg=WIN_BG, fg=TEXT_PRI).pack(pady=(20, 12))

        # 输入卡
        c1 = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c1.pack(fill="x", padx=24, pady=6)
        i1 = tk.Frame(c1, bg=CARD_BG, padx=18, pady=14)
        i1.pack(fill="both")
        tk.Label(i1, text="输入参数", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))

        ctrl = tk.Frame(i1, bg=CARD_BG)
        ctrl.pack(fill="x")
        tk.Label(ctrl, text="所需主机数:", font=F(13), bg=CARD_BG, fg=TEXT_PRI).pack(side="left")
        ttk.Entry(ctrl, textvariable=self._host_var, font=F(13, mono=True), width=16).pack(side="left", padx=8)
        ttk.Button(ctrl, text="计算掩码", command=self._calculate).pack(side="left")

        self._result_frame = tk.Frame(i1, bg=CARD_BG)
        self._result_frame.pack(fill="x", pady=(12, 0))

        # 参考表
        c2 = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c2.pack(fill="x", padx=24, pady=6)
        i2 = tk.Frame(c2, bg=CARD_BG, padx=18, pady=14)
        i2.pack(fill="both")
        tk.Label(i2, text="常见主机数参考", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))

        for count in [2, 10, 30, 62, 126, 254, 510, 1022, 2046, 4094]:
            r = tk.Frame(i2, bg=CARD_BG)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=f"{count} 台主机", font=F(12), bg=CARD_BG, fg=TEXT_PRI).pack(side="left")
            info = NetworkCalculator.calculate_mask_from_hosts(count)
            if info:
                tk.Label(r, text=f"→ /{info['cidr']} ({info['mask']})", font=F(12),
                         bg=CARD_BG, fg=TEXT_SEC).pack(side="right")

    def _calculate(self):
        try:
            hosts = int(self._host_var.get().strip())
            assert hosts > 0
        except:
            messagebox.showerror("错误", "请输入有效的主机数量（正整数）")
            return

        result = NetworkCalculator.calculate_mask_from_hosts(hosts)
        if not result:
            messagebox.showerror("错误", "主机数过大或无效，无法计算")
            return

        for w in self._result_frame.winfo_children():
            w.destroy()

        bg = BLUE_LIGHT
        f = tk.Frame(self._result_frame, bg=bg, padx=12, pady=10,
                     highlightbackground=BORDER, highlightthickness=1)
        f.pack(fill="x")
        tk.Label(f, text="计算结果", font=F(13, bold=True), bg=bg, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))

        rows = [
            ("推荐子网掩码", result["mask"], BLUE),
            ("CIDR表示",    f"/{result['cidr']}", TEXT_PRI),
            ("可容纳主机数", f"{result['max_hosts']} 台", "#34C759"),
            ("网络位数",    f"{result['cidr']} 位", TEXT_PRI),
            ("主机位数",    f"{32 - result['cidr']} 位", TEXT_PRI),
        ]
        for label, value, color in rows:
            r = tk.Frame(f, bg=bg)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=label, font=F(12, bold=True), bg=bg, width=12, anchor="w").pack(side="left")
            tk.Label(r, text=value, font=F(12, mono=True), bg=bg, fg=color).pack(side="left")

        history_mgr.add("主机数计算", f"{hosts} 台主机 → /{result['cidr']}", {})


# ══════════════════════════════════════════════
#  标签页：IPv6 计算器
# ══════════════════════════════════════════════

class IPv6Tab(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=WIN_BG)
        self._root = root
        self._ip_var = tk.StringVar()
        self._prefix_var = tk.StringVar()
        self._subpage = tk.StringVar(value="网络范围")
        self._parsed = None
        self._mac_var = tk.StringVar()
        self._new_prefix_var = tk.StringVar()
        self._preview_count = tk.IntVar(value=8)

        sf = ScrollFrame(self)
        sf.pack(fill="both", expand=True)
        self._body = sf.inner
        self._body.columnconfigure(0, weight=1)

        tk.Label(self._body, text="IPv6 计算器", font=F(20, bold=True),
                 bg=WIN_BG, fg=TEXT_PRI).pack(pady=(20, 12))

        # 输入区
        in_card = tk.Frame(self._body, bg=GRAY_BG, highlightbackground=BORDER, highlightthickness=1)
        in_card.pack(fill="x", padx=24, pady=6)
        ic = tk.Frame(in_card, bg=GRAY_BG, padx=18, pady=14)
        ic.pack(fill="both")
        ic.columnconfigure(1, weight=1)

        tk.Label(ic, text="IPv6地址:", font=F(12), bg=GRAY_BG, fg=TEXT_PRI).grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(ic, textvariable=self._ip_var, font=F(12, mono=True)).grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)

        tk.Label(ic, text="前缀长度:", font=F(12), bg=GRAY_BG, fg=TEXT_PRI).grid(row=1, column=0, sticky="w", pady=4)
        pf = tk.Frame(ic, bg=GRAY_BG)
        pf.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=4)
        ttk.Entry(pf, textvariable=self._prefix_var, font=F(12, mono=True), width=8).pack(side="left")
        ttk.Button(pf, text="计算", command=self._calculate).pack(side="left", padx=8)

        # 网络地址预览
        self._net_lbl = tk.Label(ic, text="请输入 IPv6 地址与前缀长度（0-128）",
                                  font=F(11), bg=GRAY_BG, fg=TEXT_SEC, anchor="w")
        self._net_lbl.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(4, 0))

        # 子页切换
        seg_f = tk.Frame(self._body, bg=WIN_BG)
        seg_f.pack(fill="x", padx=24, pady=6)
        SegmentedControl(seg_f, ["网络范围", "子网划分", "SLAAC"],
                         self._subpage, command=self._switch_subpage, bg=WIN_BG).pack(anchor="w")

        # 子页容器
        self._subpage_frame = tk.Frame(self._body, bg=WIN_BG)
        self._subpage_frame.pack(fill="x", padx=24, pady=4)
        self._render_subpage()

    def _calculate(self):
        ip = self._ip_var.get().strip()
        prefix_str = self._prefix_var.get().strip()

        if not ip or not prefix_str:
            self._parsed = None
            self._net_lbl.config(text="请输入 IPv6 地址与前缀长度（0-128）")
            self._render_subpage()
            return

        try:
            prefix = int(prefix_str)
            assert 0 <= prefix <= 128
        except:
            messagebox.showerror("错误", "前缀长度必须是 0-128 之间的整数")
            return

        info = IPv6Calculator.calculate(ip, prefix)
        if not info:
            messagebox.showerror("错误", "IPv6 地址格式无效，请检查输入")
            return

        self._parsed = info
        self._net_lbl.config(
            text=f"网络地址：{info['network_compressed']}",
            fg=TEXT_SEC
        )
        history_mgr.add("IPv6 计算", f"{info['ip_compressed']}/{prefix}", {})
        self._render_subpage()

    def _switch_subpage(self):
        self._render_subpage()

    def _render_subpage(self):
        for w in self._subpage_frame.winfo_children():
            w.destroy()

        page = self._subpage.get()
        if page == "网络范围":
            self._render_range()
        elif page == "子网划分":
            self._render_subnetting()
        else:
            self._render_slaac()

    def _render_range(self):
        p = self._parsed
        if not p:
            tk.Label(self._subpage_frame,
                     text="请输入 IPv6 地址与前缀后查看网络范围",
                     font=F(12), bg=WIN_BG, fg=TEXT_SEC).pack(pady=20)
            return

        root = self._root

        def make_card(title, rows, bg=CARD_BG):
            c = tk.Frame(self._subpage_frame, bg=bg, highlightbackground=BORDER, highlightthickness=1)
            c.pack(fill="x", pady=6)
            inner = tk.Frame(c, bg=bg, padx=16, pady=12)
            inner.pack(fill="both")
            tk.Label(inner, text=title, font=F(13, bold=True), bg=bg, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))
            for k, v, copyable in rows:
                r = tk.Frame(inner, bg=bg)
                r.pack(fill="x", pady=2)
                tk.Label(r, text=k, font=F(12, bold=True), bg=bg, width=12, anchor="w").pack(side="left")
                tk.Label(r, text=v, font=F(12, mono=True), bg=bg, fg=TEXT_PRI, anchor="w").pack(side="left", fill="x", expand=True)
                if copyable:
                    tv = v
                    tk.Button(r, text="复制", font=F(10), relief="flat", bg=BLUE_LIGHT, fg=BLUE,
                              cursor="hand2", padx=6, pady=1,
                              command=lambda t=tv: (root.clipboard_clear(), root.clipboard_append(t))).pack(side="right")

        make_card("网络范围", [
            ("网络地址", p["network_compressed"], True),
            ("范围起始", p["range_start_c"],     True),
            ("范围结束", p["range_end_c"],       True),
            ("总地址数", str(p["total"]),         False),
        ], BLUE_LIGHT)

        make_card("快速判断", [
            ("地址类型", p["address_type"],                          False),
            ("是否 /64",  "是（适合 SLAAC / 子网常用）" if p["is_64"] else "否", False),
        ], GREEN_LIGHT)

    def _render_subnetting(self):
        p = self._parsed
        body = self._subpage_frame
        root = self._root

        if not p:
            tk.Label(body, text="先在上方输入 IPv6 与前缀，再来做子网划分",
                     font=F(12), bg=WIN_BG, fg=TEXT_SEC).pack(pady=20)
            return

        c = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c.pack(fill="x", pady=6)
        inner = tk.Frame(c, bg=CARD_BG, padx=16, pady=12)
        inner.pack(fill="both")
        tk.Label(inner, text="子网划分", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))

        ctrl = tk.Frame(inner, bg=CARD_BG)
        ctrl.pack(fill="x")
        tk.Label(ctrl, text="新前缀 /:", font=F(12), bg=CARD_BG).pack(side="left")
        ttk.Entry(ctrl, textvariable=self._new_prefix_var, width=8, font=F(12, mono=True)).pack(side="left", padx=6)
        ttk.Button(ctrl, text="计算子网", command=lambda: self._do_subnetting(p)).pack(side="left", padx=4)

        pv_f = tk.Frame(inner, bg=CARD_BG)
        pv_f.pack(fill="x", pady=(8, 0))
        tk.Label(pv_f, text="预览数量:", font=F(12), bg=CARD_BG).pack(side="left")
        ttk.Spinbox(pv_f, from_=1, to=64, textvariable=self._preview_count, width=5).pack(side="left", padx=6)

        self._subnet_result_frame = tk.Frame(body, bg=WIN_BG)
        self._subnet_result_frame.pack(fill="x", pady=4)

    def _do_subnetting(self, p):
        for w in self._subnet_result_frame.winfo_children():
            w.destroy()

        try:
            np = int(self._new_prefix_var.get().strip())
            assert 0 <= np <= 128 and np >= p["prefix"]
        except:
            messagebox.showerror("错误", f"新前缀必须是 {p['prefix']}–128 之间的整数")
            return

        result = IPv6Calculator.subnetting(p["ip"], p["prefix"], np, self._preview_count.get())
        if not result:
            messagebox.showerror("错误", "子网划分计算失败")
            return

        root = self._root
        c = tk.Frame(self._subnet_result_frame, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c.pack(fill="x", pady=4)
        inner = tk.Frame(c, bg=CARD_BG, padx=16, pady=10)
        inner.pack(fill="both")
        tk.Label(inner, text="结果", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI).pack(anchor="w", pady=(0, 6))

        for k, v in [
            ("当前前缀", f"/{p['prefix']}"),
            ("新前缀",   f"/{np}"),
            ("子网数量", str(result["subnet_count"])),
            ("每子网地址数", str(result["addrs_per"])),
        ]:
            r = tk.Frame(inner, bg=CARD_BG)
            r.pack(fill="x", pady=1)
            tk.Label(r, text=k, font=F(12, bold=True), bg=CARD_BG, width=12, anchor="w").pack(side="left")
            tk.Label(r, text=v, font=F(12, mono=True), bg=CARD_BG).pack(side="left")

        if result["preview"]:
            c2 = tk.Frame(self._subnet_result_frame, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
            c2.pack(fill="x", pady=4)
            i2 = tk.Frame(c2, bg=CARD_BG, padx=16, pady=10)
            i2.pack(fill="both")
            tk.Label(i2, text=f"子网预览（前 {len(result['preview'])} 个）",
                     font=F(13, bold=True), bg=CARD_BG).pack(anchor="w", pady=(0, 6))
            for idx, item in enumerate(result["preview"]):
                r = tk.Frame(i2, bg=CARD_BG)
                r.pack(fill="x", pady=2)
                range_str = f"#{idx+1}  {item['start']}  -  {item['end']}"
                tk.Label(r, text=range_str, font=F(11, mono=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(side="left", fill="x", expand=True)
                rs = f"{item['start']} - {item['end']}"
                tk.Button(r, text="复制", font=F(10), relief="flat", bg=BLUE_LIGHT, fg=BLUE,
                          cursor="hand2", padx=6,
                          command=lambda t=rs: (root.clipboard_clear(), root.clipboard_append(t))).pack(side="right")

    def _render_slaac(self):
        p = self._parsed
        body = self._subpage_frame
        root = self._root

        c = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c.pack(fill="x", pady=6)
        inner = tk.Frame(c, bg=CARD_BG, padx=16, pady=12)
        inner.pack(fill="both")
        tk.Label(inner, text="SLAAC（EUI-64，手动输入 MAC）",
                 font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI).pack(anchor="w", pady=(0, 6))
        tk.Label(inner, text="说明：EUI-64 SLAAC 需要 /64 前缀。MAC 支持多种格式",
                 font=F(11), bg=CARD_BG, fg=TEXT_SEC).pack(anchor="w", pady=(0, 8))

        ctrl = tk.Frame(inner, bg=CARD_BG)
        ctrl.pack(fill="x")
        tk.Label(ctrl, text="MAC:", font=F(12), bg=CARD_BG).pack(side="left")
        ttk.Entry(ctrl, textvariable=self._mac_var, font=F(12, mono=True), width=24).pack(side="left", padx=8)
        ttk.Button(ctrl, text="生成 SLAAC", command=lambda: self._do_slaac(p)).pack(side="left")

        self._slaac_result_frame = tk.Frame(body, bg=WIN_BG)
        self._slaac_result_frame.pack(fill="x", pady=4)

    def _do_slaac(self, p):
        for w in self._slaac_result_frame.winfo_children():
            w.destroy()

        if not p:
            messagebox.showerror("错误", "请先输入 IPv6 地址与前缀")
            return
        if p["prefix"] != 64:
            messagebox.showerror("错误", "SLAAC（EUI-64）要求 /64 前缀")
            return

        mac = self._mac_var.get().strip()
        result = IPv6Calculator.slaac(p["ip"], 64, mac)
        if not result:
            messagebox.showerror("错误", "MAC 地址格式无效")
            return

        root = self._root
        for title, rows in [
            ("结果（关键信息）", [
                ("EUI-64 IID",   result["iid"],           True),
                ("SLAAC 地址",   result["slaac_address"], True),
            ]),
            ("邻居发现相关", [
                ("Solicited-node", result["solicited_node"], True),
                ("Multicast MAC",  result["multicast_mac"],  True),
            ]),
        ]:
            c = tk.Frame(self._slaac_result_frame, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
            c.pack(fill="x", pady=4)
            inner = tk.Frame(c, bg=CARD_BG, padx=16, pady=10)
            inner.pack(fill="both")
            tk.Label(inner, text=title, font=F(13, bold=True), bg=CARD_BG).pack(anchor="w", pady=(0, 6))
            for k, v, copyable in rows:
                r = tk.Frame(inner, bg=CARD_BG)
                r.pack(fill="x", pady=2)
                tk.Label(r, text=k, font=F(12, bold=True), bg=CARD_BG, width=14, anchor="w").pack(side="left")
                tk.Label(r, text=v, font=F(12, mono=True), bg=CARD_BG, anchor="w").pack(side="left", fill="x", expand=True)
                if copyable:
                    tv = v
                    tk.Button(r, text="复制", font=F(10), relief="flat", bg=BLUE_LIGHT, fg=BLUE,
                              cursor="hand2", padx=6,
                              command=lambda t=tv: (root.clipboard_clear(), root.clipboard_append(t))).pack(side="right")


# ══════════════════════════════════════════════
#  标签页：MAC 地址转换器
# ══════════════════════════════════════════════

class MACTab(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=WIN_BG)
        self._root = root
        self._input_var = tk.StringVar(value="FA:3B:02:8A:F8:87")
        self._fmt_var = tk.StringVar(value="大写（冒号）")
        self._info = None

        sf = ScrollFrame(self)
        sf.pack(fill="both", expand=True)
        body = sf.inner
        body.columnconfigure(0, weight=1)

        # 标题区
        hdr = tk.Frame(body, bg=WIN_BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="MAC地址转换器", font=F(20, bold=True), bg=WIN_BG, fg=TEXT_PRI).pack()
        tk.Label(hdr, text="支持各种格式的MAC地址转换", font=F(12), bg=WIN_BG, fg=TEXT_SEC).pack()

        # 单地址转换输入区
        c1 = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c1.pack(fill="x", padx=24, pady=6)
        i1 = tk.Frame(c1, bg=CARD_BG, padx=18, pady=14)
        i1.pack(fill="both")
        tk.Label(i1, text="单地址转换", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 6))

        for line in ["• XX:XX:XX:XX:XX:XX（冒号分隔）", "• XX-XX-XX-XX-XX-XX（短横线分隔）",
                     "• XXXX-XXXX-XXXX（分组格式）", "• XXXXXXXXXXXX（无分隔符）"]:
            tk.Label(i1, text=line, font=F(11), bg=CARD_BG, fg=TEXT_SEC, anchor="w").pack(anchor="w")

        ctrl = tk.Frame(i1, bg=CARD_BG)
        ctrl.pack(fill="x", pady=(10, 0))
        self._mac_entry = ttk.Entry(ctrl, textvariable=self._input_var, font=F(13, mono=True))
        self._mac_entry.pack(side="left", fill="x", expand=True)
        self._mac_entry.bind("<Return>", lambda e: self._convert())
        ttk.Button(ctrl, text="转换", command=self._convert).pack(side="left", padx=8)

        # 信息区
        self._info_frame = tk.Frame(body, bg=WIN_BG)
        self._info_frame.pack(fill="x", padx=24)

        # 格式转换区
        self._fmt_frame = tk.Frame(body, bg=WIN_BG)
        self._fmt_frame.pack(fill="x", padx=24)

        # ── 批量处理区 ──
        self._batch_data = []   # 存放批量结果
        batch_card = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        batch_card.pack(fill="x", padx=24, pady=6)
        bi = tk.Frame(batch_card, bg=CARD_BG, padx=18, pady=14)
        bi.pack(fill="both")

        tk.Label(bi, text="批量处理", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 6))
        for line in ["• 每行一个MAC地址", "• 支持各种MAC地址格式", "• 空行和以#开头的注释行将被忽略"]:
            tk.Label(bi, text=line, font=F(11), bg=CARD_BG, fg=TEXT_SEC, anchor="w").pack(anchor="w")

        btn_bar = tk.Frame(bi, bg=CARD_BG)
        btn_bar.pack(fill="x", pady=(12, 0))

        tk.Button(btn_bar, text="⬇ 下载CSV模板", font=F(12), relief="flat",
                  bg="#E5E5EA", fg=TEXT_PRI, padx=12, pady=6, cursor="hand2",
                  command=self._export_template).pack(side="left", padx=(0, 8))

        tk.Button(btn_bar, text="⬆ 导入CSV", font=F(12), relief="flat",
                  bg=BLUE, fg="white", padx=12, pady=6, cursor="hand2",
                  command=self._import_csv).pack(side="left", padx=(0, 8))

        self._export_result_btn = tk.Button(btn_bar, text="📊 导出结果", font=F(12), relief="flat",
                  bg=BLUE, fg="white", padx=12, pady=6, cursor="hand2",
                  command=self._export_results, state="disabled")
        self._export_result_btn.pack(side="left")

        # 批量结果预览
        self._batch_preview_frame = tk.Frame(bi, bg=CARD_BG)
        self._batch_preview_frame.pack(fill="x", pady=(10, 0))

        # 初始化
        self.after(200, self._convert)

    def _convert(self):
        mac = self._input_var.get().strip()
        if not MACConverter.is_valid(mac):
            for w in self._info_frame.winfo_children():
                w.destroy()
            for w in self._fmt_frame.winfo_children():
                w.destroy()
            if mac:
                messagebox.showerror("错误", "MAC 地址格式无效，请检查输入")
            return

        info = MACConverter.get_info(mac)
        self._info = info
        history_mgr.add("MAC地址转换", mac, {"mac": mac})
        self._render_info(info, mac)
        self._render_formats(info)

    def _render_info(self, info, original):
        for w in self._info_frame.winfo_children():
            w.destroy()

        c = tk.Frame(self._info_frame, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c.pack(fill="x", pady=6)
        inner = tk.Frame(c, bg=CARD_BG, padx=18, pady=12)
        inner.pack(fill="both")
        tk.Label(inner, text="MAC地址信息", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))

        root = self._root
        rows = [
            ("原始地址",  original,              BLUE,   True),
            ("标准化",    info["normalized"],     TEXT_PRI, True),
            ("OUI",       info["oui"],            TEXT_PRI, False),
            ("地址类型",  info["type_text"],      "#34C759" if not info["is_local"] else "#FF9500", False),
            ("本地管理",  "是" if info["is_local"] else "否", "#FF9500" if info["is_local"] else TEXT_PRI, False),
            ("组播地址",  "是" if info["is_multicast"] else "否", "#AF52DE" if info["is_multicast"] else TEXT_PRI, False),
        ]
        for label, value, color, copyable in rows:
            r = tk.Frame(inner, bg=CARD_BG)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=label, font=F(12, bold=True), bg=CARD_BG, width=10, anchor="w").pack(side="left")
            tk.Label(r, text=value, font=F(12, mono=True), bg=CARD_BG, fg=color, anchor="w").pack(side="left", fill="x", expand=True)
            if copyable:
                v = value
                tk.Button(r, text="复制", font=F(10), relief="flat", bg=BLUE_LIGHT, fg=BLUE,
                          cursor="hand2", padx=6,
                          command=lambda t=v: (root.clipboard_clear(), root.clipboard_append(t))).pack(side="right")

    def _render_formats(self, info):
        for w in self._fmt_frame.winfo_children():
            w.destroy()

        root = self._root
        mac = self._input_var.get().strip()

        # 格式选择转换
        c1 = tk.Frame(self._fmt_frame, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c1.pack(fill="x", pady=6)
        i1 = tk.Frame(c1, bg=CARD_BG, padx=18, pady=12)
        i1.pack(fill="both")
        tk.Label(i1, text="格式转换", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))

        fmt_ctrl = tk.Frame(i1, bg=CARD_BG)
        fmt_ctrl.pack(fill="x")
        tk.Label(fmt_ctrl, text="选择输出格式:", font=F(12), bg=CARD_BG).pack(side="left")
        fmt_combo = ttk.Combobox(fmt_ctrl, textvariable=self._fmt_var, values=MACConverter.FORMATS,
                                  state="readonly", width=18)
        fmt_combo.pack(side="left", padx=8)

        self._fmt_result_lbl = tk.Label(i1, text="", font=F(13, mono=True), bg=GREEN_LIGHT,
                                         fg=TEXT_PRI, anchor="w", padx=10, pady=8)

        def do_convert():
            result = MACConverter.convert(mac, self._fmt_var.get())
            self._fmt_result_lbl.config(text=result)
            self._fmt_result_lbl.pack(fill="x", pady=(8, 0))

        btn_f = tk.Frame(i1, bg=CARD_BG)
        btn_f.pack(fill="x", pady=(8, 0))
        ttk.Button(btn_f, text="转换为选定格式", command=do_convert).pack(side="left")
        tk.Button(btn_f, text="复制结果", font=F(11), relief="flat", bg=BLUE_LIGHT, fg=BLUE,
                  cursor="hand2", padx=8,
                  command=lambda: (root.clipboard_clear(), root.clipboard_append(self._fmt_result_lbl.cget("text")))).pack(side="left", padx=8)

        # 所有格式
        c2 = tk.Frame(self._fmt_frame, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        c2.pack(fill="x", pady=6)
        i2 = tk.Frame(c2, bg=CARD_BG, padx=18, pady=12)
        i2.pack(fill="both")
        tk.Label(i2, text="所有格式", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))

        grid = tk.Frame(i2, bg=CARD_BG)
        grid.pack(fill="x")
        for col in range(4):
            grid.columnconfigure(col, weight=1)

        for idx, fmt_val in enumerate(info["all_formats"]):
            col = idx % 4
            row = idx // 4
            cell = tk.Frame(grid, bg=GRAY_BG, padx=6, pady=4,
                            highlightbackground=BORDER, highlightthickness=1)
            cell.grid(row=row, column=col, padx=3, pady=3, sticky="ew")
            tk.Label(cell, text=fmt_val, font=F(10, mono=True), bg=GRAY_BG, fg=TEXT_PRI, anchor="w").pack(side="left", fill="x", expand=True)
            fv = fmt_val
            tk.Button(cell, text="⧉", font=F(10), relief="flat", bg=GRAY_BG, fg=BLUE,
                      cursor="hand2",
                      command=lambda t=fv: (root.clipboard_clear(), root.clipboard_append(t))).pack(side="right")

    # ── 批量处理方法 ──

    def _make_template_csv(self):
        return (
            "MAC\n"
            "FA:3B:02:8A:F8:87\n"
            "00-1A-2B-3C-4D-5E\n"
            "001122334455\n"
            "0011-2233-4455\n"
            "\n"
            "# 每行一个MAC地址，支持各种格式\n"
            "# 以#开头的行将被视为注释\n"
        )

    def _export_template(self):
        path = filedialog.asksaveasfilename(
            title="保存CSV模板",
            defaultextension=".csv",
            initialfile="MAC导入模板.csv",
            filetypes=[("CSV文件", "*.csv"), ("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                f.write(self._make_template_csv())
            messagebox.showinfo("成功", f"模板已保存到：\n{path}")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败：{e}")

    def _import_csv(self):
        path = filedialog.askopenfilename(
            title="选择CSV文件",
            filetypes=[("CSV文件", "*.csv"), ("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                lines = f.read().splitlines()
        except UnicodeDecodeError:
            try:
                with open(path, "r", encoding="gbk") as f:
                    lines = f.read().splitlines()
            except Exception as e:
                messagebox.showerror("错误", f"读取文件失败：{e}")
                return
        except Exception as e:
            messagebox.showerror("错误", f"读取文件失败：{e}")
            return

        items = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 取第一列（兼容多列CSV）
            mac = line.split(",")[0].strip().strip('"')
            if not MACConverter.is_valid(mac):
                continue
            info = MACConverter.get_info(mac)
            if info:
                items.append({
                    "original": mac,
                    "normalized": info["normalized"],
                    "oui": info["oui"],
                    "type": info["type_text"],
                    "all_formats": info["all_formats"],
                })

        if not items:
            messagebox.showwarning("提示", "未找到有效的MAC地址，请检查文件格式")
            return

        self._batch_data = items
        self._export_result_btn.config(state="normal")
        messagebox.showinfo("成功", f"成功导入 {len(items)} 条MAC地址")
        self._render_batch_preview()

    def _render_batch_preview(self):
        for w in self._batch_preview_frame.winfo_children():
            w.destroy()

        items = self._batch_data
        if not items:
            return

        bg = BLUE_LIGHT
        f = tk.Frame(self._batch_preview_frame, bg=bg,
                     highlightbackground=BORDER, highlightthickness=1)
        f.pack(fill="x", pady=(6, 0))
        inner = tk.Frame(f, bg=bg, padx=12, pady=10)
        inner.pack(fill="both")

        tk.Label(inner, text=f"转换结果（共 {len(items)} 条，预览前10条）",
                 font=F(12, bold=True), bg=bg, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 6))

        # 表头
        hdr = tk.Frame(inner, bg=BORDER)
        hdr.pack(fill="x")
        for text, width in [("原始地址", 20), ("标准化格式", 20), ("OUI", 10), ("地址类型", 12)]:
            tk.Label(hdr, text=text, font=F(11, bold=True), bg="#D1D1D6",
                     fg=TEXT_PRI, width=width, anchor="w", padx=4, pady=3).pack(side="left")

        for item in items[:10]:
            row = tk.Frame(inner, bg=bg)
            row.pack(fill="x")
            for text, width in [
                (item["original"],   20),
                (item["normalized"], 20),
                (item["oui"],        10),
                (item["type"],       12),
            ]:
                tk.Label(row, text=text, font=F(11, mono=True), bg=bg,
                         fg=TEXT_PRI, width=width, anchor="w", padx=4, pady=2).pack(side="left")

        if len(items) > 10:
            tk.Label(inner, text=f"… 还有 {len(items) - 10} 条",
                     font=F(11), bg=bg, fg=TEXT_SEC).pack(anchor="w", pady=(4, 0))

    def _export_results(self):
        if not self._batch_data:
            messagebox.showwarning("提示", "没有可导出的数据，请先导入CSV")
            return

        path = filedialog.asksaveasfilename(
            title="保存转换结果",
            defaultextension=".csv",
            initialfile="MAC批量转换结果.csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")]
        )
        if not path:
            return

        try:
            def q(s):
                return f'"{s.replace(chr(34), chr(34)*2)}"'

            headers = ["原始MAC地址", "标准化格式", "OUI", "地址类型",
                       "大写(冒号)", "小写(冒号)", "大写(短横线)", "小写(短横线)",
                       "无分隔符(大写)", "无分隔符(小写)", "分组(大写)", "分组(小写)"]

            rows = [",".join(headers)]
            for item in self._batch_data:
                mac = item["original"]
                fmts = item["all_formats"]
                # 按固定顺序排列格式
                uc = MACConverter.convert(mac, "大写（冒号）")
                lc = MACConverter.convert(mac, "小写（冒号）")
                uh = MACConverter.convert(mac, "大写（短横线）")
                lh = MACConverter.convert(mac, "小写（短横线）")
                up = MACConverter.convert(mac, "无分隔符（大写）")
                lp = MACConverter.convert(mac, "无分隔符（小写）")
                # 分组格式从all_formats中找（含 - 且长度14）
                group_u = next((x for x in fmts if "-" in x and len(x) == 14 and x == x.upper()), "")
                group_l = next((x for x in fmts if "-" in x and len(x) == 14 and x == x.lower()), "")

                rows.append(",".join([
                    q(item["original"]), q(item["normalized"]), q(item["oui"]), q(item["type"]),
                    q(uc), q(lc), q(uh), q(lh), q(up), q(lp), q(group_u), q(group_l)
                ]))

            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                f.write("\n".join(rows) + "\n")

            messagebox.showinfo("成功", f"已导出 {len(self._batch_data)} 条记录到：\n{path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败：{e}")


# ══════════════════════════════════════════════
#  标签页：掩码逆算
# ══════════════════════════════════════════════

class ReverseTab(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, bg=WIN_BG)
        self._root = root
        self._cidr_var = tk.IntVar(value=24)

        sf = ScrollFrame(self)
        sf.pack(fill="both", expand=True)
        body = sf.inner
        body.columnconfigure(0, weight=1)

        tk.Label(body, text="子网掩码逆算器", font=F(20, bold=True),
                 bg=WIN_BG, fg=TEXT_PRI).pack(pady=(20, 12))

        # 滑动条区
        slider_card = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        slider_card.pack(fill="x", padx=24, pady=6)
        sc = tk.Frame(slider_card, bg=CARD_BG, padx=18, pady=14)
        sc.pack(fill="both")

        tk.Label(sc, text="选择掩码位元数:", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))

        # CIDR 显示 + 滑动条
        cidr_f = tk.Frame(sc, bg=CARD_BG)
        cidr_f.pack(fill="x")
        self._cidr_display = tk.Label(cidr_f, text="CIDR: /24",
                                       font=F(18, bold=True), bg=CARD_BG, fg=BLUE)
        self._cidr_display.pack(side="left")

        self._slider = ttk.Scale(cidr_f, from_=0, to=32, orient="horizontal",
                                  variable=self._cidr_var,
                                  command=self._on_slider)
        self._slider.pack(side="right", fill="x", expand=True, padx=(20, 0))

        # 快速选择按钮（对标 Mac 版水平滚动列表）
        quick_f = tk.Frame(sc, bg=CARD_BG)
        quick_f.pack(fill="x", pady=(12, 0))
        tk.Label(quick_f, text="快速选择:", font=F(12, bold=True), bg=CARD_BG, fg=TEXT_PRI).pack(side="left")
        for v in [8, 16, 24, 25, 26, 27, 28, 29, 30]:
            vv = v
            btn = tk.Button(quick_f, text=f"/{v}", font=F(11), relief="flat",
                            padx=8, pady=3, cursor="hand2",
                            command=lambda x=vv: self._set_cidr(x))
            btn.pack(side="left", padx=2)
        self._quick_btns = [w for w in quick_f.winfo_children() if isinstance(w, tk.Button)]

        # 二进制可视化区
        bin_card = tk.Frame(body, bg=CARD_BG, highlightbackground=BORDER, highlightthickness=1)
        bin_card.pack(fill="x", padx=24, pady=6)
        bc = tk.Frame(bin_card, bg=CARD_BG, padx=18, pady=14)
        bc.pack(fill="both")
        tk.Label(bc, text="二进制表示:", font=F(13, bold=True), bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(anchor="w", pady=(0, 8))

        self._binary_frame = tk.Frame(bc, bg=CARD_BG)
        self._binary_frame.pack(anchor="w")
        self._bit_labels = []
        for i in range(32):
            lbl = tk.Label(self._binary_frame, text="0", font=F(10, mono=True),
                           bg=BIT_OFF, fg="white", width=2, relief="flat", padx=1, pady=3)
            lbl.grid(row=0, column=i + (i // 8) * 1 if False else i, padx=1, pady=2)
            self._bit_labels.append(lbl)

        # 用4段来排版（每8位一段，段间加空格）
        for w in self._binary_frame.winfo_children():
            w.destroy()
        self._bit_labels = []
        col = 0
        for i in range(32):
            if i > 0 and i % 8 == 0:
                sep = tk.Label(self._binary_frame, text=" ", bg=CARD_BG, width=1)
                sep.grid(row=0, column=col)
                col += 1
            lbl = tk.Label(self._binary_frame, text="0", font=("Courier New", 11, "bold"),
                           bg=BIT_OFF, fg="white", width=2, relief="flat", pady=4)
            lbl.grid(row=0, column=col, padx=1)
            self._bit_labels.append(lbl)
            col += 1

        # 图例
        legend_f = tk.Frame(bc, bg=CARD_BG)
        legend_f.pack(anchor="w", pady=(4, 0))
        for text, color in [("网络位", BIT_ON), ("主机位", BIT_OFF)]:
            tk.Label(legend_f, text="■", fg=color, bg=CARD_BG, font=F(14)).pack(side="left")
            tk.Label(legend_f, text=f" {text}   ", bg=CARD_BG, font=F(11), fg=TEXT_SEC).pack(side="left")

        # 结果区
        self._result_card = tk.Frame(body, bg=GRAY_BG, highlightbackground=BORDER, highlightthickness=1)
        self._result_card.pack(fill="x", padx=24, pady=6)
        self._result_inner = tk.Frame(self._result_card, bg=GRAY_BG, padx=18, pady=14)
        self._result_inner.pack(fill="both")

        self._result_labels = {}
        for k in ["子网掩码", "通配符掩码", "总IP地址数", "可用主机数", "网络位数", "主机位数"]:
            r = tk.Frame(self._result_inner, bg=GRAY_BG)
            r.pack(fill="x", pady=3)
            tk.Label(r, text=k, font=F(12, bold=True), bg=GRAY_BG, width=12, anchor="w").pack(side="left")
            lbl = tk.Label(r, text="", font=F(12, mono=True), bg=GRAY_BG, fg=TEXT_PRI, anchor="w")
            lbl.pack(side="left")
            self._result_labels[k] = lbl

        self._update_display()

    def _set_cidr(self, val):
        self._cidr_var.set(val)
        self._update_display()

    def _on_slider(self, val):
        self._cidr_var.set(int(float(val)))
        self._update_display()

    def _update_display(self):
        cidr = self._cidr_var.get()
        self._cidr_display.config(text=f"CIDR: /{cidr}")

        # 更新二进制位块
        for i, lbl in enumerate(self._bit_labels):
            if i < cidr:
                lbl.config(text="1", bg=BIT_ON)
            else:
                lbl.config(text="0", bg=BIT_OFF)

        # 计算结果
        m = NetworkCalculator.cidr_to_mask(cidr)
        if m:
            mask = m["mask"]
            wildcard = ".".join([str(255 - int(o)) for o in mask.split(".")])
            total = 2 ** (32 - cidr)
            usable = max(total - 2, 0)
            self._result_labels["子网掩码"].config(text=mask)
            self._result_labels["通配符掩码"].config(text=wildcard, fg=BLUE)
            self._result_labels["总IP地址数"].config(text=str(total))
            self._result_labels["可用主机数"].config(text=str(usable), fg="#34C759")
            self._result_labels["网络位数"].config(text=str(cidr))
            self._result_labels["主机位数"].config(text=str(32 - cidr))


# ══════════════════════════════════════════════
#  标签页：历史记录
# ══════════════════════════════════════════════

class HistoryTab(tk.Frame):
    def __init__(self, parent, root, on_restore=None):
        super().__init__(parent, bg=WIN_BG)
        self._root = root
        self._on_restore = on_restore

        # 工具栏
        bar = tk.Frame(self, bg=WIN_BG, padx=20, pady=10)
        bar.pack(fill="x")
        tk.Label(bar, text="历史记录", font=F(20, bold=True), bg=WIN_BG, fg=TEXT_PRI).pack(side="left")
        tk.Button(bar, text="清空历史", font=F(12), relief="flat",
                  bg="#FF3B30", fg="white", padx=12, pady=4, cursor="hand2",
                  command=self._clear).pack(side="right")
        tk.Button(bar, text="🔄 刷新", font=F(12), relief="flat",
                  bg=BLUE_LIGHT, fg=BLUE, padx=12, pady=4, cursor="hand2",
                  command=self.refresh).pack(side="right", padx=8)

        # 列表区
        sf = ScrollFrame(self)
        sf.pack(fill="both", expand=True)
        self._list_frame = sf.inner
        self._list_frame.columnconfigure(0, weight=1)

        self.refresh()

    def refresh(self):
        for w in self._list_frame.winfo_children():
            w.destroy()

        records = list(reversed(history_mgr.records))
        if not records:
            tk.Label(self._list_frame, text="暂无历史记录", font=F(14),
                     bg=WIN_BG, fg=TEXT_SEC).pack(pady=40)
            return

        for rec in records:
            card = tk.Frame(self._list_frame, bg=CARD_BG,
                            highlightbackground=BORDER, highlightthickness=1)
            card.pack(fill="x", padx=20, pady=4)
            inner = tk.Frame(card, bg=CARD_BG, padx=14, pady=10)
            inner.pack(fill="both")

            hdr = tk.Frame(inner, bg=CARD_BG)
            hdr.pack(fill="x")
            tk.Label(hdr, text=f"[{rec.get('type', '未知')}]", font=F(11, bold=True),
                     bg=CARD_BG, fg=BLUE).pack(side="left")
            tk.Label(hdr, text=rec.get("time", ""), font=F(10), bg=CARD_BG, fg=TEXT_SEC).pack(side="right")

            tk.Label(inner, text=rec.get("summary", ""), font=F(12, mono=True),
                     bg=CARD_BG, fg=TEXT_PRI, anchor="w").pack(fill="x", pady=(4, 0))

            if rec.get("payload") and self._on_restore:
                payload = rec["payload"]
                rtype = rec["type"]
                tk.Button(inner, text="恢复此记录", font=F(11), relief="flat",
                          bg=BLUE_LIGHT, fg=BLUE, padx=8, pady=2, cursor="hand2",
                          command=lambda p=payload, t=rtype: self._on_restore(t, p)).pack(
                    anchor="e", pady=(6, 0))

    def _clear(self):
        if messagebox.askyesno("确认", "确定要清空所有历史记录吗？"):
            history_mgr.clear()
            self.refresh()


# ══════════════════════════════════════════════
#  主应用
# ══════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("网络计算器")
        self.geometry("1100x750")
        self.minsize(1000, 700)
        self.configure(bg=WIN_BG)

        # 配置 ttk 样式
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except:
            pass

        style.configure("TNotebook", background=WIN_BG, tabmargins=[0, 0, 0, 0])
        style.configure("TNotebook.Tab", font=("Microsoft YaHei UI", 12),
                        padding=[16, 8], background="#E5E5EA", foreground=TEXT_PRI)
        style.map("TNotebook.Tab",
                  background=[("selected", CARD_BG), ("active", "#D1D1D6")],
                  foreground=[("selected", BLUE)])
        style.configure("TButton", font=("Microsoft YaHei UI", 11), padding=[8, 4])
        style.configure("TEntry", font=("Courier New", 13), padding=4)

        # 主 Notebook
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True)

        # 创建各标签页
        self.tab_ip = IPCalculatorTab(self.nb, self)
        self.tab_subnet = SubnetMaskTab(self.nb, self)
        self.tab_host = HostCalculatorTab(self.nb, self)
        self.tab_ipv6 = IPv6Tab(self.nb, self)
        self.tab_mac = MACTab(self.nb, self)
        self.tab_reverse = ReverseTab(self.nb, self)
        self.tab_history = HistoryTab(self.nb, self, on_restore=self._restore)

        self.nb.add(self.tab_ip,      text="  🌐 IP计算器  ")
        self.nb.add(self.tab_subnet,  text="  🛡️ 子网掩码  ")
        self.nb.add(self.tab_host,    text="  🖥️ 主机数计算  ")
        self.nb.add(self.tab_ipv6,    text="  🔷 IPv6计算器  ")
        self.nb.add(self.tab_mac,     text="  📡 MAC地址转换  ")
        self.nb.add(self.tab_reverse, text="  🔄 掩码逆算  ")
        self.nb.add(self.tab_history, text="  🕐 历史记录  ")

        # 切换到历史记录时刷新
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_change)

    def _on_tab_change(self, event):
        tab = self.nb.select()
        idx = self.nb.index(tab)
        if idx == 6:
            self.tab_history.refresh()

    def _restore(self, rtype, payload):
        tab_map = {
            "IPv4 计算": (0, lambda: self.tab_ip.restore(payload)),
        }
        if rtype in tab_map:
            idx, fn = tab_map[rtype]
            self.nb.select(idx)
            fn()

if __name__ == "__main__":
    app = App()
    app.mainloop()
