"""Tkinter application shell (sidebar layout) around the core engine."""

import ipaddress
import json
import os
import queue
import re
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import ttk, messagebox, filedialog, simpledialog

from .. import __version__ as APP_VERSION
from .theme import (ACCENT, ACCENT_HOVER, ACCENT_PRESS, ACCENT_SOFT, BG,
                    BORDER, BORDER_LIGHT, BRAND_MARK, CYAN, CYAN_HOVER, ERROR,
                    ERROR_HOVER, Fonts, MONO_FONT_CANDIDATES, PANEL, PANEL_ALT,
                    PANEL_ALT2, ROW_EVEN, ROW_ODD, SUCCESS, TEXT, TEXT_DIM,
                    TEXT_FAINT, UI_FONT_CANDIDATES, WARN, _pick_font)
from ..core.targets import (CIDR_ASK_THRESHOLD, find_subdomains_for_bases,
                            guess_base_domain, parse_domain_list, parse_ip_input,
                            parse_target_list, parse_target_string, resolve_host)
from ..core.netprobe import (BROWSER_FINGERPRINTS, HAVE_CURL_CFFI, browser_tls_ping,
                             check_port, sni_target_test, tcp_handshake_ping,
                             tls_handshake_ping)
from ..core.links import modify_config_link
from ..core.reality import (REALITY_PROBE_URL, REALITY_TCP_PRECHECK_ATTEMPTS,
                            REALITY_TCP_PRECHECK_MIN_TIMEOUT_MS,
                            REALITY_VERDICT_RANK, parse_reality_link,
                            reality_result_to_row, reality_sni_test,
                            reality_sort_key)
from ..core.speedtest import (SPEEDTEST_DEFAULT_DOWNLOAD_MB, SPEEDTEST_DEFAULT_HOST,
                              SPEEDTEST_DEFAULT_UPLOAD_MB, high_accuracy_speed_test)
from ..core.xraycore import (XRAY_PINNED_VERSION, XRAY_SOCKS_PORT_RANGE,
                             XRAY_TUNNEL_READY_TIMEOUT_S, XRAY_LOCAL_HOST,
                             ensure_xray_binary)


DEFAULT_SNI = "www.cloudflare.com"


NEXT_PHASE_DEFAULT_COUNT = "10"


NEXT_PHASE_DEFAULT_TIMEOUT = "1500"


DEFAULT_FILTER_TIMEOUT_MS = "3000"


SNI_MODE_DEFAULT_COUNT = "5"


SNI_MODE_DEFAULT_TIMEOUT_MS = "4000"


COMMON_REALITY_DOMAINS = [
    "www.apple.com", "gateway.icloud.com", "www.microsoft.com",
    "www.swift.org", "www.amd.com", "discord.com",
    "www.samsung.com", "cdn.jsdelivr.net", "www.cloudflare.com",
    "www.nvidia.com",
]


class ScannerApp:
    def __init__(self, root):
        self.root = root
        Fonts.init()

        self.root.title(f"DPI Cleaner Scanner v{APP_VERSION}")
        self.root.geometry("1280x860")
        self.root.configure(bg=BG)
        self.root.minsize(1060, 700)

        self.msg_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.scan_running = False
        self.phase = 1
        self.results = []
        self._live_count = 0
        self._live_online = 0
        self.current_page = "scan"
        self._tree_result_map = {}
        self.mode_var = tk.StringVar(value="ip")   # "ip"  or  "sni"

        self._build_style()
        self._build_ui()
        self._apply_mode()
        self.root.after(100, self._poll_queue)

    
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(".", background=BG, foreground=TEXT, font=Fonts.body)
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=PANEL)

        style.configure("TLabel", background=BG, foreground=TEXT, font=Fonts.body)
        style.configure("Card.TLabel", background=PANEL, foreground=TEXT, font=Fonts.body)
        style.configure("Dim.Card.TLabel", background=PANEL, foreground=TEXT_DIM, font=Fonts.label)
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=Fonts.title)
        style.configure("Subtitle.TLabel", background=BG, foreground=TEXT_DIM, font=Fonts.subtitle)
        style.configure("Section.TLabel", background=PANEL, foreground=TEXT, font=Fonts.section)

        style.configure("TEntry", fieldbackground=PANEL_ALT, foreground=TEXT,
                        insertcolor=TEXT, bordercolor=BORDER, lightcolor=BORDER,
                        darkcolor=BORDER, borderwidth=1, padding=6, relief="flat")
        style.map("TEntry",
                  fieldbackground=[("disabled", PANEL), ("focus", PANEL_ALT2)],
                  bordercolor=[("focus", ACCENT)])

        style.configure("TCombobox", fieldbackground=PANEL_ALT, background=PANEL_ALT,
                        foreground=TEXT, arrowcolor=ACCENT, bordercolor=BORDER, padding=5,
                        relief="flat")
        style.map("TCombobox",
                  fieldbackground=[("readonly", PANEL_ALT), ("disabled", PANEL)],
                  foreground=[("readonly", TEXT), ("disabled", TEXT_FAINT)],
                  background=[("readonly", PANEL_ALT)],
                  bordercolor=[("focus", ACCENT)])

        style.configure("TCheckbutton", background=PANEL, foreground=TEXT_DIM, font=Fonts.small)
        style.map("TCheckbutton",
                  background=[("active", PANEL)],
                  foreground=[("active", TEXT), ("disabled", TEXT_FAINT)])

        
        style.configure("Primary.TButton", background=ACCENT, foreground="#ffffff",
                        font=Fonts.button, padding=(18, 10), borderwidth=0, relief="flat")
        style.map("Primary.TButton",
                  background=[("active", ACCENT_HOVER), ("pressed", ACCENT_PRESS),
                              ("disabled", "#33364a")],
                  foreground=[("disabled", TEXT_FAINT)])

        style.configure("Danger.TButton", background=ERROR, foreground="#2a0c0c",
                        font=Fonts.button, padding=(16, 10), borderwidth=0, relief="flat")
        style.map("Danger.TButton",
                  background=[("active", ERROR_HOVER), ("disabled", "#33364a")],
                  foreground=[("disabled", TEXT_FAINT)])

        style.configure("Secondary.TButton", background=PANEL_ALT2, foreground=TEXT,
                        font=Fonts.body, padding=(14, 9), borderwidth=1, relief="flat",
                        bordercolor=BORDER_LIGHT)
        style.map("Secondary.TButton",
                  background=[("active", BORDER_LIGHT), ("disabled", PANEL)],
                  foreground=[("disabled", TEXT_FAINT)])

        style.configure("Accent2.TButton", background=CYAN, foreground="#04202c",
                        font=Fonts.button, padding=(16, 10), borderwidth=0, relief="flat")
        style.map("Accent2.TButton",
                  background=[("active", CYAN_HOVER), ("disabled", "#33364a")],
                  foreground=[("disabled", TEXT_FAINT)])


        style.configure("NavActive.TButton", background=ACCENT_SOFT, foreground=ACCENT,
                        font=Fonts.body_bold, padding=(14, 11), borderwidth=0, relief="flat")
        style.map("NavActive.TButton",
                  background=[("active", ACCENT_SOFT)],
                  foreground=[("active", ACCENT)])
        style.configure("NavInactive.TButton", background=PANEL, foreground=TEXT_DIM,
                        font=Fonts.body, padding=(14, 11), borderwidth=0, relief="flat")
        style.map("NavInactive.TButton",
                  background=[("active", PANEL_ALT2)],
                  foreground=[("active", TEXT)])


        style.configure("ModeActive.TButton", background=CYAN, foreground="#04202c",
                        font=Fonts.body_bold, padding=(14, 8), borderwidth=0, relief="flat")
        style.map("ModeActive.TButton", background=[("active", CYAN_HOVER)])
        style.configure("ModeInactive.TButton", background=PANEL_ALT, foreground=TEXT_DIM,
                        font=Fonts.body, padding=(14, 8), borderwidth=0, relief="flat")
        style.map("ModeInactive.TButton",
                  background=[("active", PANEL_ALT2)],
                  foreground=[("active", TEXT)])


        style.configure("Treeview", background=PANEL_ALT, fieldbackground=PANEL_ALT,
                        foreground=TEXT, rowheight=30, font=Fonts.mono, borderwidth=0, relief="flat")
        style.configure("Treeview.Heading", background=PANEL, foreground=TEXT_DIM,
                        font=Fonts.body_bold, borderwidth=0, relief="flat", padding=(8, 10))
        style.map("Treeview.Heading",
                  background=[("active", PANEL_ALT2)],
                  foreground=[("active", TEXT)])
        style.map("Treeview",
                  background=[("selected", ACCENT_SOFT)],
                  foreground=[("selected", TEXT)])
        style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])


        style.configure("TProgressbar", troughcolor=PANEL_ALT, background=ACCENT,
                        bordercolor=PANEL_ALT, lightcolor=ACCENT, darkcolor=ACCENT,
                        thickness=8)


        for orient in ("Vertical", "Horizontal"):
            style.configure(f"{orient}.TScrollbar", background=PANEL_ALT2, troughcolor=PANEL,
                            bordercolor=PANEL, arrowcolor=TEXT_DIM, gripcount=0, relief="flat")
            style.map(f"{orient}.TScrollbar", background=[("active", BORDER_LIGHT)])

    def _card(self, parent, title, icon=""):
        outer = tk.Frame(parent, bg=BORDER)
        inner = ttk.Frame(outer, style="Card.TFrame", padding=(18, 16))
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        title_label = None
        if title:
            head = ttk.Frame(inner, style="Card.TFrame")
            head.pack(fill="x", pady=(0, 12))
            if icon:
                tk.Label(head, text=icon, bg=PANEL, fg=CYAN, font=(Fonts.section[0], 13)).pack(side="left", padx=(0, 8))
            title_label = ttk.Label(head, text=title, style="Section.TLabel")
            title_label.pack(side="left")
        return outer, inner, title_label

    def _hover_cursor(self, widget):
        widget.configure(cursor="hand2")

    def _make_scrollable(self, parent):
        """Wrap `parent` in a vertically-scrolling canvas and return the
        inner frame that content should be packed into. Prevents buttons
        from getting clipped off the bottom when the page's content is
        taller than the current window."""
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0, bd=0)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        inner = tk.Frame(canvas, bg=BG)
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _sync_scrollregion(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _sync_width(event):
            canvas.itemconfigure(window_id, width=event.width)

        inner.bind("<Configure>", _sync_scrollregion)
        canvas.bind("<Configure>", _sync_width)

        def _wheel(event):
            if event.num == 4:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                canvas.yview_scroll(1, "units")
            else:
                canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

        def _bind_wheel(_):
            canvas.bind_all("<MouseWheel>", _wheel)
            canvas.bind_all("<Button-4>", _wheel)
            canvas.bind_all("<Button-5>", _wheel)

        def _unbind_wheel(_):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", _bind_wheel)
        canvas.bind("<Leave>", _unbind_wheel)

        return inner


    def _build_ui(self):
        root = self.root

        shell = tk.Frame(root, bg=BG)
        shell.pack(fill="both", expand=True)

        sidebar = tk.Frame(shell, bg=PANEL, width=238)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Frame(shell, bg=BORDER, width=1).pack(side="left", fill="y")

        brand = tk.Frame(sidebar, bg=PANEL)
        brand.pack(fill="x", padx=18, pady=(22, 20))
        mark = tk.Frame(brand, bg=ACCENT_SOFT, width=42, height=42)
        mark.pack(side="left", padx=(0, 12))
        mark.pack_propagate(False)
        tk.Label(mark, text=BRAND_MARK, bg=ACCENT_SOFT, fg=ACCENT,
                 font=(Fonts.title[0], 19)).pack(expand=True)
        brand_text = tk.Frame(brand, bg=PANEL)
        brand_text.pack(side="left")
        tk.Label(brand_text, text="DPI CLEANER", bg=PANEL, fg=TEXT,
                 font=Fonts.section).pack(anchor="w")
        tk.Label(brand_text, text=f"scanner \u00b7 v{APP_VERSION}", bg=PANEL, fg=TEXT_FAINT,
                 font=Fonts.small).pack(anchor="w")

        nav = tk.Frame(sidebar, bg=PANEL)
        nav.pack(fill="x", padx=12)
        self.nav_scan_btn = ttk.Button(nav, text="\u2699  Scan Setup", style="NavActive.TButton",
                                       command=lambda: self._show_page("scan"))
        self.nav_scan_btn.pack(fill="x", pady=(0, 6))
        self._hover_cursor(self.nav_scan_btn)
        self.nav_results_btn = ttk.Button(nav, text="\U0001F4CA  Results", style="NavInactive.TButton",
                                          command=lambda: self._show_page("results"))
        self.nav_results_btn.pack(fill="x")
        self._hover_cursor(self.nav_results_btn)

        self.status_pill = tk.Label(sidebar, text="\u25cf  READY", bg=ACCENT_SOFT, fg=ACCENT,
                                    font=Fonts.small, padx=12, pady=7)
        self.status_pill.pack(side="bottom", fill="x", padx=18, pady=(0, 18))
        tk.Label(sidebar, text="VALIDATE \u00b7 RANK \u00b7 EXPORT", bg=PANEL, fg=TEXT_FAINT,
                 font=Fonts.small).pack(side="bottom", pady=(0, 6))

        content = tk.Frame(shell, bg=BG)
        content.pack(side="left", fill="both", expand=True)

        head = tk.Frame(content, bg=BG)
        head.pack(fill="x", padx=22, pady=(18, 10))
        self.page_title = ttk.Label(head, text="Scan Setup", style="Title.TLabel")
        self.page_title.pack(anchor="w")
        self.page_sub = ttk.Label(head, text="", style="Subtitle.TLabel")
        self.page_sub.pack(anchor="w", pady=(2, 0))

        pages = tk.Frame(content, bg=BG)
        pages.pack(fill="both", expand=True, padx=22)
        pages.grid_rowconfigure(0, weight=1)
        pages.grid_columnconfigure(0, weight=1)
        self.scan_page = tk.Frame(pages, bg=BG)
        self.results_page = tk.Frame(pages, bg=BG)
        self.scan_page.grid(row=0, column=0, sticky="nsew")
        self.results_page.grid(row=0, column=0, sticky="nsew")

        scan_scroll_inner = self._make_scrollable(self.scan_page)
        self._build_scan_page(scan_scroll_inner)
        self._build_results_page(self.results_page)

        footer_outer = tk.Frame(content, bg=BORDER)
        footer_outer.pack(fill="x", padx=22, pady=(12, 18))
        footer = tk.Frame(footer_outer, bg=PANEL, padx=14, pady=11)
        footer.pack(fill="x", padx=1, pady=1)
        self.progress = ttk.Progressbar(footer, mode="determinate", style="TProgressbar")
        self.progress.pack(side="left", fill="x", expand=True, padx=(0, 14))
        self.status_var = tk.StringVar(value="Ready \u2014 pick a scan mode below and press Start")
        self.status_label = tk.Label(footer, textvariable=self.status_var, bg=PANEL, fg=TEXT_DIM,
                                     font=Fonts.small, anchor="e")
        self.status_label.pack(side="left")

        self._show_page("scan")

    def _build_scan_page(self, parent):

        mode_outer, mode_card, _ = self._card(parent, None)
        mode_outer.pack(fill="x", pady=(0, 12))
        mode_row = ttk.Frame(mode_card, style="Card.TFrame")
        mode_row.pack(fill="x")
        ttk.Label(mode_row, text="SCAN MODE", style="Dim.Card.TLabel").pack(side="left", padx=(0, 14))
        self.mode_ip_btn = ttk.Button(mode_row, text="\U0001F310  IP / CIDR List",
                                       style="ModeActive.TButton",
                                       command=lambda: self._set_mode("ip"))
        self.mode_ip_btn.pack(side="left", padx=(0, 8))
        self._hover_cursor(self.mode_ip_btn)
        self.mode_sni_btn = ttk.Button(mode_row, text="\U0001F3AF  SNI / REALITY Target",
                                        style="ModeInactive.TButton",
                                        command=lambda: self._set_mode("sni"))
        self.mode_sni_btn.pack(side="left")
        self._hover_cursor(self.mode_sni_btn)


        input_outer, input_card, self.input_title_label = self._card(parent, "Target IPs", "\U0001F310")
        input_outer.pack(fill="x", pady=(0, 12))

        self.input_desc_var = tk.StringVar(value="Enter IPs or CIDR ranges, separated by spaces or commas")
        ttk.Label(input_card, textvariable=self.input_desc_var,
                  style="Dim.Card.TLabel", font=Fonts.small).pack(anchor="w")


        self.ip_mode_frame = tk.Frame(input_card, bg=PANEL)
        self.ip_text = tk.Text(self.ip_mode_frame, height=4, bg=PANEL_ALT, fg=TEXT,
                                insertbackground=TEXT, relief="flat", font=Fonts.mono,
                                highlightthickness=1, highlightbackground=BORDER,
                                highlightcolor=ACCENT, padx=10, pady=8, wrap="word")
        self.ip_text.pack(fill="x")
        self.ip_text.insert("1.0", "104.16.0.0/28\n")

        self.sni_mode_frame = tk.Frame(input_card, bg=PANEL)
        target_box = tk.Frame(self.sni_mode_frame, bg=PANEL)
        target_box.pack(fill="x", pady=(4, 4), anchor="w")
        ttk.Label(target_box, text="TARGET  (domain or IP, optional :port)",
                  style="Dim.Card.TLabel").pack(anchor="w")
        self.target_var = tk.StringVar(value="python.org:443")
        ttk.Entry(target_box, textvariable=self.target_var, width=48).pack(anchor="w", pady=(4, 4))
        self.resolved_summary_var = tk.StringVar(value="")
        tk.Label(target_box, textvariable=self.resolved_summary_var, bg=PANEL, fg=CYAN,
                 font=Fonts.small, justify="left", anchor="w").pack(anchor="w", fill="x")
        ttk.Label(target_box, text="The target above is resolved to its real IP, and every SNI "
                                    "candidate below is TLS-tested against it \u2014 for scouting "
                                    "REALITY dest/serverNames for that one site.",
                  style="Dim.Card.TLabel", font=Fonts.small, justify="left",
                  wraplength=560).pack(anchor="w", pady=(0, 8))

        override_box = tk.Frame(self.sni_mode_frame, bg=PANEL)
        override_box.pack(fill="x", pady=(0, 4), anchor="w")
        ttk.Label(override_box, text="TEST AGAINST YOUR OWN SERVER INSTEAD (optional \u2014 IP or IP:port)",
                  style="Dim.Card.TLabel").pack(anchor="w")
        self.override_ip_var = tk.StringVar(value="")
        ttk.Entry(override_box, textvariable=self.override_ip_var, width=28).pack(anchor="w", pady=(4, 4))
        ttk.Label(override_box, text="Fill this in with your own server's IP (add :port if it's not "
                                      "the same port as above, e.g. 1.2.3.4:8007) to test every SNI "
                                      "candidate against THAT server instead of the target's own IP "
                                      "\u2014 useful for checking your Xray/REALITY inbound itself. "
                                      "Leave empty to test the target's own IP and port (the default).",
                  style="Dim.Card.TLabel", font=Fonts.small, justify="left",
                  wraplength=560).pack(anchor="w", pady=(0, 4))

        ttk.Label(self.sni_mode_frame,
                  text="Every row below now reports TCP and TLS+SNI SEPARATELY (they can legitimately "
                       "disagree \u2014 e.g. a bare TCP probe times out on your port while a real TLS "
                       "ClientHello with the right SNI gets through, or vice versa), plus a best-effort "
                       "ALPN probe and a VERDICT. \u201cGOOD TARGET\u201d means both TCP and TLS+SNI "
                       "succeeded; \u201cVALID TLS TARGET\u201d means TLS+SNI worked even though a raw "
                       "TCP connect() didn't \u2014 which is exactly the situation described where a bare "
                       "port check times out but a real VLESS/REALITY client still connects. None of this "
                       "is a full REALITY handshake validation (that also depends on your server's public "
                       "key / shortId), so treat the verdict as \u201cworth trying in your real client\u201d, "
                       "not a guarantee. Tick \u201cValidate with a real REALITY handshake\u201d below to "
                       "replace this generic-TLS verdict with an actual xray-core REALITY session test.",
                  style="Dim.Card.TLabel", font=Fonts.small, justify="left",
                  wraplength=560).pack(anchor="w", pady=(2, 8))

        # ---- Real REALITY handshake validation toggle ----
        reality_box = tk.Frame(self.sni_mode_frame, bg=PANEL)
        reality_box.pack(fill="x", pady=(0, 8), anchor="w")
        self.use_reality_var = tk.BooleanVar(value=False)
        self.use_reality_cb = ttk.Checkbutton(
            reality_box,
            text="Validate with a real REALITY handshake (uses the xray-core binary + REALITY "
                 "config link set below, under Speed Test Settings) instead of generic TLS",
            variable=self.use_reality_var, command=self._toggle_reality_mode)
        self.use_reality_cb.pack(anchor="w")
        reality_workers_row = tk.Frame(reality_box, bg=PANEL)
        reality_workers_row.pack(anchor="w", pady=(6, 0))
        ttk.Label(reality_workers_row, text="REALITY WORKERS (concurrent xray processes)",
                  style="Dim.Card.TLabel").pack(side="left", padx=(0, 8))
        self.reality_workers_var = tk.StringVar(value="4")
        ttk.Entry(reality_workers_row, textvariable=self.reality_workers_var, width=6).pack(side="left")
        ttk.Label(reality_box,
                  text="Real REALITY validation launches one xray-core process per attempt \u2014 keep "
                       "this small (4\u20138) so dozens of SNI candidates don't spawn dozens of xray "
                       "processes at once. REPETITIONS below becomes the number of separate REALITY "
                       "handshake attempts per SNI (not generic-TLS pings), and the verdict becomes "
                       "VALID / FLAKY / INVALID / TIMEOUT / NETWORK_ERROR based on actual handshake "
                       "results, ranked with VALID always above FLAKY always above the rest. The TCP "
                       f"precheck before each SNI now always retries up to {REALITY_TCP_PRECHECK_ATTEMPTS} "
                       f"times with at least {REALITY_TCP_PRECHECK_MIN_TIMEOUT_MS}ms per try, regardless "
                       "of the TIMEOUT (MS) field above, so a single slow/dropped probe can't falsely "
                       "mark a working server as unreachable before xray even gets a chance to run.",
                  style="Dim.Card.TLabel", font=Fonts.small, justify="left",
                  wraplength=560).pack(anchor="w", pady=(6, 0))

        ttk.Label(self.sni_mode_frame, text="SNI candidates to test (tested against the target above):",
                  style="Dim.Card.TLabel").pack(anchor="w", pady=(6, 0))

        self.sni_text = tk.Text(self.sni_mode_frame, height=4, bg=PANEL_ALT, fg=TEXT,
                                 insertbackground=TEXT, relief="flat", font=Fonts.mono,
                                 highlightthickness=1, highlightbackground=BORDER,
                                 highlightcolor=CYAN, padx=10, pady=8, wrap="word")
        self.sni_text.pack(fill="x", pady=(0, 8))
        self.sni_text.insert("1.0", "apps.mzstatic.com\napi.music.apple.com\nconfiguration.apple.com\n"
                                     "api.itunes.apple.com\nitunes.apple.com\n")

        sni_btn_row = tk.Frame(self.sni_mode_frame, bg=PANEL)
        sni_btn_row.pack(anchor="w", fill="x")

        self.discover_btn = ttk.Button(sni_btn_row, text="\U0001F50D  Find SNIs for target",
                                        style="Accent2.TButton", command=self._discover_domains)
        self.discover_btn.pack(side="left", padx=(0, 8))
        self._hover_cursor(self.discover_btn)

        fill_btn = ttk.Button(sni_btn_row, text="\u2728  Fill common REALITY domains",
                               style="Secondary.TButton", command=self._fill_common_domains)
        fill_btn.pack(side="left", padx=(0, 8))
        self._hover_cursor(fill_btn)

        self.sni_json_btn = ttk.Button(sni_btn_row, text="\U0001F4CB  SNI JSON",
                                        style="Primary.TButton", command=self._copy_sni_json)
        self.sni_json_btn.pack(side="left")
        self._hover_cursor(self.sni_json_btn)

        self.discover_hint_var = tk.StringVar(value="")
        tk.Label(self.sni_mode_frame, textvariable=self.discover_hint_var, bg=PANEL, fg=TEXT_DIM,
                 font=Fonts.small, justify="left", wraplength=560).pack(anchor="w", pady=(6, 0))

        ttk.Label(self.sni_mode_frame, text="Note: candidates found above (crt.sh / pasted) are only "
                                             "\u201cCandidate SNI\u201d \u2014 being seen in a certificate "
                                             "transparency log does not mean a REALITY server will accept "
                                             "it; only the scan/validation step below decides that.",
                  style="Dim.Card.TLabel", font=Fonts.small, justify="left",
                  wraplength=560).pack(anchor="w", pady=(4, 0))

        self.ip_mode_frame.pack(fill="x") 


        settings_outer, settings_card, _ = self._card(parent, "Scan Settings", "\u2699")
        settings_outer.pack(fill="x", pady=(0, 12))

        row1 = ttk.Frame(settings_card, style="Card.TFrame")
        row1.pack(fill="x", pady=(0, 14))
        self.port_var = tk.StringVar(value="443")
        self.method_var = tk.StringVar(value="TCP Handshake")
        self.sni_var = tk.StringVar(value=DEFAULT_SNI)
        self.count_var = tk.StringVar(value="4")
        self.timeout_var = tk.StringVar(value="1000")
        self._labeled_entry(row1, "PORT", self.port_var, 6, 0)
        self.method_label, self.method_combo = self._labeled_combo(
            row1, "TEST METHOD", self.method_var,
            ["TCP Handshake", "TLS Handshake", "Browser TLS (JA3)"], 18, 1)
        self.sni_label, self.sni_entry = self._labeled_entry(row1, "SNI", self.sni_var, 22, 2)
        self._labeled_entry(row1, "REPETITIONS", self.count_var, 6, 3)
        self._labeled_entry(row1, "TIMEOUT (MS)", self.timeout_var, 7, 4)

        row1b = ttk.Frame(settings_card, style="Card.TFrame")
        row1b.pack(fill="x", pady=(0, 14))
        self.fingerprint_var = tk.StringVar(value="chrome")
        self.fingerprint_label, self.fingerprint_combo = self._labeled_combo(
            row1b, "BROWSER FINGERPRINT (JA3)", self.fingerprint_var, BROWSER_FINGERPRINTS, 16, 0)
        ttk.Label(row1b,
                  text="Match this to the fingerprint (fp=...) set in your real REALITY client "
                       "config. Needs curl_cffi installed (pip install curl_cffi).",
                  style="Dim.Card.TLabel", font=Fonts.small, justify="left",
                  wraplength=520).grid(row=0, column=1, sticky="w", padx=(10, 0))

        self._toggle_sni()

        row2 = ttk.Frame(settings_card, style="Card.TFrame")
        row2.pack(fill="x")
        self.threads_var = tk.StringVar(value="100")
        self.max_cidr_var = tk.StringVar(value=str(CIDR_ASK_THRESHOLD))
        self.threads_label, self.threads_entry = self._labeled_entry(row2, "THREADS", self.threads_var, 6, 0)
        self.max_cidr_label, self.max_cidr_entry = self._labeled_entry(
            row2, "MAX IPs / CIDR", self.max_cidr_var, 8, 1)

        self.filter_port_var = tk.BooleanVar(value=False)
        self.filter_cb = ttk.Checkbutton(row2, text="Pre-filter by open port before testing",
                                          variable=self.filter_port_var,
                                          command=self._toggle_filter_timeout)
        self.filter_cb.grid(row=0, column=2, padx=(20, 8), sticky="sw", pady=(10, 0))

        self.filter_timeout_var = tk.StringVar(value=DEFAULT_FILTER_TIMEOUT_MS)
        self.filter_timeout_label, self.filter_timeout_entry = self._labeled_entry(
            row2, "FILTER TIMEOUT (MS)", self.filter_timeout_var, 9, 3)
        self._toggle_filter_timeout()

        # ===== Speed Test Settings (SNI/REALITY mode only) =====
        speed_outer, speed_card, _ = self._card(parent, "Speed Test Settings (SNI/REALITY)", "\u26a1")
        speed_outer.pack(fill="x", pady=(0, 12))
        self.speed_settings_card = speed_outer

        speed_row1 = ttk.Frame(speed_card, style="Card.TFrame")
        speed_row1.pack(fill="x", pady=(0, 12))
        self.download_mb_var = tk.StringVar(value=SPEEDTEST_DEFAULT_DOWNLOAD_MB)
        self.upload_mb_var = tk.StringVar(value=SPEEDTEST_DEFAULT_UPLOAD_MB)
        self._labeled_entry(speed_row1, "DOWNLOAD SIZE (MB)", self.download_mb_var, 10, 0)
        self._labeled_entry(speed_row1, "UPLOAD SIZE (MB)", self.upload_mb_var, 10, 1)

        speed_row3 = ttk.Frame(speed_card, style="Card.TFrame")
        speed_row3.pack(fill="x", pady=(6, 4), anchor="w")
        ttk.Label(speed_row3, text="YOUR VLESS/TROJAN + REALITY CONFIG LINK (vless://... or "
                                    "trojan://...)  \u2014 used for High Accuracy speed test AND, when "
                                    "the checkbox above is ticked, for real REALITY handshake "
                                    "validation of every SNI candidate (only serverName is swapped per "
                                    "candidate; every other credential comes from this link)",
                  style="Dim.Card.TLabel").pack(anchor="w", pady=(8, 0))
        self.vless_link_text = tk.Text(speed_row3, height=2, bg=PANEL_ALT, fg=TEXT,
                                        insertbackground=TEXT, relief="flat", font=Fonts.mono,
                                        highlightthickness=1, highlightbackground=BORDER,
                                        highlightcolor=CYAN, padx=10, pady=8, wrap="none")
        self.vless_link_text.pack(fill="x", pady=(4, 4))

        ttk.Label(speed_card,
                  text="High Accuracy launches a real xray-core client with your pasted VLESS or "
                       "Trojan config, opens an actual REALITY tunnel to the target/SNI combo, and "
                       "measures real throughput through it. The xray-core binary is located "
                       "automatically (from PATH, or downloaded on first use) \u2014 no manual path "
                       "needed. High Accuracy only produces a meaningful result against a target IP "
                       "that is actually YOUR REALITY server (matching the Public Key / Short ID in "
                       "the config link) \u2014 use the \u201cTest against your own server\u201d "
                       "override above for that.",
                  style="Dim.Card.TLabel", font=Fonts.small, justify="left",
                  wraplength=1000).pack(anchor="w", pady=(8, 0))

        # ===== Action row =====
        action_outer = tk.Frame(parent, bg=BG)
        action_outer.pack(fill="x", pady=(0, 12))

        self.start_btn = ttk.Button(action_outer, text="\u25b6   Start Scan",
                                     style="Primary.TButton", command=self.start_scan)
        self.start_btn.pack(side="left", padx=(0, 8))
        self._hover_cursor(self.start_btn)

        self.stop_btn = ttk.Button(action_outer, text="\u25a0   Stop",
                                    style="Danger.TButton", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 24))
        self._hover_cursor(self.stop_btn)

        next_phase_box = tk.Frame(action_outer, bg=BG)
        next_phase_box.pack(side="left", padx=(0, 8))
        ttk.Label(next_phase_box, text="Top N for next phase", style="Subtitle.TLabel",
                  font=Fonts.small).pack(anchor="w")
        inner_np = tk.Frame(next_phase_box, bg=BG)
        inner_np.pack(anchor="w", pady=(3, 0))
        self.top_n_var = tk.StringVar(value="20")
        ttk.Entry(inner_np, textvariable=self.top_n_var, width=6).pack(side="left", padx=(0, 8))
        self.next_phase_btn = ttk.Button(inner_np, text="Next Phase \u25b6",
                                          style="Accent2.TButton", command=self.run_next_phase,
                                          state="disabled")
        self.next_phase_btn.pack(side="left", padx=(0, 8))
        self._hover_cursor(self.next_phase_btn)

        self.high_acc_btn = ttk.Button(inner_np, text="High Accuracy ST \u25b6",
                                        style="Primary.TButton",
                                        command=lambda: self.run_speed_test("high"),
                                        state="disabled")
        self.high_acc_btn.pack(side="left")
        self._hover_cursor(self.high_acc_btn)

        spacer = tk.Frame(action_outer, bg=BG)
        spacer.pack(side="left", expand=True, fill="x")

        view_results_btn = ttk.Button(action_outer, text="View Results \u2192",
                                       style="Secondary.TButton",
                                       command=lambda: self._show_page("results"))
        view_results_btn.pack(side="left")
        self._hover_cursor(view_results_btn)

        
        tk.Frame(parent, bg=BG, height=16).pack(fill="x")


    def _build_results_page(self, parent):
        summary_outer, summary_card, _ = self._card(parent, None)
        summary_outer.pack(fill="x", pady=(0, 12))
        stats_row = ttk.Frame(summary_card, style="Card.TFrame")
        stats_row.pack(fill="x")

        self.stat_tested_var = tk.StringVar(value="0")
        self.stat_online_var = tk.StringVar(value="0")
        self.stat_avg_var = tk.StringVar(value="-")
        self.stat_best_var = tk.StringVar(value="-")

        self._stat_block(stats_row, "TESTED", self.stat_tested_var, TEXT, 0)
        self._stat_block(stats_row, "ONLINE", self.stat_online_var, SUCCESS, 1)
        self._stat_block(stats_row, "AVG PING (ONLINE)", self.stat_avg_var, CYAN, 2)
        self.stat_best_label = self._stat_block(stats_row, "BEST IP", self.stat_best_var,
                                                  ACCENT_HOVER, 3, wide=True)

        action_outer = tk.Frame(parent, bg=BG)
        action_outer.pack(fill="x", pady=(0, 12))

        self.export_btn = ttk.Button(action_outer, text="\U0001F4BE  Save Results",
                                      style="Secondary.TButton", command=self.export_results,
                                      state="disabled")
        self.export_btn.pack(side="left", padx=(0, 8))
        self._hover_cursor(self.export_btn)

        self.config_btn = ttk.Button(action_outer, text="\U0001F680  Generate Clean Configs",
                                      style="Primary.TButton", command=self.open_config_dialog,
                                      state="disabled")
        self.config_btn.pack(side="left")
        self._hover_cursor(self.config_btn)

        spacer = tk.Frame(action_outer, bg=BG)
        spacer.pack(side="left", expand=True, fill="x")

        back_btn = ttk.Button(action_outer, text="\u2190 Back to Scan Setup",
                               style="Secondary.TButton",
                               command=lambda: self._show_page("scan"))
        back_btn.pack(side="left")
        self._hover_cursor(back_btn)

        results_outer, results_card, _ = self._card(parent, "Results", "\U0001F4CA")
        results_outer.pack(fill="both", expand=True)

        hint = ttk.Label(results_card, text="Click a column header to sort \u2014 click \"Jitter\" "
                                             "to rank by stability instead of raw speed",
                          style="Dim.Card.TLabel", font=Fonts.small)
        hint.pack(anchor="w", pady=(0, 8))

        tree_frame = ttk.Frame(results_card, style="Card.TFrame")
        tree_frame.pack(fill="both", expand=True)

        cols = ("rank", "target", "ip", "tcp", "status", "pings", "loss", "ping", "jitter",
                "alpn", "verdict", "dl", "ul")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings")
        self._tree_headings = {"rank": "#", "target": "Target", "ip": "IP Address", "tcp": "TCP",
                                "status": "TLS+SNI", "pings": "Pings (ok/total)", "loss": "Packet Loss %",
                                "ping": "Avg Ping (ms)", "jitter": "Jitter (ms)", "alpn": "ALPN",
                                "verdict": "Verdict", "dl": "DL (Mbps)", "ul": "UL (Mbps)"}
        widths = {"rank": 50, "target": 150, "ip": 190, "tcp": 90, "status": 100,
                  "pings": 140, "loss": 130, "ping": 130, "jitter": 110,
                  "alpn": 80, "verdict": 150, "dl": 100, "ul": 100}
        for c in cols:
            self.tree.heading(c, text=self._tree_headings[c], command=lambda cc=c: self._sort_by(cc))
            self.tree.column(c, width=widths[c], anchor="center")
        # "target"/"tcp"/"alpn"/"verdict" columns only make sense in SNI mode; hidden by default (IP mode)
        self.tree["displaycolumns"] = ("rank", "ip", "status", "pings", "loss", "ping", "jitter")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Double-1>", self._show_result_details)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="we")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.tree.tag_configure("online_even", foreground=SUCCESS, background=ROW_EVEN)
        self.tree.tag_configure("online_odd", foreground=SUCCESS, background=ROW_ODD)
        self.tree.tag_configure("offline_even", foreground=ERROR, background=ROW_EVEN)
        self.tree.tag_configure("offline_odd", foreground=ERROR, background=ROW_ODD)

    def _stat_block(self, parent, label, var, color, col, wide=False):
        box = tk.Frame(parent, bg=PANEL)
        box.grid(row=0, column=col, padx=(0 if col == 0 else 28, 0), sticky="w")
        tk.Label(box, textvariable=var, bg=PANEL, fg=color, font=Fonts.stat_num).pack(anchor="w")
        lbl = tk.Label(box, text=label, bg=PANEL, fg=TEXT_DIM, font=Fonts.stat_label)
        lbl.pack(anchor="w")
        return lbl

    def _show_page(self, name):
        self.current_page = name
        if name == "scan":
            self.scan_page.tkraise()
            self.nav_scan_btn.configure(style="NavActive.TButton")
            self.nav_results_btn.configure(style="NavInactive.TButton")
            self.page_title.configure(text="Scan Setup")
            self.page_sub.configure(text="Feed targets in, rank what answers \u2014 IP/CIDR or SNI/REALITY.")
        else:
            self.results_page.tkraise()
            self.nav_scan_btn.configure(style="NavInactive.TButton")
            self.nav_results_btn.configure(style="NavActive.TButton")
            self.page_title.configure(text="Results")
            self.page_sub.configure(text="Sorted verdict-first \u2014 export TXT/JSON or copy a ready config.")

    def _labeled_entry(self, parent, label, var, width, col):
        box = ttk.Frame(parent, style="Card.TFrame")
        box.grid(row=0, column=col, padx=(0, 20), sticky="w")
        lbl = ttk.Label(box, text=label, style="Dim.Card.TLabel")
        lbl.pack(anchor="w")
        entry = ttk.Entry(box, textvariable=var, width=width)
        entry.pack(anchor="w", pady=(4, 0))
        return lbl, entry

    def _labeled_combo(self, parent, label, var, values, width, col):
        box = ttk.Frame(parent, style="Card.TFrame")
        box.grid(row=0, column=col, padx=(0, 20), sticky="w")
        ttk.Label(box, text=label, style="Dim.Card.TLabel").pack(anchor="w")
        combo = ttk.Combobox(box, textvariable=var, values=values, state="readonly", width=width)
        combo.pack(anchor="w", pady=(4, 0))
        combo.bind("<<ComboboxSelected>>", lambda e: self._toggle_sni())
        return combo, combo

    def _toggle_sni(self):
        method = self.method_var.get()
        if self.mode_var.get() == "sni":
            self.sni_entry.configure(state="disabled")
            self.fingerprint_combo.configure(state="readonly")
            return
        is_tls = method.startswith("TLS")
        is_browser_tls = method.startswith("Browser")
        self.sni_entry.configure(state="normal" if (is_tls or is_browser_tls) else "disabled")
        self.fingerprint_combo.configure(state="readonly" if is_browser_tls else "disabled")

    def _toggle_filter_timeout(self):
        if self.mode_var.get() == "sni":
            self.filter_timeout_entry.configure(state="disabled")
            return
        state = "normal" if self.filter_port_var.get() else "disabled"
        self.filter_timeout_entry.configure(state=state)

    def _toggle_reality_mode(self):
        """When real REALITY validation is enabled, generic-TLS-only
        controls (fingerprint / method) stop being meaningful for SNI
        mode, and the REPETITIONS field means "REALITY handshake
        attempts" instead of "TLS pings" - update labels/state to match."""
        use_reality = self.use_reality_var.get() and self.mode_var.get() == "sni"
        try:
            self.fingerprint_combo.configure(state="disabled" if use_reality else "readonly")
        except Exception:
            pass

    def _set_status_pill(self, text, fg, bg=None):
        self.status_pill.configure(text=f"\u25cf  {text}", fg=fg, bg=bg or ACCENT_SOFT)

    def _fill_common_domains(self):
        self.sni_text.delete("1.0", "end")
        self.sni_text.insert("1.0", "\n".join(COMMON_REALITY_DOMAINS) + "\n")

    def _current_target(self, silent=False):
        """Parse the single target field. Returns (raw_label, host, port)
        or None (and shows an error, unless silent) if nothing valid was entered."""
        try:
            fallback_port = int(self.port_var.get())
        except ValueError:
            fallback_port = 443
        raw = self.target_var.get().strip()
        if not raw:
            if not silent:
                messagebox.showerror("Error", "Enter a target (domain or IP).")
            return None
        host, port, err = parse_target_string(raw, fallback_port)
        if err:
            if not silent:
                messagebox.showerror("Error", err)
            return None
        return (raw, host, port)

    def _sni_candidates(self, silent=False):
        """Parse the SNI candidates box. Returns a list of domains, or
        None (and shows an error unless silent) if none are valid."""
        raw = self.sni_text.get("1.0", "end").strip()
        if not raw:
            if not silent:
                messagebox.showerror("Error", "Enter at least one SNI/domain to test.")
            return None
        domain_list, errors = parse_domain_list(raw)
        if errors and not silent:
            messagebox.showwarning("Invalid entries",
                                    "These entries didn't look like valid domains and were ignored:\n"
                                    + ", ".join(errors))
        if not domain_list:
            if not silent:
                messagebox.showerror("Error", "No valid domains were found.")
            return None
        return domain_list

    def _copy_sni_json(self):
        """Build a ready-to-paste realitySettings JSON snippet from the
        current Target (as `target`) and the SNI candidates box (as
        `serverNames`), and copy it to the clipboard."""
        target = self._current_target(silent=False)
        if not target:
            return
        _, host, port = target
        domains = self._sni_candidates(silent=False)
        if not domains:
            return

        target_str = f"{host}:{port}"
        server_names = list(dict.fromkeys(domains))
        snippet = {
            "security": "reality",
            "realitySettings": {
                "show": False,
                "xver": 0,
                "target": target_str,
                "serverNames": server_names
            }
        }
        # Render with the same 2-space indentation / key order shown above,
        # then strip the outer braces so it can be pasted straight into an
        # existing streamSettings block.
        text = json.dumps(snippet, indent=2, ensure_ascii=False)
        inner_lines = text.splitlines()[1:-1]  # drop the leading "{" and trailing "}"
        result = "\n".join(inner_lines)

        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            self.root.update()
            messagebox.showinfo("Copied", "REALITY settings JSON copied to clipboard:\n\n" + result)
        except Exception as e:
            messagebox.showerror("Error", f"Could not copy to clipboard: {e}")

    def _discover_domains(self):
        if getattr(self, "_discovering", False) or self.scan_running:
            return
        target = self._current_target()
        if not target:
            return
        _, host, _port = target

        try:
            ipaddress.ip_address(host)
            messagebox.showerror("Error", "SNI discovery needs a domain-based target \u2014 raw IPs "
                                           "have no certificate-transparency history to search.")
            return
        except ValueError:
            pass

        base = guess_base_domain(host)
        bases = [base]

        self._discovering = True
        self.discover_btn.configure(state="disabled", text="\u23f3  Searching\u2026")
        self.discover_hint_var.set(f"Looking up subdomains of: {base} in certificate transparency logs ...")

        def worker():
            merged, errs, empty_bases = find_subdomains_for_bases(bases)
            self.msg_queue.put(("discovered", (bases, merged, errs, empty_bases)))

        threading.Thread(target=worker, daemon=True).start()

    def _set_mode(self, mode):
        if self.scan_running:
            return
        self.mode_var.set(mode)
        self._apply_mode()

    def _apply_mode(self):
        sni_mode = self.mode_var.get() == "sni"

        self.mode_ip_btn.configure(style="ModeInactive.TButton" if sni_mode else "ModeActive.TButton")
        self.mode_sni_btn.configure(style="ModeActive.TButton" if sni_mode else "ModeInactive.TButton")

        if sni_mode:
            self.input_title_label.configure(text="REALITY Target + SNI")
            self.input_desc_var.set("Enter a Target below (domain or IP) \u2014 it's resolved to its "
                                     "own IP, then every SNI candidate is TLS-tested against it")
            self.ip_mode_frame.pack_forget()
            self.sni_mode_frame.pack(fill="x")

            self.method_var.set("Browser TLS (JA3)")
            self.method_combo.configure(state="disabled")
            self.filter_port_var.set(False)
            self.filter_cb.configure(state="disabled")
            self.max_cidr_entry.configure(state="disabled")
            self.tree.heading("ip", text="SNI / Domain")
            self.tree["displaycolumns"] = ("rank", "target", "ip", "tcp", "status", "pings", "loss",
                                            "ping", "jitter", "alpn", "verdict", "dl", "ul")
            self.stat_best_label.configure(text="BEST TARGET / SNI")

            if self.count_var.get() == "4":
                self.count_var.set(SNI_MODE_DEFAULT_COUNT)
            if self.timeout_var.get() == "1000":
                self.timeout_var.set(SNI_MODE_DEFAULT_TIMEOUT_MS)
        else:
            self.input_title_label.configure(text="Target IPs")
            self.input_desc_var.set("Enter IPs or CIDR ranges, separated by spaces or commas")
            self.sni_mode_frame.pack_forget()
            self.ip_mode_frame.pack(fill="x")
            self.method_combo.configure(state="readonly")
            self.filter_cb.configure(state="normal")
            self.max_cidr_entry.configure(state="normal")
            self.tree.heading("ip", text="IP Address")
            self.tree["displaycolumns"] = ("rank", "ip", "status", "pings", "loss", "ping", "jitter")
            self.stat_best_label.configure(text="BEST IP")
            self.high_acc_btn.config(state="disabled")
            if self.count_var.get() == SNI_MODE_DEFAULT_COUNT:
                self.count_var.set("4")
            if self.timeout_var.get() == SNI_MODE_DEFAULT_TIMEOUT_MS:
                self.timeout_var.set("1000")

        self._toggle_sni()
        self._toggle_filter_timeout()
        self._toggle_reality_mode()

        if sni_mode:
            self.config_btn.configure(state="disabled")

        has_sni_results = sni_mode and len(self.results) > 0 and not self.scan_running
        self.high_acc_btn.config(state="normal" if has_sni_results else "disabled")


    def start_scan(self):
        if self.scan_running:
            return
        if self.mode_var.get() == "sni":
            self._start_sni_scan()
        else:
            self._start_ip_scan()

    def _start_ip_scan(self):
        raw = self.ip_text.get("1.0", "end").strip()
        if not raw:
            messagebox.showerror("Error", "Enter at least one IP address or CIDR range.")
            return
        try:
            max_cidr = int(self.max_cidr_var.get())
        except ValueError:
            max_cidr = CIDR_ASK_THRESHOLD

        ip_list, errors, truncated = parse_ip_input(raw, max_per_cidr=max_cidr)
        if errors:
            messagebox.showwarning("Invalid entries",
                                    "These entries were invalid and were ignored:\n" + ", ".join(errors))
        if truncated:
            lines = [f"\u2022 {cidr}: contains {total} IPs, only {used} will be tested"
                     for cidr, total, used in truncated]
            messagebox.showinfo(
                "Large range limited",
                "The following range(s) exceeded the configured cap:\n\n" + "\n".join(lines) +
                "\n\nIncrease 'Max IPs / CIDR' to test the full range."
            )
        if not ip_list:
            messagebox.showerror("Error", "No valid IP addresses were found.")
            return

        try:
            port = int(self.port_var.get())
            count = int(self.count_var.get())
            timeout_ms = int(self.timeout_var.get())
            threads = max(1, min(1000, int(self.threads_var.get())))
        except ValueError:
            messagebox.showerror("Error", "Port / repetitions / timeout / threads must be numbers.")
            return

        do_filter = self.filter_port_var.get()
        filter_timeout_ms = timeout_ms
        if do_filter:
            try:
                filter_timeout_ms = int(self.filter_timeout_var.get())
            except ValueError:
                messagebox.showerror("Error", "Filter timeout must be a number.")
                return

        method_choice = self.method_var.get()
        if method_choice.startswith("Browser"):
            method = "browser"
        elif method_choice.startswith("TLS"):
            method = "tls"
        else:
            method = "tcp"
        sni = self.sni_var.get().strip() or DEFAULT_SNI

        if method == "browser" and not HAVE_CURL_CFFI:
            messagebox.showerror("Error",
                                  "Browser TLS (JA3) method needs curl_cffi.\n\n"
                                  "Install it first:\n    pip install curl_cffi")
            return

        self.phase = 1
        self._launch_phase_ip(ip_list, port, count, timeout_ms, threads, method, sni,
                               do_port_filter=do_filter, filter_timeout_ms=filter_timeout_ms)

    def _validate_override(self, fallback_port):
        """Returns (override_host, override_port) or (None, None) if no
        override is set, or raises via messagebox and returns (False, False)
        on invalid input."""
        override_text = self.override_ip_var.get().strip()
        if not override_text:
            return None, None
        override_host, override_port, ov_err = parse_target_string(override_text, fallback_port)
        if ov_err:
            messagebox.showerror("Error", ov_err)
            return False, False
        try:
            ipaddress.ip_address(override_host)
        except ValueError:
            messagebox.showerror("Error", "Server IP override must be a valid IPv4/IPv6 address "
                                           "(optionally with :port).")
            return False, False
        return override_host, override_port

    def _get_reality_setup(self):
        """Validate and parse everything needed for real REALITY handshake
        validation. Returns (xray_path, vless_params, workers) or
        (None, None, None) (after showing an error) if anything is
        missing/invalid. The xray binary is located/downloaded
        automatically - no path field for the user to manage."""
        try:
            xray_path, _ = ensure_xray_binary()
        except Exception as e:
            messagebox.showerror("Xray setup failed", str(e))
            return None, None, None
        vless_link = self.vless_link_text.get("1.0", "end").strip()
        if not vless_link:
            messagebox.showerror("Error", "Real REALITY validation needs your VLESS/Trojan REALITY "
                                           "config link (paste it under Speed Test Settings).")
            return None, None, None
        vless_params = parse_reality_link(vless_link)
        if vless_params.get("error"):
            messagebox.showerror("Invalid config link", vless_params["error"])
            return None, None, None
        try:
            workers = max(1, min(32, int(self.reality_workers_var.get())))
        except ValueError:
            workers = 4
        return xray_path, vless_params, workers

    def _start_sni_scan(self):
        use_reality = self.use_reality_var.get()

        if not use_reality and not HAVE_CURL_CFFI:
            messagebox.showerror("Error",
                                  "SNI / REALITY mode uses real browser TLS fingerprints and needs "
                                  "curl_cffi.\n\nInstall it first:\n    pip install curl_cffi")
            return
        if use_reality and not HAVE_CURL_CFFI:
            messagebox.showerror("Error",
                                  "Real REALITY validation also needs curl_cffi (used to probe "
                                  "through the xray SOCKS tunnel).\n\nInstall it first:\n    "
                                  "pip install curl_cffi")
            return

        target = self._current_target()
        if not target:
            return
        label, host, port = target

        try:
            fallback_port = int(self.port_var.get())
        except ValueError:
            fallback_port = 443

        override_host, override_port = self._validate_override(fallback_port)
        if override_host is False:
            return

        domain_list = self._sni_candidates()
        if not domain_list:
            return

        try:
            count = int(self.count_var.get())
            timeout_ms = int(self.timeout_var.get())
            threads = max(1, min(1000, int(self.threads_var.get())))
        except ValueError:
            messagebox.showerror("Error", "Repetitions / timeout / threads must be numbers.")
            return

        reality_setup = None
        if use_reality:
            xray_path, vless_params, reality_workers = self._get_reality_setup()
            if xray_path is None:
                return
            if not override_host:
                proceed = messagebox.askyesno(
                    "No server override set",
                    "\u201cTest against your own server\u201d is empty, so real REALITY validation "
                    "will try a REALITY handshake against the target's OWN IP using your pasted "
                    "credentials. That only produces a meaningful VALID/INVALID verdict if the target "
                    "actually IS your own REALITY server (matching Public Key / Short ID) \u2014 "
                    "otherwise every combo will correctly come back INVALID or NETWORK_ERROR.\n\n"
                    "Fill in your server's IP under \u201cTest against your own server\u201d for a "
                    "real scouting run. Continue anyway?"
                )
                if not proceed:
                    return
            reality_setup = (xray_path, vless_params, reality_workers)

        self.resolved_summary_var.set("")
        self.phase = 1
        self._launch_phase_sni_setup([(label, host, port)], domain_list, count, timeout_ms, threads,
                                      override_host, override_port, reality_setup)

    def run_next_phase(self):
        if self.scan_running or not self.results:
            return
        try:
            top_n = max(1, int(self.top_n_var.get()))
        except ValueError:
            top_n = 20
        top_n = min(top_n, len(self.results))

        try:
            port = int(self.port_var.get())
            count = int(self.count_var.get())
            timeout_ms = int(self.timeout_var.get())
            threads = max(1, min(1000, int(self.threads_var.get())))
        except ValueError:
            messagebox.showerror("Error", "Port / repetitions / timeout / threads must be numbers.")
            return

        self.phase += 1
        if self.mode_var.get() == "sni":
            # Re-test exactly the same (target, SNI) combos that ranked best,
            # reusing the already-resolved connect host/port from phase 1 -
            # no need to re-resolve anything.
            combos = []
            for r in self.results[:top_n]:
                combos.append({
                    "target": r["target"],
                    "connect_host": r["connect_host"],
                    "port": r["port"],
                    "domain": r["ip"],
                })
            reality_setup = None
            if self.use_reality_var.get():
                xray_path, vless_params, reality_workers = self._get_reality_setup()
                if xray_path is None:
                    self.phase -= 1
                    return
                reality_setup = (xray_path, vless_params, reality_workers)
            self._launch_phase_sni_combos(combos, count, timeout_ms, threads, reality_setup)
        else:
            target_list = [r["ip"] for r in self.results[:top_n]]
            method_choice = self.method_var.get()
            if method_choice.startswith("Browser"):
                method = "browser"
            elif method_choice.startswith("TLS"):
                method = "tls"
            else:
                method = "tcp"
            sni = self.sni_var.get().strip() or DEFAULT_SNI
            self._launch_phase_ip(target_list, port, count, timeout_ms, threads, method, sni,
                                   do_port_filter=False, filter_timeout_ms=timeout_ms)

    def run_speed_test(self, accuracy):
        """accuracy is always 'high' now. Runs on the Top N rows of the
        current (SNI/REALITY mode) results."""
        if self.scan_running:
            return
        if self.mode_var.get() != "sni":
            messagebox.showinfo("Not applicable",
                                 "Speed testing is only available in SNI / REALITY Target mode.")
            return
        if not self.results:
            messagebox.showerror("Error", "Run a scan first to get some results to speed-test.")
            return

        try:
            top_n = max(1, int(self.top_n_var.get()))
        except ValueError:
            top_n = 20
        top_n = min(top_n, len(self.results))
        combos = [{"target": r["target"], "connect_host": r["connect_host"],
                   "port": r["port"], "domain": r["ip"]} for r in self.results[:top_n]]

        try:
            download_mb = float(self.download_mb_var.get())
            upload_mb = float(self.upload_mb_var.get())
            if download_mb < 0 or upload_mb < 0:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Download/Upload size must be non-negative numbers (MB).")
            return

        try:
            timeout_ms = int(self.timeout_var.get())
        except ValueError:
            timeout_ms = 15000
        # speed tests need much more time than a bare handshake/ping
        timeout_ms = max(timeout_ms, 8000)

        try:
            xray_path, _ = ensure_xray_binary()
        except Exception as e:
            messagebox.showerror("Xray setup failed", str(e))
            return
        vless_link = self.vless_link_text.get("1.0", "end").strip()
        if not vless_link:
            messagebox.showerror("Error", "Paste your VLESS or Trojan REALITY config link for "
                                           "the speed test.")
            return
        vless_params = parse_reality_link(vless_link)
        if vless_params.get("error"):
            messagebox.showerror("Invalid config link", vless_params["error"])
            return
        if not self.override_ip_var.get().strip():
            proceed = messagebox.askyesno(
                "No server override set",
                "\u201cTest against your own server\u201d is empty, so the speed test will try a "
                "real REALITY handshake against the target's OWN IP using your pasted key. "
                "That only works if the target IS your own REALITY server \u2014 otherwise the "
                "row will fail and DL/UL will stay \u201c-\u201d.\n\n"
                "Fill in your server's IP under \u201cTest against your own server\u201d and "
                "re-run the scan first if you haven't. Continue anyway?"
            )
            if not proceed:
                return
        self._launch_speed_test(combos, download_mb, upload_mb, timeout_ms,
                                 xray_path=xray_path, vless_params=vless_params)

    def _reset_speedtest_state(self, total_jobs):
        """Like _reset_run_state, but keeps the existing results/table
        intact (a speed test augments rows already on screen with DL/UL
        numbers instead of replacing them)."""
        self.scan_running = True
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.next_phase_btn.config(state="disabled")
        self.high_acc_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        self.config_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.mode_ip_btn.config(state="disabled")
        self.mode_sni_btn.config(state="disabled")
        self.progress.config(value=0, maximum=max(1, total_jobs))
        self._set_status_pill("SPEED TESTING", "#0c0d13", ACCENT)
        self._show_page("results")

    def _launch_speed_test(self, combos, download_mb, upload_mb, timeout_ms, xray_path, vless_params):
        self._reset_speedtest_state(len(combos))
        self.status_var.set(f"High Accuracy speed test: testing {len(combos)} target/SNI combo(s) "
                             f"({download_mb} MB down / {upload_mb} MB up each) ...")
        t = threading.Thread(
            target=self._speed_test_worker,
            args=(combos, download_mb, upload_mb, timeout_ms, xray_path, vless_params),
            daemon=True
        )
        t.start()

    def _speed_test_worker(self, combos, download_mb, upload_mb, timeout_ms, xray_path, vless_params):
        try:
            results = []
            self.msg_queue.put(("progress_max", len(combos)))
            self.msg_queue.put(("progress", 0))
            # Deliberately SERIAL (one combo at a time): speed tests contend for the
            # same local bandwidth, and each combo needs its own xray process.
            errors_seen = []
            for done, combo in enumerate(combos, start=1):
                if self.stop_event.is_set():
                    break
                self.msg_queue.put(("status",
                                     f"[{done}/{len(combos)}] testing {combo['target']} / "
                                     f"{combo['domain']} ..."))
                res = high_accuracy_speed_test(
                    xray_path, vless_params, combo["connect_host"], combo["port"],
                    combo["domain"], download_mb, upload_mb, timeout_ms)
                res["target"] = combo["target"]
                res["ip"] = combo["domain"]
                results.append(res)
                if res.get("error"):
                    errors_seen.append(res["error"])
                self.msg_queue.put(("progress", done))
                self.msg_queue.put(("speed_result", res))
            self.msg_queue.put(("speed_done", (results, errors_seen)))
        except Exception as e:
            self.msg_queue.put(("error", str(e)))

    def _reset_run_state(self, total_jobs):
        self.scan_running = True
        self.stop_event.clear()
        self.start_btn.config(state="disabled")
        self.next_phase_btn.config(state="disabled")
        self.high_acc_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        self.config_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.mode_ip_btn.config(state="disabled")
        self.mode_sni_btn.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self._live_count = 0
        self._live_online = 0
        self._update_summary([])
        self.progress.config(value=0, maximum=max(1, total_jobs))
        self._set_status_pill("SCANNING", "#0c0d13", ACCENT)
        self._show_page("results")

    def _launch_phase_ip(self, ip_list, port, count, timeout_ms, threads, method, sni,
                          do_port_filter, filter_timeout_ms):
        self._reset_run_state(len(ip_list))
        self.status_var.set(f"Phase {self.phase}: scanning {len(ip_list)} IP(s) ...")
        t = threading.Thread(
            target=self._scan_worker_ip,
            args=(ip_list, port, count, timeout_ms, threads, method, sni,
                  do_port_filter, filter_timeout_ms),
            daemon=True
        )
        t.start()

    def _launch_phase_sni_setup(self, targets, domain_list, count, timeout_ms, threads,
                                 override_host, override_port, reality_setup):
        self._reset_run_state(len(targets) * len(domain_list))
        label = "real REALITY handshake(s)" if reality_setup else "SNI(s)"
        self.status_var.set(f"Phase {self.phase}: preparing to test {len(domain_list)} {label} "
                             f"against {len(targets)} target(s) ...")
        t = threading.Thread(
            target=self._scan_worker_sni_setup,
            args=(targets, domain_list, count, timeout_ms, threads, override_host, override_port,
                  reality_setup),
            daemon=True
        )
        t.start()

    def _launch_phase_sni_combos(self, combos, count, timeout_ms, threads, reality_setup=None):
        self._reset_run_state(len(combos))
        label = "real REALITY combo(s)" if reality_setup else "target/SNI combo(s)"
        self.status_var.set(f"Phase {self.phase}: re-testing {len(combos)} {label} ...")
        t = threading.Thread(
            target=self._scan_worker_sni_combos,
            args=(combos, count, timeout_ms, threads, reality_setup),
            daemon=True
        )
        t.start()

    def stop_scan(self):
        self.stop_event.set()
        self._set_status_pill("STOPPING", "#0c0d13", WARN)
        self.status_var.set("Stopping ...")

    def _scan_worker_ip(self, ip_list, port, count, timeout_ms, threads, method, sni,
                         do_port_filter, filter_timeout_ms):
        try:
            if do_port_filter:
                self.msg_queue.put(("status", f"Pre-filtering port {port} on {len(ip_list)} IP(s) "
                                               f"(timeout {filter_timeout_ms}ms) ..."))
                filtered = []
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = {executor.submit(check_port, ip, port, filter_timeout_ms / 1000): ip
                               for ip in ip_list}
                    done = 0
                    total = len(futures)
                    self.msg_queue.put(("progress_max", total))
                    for future in as_completed(futures):
                        if self.stop_event.is_set():
                            break
                        done += 1
                        self.msg_queue.put(("progress", done))
                        if future.result():
                            filtered.append(futures[future])
                ip_list = filtered
                self.msg_queue.put(("status", f"{len(ip_list)} IP(s) with the port open. Starting ping test ..."))
                if not ip_list:
                    self.msg_queue.put(("done", []))
                    return

            if method == "tls":
                test_func = tls_handshake_ping
                args = (port, sni, count, timeout_ms)
            elif method == "browser":
                test_func = browser_tls_ping
                args = (port, sni, count, timeout_ms, self.fingerprint_var.get())
            else:
                test_func = tcp_handshake_ping
                args = (port, count, timeout_ms)

            results = []
            self.msg_queue.put(("progress_max", len(ip_list)))
            self.msg_queue.put(("progress", 0))
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(test_func, ip, *args): ip for ip in ip_list}
                done = 0
                for future in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    done += 1
                    res = future.result()
                    results.append(res)
                    self.msg_queue.put(("progress", done))
                    self.msg_queue.put(("result", res))

            results.sort(key=lambda x: (x['packet_loss'], x['avg_ping'], x.get('jitter') or 0))
            self.msg_queue.put(("done", results))
        except Exception as e:
            self.msg_queue.put(("error", str(e)))

    def _resolve_targets(self, targets, override_host, override_port):
        """Resolve every (label, host, port) target to a connect IP.
        If override_host is set, every target reuses that same connect
        host/port instead of being resolved individually.
        Returns (resolved, had_error) where resolved is a list of
        dicts {label, connect_host, port} for the targets that resolved OK."""
        resolved = []
        summary_lines = []
        for label, host, port in targets:
            if override_host:
                connect_host, connect_port = override_host, override_port
                summary_lines.append(f"{label} \u2192 {connect_host}:{connect_port} (override)")
            else:
                is_literal_ip = True
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    is_literal_ip = False
                if is_literal_ip:
                    connect_host, connect_port = host, port
                    summary_lines.append(f"{label} \u2192 {connect_host}:{connect_port}")
                else:
                    self.msg_queue.put(("status", f"Resolving {host} ..."))
                    ip, resolve_err = resolve_host(host)
                    if resolve_err or not ip:
                        summary_lines.append(f"{label} \u2192 FAILED ({resolve_err})")
                        continue
                    connect_host, connect_port = ip, port
                    summary_lines.append(f"{label} \u2192 {connect_host}:{connect_port}")
            resolved.append({"label": label, "connect_host": connect_host, "port": connect_port})
        self.msg_queue.put(("resolved_summary", summary_lines))
        return resolved

    def _scan_worker_sni_setup(self, targets, domain_list, count, timeout_ms, threads,
                                override_host, override_port, reality_setup):
        try:
            resolved = self._resolve_targets(targets, override_host, override_port)
            if not resolved:
                self.msg_queue.put(("error", "The target could not be resolved."))
                return

            combos = []
            for t in resolved:
                for domain in domain_list:
                    combos.append({"target": t["label"], "connect_host": t["connect_host"],
                                    "port": t["port"], "domain": domain})

            if reality_setup:
                self.msg_queue.put(("status", f"Running real REALITY handshakes for "
                                               f"{len(domain_list)} SNI candidate(s) against "
                                               f"{len(resolved)} target(s) ({len(combos)} combo(s)) ..."))
                self._run_reality_combos(combos, count, timeout_ms, reality_setup)
            else:
                self.msg_queue.put(("status", f"Testing {len(domain_list)} SNI candidate(s) against "
                                               f"{len(resolved)} target(s) ({len(combos)} combo(s)) ..."))
                self._run_sni_combos(combos, count, timeout_ms, threads)
        except Exception as e:
            self.msg_queue.put(("error", str(e)))

    def _scan_worker_sni_combos(self, combos, count, timeout_ms, threads, reality_setup=None):
        try:
            if reality_setup:
                self._run_reality_combos(combos, count, timeout_ms, reality_setup)
            else:
                self._run_sni_combos(combos, count, timeout_ms, threads)
        except Exception as e:
            self.msg_queue.put(("error", str(e)))

    def _run_sni_combos(self, combos, count, timeout_ms, threads):
        results = []
        self.msg_queue.put(("progress_max", len(combos)))
        self.msg_queue.put(("progress", 0))
        impersonate = self.fingerprint_var.get()
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for combo in combos:
                fut = executor.submit(sni_target_test, combo["connect_host"], combo["port"],
                                       combo["domain"], count, timeout_ms, impersonate)
                futures[fut] = combo
            done = 0
            for future in as_completed(futures):
                if self.stop_event.is_set():
                    break
                done += 1
                combo = futures[future]
                res = future.result()
                res["ip"] = combo["domain"]
                res["target"] = combo["target"]
                res["connect_host"] = combo["connect_host"]
                res["port"] = combo["port"]
                results.append(res)
                self.msg_queue.put(("progress", done))
                self.msg_queue.put(("result", res))
        results.sort(key=lambda x: (x['packet_loss'], x['avg_ping'], x.get('jitter') or 0))
        self.msg_queue.put(("done", results))

    def _run_reality_combos(self, combos, attempts, tcp_timeout_ms, reality_setup):
        """Same shape as _run_sni_combos, but drives real REALITY
        handshakes via reality_sni_test() with a small, dedicated worker
        pool (each worker spawns its own xray-core process per attempt -
        see reality_workers), and ranks VALID/FLAKY ahead of everything
        else regardless of raw latency."""
        xray_path, vless_params, reality_workers = reality_setup
        results = []
        self.msg_queue.put(("progress_max", len(combos)))
        self.msg_queue.put(("progress", 0))
        with ThreadPoolExecutor(max_workers=max(1, min(reality_workers, len(combos) or 1))) as executor:
            futures = {}
            for combo in combos:
                fut = executor.submit(reality_sni_test, xray_path, vless_params,
                                       combo["connect_host"], combo["port"], combo["domain"],
                                       attempts, tcp_timeout_ms)
                futures[fut] = combo
            done = 0
            for future in as_completed(futures):
                if self.stop_event.is_set():
                    break
                done += 1
                combo = futures[future]
                raw_res = future.result()
                res = reality_result_to_row(raw_res)
                res["target"] = combo["target"]
                results.append(res)
                self.msg_queue.put(("progress", done))
                self.msg_queue.put(("result", res))
        results.sort(key=reality_sort_key)
        self.msg_queue.put(("done", results))

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "status":
                    self.status_var.set(payload)
                elif kind == "resolved_summary":
                    text = "\n".join(payload)
                    if len(text) > 400:
                        text = text[:400] + " ..."
                    self.resolved_summary_var.set(text)
                elif kind == "discovered":
                    bases, domains, lookup_errs, empty_bases = payload
                    self._discovering = False
                    self.discover_btn.configure(state="normal", text="\U0001F50D  Find SNIs for target")
                    if lookup_errs and not domains:
                        err_text = "; ".join(f"{b}: {e}" for b, e in lookup_errs)
                        self.discover_hint_var.set("")
                        messagebox.showerror(
                            "Discovery failed",
                            "Couldn't look up subdomains for the target - the lookup failed:\n\n"
                            + err_text
                        )
                    elif not domains:
                        note = f" (lookup issues: {'; '.join(f'{b}: {e}' for b, e in lookup_errs)})" if lookup_errs else ""
                        self.discover_hint_var.set(f"No subdomains found for: {', '.join(bases)}.{note}")
                    else:
                        self.sni_text.delete("1.0", "end")
                        self.sni_text.insert("1.0", "\n".join(domains) + "\n")
                        details = []
                        if empty_bases:
                            details.append(f"no certs logged for: {', '.join(empty_bases)}")
                        if lookup_errs:
                            details.append("lookup failed for: " + ", ".join(
                                f"{b} ({e})" for b, e in lookup_errs))
                        err_note = f" ({'; '.join(details)})" if details else ""
                        self.discover_hint_var.set(
                            f"Found {len(domains)} candidate SNI(s) for {', '.join(bases)} from "
                            f"certificate transparency logs{err_note} \u2014 these are just hostnames "
                            f"seen in CT logs, not confirmed-good REALITY SNIs \u2014 review the list, "
                            f"then Start Scan to validate them")
                elif kind == "progress_max":
                    self.progress.config(maximum=max(1, payload), value=0)
                elif kind == "progress":
                    self.progress.config(value=payload)
                elif kind == "result":
                    self._live_count += 1
                    res = payload
                    if res["status"] == "Online":
                        self._live_online += 1
                    ping_display = f"{res['avg_ping']:.1f}" if res['avg_ping'] != float('inf') else "-"
                    pings_display = f"{res.get('success', 0)}/{res.get('count', 0)}"
                    jitter_display = f"{res['jitter']:.1f}" if res.get('jitter') is not None else "-"
                    tcp_display = res.get("tcp_status", "-")
                    alpn_display = res.get("alpn", "-")
                    verdict_display = res.get("verdict", "-")
                    parity = "even" if self._live_count % 2 else "odd"
                    tag = f"online_{parity}" if res["status"] == "Online" else f"offline_{parity}"
                    iid = f"live_{self._live_count}"
                    self.tree.insert("", "end", iid=iid,
                                      values=(self._live_count, res.get("target", "-"), res["ip"],
                                              tcp_display, res["status"], pings_display, res["packet_loss"],
                                              ping_display, jitter_display, alpn_display, verdict_display,
                                              "-", "-"),
                                      tags=(tag,))
                    self.tree.see(iid)
                    self.stat_tested_var.set(str(self._live_count))
                    self.stat_online_var.set(str(self._live_online))
                elif kind == "speed_result":
                    res = payload
                    dl_display = f"{res['download_mbps']:.2f}" if res.get("download_ok") else "-"
                    ul_display = f"{res['upload_mbps']:.2f}" if res.get("upload_ok") else "-"
                    for idx, r in enumerate(self.results, start=1):
                        if r.get("target") == res.get("target") and r.get("ip") == res.get("ip"):
                            iid = str(idx)
                            if self.tree.exists(iid):
                                self.tree.set(iid, "dl", dl_display)
                                self.tree.set(iid, "ul", ul_display)
                            r["download_mbps"] = res.get("download_mbps", 0.0)
                            r["upload_mbps"] = res.get("upload_mbps", 0.0)
                            r["download_ok"] = res.get("download_ok", False)
                            r["upload_ok"] = res.get("upload_ok", False)
                            break
                    if res.get("error"):
                        self.status_var.set(f"{res.get('target','-')} / {res.get('ip','-')}: "
                                             f"{res['error']}")
                elif kind == "speed_done":
                    results_list, errors_seen = payload
                    tested = len(results_list)
                    ok_count = sum(1 for r in results_list if r.get("download_ok") or r.get("upload_ok"))
                    self.status_var.set(f"Speed test complete: {tested} combo(s) tested, "
                                         f"{ok_count} produced a result.")
                    if self.stop_event.is_set():
                        self._set_status_pill("STOPPED", "#0c0d13", ERROR)
                    elif ok_count == 0 and errors_seen:
                        self._set_status_pill("DONE (0 OK)", "#0c0d13", WARN)
                        messagebox.showwarning(
                            "No throughput measured",
                            "None of the tested rows produced a download/upload number. The most "
                            "common cause is that the target IP isn't actually your own REALITY "
                            "server, so the REALITY handshake fails before any data moves.\n\n"
                            "First error seen:\n" + errors_seen[0]
                        )
                    else:
                        self._set_status_pill("DONE", "#0c0d13", SUCCESS)
                    self._on_scan_finished(is_speed_test=True)
                elif kind == "done":
                    self.results = payload
                    self._populate_tree(self.results)
                    online = sum(1 for r in self.results if r["status"] == "Online")
                    self.status_var.set(
                        f"Phase {self.phase} complete: {len(self.results)} tested, {online} online."
                    )
                    if self.stop_event.is_set():
                        self._set_status_pill("STOPPED", "#0c0d13", ERROR)
                    else:
                        self._set_status_pill("DONE", "#0c0d13", SUCCESS)
                    self._on_scan_finished()
                elif kind == "error":
                    messagebox.showerror("Error", payload)
                    self._set_status_pill("ERROR", "#0c0d13", ERROR)
                    self._on_scan_finished()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _on_scan_finished(self, is_speed_test=False):
        self.scan_running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.mode_ip_btn.config(state="normal")
        self.mode_sni_btn.config(state="normal")
        has_results = len(self.results) > 0
        self.next_phase_btn.config(state="normal" if has_results else "disabled")
        self.export_btn.config(state="normal" if has_results else "disabled")

        if has_results and self.mode_var.get() == "ip":
            self.config_btn.config(state="normal")
        else:
            self.config_btn.config(state="disabled")

        has_sni_results = has_results and self.mode_var.get() == "sni"
        self.high_acc_btn.config(state="normal" if has_sni_results else "disabled")

        if has_results and not is_speed_test:
            self.count_var.set(NEXT_PHASE_DEFAULT_COUNT)
            self.timeout_var.set(NEXT_PHASE_DEFAULT_TIMEOUT)

    def _show_result_details(self, event=None):
        iid=self.tree.focus()
        if not iid: return
        res=self._tree_result_map.get(iid)
        if not res:
            try:
                idx=int(iid)-1
                if 0<=idx<len(self.results): res=self.results[idx]
            except Exception: pass
        if not res: return
        lines=[
            f"SNI: {res.get('ip','-')}",
            f"Target: {res.get('target','-')}",
            f"Connect: {res.get('connect_host','-')}:{res.get('port','-')}",
            f"Verdict: {res.get('verdict','-')}",
            f"Failure reason: {res.get('failure_reason','-')}",
            "",
            f"TCP: {res.get('tcp_status','-')}",
            f"Last error: {res.get('reality_last_error') or '-'}",
            "",
            "Attempt diagnostics:"
        ]
        ds=res.get("attempt_diagnostics",[])
        if not ds: lines.append("  No attempt diagnostics recorded.")
        for d in ds:
            lat=f" | {d['latency_ms']} ms" if d.get("latency_ms") is not None else ""
            lines.append(f"  Attempt {d.get('attempt','?')}: {d.get('phase','?')} -> {d.get('category','?')}{lat}")
            lines.append(f"    {d.get('error') or 'OK'}")
        messagebox.showinfo("REALITY diagnostic details","\n".join(lines),parent=self.root)

    def _populate_tree(self, results):
        self.tree.delete(*self.tree.get_children())
        self._tree_result_map = {}
        for idx, res in enumerate(results, start=1):
            ping_display = f"{res['avg_ping']:.1f}" if res['avg_ping'] != float('inf') else "-"
            pings_display = f"{res.get('success', 0)}/{res.get('count', 0)}"
            jitter_display = f"{res['jitter']:.1f}" if res.get('jitter') is not None else "-"
            tcp_display = res.get("tcp_status", "-")
            alpn_display = res.get("alpn", "-")
            verdict_display = res.get("verdict", "-")
            parity = "even" if idx % 2 else "odd"
            tag = f"online_{parity}" if res["status"] == "Online" else f"offline_{parity}"
            dl_display = f"{res['download_mbps']:.2f}" if res.get("download_ok") else "-"
            ul_display = f"{res['upload_mbps']:.2f}" if res.get("upload_ok") else "-"
            self.tree.insert("", "end", iid=str(idx),
                              values=(idx, res.get("target", "-"), res["ip"], tcp_display, res["status"],
                                      pings_display, res["packet_loss"], ping_display, jitter_display,
                                      alpn_display, verdict_display, dl_display, ul_display),
                              tags=(tag,))
        self._update_summary(results)

    def _update_summary(self, results):
        tested = len(results)
        online_rows = [r for r in results if r["status"] == "Online"]
        online = len(online_rows)
        self.stat_tested_var.set(str(tested))
        self.stat_online_var.set(str(online))
        if online_rows:
            avg = sum(r["avg_ping"] for r in online_rows if r["avg_ping"] != float('inf')) / online
            self.stat_avg_var.set(f"{avg:.1f} ms")
            best = min(online_rows, key=lambda r: (r["packet_loss"], r["avg_ping"], r.get("jitter") or 0))
            if "target" in best and best["target"] not in (None, "-"):
                self.stat_best_var.set(f"{best['target']} / {best['ip']}  ({best['avg_ping']:.1f} ms)")
            else:
                self.stat_best_var.set(f"{best['ip']}  ({best['avg_ping']:.1f} ms)")
        else:
            self.stat_avg_var.set("-")
            self.stat_best_var.set("-")


    def _sort_by(self, col):
        key_map = {
            "rank": lambda r: r[0],
            "target": lambda r: r[1],
            "ip": lambda r: tuple(int(p) for p in r[2].split('.')) if re.match(r'^\d+\.\d+\.\d+\.\d+$', r[2]) else r[2],
            "tcp": lambda r: r[3],
            "status": lambda r: r[4],
            "pings": lambda r: int(r[5].split('/')[0]) if '/' in r[5] else 0,
            "loss": lambda r: float(r[6]),
            "ping": lambda r: float('inf') if r[7] == "-" else float(r[7]),
            "jitter": lambda r: float('inf') if r[8] == "-" else float(r[8]),
            "alpn": lambda r: r[9],
            "verdict": lambda r: r[10],
        }
        if col not in key_map:
            return
        items = [(self.tree.set(k, "rank"), self.tree.set(k, "target"), self.tree.set(k, "ip"),
                  self.tree.set(k, "tcp"), self.tree.set(k, "status"), self.tree.set(k, "pings"),
                  self.tree.set(k, "loss"), self.tree.set(k, "ping"), self.tree.set(k, "jitter"),
                  self.tree.set(k, "alpn"), self.tree.set(k, "verdict"), k)
                 for k in self.tree.get_children("")]
        reverse = getattr(self, f"_sort_rev_{col}", False)
        items.sort(key=lambda r: key_map[col](r), reverse=reverse)
        setattr(self, f"_sort_rev_{col}", not reverse)
        for pos, item in enumerate(items):
            self.tree.move(item[11], "", pos)


    def export_results(self):
        if not self.results:
            return
        sni_mode = self.mode_var.get() == "sni"
        label_header = "SNI / Domain" if sni_mode else "IP Address"
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"Phase_{self.phase}_Results.txt",
            filetypes=[("Text file", "*.txt")]
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write("=" * 160 + "\n")
            f.write(f"PHASE {self.phase} RANKINGS\n")
            f.write("=" * 160 + "\n")
            if sni_mode:
                f.write(f"{'Rank':<6} | {'Target':<20} | {label_header:<24} | {'TCP':<8} | "
                        f"{'TLS+SNI':<8} | {'Pings (ok/total)':<17} | {'Packet Loss (%)':<15} | "
                        f"{'Avg Ping (ms)':<15} | {'Jitter (ms)':<12} | {'ALPN':<8} | {'Verdict':<20} | {'Reason':<28}\n")
                f.write("=" * 160 + "\n")
                for idx, res in enumerate(self.results, start=1):
                    ping_display = f"{res['avg_ping']:.1f}" if res['avg_ping'] != float('inf') else "-"
                    pings_display = f"{res.get('success', 0)}/{res.get('count', 0)}"
                    jitter_display = f"{res['jitter']:.1f}" if res.get('jitter') is not None else "-"
                    tcp_display = res.get("tcp_status", "-")
                    alpn_display = res.get("alpn", "-")
                    verdict_display = res.get("verdict", "-")
                    reason_display = res.get("failure_reason") or "-"
                    target_display = res.get("target") or "-"
                    f.write(f"#{idx:<5} | {target_display:<20} | {res['ip']:<24} | "
                            f"{tcp_display:<8} | {res['status']:<8} | {pings_display:<17} | "
                            f"{res['packet_loss']:<15}% | {ping_display:<15} | {jitter_display:<12} | "
                            f"{alpn_display:<8} | {verdict_display:<20} | {reason_display:<28}\n")
                    if res.get("reality_last_error"):
                        f.write(f"    ERROR: {res['reality_last_error']}\n")
            else:
                f.write(f"{'Rank':<6} | {label_header:<24} | {'Status':<8} | {'Pings (ok/total)':<17} | "
                        f"{'Packet Loss (%)':<15} | {'Avg Ping (ms)':<15} | {'Jitter (ms)':<12}\n")
                f.write("=" * 160 + "\n")
                for idx, res in enumerate(self.results, start=1):
                    ping_display = f"{res['avg_ping']:.1f}" if res['avg_ping'] != float('inf') else "-"
                    pings_display = f"{res.get('success', 0)}/{res.get('count', 0)}"
                    jitter_display = f"{res['jitter']:.1f}" if res.get('jitter') is not None else "-"
                    f.write(f"#{idx:<5} | {res['ip']:<24} | {res['status']:<8} | {pings_display:<17} | "
                            f"{res['packet_loss']:<15}% | {ping_display:<15} | {jitter_display:<12}\n")
        messagebox.showinfo("Saved", f"Results saved to:\n{path}")


    def open_config_dialog(self):
        if self.mode_var.get() == "sni":
            messagebox.showinfo("Not applicable",
                                 "Config generation applies to IP-scan results. "
                                 "Use your best target/SNI result in your REALITY server config instead.")
            return

        active_ips = [r["ip"] for r in self.results if r["status"] == "Online"]
        if not active_ips:
            messagebox.showerror("Error", "No online IPs available to build configs.")
            return

        config_link = simpledialog.askstring(
            "Config link", "Paste your VLESS/VMess/Trojan/SS config link:", parent=self.root
        )
        if not config_link:
            return
        config_link = config_link.strip()
        if not config_link.startswith(("vless://", "vmess://", "trojan://", "ss://")):
            messagebox.showerror("Error", "Invalid config format.")
            return

        generated = {}
        for ip in active_ips:
            modified = modify_config_link(config_link, ip)
            if modified:
                generated[ip] = modified

        if not generated:
            messagebox.showerror("Error", "Failed to build any configs (unsupported protocol).")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"clean_configs_phase_{self.phase}.txt",
            filetypes=[("Text file", "*.txt")]
        )
        if not save_path:
            return
        with open(save_path, "w", encoding="utf-8") as f:
            f.write("\n".join(generated.values()))
        messagebox.showinfo("Saved", f"{len(generated)} clean configs saved to:\n{save_path}")



def run():
    """Open the Tkinter application window."""
    root = tk.Tk()
    ScannerApp(root)
    root.mainloop()
