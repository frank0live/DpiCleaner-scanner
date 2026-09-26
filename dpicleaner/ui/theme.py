"""Visual identity: graphite base, emerald accent, font stack."""

import tkinter.font as tkfont

BRAND_MARK = "\u25c8"

# ---- surfaces ----
BG           = "#0b0f14"
PANEL        = "#111820"
PANEL_ALT    = "#161f2b"
PANEL_ALT2   = "#1d2937"

# ---- text ----
TEXT         = "#e7eef6"
TEXT_DIM     = "#8fa1b3"
TEXT_FAINT   = "#5b6b7c"

# ---- lines ----
BORDER       = "#1e2a38"
BORDER_LIGHT = "#2c3d50"

# ---- accents ----
ACCENT        = "#10b981"
ACCENT_HOVER  = "#34d399"
ACCENT_PRESS  = "#0b8f65"
ACCENT_SOFT   = "#0f2a22"

CYAN          = "#38bdf8"
CYAN_HOVER    = "#7dd3fc"

SUCCESS       = "#22c55e"
ERROR         = "#f87171"
ERROR_HOVER   = "#fca5a5"
WARN          = "#fbbf24"

# ---- table rows ----
ROW_EVEN      = "#111820"
ROW_ODD       = "#141d29"


UI_FONT_CANDIDATES = ["Inter", "Ubuntu", "DejaVu Sans", "Segoe UI", "Helvetica Neue", "Helvetica", "Arial"]


MONO_FONT_CANDIDATES = ["JetBrains Mono", "Cascadia Mono", "DejaVu Sans Mono", "Consolas", "Menlo", "Courier New"]


def _pick_font(candidates, size, weight="normal"):
    try:
        available = set(tkfont.families())
    except Exception:
        available = set()
    for name in candidates:
        if name in available:
            return (name, size, weight) if weight != "normal" else (name, size)
    return ("Helvetica", size, weight) if weight != "normal" else ("Helvetica", size)


class Fonts:
    ready = False

    @classmethod
    def init(cls):
        if cls.ready:
            return
        cls.body = _pick_font(UI_FONT_CANDIDATES, 10)
        cls.body_bold = _pick_font(UI_FONT_CANDIDATES, 10, "bold")
        cls.small = _pick_font(UI_FONT_CANDIDATES, 9)
        cls.label = _pick_font(UI_FONT_CANDIDATES, 8, "bold")
        cls.title = _pick_font(UI_FONT_CANDIDATES, 21, "bold")
        cls.subtitle = _pick_font(UI_FONT_CANDIDATES, 10)
        cls.section = _pick_font(UI_FONT_CANDIDATES, 11, "bold")
        cls.mono = _pick_font(MONO_FONT_CANDIDATES, 10)
        cls.button = _pick_font(UI_FONT_CANDIDATES, 10, "bold")
        cls.stat_num = _pick_font(UI_FONT_CANDIDATES, 18, "bold")
        cls.stat_label = _pick_font(UI_FONT_CANDIDATES, 8, "bold")
        cls.ready = True
