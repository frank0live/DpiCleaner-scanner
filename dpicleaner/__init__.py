"""DPI Cleaner Scanner — clean-IP finder + REALITY/SNI validator.

A desktop app (Tkinter) and a headless CLI on top of the same engine:

    python -m dpicleaner              # open the GUI
    python -m dpicleaner ip 1.1.1.1   # headless TCP probe
    python -m dpicleaner sni  host --names a.com,b.com
    python -m dpicleaner reality --link 'vless://...' --names a.com,b.com
"""

__version__ = "2.0.0"
__all__ = ["__version__"]
