from threading import Lock, Event
from dotenv import load_dotenv
import os

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
NVD_API_URL = os.getenv("NVD_API_URL")

vt_cache = {}
nvd_cache = {}
cache_lock = Lock()

DARK_BG = "#23272e"
DARK_FG = "#e0e0e0"
ACCENT_GREEN = "#00b894"
ACCENT_ORANGE = "#fdcb6e"
ACCENT_RED = "#d63031"
ACCENT_PURPLE = "#6c5ce7"
ACCENT_BLUE = "#0984e3"
ROW_COLORS = {
    "Safe": "#2ecc71",
    "Suspicious": "#fdcb6e",
    "Unsafe": "#e17055",
    "Very Unsafe": "#d63031",
}