"""Writes src/styles/dark.css: the "night sea" version of every colour in the app's stylesheets.

Run from the frontend folder after changing colours:  python scripts/make_dark_theme.py

Each colour declaration is repeated under :root[data-theme="dark"], so the light theme is
untouched and rules keep the same order of precedence. Colours are converted in OKLCH
(even steps of perceived lightness): pale surfaces become deep navy, dark text becomes
pale, tints keep their hue so red, amber and green still mean the same thing.
Hand-tuned parts (tokens, page gradient, welcome scene) live in src/styles/night.css.
"""
import math
import re
from pathlib import Path

STYLES = Path(__file__).resolve().parent.parent / "src" / "styles"
# Same order as the imports in main.jsx. night.css then refines the welcome scene.
SOURCES = ["index.css", "upload.css", "dashboard.css", "report.css", "workspace.css", "v2.css", "welcome.css", "sea.css"]
PREFIX = ':root[data-theme="dark"]'
SEA_HUE = 245.0  # the blue of the dark surfaces
ACCENT = "#2a6f97"  # replaces navy fills (selected tabs, avatars) that carry white text

COLOUR_PROPERTY = re.compile(
    r"^(color|background|background-color|background-image|border(-(top|right|bottom|left))?(-color)?|"
    r"outline(-color)?|box-shadow|fill|stroke|caret-color)$"
)
LITERAL = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\([^()]*\)|(?<![-\w])(?:white|black)(?![-\w])")
DARK_TOKEN = re.compile(r"var\(--(?:ink|text-primary)\)")


def to_oklch(r, g, b):
    def linear(c):
        c /= 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = linear(r), linear(g), linear(b)
    l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    L = 0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s
    a = 1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s
    bb = 0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s
    return L, math.hypot(a, bb), math.degrees(math.atan2(bb, a)) % 360


def from_oklch(L, C, h):
    a, bb = C * math.cos(math.radians(h)), C * math.sin(math.radians(h))
    l = (L + 0.3963377774 * a + 0.2158037573 * bb) ** 3
    m = (L - 0.1055613458 * a - 0.0638541728 * bb) ** 3
    s = (L - 0.0894841775 * a - 1.2914855480 * bb) ** 3
    channels = (
        4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
        -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
        -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s,
    )

    def encode(c):
        c = min(1, max(0, c))
        return round(255 * (12.92 * c if c <= 0.0031308 else 1.055 * c ** (1 / 2.4) - 0.055))

    return tuple(encode(c) for c in channels)


def parse(text):
    """(r, g, b, alpha) for a literal colour, or None."""
    t = text.lower()
    if t in ("white", "black"):
        v = 255 if t == "white" else 0
        return v, v, v, 1.0
    if t.startswith("#"):
        h = t[1:]
        if len(h) in (3, 4):
            h = "".join(ch * 2 for ch in h)
        if len(h) not in (6, 8):
            return None
        alpha = int(h[6:], 16) / 255 if len(h) == 8 else 1.0
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), alpha
    parts = [p for p in re.split(r"[\s,/]+", t[t.index("(") + 1:-1]) if p]
    if len(parts) < 3:
        return None
    try:
        r, g, b = (float(p) for p in parts[:3])
        alpha = 1.0
        if len(parts) > 3:
            alpha = float(parts[3][:-1]) / 100 if parts[3].endswith("%") else float(parts[3])
    except ValueError:
        return None
    return r, g, b, alpha


def write(rgb, alpha):
    code = "#%02x%02x%02x" % rgb
    return code if alpha >= 0.999 else code + "%02x" % round(alpha * 255)


def night(text, role):
    parsed = parse(text)
    if not parsed:
        return text
    r, g, b, alpha = parsed
    L, C, h = to_oklch(r, g, b)
    bluish_or_grey = C < 0.012 or 190 <= h <= 290 or (C < 0.03 and 70 <= h <= 130)  # includes old cream
    if role == "shadow":
        return write((2, 8, 16), min(0.6, alpha * 1.8)) if alpha < 0.999 or L < 0.6 else write((2, 8, 16), 0.35)
    if role == "background":
        if L >= 0.80 and (bluish_or_grey and C < 0.06):
            # white cards sit highest; slightly greyer surfaces step up from them
            step = min(1.0, max(0.0, (1.0 - L) / 0.16))
            return write(from_oklch(0.255 + 0.09 * step, 0.040, SEA_HUE), alpha)
        if L >= 0.80:  # pale red, amber, green: a deep tint of the same hue
            return write(from_oklch(0.30, min(0.065, max(0.040, C * 1.6)), h), alpha)
        if L < 0.42 and C < 0.09 and alpha > 0.5:  # navy fills that carry white text
            return write(parse(ACCENT)[:3], alpha)
        return text
    if role == "border":
        if L >= 0.72:
            if bluish_or_grey:
                return write(from_oklch(0.39, 0.045, SEA_HUE), alpha)
            return write(from_oklch(0.46, min(0.10, C * 1.4), h), alpha)
        if L < 0.42:
            return write(from_oklch(0.62, 0.05, SEA_HUE), alpha)
        return text
    # text, icons and chart lines
    if L >= 0.78:
        return text
    if C < 0.06:  # navy and grey wording
        return write(from_oklch(min(0.94, max(0.74, 1.12 - L * 0.9)), 0.022, SEA_HUE - 10), alpha)
    return write(from_oklch(max(0.78, L), min(C, 0.14), h), alpha)


def role_of(prop):
    if prop.startswith("background"):
        return "background"
    if prop.startswith(("border", "outline")):
        return "border"
    if prop == "box-shadow":
        return "shadow"
    return "text"


def convert(prop, value):
    role = role_of(prop)
    if role == "background":
        value = DARK_TOKEN.sub(ACCENT, value)
    return LITERAL.sub(lambda m: night(m.group(0), role), value)


def split_top(text, separator):
    parts, depth, quote, current = [], 0, "", ""
    for ch in text:
        if quote:
            quote = "" if ch == quote else quote
        elif ch in "\"'":
            quote = ch
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == separator and depth == 0:
            parts.append(current)
            current = ""
            continue
        current += ch
    parts.append(current)
    return parts


def blocks(css):
    """Top-level (prelude, body) pairs."""
    i = 0
    while True:
        open_at = css.find("{", i)
        if open_at < 0:
            return
        prelude = css[i:open_at].split(";")[-1].strip()  # drops @import lines
        depth, j = 1, open_at + 1
        while depth:
            depth += {"{": 1, "}": -1}.get(css[j], 0)
            j += 1
        yield prelude, css[open_at + 1:j - 1]
        i = j


def prefixed(selector):
    selector = selector.strip()
    for root in (":root", "html"):
        if selector == root or re.match(re.escape(root) + r"(?![-\w])", selector):
            return PREFIX + selector[len(root):]
    return f"{PREFIX} {selector}"


def transform(css):
    out = []
    for prelude, body in blocks(css):
        if prelude.startswith("@"):
            if prelude.startswith(("@media", "@supports")):
                inner = transform(body)
                if inner:
                    out.append(f"{prelude} {{\n{inner}\n}}")
            continue
        kept = []
        for declaration in split_top(body, ";"):
            prop, colon, value = declaration.partition(":")
            prop, value = prop.strip().lower(), value.strip()
            if colon and COLOUR_PROPERTY.match(prop) and "url(" not in value:
                kept.append(f"{prop}: {convert(prop, value)}")
        if kept:
            selectors = ", ".join(prefixed(s) for s in split_top(prelude, ",") if s.strip())
            out.append(f"{selectors} {{ {'; '.join(kept)}; }}")
    return "\n".join(out)


def build():
    parts = ["/* Generated by scripts/make_dark_theme.py. Do not edit: change the script or night.css. */"]
    for name in SOURCES:
        css = re.sub(r"/\*.*?\*/", "", (STYLES / name).read_text(encoding="utf-8"), flags=re.S)
        parts.append(f"/* from {name} */\n{transform(css)}")
    return "\n".join(parts) + "\n"


if __name__ == "__main__":
    (STYLES / "dark.css").write_text(build(), encoding="utf-8", newline="\n")
    print("wrote", STYLES / "dark.css")
