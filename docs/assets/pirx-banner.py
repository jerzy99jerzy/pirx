#!/usr/bin/env python3
"""Pirx animated banner -> GIF. Matches cve-digest / RAPPAPORT terminal aesthetic."""
import math
import pyfiglet
from PIL import Image, ImageDraw, ImageFont

# ---- palette (pulled from the reference banner) ----
BG_PAGE   = (13, 17, 23)     # outer page (github dark)
BG_PANEL  = (16, 22, 31)     # inner panel
BORDER    = (35, 44, 56)
TEXT      = (205, 217, 229)  # blue-white block letters
TEXT_DIM  = (120, 140, 165)  # subtitle
SHELL     = (198, 212, 227)
SHELL_HI  = (236, 243, 250)
SHELL_SH  = (120, 140, 166)
VISOR     = (10, 15, 22)
HUD       = (96, 214, 232)   # cyan HUD accent (animated)
HUD_DIM   = (40, 96, 110)
LED       = (255, 176, 72)   # amber status LED (blink)
SUIT      = (70, 86, 108)
SUIT_SH   = (46, 58, 76)
OUTLINE   = (24, 31, 41)

W, H = 1040, 260
RADIUS = 14
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

# ---------------------------------------------------------------- figlet -> img
def figlet_img(text, font, px, color, leading=0.80):
    art = pyfiglet.figlet_format(text, font=font).rstrip("\n")
    lines = [ln.rstrip() for ln in art.split("\n")]
    lines = [ln for ln in lines if ln.strip() != ""]
    f = ImageFont.truetype(MONO, px)
    # cell metrics from a full block glyph
    bb = f.getbbox("█")
    cw = f.getlength("█")
    line_h = int(px * leading)
    max_cols = max(len(ln) for ln in lines)
    img_w = int(cw * max_cols) + 4
    img_h = line_h * len(lines) + int(px * 0.4)
    img = Image.new("RGBA", (img_w, img_h), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    for i, ln in enumerate(lines):
        d.text((2, i * line_h - bb[1]), ln, font=f, fill=color)
    return img.crop(img.getbbox())

# ---------------------------------------------------------------- pilot sprite
# drawn on a small grid, upscaled NEAREST for crisp pixel edges
GW, GH, SCALE = 66, 72, 3

def draw_pilot(scan_t, reticle_t, led_on, glow):
    """scan_t 0..1 visor sweep, reticle_t 0..1 drift, led_on bool, glow 0..1"""
    g = Image.new("RGBA", (GW, GH), (0, 0, 0, 0))
    d = ImageDraw.Draw(g)
    cx = GW // 2

    # --- suit / shoulders ---
    d.polygon([(10, GH-1), (18, 52), (GW-18, 52), (GW-10, GH-1)], fill=SUIT)
    d.polygon([(10, GH-1), (18, 52), (cx, 56), (cx, GH-1)], fill=SUIT_SH)
    d.rectangle([cx-12, 47, cx+12, 55], fill=SUIT_SH)          # neck ring shade
    d.rectangle([cx-12, 46, cx+12, 51], fill=SHELL_SH)         # neck ring
    # chest status bar
    for i, on in enumerate([led_on, True, glow > 0.5]):
        col = LED if (i == 0 and on) else (HUD if on else HUD_DIM)
        d.rectangle([cx-9+i*7, 60, cx-4+i*7, 63], fill=col)

    # --- helmet shell ---
    hx0, hy0, hx1, hy1 = 8, 4, GW-8, 52
    d.ellipse([hx0, hy0, hx1, hy1], fill=SHELL)
    d.ellipse([hx0, hy0, hx1-14, hy1-16], fill=SHELL_HI)       # top-left highlight
    d.ellipse([hx0+16, hy0+18, hx1, hy1], fill=SHELL_SH, )     # bottom-right shade
    d.ellipse([hx0+3, hy0+3, hx1-3, hy1-3], outline=OUTLINE, width=1)

    # --- visor (dark inset) ---
    vx0, vy0, vx1, vy1 = 15, 15, GW-15, 44
    d.rounded_rectangle([vx0, vy0, vx1, vy1], radius=9, fill=VISOR)
    d.rounded_rectangle([vx0, vy0, vx1, vy1], radius=9, outline=OUTLINE, width=1)

    # static reflection streaks
    d.line([(vx0+6, vy1-4), (vx0+16, vy0+3)], fill=(30, 40, 54), width=1)
    d.line([(vx0+11, vy1-4), (vx0+21, vy0+3)], fill=(26, 35, 48), width=1)

    # --- HUD scanline (animated) inside visor ---
    sy = int(vy0 + 3 + scan_t * (vy1 - vy0 - 6))
    d.line([(vx0+3, sy), (vx1-3, sy)], fill=HUD, width=1)
    if sy-1 > vy0:
        d.line([(vx0+3, sy-1), (vx1-3, sy-1)], fill=HUD_DIM, width=1)

    # --- HUD reticle (drifting) ---
    rx = int(vx0 + 8 + reticle_t * (vx1 - vx0 - 16))
    ry = int((vy0 + vy1) / 2 + math.sin(reticle_t * math.tau) * 4)
    d.line([(rx-4, ry), (rx+4, ry)], fill=HUD, width=1)
    d.line([(rx, ry-4), (rx, ry+4)], fill=HUD, width=1)
    d.point([(rx, ry)], fill=SHELL_HI)

    # --- side comms box ---
    d.rectangle([hx1-9, 24, hx1-4, 34], fill=SUIT_SH)
    d.rectangle([hx1-8, 25, hx1-6, 27], fill=HUD if glow > 0.4 else HUD_DIM)

    # --- antenna + LED ---
    d.line([(cx+8, hy0+2), (cx+14, hy0-6)], fill=SHELL_SH, width=1)
    lx, ly = cx+14, hy0-7
    if led_on:
        d.ellipse([lx-3, ly-3, lx+3, ly+3], fill=(*LED, 90))   # glow
    d.ellipse([lx-1, ly-1, lx+2, ly+2], fill=LED if led_on else (90, 66, 34))

    return g.resize((GW*SCALE, GH*SCALE), Image.NEAREST)

# ---------------------------------------------------------------- panel base
def base_panel():
    img = Image.new("RGB", (W, H), BG_PAGE)
    d = ImageDraw.Draw(img)
    m = 6
    d.rounded_rectangle([m, m, W-m-1, H-m-1], radius=RADIUS, fill=BG_PANEL,
                        outline=BORDER, width=1)
    return img

# ---------------------------------------------------------------- compose text (static)
big = figlet_img("PIRX", "ansi_shadow", 27, TEXT, leading=0.80)
sub = figlet_img("REMEDIATION AGENT", "calvin_s", 17, TEXT_DIM, leading=0.95)
print("big", big.size, "sub", sub.size)

# ---------------------------------------------------------------- frames
N = 24
frames = []
tx = 50
big_y = 42
sub_y = big_y + big.height + 20
sub_x = tx + 2                               # left-align under title

for i in range(N):
    t = i / N
    frame = base_panel()
    frame.paste(big, (tx, big_y), big)
    frame.paste(sub, (sub_x, sub_y), sub)

    d = ImageDraw.Draw(frame)
    # blinking terminal cursor after subtitle
    if (i % 12) < 6:
        cyx = sub_x + sub.width + 8
        d.rectangle([cyx, sub_y + 1, cyx + 9, sub_y + sub.height - 1], fill=HUD)

    # pilot
    scan_t   = (t * 1.5) % 1.0
    ret_t    = t
    led_on   = (i % 12) < 3
    glow     = 0.5 + 0.5 * math.sin(t * math.tau)
    pilot = draw_pilot(scan_t, ret_t, led_on, glow)
    px = W - pilot.width - 70
    py = (H - pilot.height) // 2 + 6
    frame.paste(pilot, (px, py), pilot)

    # faint CRT scan band across whole panel
    band_y = int((t * H) % H)
    ov = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    od = ImageDraw.Draw(ov)
    od.rectangle([8, band_y, W-9, band_y+2], fill=(96, 214, 232, 14))
    frame = Image.alpha_composite(frame.convert("RGBA"), ov).convert("RGB")

    frames.append(frame)

frames[0].save("/home/claude/pirx_preview.png")
frames[0].save(
    "/home/claude/pirx-banner.gif", save_all=True, append_images=frames[1:],
    duration=90, loop=0, optimize=True, disposal=2,
)
import os
print("preview + gif written; gif size:",
      round(os.path.getsize("/home/claude/pirx-banner.gif")/1024, 1), "KB")
