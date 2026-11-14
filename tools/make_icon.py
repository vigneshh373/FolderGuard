#!/usr/bin/env python3
"""Generates FolderGuard/Resources/AppIcon.ico and AppLogo.png.

The icon is drawn procedurally (no binary assets in the repository) as an
Windows 11 style app tile with a padlock. The .ico contains 32-bit DIB frames
for 16/32/48 px (best compatibility, including WPF) and a PNG frame for 256 px.
"""
import math
import os
import struct
import zlib

ACCENT_TOP = (0x2B, 0x88, 0xD8)
ACCENT_BOTTOM = (0x0F, 0x6C, 0xBD)
WHITE = (0xFF, 0xFF, 0xFF)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESOURCES = os.path.join(ROOT, "FolderGuard", "Resources")


def rounded_rect_alpha(x, y, x0, y0, x1, y1, radius):
    """Coverage of a rounded rectangle for one sample point."""
    cx = min(max(x, x0 + radius), x1 - radius)
    cy = min(max(y, y0 + radius), y1 - radius)
    dx, dy = x - cx, y - cy
    if dx * dx + dy * dy <= radius * radius:
        return 1.0
    return 0.0


def inside(x, y, x0, y0, x1, y1):
    return x0 <= x <= x1 and y0 <= y <= y1


def render(size):
    """Returns RGBA rows (top to bottom) at the requested pixel size."""
    ss = 4  # supersampling factor
    n = size * ss
    # geometry in 0..1 space
    tile = (0.02, 0.02, 0.98, 0.98)
    tile_r = 0.22
    body = (0.27, 0.44, 0.73, 0.80)      # padlock body
    body_r = 0.075
    ring_cx, ring_cy = 0.5, 0.455
    ring_outer, ring_inner = 0.185, 0.125
    key_cx, key_cy, key_r = 0.5, 0.585, 0.043

    acc = [[[0.0, 0.0, 0.0, 0.0] for _ in range(size)] for _ in range(size)]

    for py in range(n):
        fy = (py + 0.5) / n
        for px in range(n):
            fx = (px + 0.5) / n
            r = g = b = 0.0
            a = 0.0

            # tile with vertical gradient
            if rounded_rect_alpha(fx, fy, *tile, tile_r) > 0:
                t = (fy - tile[1]) / (tile[3] - tile[1])
                t = min(max(t, 0.0), 1.0)
                tr = ACCENT_TOP[0] + (ACCENT_BOTTOM[0] - ACCENT_TOP[0]) * t
                tg = ACCENT_TOP[1] + (ACCENT_BOTTOM[1] - ACCENT_TOP[1]) * t
                tb = ACCENT_TOP[2] + (ACCENT_BOTTOM[2] - ACCENT_TOP[2]) * t
                r, g, b, a = tr, tg, tb, 1.0

            # shackle: upper half annulus
            dx, dy = fx - ring_cx, fy - ring_cy
            dist = math.hypot(dx, dy)
            if fy <= ring_cy + 0.01 and ring_inner <= dist <= ring_outer:
                r, g, b, a = WHITE[0], WHITE[1], WHITE[2], 1.0

            # padlock body
            if rounded_rect_alpha(fx, fy, *body, body_r) > 0:
                r, g, b, a = WHITE[0], WHITE[1], WHITE[2], 1.0

            # keyhole (punched out, accent colour)
            if math.hypot(fx - key_cx, fy - key_cy) <= key_r:
                r, g, b, a = ACCENT_BOTTOM[0], ACCENT_BOTTOM[1], ACCENT_BOTTOM[2], 1.0
            if inside(fx, fy, key_cx - 0.016, key_cy, key_cx + 0.016, 0.655):
                r, g, b, a = ACCENT_BOTTOM[0], ACCENT_BOTTOM[1], ACCENT_BOTTOM[2], 1.0

            ax = px // ss
            ay = py // ss
            cell = acc[ay][ax]
            cell[0] += r
            cell[1] += g
            cell[2] += b
            cell[3] += a

    samples = float(ss * ss)
    rows = []
    for y in range(size):
        row = []
        for x in range(size):
            r, g, b, a = acc[y][x]
            if a <= 0.0:
                row.append((0, 0, 0, 0))
                continue
            alpha = a / samples
            row.append((
                int(round(min(255, r / a))),
                int(round(min(255, g / a))),
                int(round(min(255, b / a))),
                int(round(alpha * 255)),
            ))
        rows.append(row)
    return rows


def png_bytes(rows):
    size = len(rows)
    raw = bytearray()
    for row in rows:
        raw.append(0)
        for r, g, b, a in row:
            raw.extend((r, g, b, a))

    def chunk(tag, data):
        payload = tag + data
        return struct.pack(">I", len(data)) + payload + struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) +
            chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


def dib_bytes(rows):
    """32-bit BGRA bottom-up DIB with an AND mask, as stored inside .ico files."""
    size = len(rows)
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, size * size * 4, 0, 0, 0, 0)
    pixels = bytearray()
    for y in range(size - 1, -1, -1):
        for r, g, b, a in rows[y]:
            pixels.extend((b, g, r, a))
    mask_row = ((size + 31) // 32) * 4
    mask = bytes(mask_row * size)  # all zero: fully opaque, alpha channel wins
    return header + bytes(pixels) + mask


def ico_bytes(images):
    """images: list of (size, payload, is_png)."""
    count = len(images)
    out = struct.pack("<HHH", 0, 1, count)
    offset = 6 + 16 * count
    entries = b""
    body = b""
    for size, payload, is_png in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(payload), offset)
        offset += len(payload)
        body += payload
    return out + entries + body


def main():
    os.makedirs(RESOURCES, exist_ok=True)

    logo = render(256)
    with open(os.path.join(RESOURCES, "AppLogo.png"), "wb") as handle:
        handle.write(png_bytes(logo))

    frames = []
    for size in (16, 32, 48):
        frames.append((size, dib_bytes(render(size)), False))
    frames.append((256, png_bytes(render(256)), True))

    with open(os.path.join(RESOURCES, "AppIcon.ico"), "wb") as handle:
        handle.write(ico_bytes(frames))

    print("wrote", os.path.join(RESOURCES, "AppIcon.ico"))
    print("wrote", os.path.join(RESOURCES, "AppLogo.png"))


if __name__ == "__main__":
    main()
