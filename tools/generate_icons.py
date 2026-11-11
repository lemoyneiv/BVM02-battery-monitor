#!/usr/bin/env python3
"""Deterministic, zero-dependency PNG icon generator for BVM02 Battery Monitor.

Generates:
  - app/res/drawable-hdpi/ic_app.png (512x512)
  - mod/icons/tile.png               (128x128)
  - mod/icons/tile_disabled.png      (128x128)
"""
import math
import os
import struct
import zlib

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def write_png(path: str, width: int, height: int, rgba_bytes: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)

    def chunk(tag: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(tag + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", crc)

    raw_rows = bytearray()
    stride = width * 4
    for y in range(height):
        raw_rows.append(0)  # Filter type 0 (None)
        raw_rows.extend(rgba_bytes[y * stride : (y + 1) * stride])

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(raw_rows), 9)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def point_in_poly(x: float, y: float, poly: list) -> bool:
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if ((yi > y) != (yj > y)) and (x < (xj - xi) * (y - yi) / ((yj - yi) + 1e-9) + xi):
            inside = not inside
        j = i
    return inside


def dist_to_segment(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    dx, dy = bx - ax, by - ay
    denom = dx * dx + dy * dy
    if denom <= 1e-9:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / denom))
    cx, cy = ax + t * dx, ay + t * dy
    return math.hypot(px - cx, py - cy)


def rounded_rect_sdf(x: float, y: float, x0: float, y0: float, x1: float, y1: float, r: float) -> float:
    cx = (x0 + x1) * 0.5
    cy = (y0 + y1) * 0.5
    hx = (x1 - x0) * 0.5 - r
    hy = (y1 - y0) * 0.5 - r
    dx = max(abs(x - cx) - hx, 0.0)
    dy = max(abs(y - cy) - hy, 0.0)
    return math.hypot(dx, dy) + min(max(abs(x - cx) - hx, abs(y - cy) - hy), 0.0) - r


def blend(dst: tuple, src: tuple, cov: float) -> tuple:
    a_s = (src[3] / 255.0) * max(0.0, min(1.0, cov))
    if a_s <= 0.0:
        return dst
    a_d = dst[3] / 255.0
    out_a = a_s + a_d * (1.0 - a_s)
    if out_a <= 1e-6:
        return (0, 0, 0, 0)
    r = int(round((src[0] * a_s + dst[0] * a_d * (1.0 - a_s)) / out_a))
    g = int(round((src[1] * a_s + dst[1] * a_d * (1.0 - a_s)) / out_a))
    b = int(round((src[2] * a_s + dst[2] * a_d * (1.0 - a_s)) / out_a))
    return (max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b)), int(round(out_a * 255.0)))


def render_icon(size: int, disabled: bool = False) -> bytes:
    buf = bytearray(size * size * 4)

    # Normalized coordinates [0, 1]
    bolt_poly = [
        (0.51, 0.31),
        (0.39, 0.53),
        (0.49, 0.53),
        (0.44, 0.72),
        (0.60, 0.49),
        (0.50, 0.49),
    ]

    # Bluetooth rune subtle badge on right side of battery
    bt_segments = [
        ((0.70, 0.40), (0.70, 0.62)),
        ((0.70, 0.40), (0.76, 0.455)),
        ((0.76, 0.455), (0.65, 0.565)),
        ((0.70, 0.62), (0.76, 0.565)),
        ((0.76, 0.565), (0.65, 0.455)),
    ]

    px_scale = 1.0 / size
    aa = 1.25 * px_scale

    for py in range(size):
        ny = (py + 0.5) / size
        for px in range(size):
            nx = (px + 0.5) / size
            col = (0, 0, 0, 0)

            # 1. Outer rounded square background tile
            d_tile = rounded_rect_sdf(nx, ny, 0.06, 0.06, 0.94, 0.94, 0.19)
            if d_tile < aa:
                cov = max(0.0, min(1.0, 0.5 - d_tile / (2.0 * aa)))
                if disabled:
                    bg = (34, 38, 44, 255)
                else:
                    # Subtle top-to-bottom automotive dark slate gradient
                    t = max(0.0, min(1.0, ny))
                    bg = (
                        int(24 + 10 * (1.0 - t)),
                        int(30 + 14 * (1.0 - t)),
                        int(40 + 22 * (1.0 - t)),
                        255,
                    )
                col = blend(col, bg, cov)

                # Subtle outer border ring
                border_dist = abs(d_tile + 0.012) - 0.008
                if border_dist < aa:
                    bcov = max(0.0, min(1.0, 0.5 - border_dist / (2.0 * aa))) * cov
                    bcol = (90, 96, 106, 160) if disabled else (0, 145, 255, 175)
                    col = blend(col, bcol, bcov)

            # 2. Battery negative & positive terminal posts
            for tx0, tx1 in ((0.27, 0.36), (0.64, 0.73)):
                d_term = rounded_rect_sdf(nx, ny, tx0, 0.23, tx1, 0.31, 0.02)
                if d_term < aa:
                    tcov = max(0.0, min(1.0, 0.5 - d_term / (2.0 * aa)))
                    if disabled:
                        tcol = (120, 126, 134, 255)
                    else:
                        tcol = (0, 162, 255, 255) if tx0 < 0.5 else (46, 204, 113, 255)
                    col = blend(col, tcol, tcov)

            # 3. Main 12V Automotive Battery body
            d_body = rounded_rect_sdf(nx, ny, 0.18, 0.29, 0.82, 0.76, 0.06)
            if d_body < aa:
                bcov = max(0.0, min(1.0, 0.5 - d_body / (2.0 * aa)))
                fill_col = (52, 57, 65, 255) if disabled else (18, 44, 68, 255)
                col = blend(col, fill_col, bcov)

                # Outline stroke of battery body
                stroke_d = abs(d_body + 0.018) - 0.018
                if stroke_d < aa:
                    scov = max(0.0, min(1.0, 0.5 - stroke_d / (2.0 * aa))) * bcov
                    scol = (138, 145, 155, 255) if disabled else (0, 158, 255, 255)
                    col = blend(col, scol, scov)

            # 4. Lightning bolt (2x2 supersampled for crisp diagonal edges)
            if 0.36 <= nx <= 0.63 and 0.29 <= ny <= 0.74:
                hits = 0
                for sy in (-0.25, 0.25):
                    for sx in (-0.25, 0.25):
                        if point_in_poly(nx + sx * px_scale, ny + sy * px_scale, bolt_poly):
                            hits += 1
                if hits > 0:
                    bolt_col = (175, 180, 188, 255) if disabled else (46, 218, 122, 255)
                    col = blend(col, bolt_col, hits / 4.0)

            # 5. Bluetooth rune glyph inside right side of battery
            if 0.62 <= nx <= 0.79 and 0.37 <= ny <= 0.65:
                min_seg = min(
                    dist_to_segment(nx, ny, a[0], a[1], b[0], b[1]) for a, b in bt_segments
                )
                bt_d = min_seg - 0.012
                if bt_d < aa:
                    bt_cov = max(0.0, min(1.0, 0.5 - bt_d / (2.0 * aa)))
                    bt_col = (145, 152, 162, 240) if disabled else (110, 200, 255, 245)
                    col = blend(col, bt_col, bt_cov)

            idx = (py * size + px) * 4
            buf[idx] = col[0]
            buf[idx + 1] = col[1]
            buf[idx + 2] = col[2]
            buf[idx + 3] = col[3]

    return bytes(buf)


def main() -> None:
    ic_app = os.path.join(BASE_DIR, "app", "res", "drawable-hdpi", "ic_app.png")
    tile = os.path.join(BASE_DIR, "mod", "icons", "tile.png")
    tile_dis = os.path.join(BASE_DIR, "mod", "icons", "tile_disabled.png")

    print("Generating icons...")
    write_png(ic_app, 512, 512, render_icon(512, disabled=False))
    write_png(tile, 128, 128, render_icon(128, disabled=False))
    write_png(tile_dis, 128, 128, render_icon(128, disabled=True))
    for p in (ic_app, tile, tile_dis):
        print(f"  Wrote {p} ({os.path.getsize(p):,} bytes)")


if __name__ == "__main__":
    main()
