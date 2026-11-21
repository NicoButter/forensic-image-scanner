"""Deterministic synthetic negative controls generated from simple RGB patterns."""

from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

SIZE = 224


def generate_negative_controls(directory: Path) -> list[Path]:
    """Write generated PNG controls to a caller-owned temporary directory."""
    controls = {
        f"solid-{color}": Image.new("RGB", (SIZE, SIZE), color)
        for color in ("white", "black", "gray", "red", "green", "blue")
    }
    axis = np.linspace(0, 255, SIZE, dtype=np.uint8)
    gradient = np.tile(axis, (SIZE, 1))
    controls["horizontal-gradient"] = Image.fromarray(gradient)
    controls["vertical-gradient"] = Image.fromarray(gradient.T)

    blocks = np.arange(SIZE) // 28
    checkerboard = ((blocks[:, None] + blocks[None, :]) % 2 * 255).astype(np.uint8)
    controls["checkerboard"] = Image.fromarray(checkerboard)

    for name in ("circles", "rectangles", "lines"):
        controls[name] = Image.new("RGB", (SIZE, SIZE), "white")
    circles = ImageDraw.Draw(controls["circles"])
    circles.ellipse((24, 24, 124, 124), fill="navy")
    circles.ellipse((104, 104, 200, 200), fill="orange")
    rectangles = ImageDraw.Draw(controls["rectangles"])
    rectangles.rectangle((18, 22, 158, 80), fill="black")
    rectangles.rectangle((76, 106, 204, 188), fill="green")
    lines = ImageDraw.Draw(controls["lines"])
    for offset in range(16, SIZE, 32):
        lines.line((0, offset, offset, 0), fill="black", width=3)

    noise = np.random.default_rng(0).integers(0, 256, (SIZE, SIZE), dtype=np.uint8)
    controls["simple-noise"] = Image.fromarray(noise)
    paths = []
    for name, image in controls.items():
        path = directory / f"{name}.png"
        image.convert("RGB").save(path)
        paths.append(path)
    return paths
