from pathlib import Path
from PIL import Image, ImageOps, ImageDraw

logos = Path("static/logos")
base_path = logos / "logo.png"
if not base_path.exists():
    raise FileNotFoundError(f"Missing {base_path}")

base = Image.open(base_path).convert("RGBA")


def fit_square(img, size):
    return ImageOps.fit(img, (size, size), method=Image.Resampling.LANCZOS)

# Core square assets
fit_square(base, 64).save(logos / "favicon.png", format="PNG")
fit_square(base, 180).save(logos / "apple-touch-icon.png", format="PNG")
fit_square(base, 192).save(logos / "logo-192.png", format="PNG")
fit_square(base, 512).save(logos / "logo-512.png", format="PNG")
fit_square(base, 64).save(logos / "logo-navbar.png", format="PNG")

# Real ICO with multiple sizes
ico_src = fit_square(base, 256)
ico_src.save(logos / "favicon.ico", format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128)])

# OG image: 1200x630 solid blue with centered logo
og = Image.new("RGBA", (1200, 630), "#0d6efd")
logo_big = fit_square(base, 360)
shadow = Image.new("RGBA", (420, 420), (0, 0, 0, 0))
draw = ImageDraw.Draw(shadow)
draw.rounded_rectangle((20, 20, 400, 400), radius=36, fill=(0, 0, 0, 55))
og.alpha_composite(shadow, (390, 125))
og.alpha_composite(logo_big, (420, 135))
og.convert("RGB").save(logos / "og-image.png", format="PNG", optimize=True)

print("Updated logo derivatives in static/logos")
