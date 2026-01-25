from PIL import Image, ImageDraw, ImageFont
import os

out_dir = os.path.join(os.path.dirname(__file__), "..", "static", "icons")
os.makedirs(out_dir, exist_ok=True)

def make_icon(size, path):
    img = Image.new("RGBA", (size, size), (102, 126, 234, 255))
    draw = ImageDraw.Draw(img)
    draw.polygon([(0, 0), (size, 0), (0, size)], fill=(118, 75, 162, 255))
    pad = size // 10
    draw.rounded_rectangle(
        [pad, pad, size - pad, size - pad],
        radius=size // 6,
        outline=(255, 255, 255, 200),
        width=max(2, size // 64),
    )
    try:
        font = ImageFont.truetype("arial.ttf", size // 2)
    except Exception:
        font = ImageFont.load_default()
    text = "N"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text(((size - tw) // 2, (size - th) // 2), text, font=font, fill=(10, 14, 20, 230))
    img.save(path)

make_icon(192, os.path.join(out_dir, "icon-192x192.png"))
make_icon(512, os.path.join(out_dir, "icon-512x512.png"))

fav = Image.new("RGBA", (64, 64), (102, 126, 234, 255))
draw = ImageDraw.Draw(fav)
draw.polygon([(0, 0), (64, 0), (0, 64)], fill=(118, 75, 162, 255))
try:
    font = ImageFont.truetype("arial.ttf", 28)
except Exception:
    font = ImageFont.load_default()
text = "N"
bbox = draw.textbbox((0, 0), text, font=font)
tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
draw.text(((64 - tw) // 2, (64 - th) // 2), text, font=font, fill=(10, 14, 20, 230))

favicon_path = os.path.join(os.path.dirname(__file__), "..", "static", "favicon.ico")
fav.save(favicon_path, format="ICO")
print("Icons generated.")
