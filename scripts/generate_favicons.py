from PIL import Image, ImageDraw, ImageFont
import os

out_dir = os.path.join(os.path.dirname(__file__), "..", "static", "icons")
os.makedirs(out_dir, exist_ok=True)

def create_favicon(bg_color, text_color, filename):
    size = 64
    img = Image.new("RGBA", (size, size), bg_color)
    draw = ImageDraw.Draw(img)
    
    # Draw NB
    try:
        # Try to find a bold san-serif font
        font = ImageFont.truetype("arialbd.ttf", 36)
    except:
        try:
           font = ImageFont.truetype("arial.ttf", 36)
        except:
           font = ImageFont.load_default()
            
    text = "NB"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    
    # Center text
    draw.text(((size - tw) // 2, (size - th) // 2), text, font=font, fill=text_color)
    
    path = os.path.join(out_dir, filename)
    img.save(path)
    print(f"Generated {path}")

# Dark Theme Icon (Black BG, White Text) -> displayed on Light Theme Browser? No, displayed when App is Dark?
# Actually, favicon usually contrasts with the Browser Tab Bar.
# But user said "black/white (depending on the theme)".
# We will create both and switch them in JS.

# favicon-dark-theme.png (For when the site is in Dark Mode: Black BG, White Text)
create_favicon((10, 14, 20, 255), (255, 255, 255, 255), "favicon-theme-dark.png")

# favicon-light-theme.png (For when the site is in Light Mode: White BG, Black Text)
create_favicon((255, 255, 255, 255), (10, 14, 20, 255), "favicon-theme-light.png")
