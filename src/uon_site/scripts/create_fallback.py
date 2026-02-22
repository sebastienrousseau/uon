from PIL import Image
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
png_path = os.path.join(script_dir, "../assets/noun-rune-3458897.png")
out_path = os.path.join(script_dir, "../assets/fallback.webp")

try:
    print("Loading image...")
    logo = Image.open(png_path).convert("RGBA")
    
    # User requested precise aspect ratio
    bg_w, bg_h = 1206, 676
    bg_color = (235, 235, 235, 255) # Light grey (#ebebeb)
    bg = Image.new('RGBA', (bg_w, bg_h), bg_color)
    
    # Resize logo
    logo.thumbnail((400, 400), Image.Resampling.LANCZOS)
    
    logo_w, logo_h = logo.size
    offset = ((bg_w - logo_w) // 2, (bg_h - logo_h) // 2)
    
    # Replace solid black with a softer medium-grey for the logo
    data = list(logo.getdata())
    new_data = []
    for item in data:
        if item[3] > 0 and item[0] < 50 and item[1] < 50 and item[2] < 50:
            new_data.append((150, 150, 150, item[3]))
        else:
            new_data.append(item)
    logo.putdata(new_data)
    
    bg.paste(logo, offset, logo)
    bg.save(out_path, 'WEBP')
    print(f"Successfully generated {out_path}")
except Exception as e:
    print(f"Error: {e}")
