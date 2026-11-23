"""Rebuild synthetic fixtures: no customer files or actual credentials."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont

out = Path(__file__).parent / "fixtures/file_detection"
out.mkdir(parents=True, exist_ok=True)
text = "合成测试客户手机 13812345678"
font = ImageFont.truetype("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 46)
image = Image.new("RGB", (1200, 200), "white")
ImageDraw.Draw(image).text((35, 60), text, fill="black", font=font)
image.save(out / "chinese-phone.png")
image.save(out / "scanned-chinese-phone.pdf", resolution=150)
pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
pdf = canvas.Canvas(str(out / "chinese-phone.pdf"), pagesize=(600, 220))
pdf.setFont("STSong-Light", 22)
pdf.drawString(30, 120, text)
pdf.save()
