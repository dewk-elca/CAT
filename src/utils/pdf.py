from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Image,
    PageTemplate,
    Frame,
)
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.lib.units import inch
import os


class NumberedCanvas(Canvas):
    def __init__(self, *args, **kwargs):
        Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        # Calculate total page count
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(total_pages)
            Canvas.showPage(self)
        Canvas.save(self)

    def draw_page_number(self, total_pages):
        page_num = self.getPageNumber()
        text = f"Page {page_num} of {total_pages}"
        # Will use the font selected by setup_font()
        font_name = getattr(self, "_font_name", "Helvetica")
        self.setFont(font_name, 9)
        self.drawRightString(LETTER[0] - inch, 0.75 * inch, text)


def setup_font():
    """Setup the best available monospace font for Linux"""
    try:
        # Option 1: Liberation Mono (common on Linux)
        liberation_paths = [
            "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
            "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
            "/usr/share/fonts/TTF/LiberationMono-Regular.ttf",
        ]

        for path in liberation_paths:
            if os.path.exists(path):
                pdfmetrics.registerFont(TTFont("LiberationMono", path))
                print("Using Liberation Mono font")
                return "LiberationMono"

        # Option 2: DejaVu Sans Mono (very common on Linux)
        dejavu_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        ]

        for path in dejavu_paths:
            if os.path.exists(path):
                pdfmetrics.registerFont(TTFont("DejaVuSansMono", path))
                print("Using DejaVu Sans Mono font")
                return "DejaVuSansMono"

        # Option 3: Ubuntu Mono (on Ubuntu systems)
        ubuntu_paths = [
            "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf",
            "/usr/share/fonts/ubuntu/UbuntuMono-R.ttf",
        ]

        for path in ubuntu_paths:
            if os.path.exists(path):
                pdfmetrics.registerFont(TTFont("UbuntuMono", path))
                print("Using Ubuntu Mono font")
                return "UbuntuMono"

        return "Helvetica"

    except Exception as e:
        print(f"Could not load fonts: {e}")
        return "Helvetica"


def create_pdf(filename, title, text, image_paths=None, save_tmp=True):
    # Setup the best available font
    font_name = setup_font()

    file_paths = [filename]
    if save_tmp:
        file_paths.append(os.path.join("/tmp", filename.lstrip("/")))

    for file in file_paths:
        os.makedirs(os.path.dirname(file), exist_ok=True)

        doc = SimpleDocTemplate(
            file,
            pagesize=LETTER,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        frame = Frame(
            doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="normal"
        )
        doc.addPageTemplates([PageTemplate(id="with-footer", frames=frame)])

        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="MonoBody",
                parent=styles["BodyText"],
                fontName=font_name,
                fontSize=10,
                leading=14,
                spaceAfter=6,
            )
        )
        styles.add(
            ParagraphStyle(
                name="CustomTitle",
                parent=styles["Heading1"],
                fontName=font_name,
                fontSize=18,
                leading=22,
                spaceAfter=14,
            )
        )

        story = []
        for line in title.strip().split("\n"):
            if line.strip():
                story.append(Paragraph(line.strip(), styles["CustomTitle"]))
        story.append(Spacer(1, 12))

        if image_paths:
            for img_path in image_paths:
                story.append(Image(img_path, width=4 * inch, height=4 * inch))
                story.append(Spacer(1, 12))

        for para in text.strip().split("\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), styles["MonoBody"]))

        # Store font name in canvas for page numbering
        def canvasmaker(filename, *args, **kwargs):
            canvas = NumberedCanvas(filename, *args, **kwargs)
            canvas._font_name = font_name
            return canvas

        doc.build(story, canvasmaker=canvasmaker)
