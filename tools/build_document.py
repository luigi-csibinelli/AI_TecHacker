"""Gera o PDF de quatro páginas a partir do Markdown; requer reportlab."""
from html import escape
from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak


ROOT = Path(__file__).resolve().parents[1]


def build():
    fonts = Path('/usr/share/fonts/truetype/dejavu')
    if (fonts / 'DejaVuSans.ttf').exists():
        for name, file in [('Doc', 'DejaVuSans.ttf'), ('DocBold', 'DejaVuSans-Bold.ttf')]:
            pdfmetrics.registerFont(TTFont(name, str(fonts / file)))
        pdfmetrics.registerFontFamily('Doc', normal='Doc', bold='DocBold', italic='Doc', boldItalic='DocBold')
        normal, bold = 'Doc', 'DocBold'
    else:
        normal, bold = 'Helvetica', 'Helvetica-Bold'
    ink, accent, pale = colors.HexColor('#182f42'), colors.HexColor('#176980'), colors.HexColor('#edf3f6')
    styles = {
        'body': ParagraphStyle('body', fontName=normal, fontSize=9.3, leading=13.5, textColor=ink, spaceAfter=8),
        'h1': ParagraphStyle('h1', fontName=bold, fontSize=26, leading=31, textColor=ink, spaceAfter=13),
        'h2': ParagraphStyle('h2', fontName=bold, fontSize=17, leading=22, textColor=accent, spaceAfter=13),
        'h3': ParagraphStyle('h3', fontName=bold, fontSize=11.2, leading=15, textColor=accent, spaceBefore=7, spaceAfter=7),
        'cell': ParagraphStyle('cell', fontName=normal, fontSize=8.2, leading=11.5, textColor=ink, splitLongWords=True),
        'head': ParagraphStyle('head', fontName=bold, fontSize=8.1, leading=11, textColor=colors.white),
    }

    def inline(text):
        text = escape(text)
        text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
        text = re.sub(r'`(.+?)`', r'<font color="#176980">\1</font>', text)
        return text

    source = (ROOT / 'docs' / 'Documento_Tecnico.md').read_text(encoding='utf-8')
    parts = source.split('<!-- pagebreak -->')
    story = []
    for page_number, part in enumerate(parts):
        if page_number:
            story.append(PageBreak())
        lines = part.strip().splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            if line.startswith('|'):
                rows = []
                while i < len(lines) and lines[i].strip().startswith('|'):
                    cells = [x.strip() for x in lines[i].strip().strip('|').split('|')]
                    if not all(re.fullmatch(r':?-+:?', cell) for cell in cells):
                        rows.append(cells)
                    i += 1
                available = A4[0] - 96
                columns = len(rows[0])
                if columns == 2:
                    widths = [available * .34, available * .66]
                elif columns == 3 and rows[0][0] == 'Regra':
                    widths = [available * .10, available * .63, available * .27]
                elif columns == 3:
                    widths = [available * .23, available * .29, available * .48]
                else:
                    widths = [available * .30, available * .17, available * .17, available * .36]
                table = Table([[Paragraph(inline(c), styles['head' if row == 0 else 'cell']) for c in cells]
                               for row, cells in enumerate(rows)], colWidths=widths, repeatRows=1)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), accent),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [pale, colors.white]),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8), ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 6), ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LINEBELOW', (0, -1), (-1, -1), .4, colors.HexColor('#cad7df')),
                ]))
                story.extend([table, Spacer(1, 10)])
                continue
            if line.startswith('# '):
                style, text = 'h1', line[2:]
            elif line.startswith('## '):
                style, text = 'h2', line[3:]
            elif line.startswith('### '):
                style, text = 'h3', line[4:]
            else:
                style, text = 'body', line
                while i + 1 < len(lines) and lines[i + 1].strip() and not lines[i + 1].startswith(('#', '|')):
                    i += 1
                    text += ' ' + lines[i].strip()
            story.append(Paragraph(inline(text), styles[style]))
            i += 1

    def frame(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(accent)
        canvas.rect(0, A4[1] - 13, A4[0], 13, fill=1, stroke=0)
        canvas.setFont(normal, 7.5)
        canvas.setFillColor(colors.HexColor('#617587'))
        canvas.drawString(48, 30, 'ENDPOINT INVESTIGATOR | TECNOLOGIAS HACKERS | 2026.2')
        canvas.drawRightString(A4[0] - 48, 30, f'{doc.page} / 4')
        canvas.restoreState()

    destination = ROOT / 'docs' / 'Documento_Tecnico.pdf'
    doc = SimpleDocTemplate(str(destination), pagesize=A4, rightMargin=48, leftMargin=48,
                            topMargin=42, bottomMargin=48,
                            title='Endpoint Investigator - Documento Técnico', author='Projeto de Tecnologias Hackers')
    doc.build(story, onFirstPage=frame, onLaterPages=frame)
    print(destination)


if __name__ == '__main__':
    build()
