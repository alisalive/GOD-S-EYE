"""
PDF Export — converts HTML report to PDF using weasyprint or print-CSS fallback.
"""

import os
import time
from pathlib import Path


def export_pdf(html_path: str, output_dir: str, target: str, console=None) -> str:
    """
    Convert HTML report to PDF.
    Returns path to PDF file, or empty string on failure.
    """
    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace(":", "_")
    pdf_filename = f"report_{safe_target}_{timestamp}.pdf"
    pdf_path = os.path.join(output_dir, pdf_filename)

    os.makedirs(output_dir, exist_ok=True)

    # Try weasyprint first
    try:
        from weasyprint import HTML, CSS
        log("Generating PDF with WeasyPrint...")
        HTML(filename=html_path).write_pdf(pdf_path)
        log(f"PDF saved: {pdf_path}")
        return pdf_path
    except ImportError:
        log("WeasyPrint not installed — trying fallback method")
    except Exception as e:
        log(f"WeasyPrint error: {e} — trying fallback")

    # Fallback: inject print-CSS into HTML and save a print-ready copy
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        print_css = """
<style>
@media print {
  body { background: white !important; color: black !important; }
  .dark-toggle, nav, .no-print { display: none !important; }
  .page-break { page-break-before: always; }
  pre, code { white-space: pre-wrap; word-break: break-all; }
  a { color: black; text-decoration: none; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ccc; padding: 4px 8px; }
}
</style>
<script>window.onload = function() { window.print(); }</script>
"""
        # Insert before </head>
        html_content = html_content.replace("</head>", print_css + "</head>", 1)

        print_html_path = pdf_path.replace(".pdf", "_printable.html")
        with open(print_html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        log(f"WeasyPrint unavailable. Print-ready HTML saved: {print_html_path}")
        log("To generate PDF: open the file in a browser and use File → Print → Save as PDF")

        if console:
            console.print(
                f"  [yellow]⚠[/yellow] Install WeasyPrint for automatic PDF: "
                f"[dim]pip install weasyprint[/dim]"
            )
        return print_html_path

    except Exception as e:
        log(f"PDF export failed: {e}")
        return ""
