# ✅ Steps to Install LibreOffice on Windows
# 1. Download LibreOffice Installer(https://www.libreoffice.org/download/download-libreoffice/)
# Download LibreOffice

# 2. Install LibreOffice
# Run the .msi installer.
# Follow the installation wizard.
# Note the installation path (C:\Program Files\LibreOffice\program).
# 3. Set Environment Variables
# Open Environment Variables settings.
# Add C:\Program Files\LibreOffice\program to the system PATH.
# 4. Verify Setup
# soffice --version

import os
import subprocess
import time
import pymupdf
from datetime import datetime
import traceback
import time
import win32com.client
from docx import Document

def convert_to_pdf(input_path: str, output_dir: str = None):
    time.sleep(3) 
    try:
        if output_dir is None:
            output_dir = os.path.dirname(input_path)
    
        output_path = os.path.join(output_dir, os.path.splitext(os.path.basename(input_path))[0] + ".pdf")

        subprocess.run([
        "soffice", "--headless", "--convert-to", "pdf", input_path, "--outdir", output_dir
        ], check=True)

        log.info(f"Document saved as PDF at: {output_path}")

    except Exception as e:
        error_traceback = traceback.format_exc()  
        log.error("Error creating PDF file from Word file using LibreOffice")  
        return None

    log.info(output_path)
    pdf_text = read_pdf_content(output_path)
    return pdf_text


def convert_to_pdf_win32(docx_path):
    """Converts a Word document (.docx) to a PDF and returns the extracted text."""
    docx_path = os.path.abspath(docx_path)
    pdf_path = docx_path.replace('.docx', '.pdf')

    log.info(f"Starting conversion of Word document to PDF.")
    log.info(f"Word document path: {docx_path}")
    log.info(f"PDF output path: {pdf_path}")

    word = None
    doc = None

    try:
        word = win32com.client.Dispatch("Word.Application")
        word.Visible = False

        doc = word.Documents.Open(docx_path)
        log.info("Word document opened successfully.")

        doc.SaveAs(pdf_path, FileFormat=17)
        log.info(f"Document saved as PDF at: {pdf_path}")

    except Exception as e:
        log.error(f"Error during Word to PDF conversion: {e}")
        return None  # Return None or raise an exception based on your error handling policy

    finally:
        if doc:
            doc.Close(False)
            log.info("Word document closed successfully.")
        if word:
            word.Quit()
            log.info("Closed the Word application.")

    pdf_text = read_pdf_content(pdf_path)  # Ensure read_pdf_content is defined elsewhere
    return pdf_text

def read_pdf_content(pdf_path):
    """
    Reads the content from a PDF file and prints it.

    Parameters:
    pdf_path (str): The path to the PDF file.

    Returns:
    None
    """
    try:
        with pymupdf.open(pdf_path) as doc:
            pdf_text = "\n".join(page.get_text("text") for page in doc)
        
        log.info("PDF content extracted successfully.")
       
        return pdf_text

    except Exception as e:
        log.error(f"Error reading PDF file: {e}", exc_info=True)
        return ""