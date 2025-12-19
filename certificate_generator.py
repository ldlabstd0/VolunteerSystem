from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Image, Table, TableStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from datetime import datetime
import os

class CertificateGenerator:
    @staticmethod
    def draw_border(canvas, doc):
        """Draws a formal border on the certificate"""
        canvas.saveState()
        
        # Outer double line border
        canvas.setStrokeColor(colors.darkblue)
        canvas.setLineWidth(5)
        canvas.rect(0.5*inch, 0.5*inch, 10*inch, 7.5*inch)
        
        canvas.setStrokeColor(colors.gold)
        canvas.setLineWidth(2)
        canvas.rect(0.6*inch, 0.6*inch, 9.8*inch, 7.3*inch)
        
        # Inner corner ornaments (simple lines for now)
        canvas.setStrokeColor(colors.darkblue)
        canvas.setLineWidth(1)
        
        # Top Left
        canvas.line(0.8*inch, 7.8*inch, 1.8*inch, 7.8*inch)
        canvas.line(0.8*inch, 7.8*inch, 0.8*inch, 6.8*inch)
        
        # Bottom Right
        canvas.line(10.2*inch, 0.7*inch, 9.2*inch, 0.7*inch)
        canvas.line(10.2*inch, 0.7*inch, 10.2*inch, 1.7*inch)
        
        canvas.restoreState()

    @staticmethod
    def generate_certificate(student_name, org_name, event_name, hours_earned, 
                           issue_date, certificate_number, org_logo=None, signature_path=None):
        """
        Generate a PDF certificate
        """
        # Create filename
        filename = f"certificate_{certificate_number}.pdf"
        output_dir = os.path.join('static', 'uploads', 'certificates')
        
        # Ensure directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        filepath = os.path.join(output_dir, filename)
        
        # Create PDF document in Landscape
        doc = SimpleDocTemplate(filepath, pagesize=landscape(letter),
                                rightMargin=1*inch, leftMargin=1*inch,
                                topMargin=1*inch, bottomMargin=1*inch)
        story = []
        
        # Styles
        styles = getSampleStyleSheet()
        
        # Custom Styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontName='Times-Bold',
            fontSize=36,
            textColor=colors.darkblue,
            spaceAfter=30,
            alignment=1  # Center
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Normal'],
            fontName='Times-Roman',
            fontSize=16,
            textColor=colors.black,
            spaceAfter=10,
            alignment=1
        )
        
        name_style = ParagraphStyle(
            'RecipientName',
            parent=styles['Normal'],
            fontName='Times-BoldItalic',
            fontSize=32,
            textColor=colors.black,
            spaceAfter=20,
            alignment=1
        )
        
        event_style = ParagraphStyle(
            'EventTitle',
            parent=styles['Normal'],
            fontName='Times-Bold',
            fontSize=22,
            textColor=colors.black,
            spaceAfter=15,
            alignment=1
        )
        
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['Normal'],
            fontName='Times-Roman',
            fontSize=14,
            leading=18,
            alignment=1
        )
        
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.grey,
            alignment=1
        )

        # -- CONTENT FLOW --
        
        # 1. Organization Logo (Centered Top)
        if org_logo and os.path.exists(org_logo):
            im = Image(org_logo, width=1.5*inch, height=1.5*inch)
            im.hAlign = 'CENTER'
            story.append(im)
            story.append(Spacer(1, 0.2*inch))
        else:
            story.append(Spacer(1, 1*inch))
            
        # 2. Main Title
        story.append(Paragraph("CERTIFICATE OF PARTICIPATION", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # 3. Presentation Text
        story.append(Paragraph("This certificate is proudly awarded to", subtitle_style))
        story.append(Spacer(1, 0.1*inch))
        
        # 4. Student Name
        story.append(Paragraph(student_name, name_style))
        
        # 5. Divider Line (Visual)
        # story.append(HRFlowable(width="50%", thickness=1, color=colors.gold, spaceAfter=20))
        
        # 6. Description
        story.append(Paragraph("In recognition of their outstanding contribution and completion of", subtitle_style))
        story.append(Paragraph(event_name, event_style))
        
        # 7. Details
        details_text = f"Total Service Hours: <b>{hours_earned}</b><br/>Date: <b>{issue_date.strftime('%B %d, %Y')}</b>"
        story.append(Paragraph(details_text, body_style))
        story.append(Spacer(1, 0.8*inch))
        
        # 8. Signatures Layout (Table)
        # We use a table to position signatures nicely at the bottom
        # Left: Organization Signature, Right: (Optional) or just centered
        
        sig_data = []
        sig_images = []
        sig_labels = []
        
        # Org Signature
        if signature_path and os.path.exists(signature_path):
            sig_img = Image(signature_path, width=2*inch, height=1*inch)
            sig_images.append(sig_img)
        else:
            sig_images.append(Spacer(1, 1*inch))
            
        sig_labels.append(Paragraph(f"<b>{org_name}</b><br/>Organization Representative", body_style))
        
        # Layout table
        data = [
            sig_images,
            sig_labels
        ]
        
        sig_table = Table(data, colWidths=[4*inch])
        sig_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'BOTTOM'),
            ('LINEBELOW', (0,0), (-1,0), 1, colors.black), # Line under signature image
        ]))
        
        story.append(sig_table)
        story.append(Spacer(1, 0.5*inch))
        
        # 9. Certificate ID Footer
        story.append(Paragraph(f"Certificate ID: {certificate_number}", footer_style))
        
        # Build PDF with Border
        doc.build(story, onFirstPage=CertificateGenerator.draw_border)
        
        return filepath
