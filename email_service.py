import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app

class EmailService:
    @staticmethod
    def send_email(to_email, subject, body, html_body=None):
        """
        Send email using SMTP
        """
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = current_app.config['MAIL_USERNAME']
            msg['To'] = to_email
            
            # Attach plain text version
            part1 = MIMEText(body, 'plain')
            msg.attach(part1)
            
            # Attach HTML version if provided
            if html_body:
                part2 = MIMEText(html_body, 'html')
                msg.attach(part2)
            
            # Send email
            mail_password = current_app.config['MAIL_PASSWORD']
            if mail_password:
                mail_password = mail_password.replace(' ', '')
                
            with smtplib.SMTP(current_app.config['MAIL_SERVER'], 
                            current_app.config['MAIL_PORT']) as server:
                server.starttls()
                server.login(current_app.config['MAIL_USERNAME'],
                           mail_password)
                server.send_message(msg)
            
            return True, "Email sent successfully"
        except smtplib.SMTPAuthenticationError:
            return False, "Authentication failed. Please check your MAIL_USERNAME and MAIL_PASSWORD in the .env file. You must use a Google App Password, not your regular password."
        except socket.gaierror:
            return False, "Network error: Could not connect to mail server. Please check your internet connection."
        except Exception as e:
            print(f"Error sending email: {e}")
            return False, str(e)
    
    @staticmethod
    def send_organization_pending_email(org_email, org_name):
        subject = "Organization Registration Received - ACP Volunteer System"
        body = f"""
        Dear {org_name},
        
        Thank you for registering with the ACP Volunteer System.
        
        Your registration request has been received and is currently pending administrator approval.
        You will receive another email once your account has been approved.
        
        Best regards,
        ACP Volunteer System Team
        """
        
        html_body = f"""
        <html>
            <body>
                <h2>Registration Received</h2>
                <p>Dear {org_name},</p>
                <p>Thank you for registering with the ACP Volunteer System.</p>
                <p>Your registration request has been received and is currently <strong>pending administrator approval</strong>.</p>
                <p>You will receive another email once your account has been approved.</p>
                <br>
                <p>Best regards,<br>ACP Volunteer System Team</p>
            </body>
        </html>
        """
        
        return EmailService.send_email(org_email, subject, body, html_body)

    @staticmethod
    def send_organization_approval_email(org_email, username):
        subject = "Organization Registration Approved - ACP Volunteer System"
        body = f"""
        Dear Organization,
        
        Your registration has been approved!
        
        You can now log in using the username and password you created during registration.
        
        Username: {username}
        
        Please log in at: http://yourdomain.com/login
        
        Best regards,
        ACP Volunteer System Team
        """
        
        html_body = f"""
        <html>
            <body>
                <h2>Organization Registration Approved</h2>
                <p>Dear Organization,</p>
                <p>Your registration has been approved!</p>
                <p>You can now log in using the username and password you created during registration.</p>
                <p><strong>Username:</strong> {username}</p>
                <p>Please log in at: <a href="http://yourdomain.com/login">http://yourdomain.com/login</a></p>
                <br>
                <p>Best regards,<br>ACP Volunteer System Team</p>
            </body>
        </html>
        """
        
        return EmailService.send_email(org_email, subject, body, html_body)
    
    @staticmethod
    def send_certificate_notification(student_email, student_name, org_name, event_name):
        subject = f"Certificate Issued - {event_name}"
        body = f"""
        Dear {student_name},
        
        A certificate has been issued for your participation in "{event_name}" 
        organized by {org_name}.
        
        You can download your certificate from your dashboard.
        
        Best regards,
        ACP Volunteer System Team
        """
        
        html_body = f"""
        <html>
            <body>
                <h2>Certificate Issued</h2>
                <p>Dear {student_name},</p>
                <p>A certificate has been issued for your participation in 
                <strong>"{event_name}"</strong> organized by <strong>{org_name}</strong>.</p>
                <p>You can download your certificate from your dashboard.</p>
                <br>
                <p>Best regards,<br>ACP Volunteer System Team</p>
            </body>
        </html>
        """
        
        return EmailService.send_email(student_email, subject, body, html_body)

    @staticmethod
    def send_password_reset_code(to_email, code):
        subject = "Password Reset Code - ACP Volunteer System"
        body = f"""
        You have requested to reset your password.
        
        Your verification code is: {code}
        
        This code will expire in 15 minutes.
        
        If you did not request this, please ignore this email.
        """
        
        html_body = f"""
        <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>You have requested to reset your password.</p>
                <p>Your verification code is:</p>
                <h1 style="color: #4e73df; letter-spacing: 5px;">{code}</h1>
                <p>This code will expire in 15 minutes.</p>
                <p>If you did not request this, please ignore this email.</p>
            </body>
        </html>
        """
        
        return EmailService.send_email(to_email, subject, body, html_body)
