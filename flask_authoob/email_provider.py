from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask import current_app


class SendGridEmailProvider:
    def __init__(self, app):
        self.apikey = app.config.get("SENDGRID_API_KEY", None)
        self.sender = app.config.get("EMAIL_SENDER")
        if self.apikey is None:
            raise Exception(
                "Missing SENDGRID_API_KEY configuration for sendgrid email provider"
            )

    def send_mail(self, to_emails=None, subject=None, html=None):
        if current_app.config.get("PREVENT_MAIL_SEND"):
            return
        to_emails = (
            current_app.config.get("EMAIL_SENDER")
            if current_app.config.get("FLASK_DEBUG") == 1
            else to_emails
        )
        message = Mail(
            from_email=self.sender,
            to_emails=to_emails,
            subject=subject,
            html_content=html,
        )
        try:
            SendGridAPIClient(self.apikey).send(message)
        except Exception as e:
            print(e)
