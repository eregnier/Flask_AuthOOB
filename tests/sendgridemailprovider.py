import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


class SendGridEmailProvider:
    def __init__(self, apikey):
        self.apikey = apikey

    def send_mail(self, from_email=None, to_emails=None, subject=None, html=None):
        message = Mail(
            from_email=from_email,
            to_emails=to_emails,
            subject=subject,
            html_content=html,
        )
        try:
            SendGridAPIClient(self.apikey).send(message)
        except Exception as e:
            print(e.message)
