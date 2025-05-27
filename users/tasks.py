from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

@shared_task
def send_welcome_email(email, first_name):
    subject = "Welcome to Our Platform!"
    message = f"""
    Hi {first_name},

    Thank you for joining our platform! We're excited to have you with us.
    Explore our features and enjoy your experience.

    Best regards,
    Your Platform Team
    """
    html_message = f"""
    <h1>Welcome, {first_name}!</h1>
    <p>Thank you for joining our platform! We're excited to have you with us.</p>
    <p>Explore our features and enjoy your experience.</p>
    <p>Best regards,<br>Your Platform Team</p>
    """
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
            html_message=html_message
        )
        logger.info(f"Welcome email sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send welcome email to {email}: {str(e)}")
        raise

@shared_task
def send_password_reset_email(email, user_id):
    from .models import CustomUser
    from django.urls import reverse
    from django.contrib.auth.tokens import default_token_generator
    from django.utils.http import urlsafe_base64_encode
    from django.utils.encoding import force_bytes

    logger.info(f"Starting password reset email task for {email}, user_id={user_id}")
    try:
        user = CustomUser.objects.get(pk=user_id)
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_url = f"{settings.SITE_URL}{reverse('users:password_reset_confirm', kwargs={'uidb64': uid, 'token': token})}"
        subject = "Password Reset Request"
        message = f"""
        Hi {user.first_name or user.email},

        Please click the link below to reset your password:
        {reset_url}

        If you did not request this, please ignore this email.

        Best regards,
        Your Platform Team
        """
        html_message = f"""
        <h1>Password Reset Request</h1>
        <p>Hi {user.first_name or user.email},</p>
        <p>Please click the link below to reset your password:</p>
        <p><a href="{reset_url}">{reset_url}</a></p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Best regards,<br>Your Platform Team</p>
        """
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
            html_message=html_message
        )
        logger.info(f"Password reset email sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send password reset email to {email}: {str(e)}")
        raise