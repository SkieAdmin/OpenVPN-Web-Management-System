from django.contrib.auth.models import User
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create the first administrator account if it does not exist yet."

    def add_arguments(self, parser):
        parser.add_argument("--username", default="admin")
        parser.add_argument("--password", default="admin2027")

    def handle(self, *args, username, password, **options):
        if User.objects.filter(username=username).exists():
            self.stdout.write(f"Account '{username}' already exists, nothing changed.")
            return
        User.objects.create_superuser(username=username, email="", password=password)
        self.stdout.write(self.style.SUCCESS(f"Created administrator '{username}'. Change the password after first login."))
