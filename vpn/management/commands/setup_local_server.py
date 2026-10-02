import socket

from django.core.management.base import BaseCommand, CommandError

from vpn import services
from vpn.models import Server


class Command(BaseCommand):
    help = "Register the WireGuard server this app runs on, and import its existing peers."

    def add_arguments(self, parser):
        parser.add_argument("--interface", default="wg0")
        parser.add_argument("--endpoint", default="", help="Public IP or hostname clients connect to.")
        parser.add_argument("--name", default="")

    def handle(self, *args, interface, endpoint, name, **options):
        server = Server.objects.filter(connection=Server.CONNECTION_LOCAL, interface=interface).first()
        if server:
            self.stdout.write(f"Local service '{server}' already registered, skipping creation.")
        else:
            server = Server.objects.create(
                name=name or socket.gethostname()[:64],
                connection=Server.CONNECTION_LOCAL,
                interface=interface,
                config_path=f"/etc/wireguard/{interface}.conf",
                endpoint_host=endpoint,
            )
            self.stdout.write(f"Registered local service '{server}'.")

        result = services.import_from_server(server)
        for line in [result.message, *result.details]:
            self.stdout.write(f"  {line}")
        if not result.ok:
            raise CommandError("Import failed. Fix the error above, then use 'Import from server' in the web UI.")
        server.refresh_from_db()
        if not server.endpoint_host:
            self.stdout.write(self.style.WARNING(
                "  No public endpoint known yet. Set it under Services > Edit before downloading configs."))
