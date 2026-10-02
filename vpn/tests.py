import base64
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase

from . import services, wg
from .forms import ClientForm
from .models import Client, Server

SERVER_PRIV = wg.generate_private_key()
PEER_PRIV = wg.generate_private_key()
PEER_PUB = wg.public_key_from_private(PEER_PRIV)

SERVER_CONF = f"""# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT 103.164.54.159

[Interface]
Address = 10.7.0.1/24, fddd:2c4:2c4:2c4::1/64
PrivateKey = {SERVER_PRIV}
ListenPort = 51820

# BEGIN_PEER skie
[Peer]
PublicKey = {PEER_PUB}
PresharedKey = {wg.generate_preshared_key()}
AllowedIPs = 10.7.0.2/32, fddd:2c4:2c4:2c4::2/128
# END_PEER skie
"""

CLIENT_CONF = f"""[Interface]
Address = 10.7.0.2/24
PrivateKey = {PEER_PRIV}
"""


class FakeRunner:
    """Stands in for SSH: keeps one file in memory and records commands."""

    def __init__(self, files):
        self.files = files
        self.commands = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def run(self, command, stdin=None, check=True):
        self.commands.append(command)
        if command.startswith("cat ") and ">" not in command:
            path = command[4:].strip("'")
            if path in self.files:
                return 0, self.files[path], ""
            return 1, "", "No such file"
        if "cat >" in command:
            self.files["/etc/wireguard/wg0.conf"] = stdin
            return 0, "", ""
        if "is-active" in command:
            return 0, "active\n", ""
        return 0, "", ""


class KeyTests(TestCase):
    def test_rfc7748_vector(self):
        priv = base64.b64encode(bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")).decode()
        expected = base64.b64encode(bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")).decode()
        self.assertEqual(wg.public_key_from_private(priv), expected)

    def test_generated_keys_valid(self):
        priv, pub = wg.generate_keypair()
        self.assertTrue(wg.is_valid_key(priv))
        self.assertTrue(wg.is_valid_key(pub))
        self.assertTrue(wg.is_valid_key(wg.generate_preshared_key()))


class ConfigTests(TestCase):
    def test_parse_server_config(self):
        conf = wg.parse_server_config(SERVER_CONF)
        self.assertEqual(conf.endpoint_hint, "103.164.54.159")
        self.assertEqual(conf.interface.values["ListenPort"], "51820")
        self.assertEqual(len(conf.peers), 1)
        self.assertEqual(conf.peers[0].name, "skie")
        self.assertNotIn("[Peer]", conf.head)


class ServerFlowTests(TestCase):
    def setUp(self):
        self.server = Server.objects.create(
            name="SG", endpoint_host="", ssh_host="103.164.54.159",
            server_address="10.7.0.1/24",
        )
        self.files = {"/etc/wireguard/wg0.conf": SERVER_CONF, "/root/skie.conf": CLIENT_CONF}
        self.runner = FakeRunner(self.files)
        patcher = mock.patch.object(services, "connect", return_value=self.runner)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_import_then_add_then_apply(self):
        result = services.import_from_server(self.server)
        self.assertTrue(result.ok, result.message)
        self.server.refresh_from_db()
        self.assertEqual(self.server.public_key, wg.public_key_from_private(SERVER_PRIV))
        self.assertEqual(self.server.endpoint_host, "103.164.54.159")
        self.assertEqual(str(self.server.ipv6_network), "fddd:2c4:2c4:2c4::/64")

        skie = Client.objects.get(name="skie")
        self.assertEqual(skie.ipv4, "10.7.0.2")
        self.assertEqual(skie.private_key, PEER_PRIV)  # recovered from /root/skie.conf
        self.assertTrue(skie.can_download)

        form = ClientForm({"server": self.server.pk, "name": "friend1", "enabled": "on"})
        self.assertTrue(form.is_valid(), form.errors)
        friend = form.save()
        self.assertEqual(friend.ipv4, "10.7.0.3")
        self.assertEqual(friend.ipv6, "fddd:2c4:2c4:2c4::3")

        result = services.apply_to_server(self.server)
        self.assertTrue(result.ok, result.message)
        new_conf = self.files["/etc/wireguard/wg0.conf"]
        self.assertIn(f"PrivateKey = {SERVER_PRIV}", new_conf)  # interface kept verbatim
        self.assertIn("# BEGIN_PEER friend1", new_conf)
        self.assertIn(friend.public_key, new_conf)
        self.assertIn(PEER_PUB, new_conf)
        self.assertTrue(any("wg syncconf" in c for c in self.runner.commands))

        cfg = friend.render_config()
        self.assertIn("Endpoint = 103.164.54.159:51820", cfg)
        self.assertIn("Address = 10.7.0.3/24, fddd:2c4:2c4:2c4::3/64", cfg)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", cfg)

        friend.enabled = False
        friend.save()
        services.apply_to_server(self.server)
        self.assertNotIn(friend.public_key, self.files["/etc/wireguard/wg0.conf"])

    def test_apply_refuses_unknown_peers(self):
        result = services.apply_to_server(self.server)
        self.assertFalse(result.ok)
        self.assertIn("Import", result.message)
        self.assertEqual(self.files["/etc/wireguard/wg0.conf"], SERVER_CONF)


class ViewTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser("admin", "", "admin2027")
        self.user = User.objects.create_user("bob", "", "bobpass123")
        self.server = Server.objects.create(
            name="SG", endpoint_host="103.164.54.159", ssh_host="103.164.54.159",
            public_key=wg.generate_keypair()[1], auto_apply=False,
        )
        priv, pub = wg.generate_keypair()
        self.mine = Client.objects.create(server=self.server, name="bob-pc", ipv4="10.7.0.2",
                                          private_key=priv, public_key=pub, owner=self.user)
        priv, pub = wg.generate_keypair()
        self.other = Client.objects.create(server=self.server, name="other", ipv4="10.7.0.3",
                                           private_key=priv, public_key=pub)

    def test_admin_pages_render(self):
        self.client.login(username="admin", password="admin2027")
        for url in ["/", "/servers/", "/servers/new/", f"/servers/{self.server.pk}/",
                    f"/servers/{self.server.pk}/edit/", "/clients/", "/clients/new/",
                    f"/clients/{self.mine.pk}/", f"/clients/{self.mine.pk}/edit/",
                    "/accounts/", "/accounts/new/", f"/accounts/{self.user.pk}/edit/", "/logs/", "/password/"]:
            self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_download(self):
        self.client.login(username="admin", password="admin2027")
        resp = self.client.get(f"/clients/{self.mine.pk}/download/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"[Interface]", resp.content)
        self.assertIn("attachment", resp["Content-Disposition"])

    def test_normal_user_sees_only_own(self):
        self.client.login(username="bob", password="bobpass123")
        self.assertEqual(self.client.get(f"/clients/{self.mine.pk}/download/").status_code, 200)
        self.assertEqual(self.client.get(f"/clients/{self.other.pk}/download/").status_code, 404)
        self.assertEqual(self.client.get("/servers/").status_code, 403)
        self.assertEqual(self.client.get("/accounts/").status_code, 403)

    def test_login_required(self):
        self.assertEqual(self.client.get("/clients/").status_code, 302)
