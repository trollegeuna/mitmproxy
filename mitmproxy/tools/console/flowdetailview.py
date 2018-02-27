import urwid

from mitmproxy import http
from mitmproxy.tools.console import common, searchable
from mitmproxy.utils import human
from mitmproxy.utils import strutils


def maybe_timestamp(base, attr):
    if base is not None and getattr(base, attr):
        return human.format_timestamp_with_milli(getattr(base, attr))
    else:
        return "active"


def flowdetails(state, flow: http.HTTPFlow):
    text = []

    sc = flow.server_conn
    cc = flow.client_conn
    req = flow.request
    resp = flow.response
    metadata = flow.metadata

    if metadata is not None and len(metadata) > 0:
        with open("test_output_flowdetails.txt", "a") as text_file:
            text_file.write("Branch 1\n")
        parts = [(str(k), repr(v)) for k, v in metadata.items()]
        text.append(urwid.Text([("head", "Metadata:")]))
        text.extend(common.format_keyvals(parts, indent=4))

    if sc is not None and sc.ip_address:
        with open("test_output_flowdetails.txt", "a") as text_file:
            text_file.write("Branch 2\n")
        text.append(urwid.Text([("head", "Server Connection:")]))
        parts = [
            ("Address", human.format_address(sc.address)),
        ]
        if sc.ip_address:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 3\n")
            parts.append(("Resolved Address", human.format_address(sc.ip_address)))
        if resp:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 4\n")
            parts.append(("HTTP Version", resp.http_version))
        if sc.alpn_proto_negotiated:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 5\n")
            parts.append(("ALPN", sc.alpn_proto_negotiated))

        text.extend(
            common.format_keyvals(parts, indent=4)
        )

        c = sc.cert
        if c:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 6\n")
            text.append(urwid.Text([("head", "Server Certificate:")]))
            parts = [
                ("Type", "%s, %s bits" % c.keyinfo),
                ("SHA1 digest", c.digest("sha1")),
                ("Valid to", str(c.notafter)),
                ("Valid from", str(c.notbefore)),
                ("Serial", str(c.serial)),
                (
                    "Subject",
                    urwid.BoxAdapter(
                        urwid.ListBox(
                            common.format_keyvals(
                                c.subject,
                                key_format="highlight"
                            )
                        ),
                        len(c.subject)
                    )
                ),
                (
                    "Issuer",
                    urwid.BoxAdapter(
                        urwid.ListBox(
                            common.format_keyvals(
                                c.issuer,
                                key_format="highlight"
                            )
                        ),
                        len(c.issuer)
                    )
                )
            ]

            if c.altnames:
                with open("test_output_flowdetails.txt", "a") as text_file:
                    text_file.write("Branch 7\n")
                parts.append(
                    (
                        "Alt names",
                        ", ".join(strutils.bytes_to_escaped_str(x) for x in c.altnames)
                    )
                )
            text.extend(
                common.format_keyvals(parts, indent=4)
            )

    if cc is not None:
        with open("test_output_flowdetails.txt", "a") as text_file:
            text_file.write("Branch 8\n")
        text.append(urwid.Text([("head", "Client Connection:")]))

        parts = [
            ("Address", "{}:{}".format(cc.address[0], cc.address[1])),
        ]
        if req:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 9\n")
            parts.append(("HTTP Version", req.http_version))
        if cc.tls_version:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 10\n")
            parts.append(("TLS Version", cc.tls_version))
        if cc.sni:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 11\n")
            parts.append(("Server Name Indication", cc.sni))
        if cc.cipher_name:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 12\n")
            parts.append(("Cipher Name", cc.cipher_name))
        if cc.alpn_proto_negotiated:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 13\n")
            parts.append(("ALPN", cc.alpn_proto_negotiated))

        text.extend(
            common.format_keyvals(parts, indent=4)
        )

    parts = []

    if cc is not None and cc.timestamp_start:
        with open("test_output_flowdetails.txt", "a") as text_file:
            text_file.write("Branch 14\n")
        parts.append(
            (
                "Client conn. established",
                maybe_timestamp(cc, "timestamp_start")
            )
        )
        if cc.tls_established:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 15\n")
            parts.append(
                (
                    "Client conn. TLS handshake",
                    maybe_timestamp(cc, "timestamp_tls_setup")
                )
            )

    if sc is not None and sc.timestamp_start:
        with open("test_output_flowdetails.txt", "a") as text_file:
            text_file.write("Branch 16\n")
        parts.append(
            (
                "Server conn. initiated",
                maybe_timestamp(sc, "timestamp_start")
            )
        )
        parts.append(
            (
                "Server conn. TCP handshake",
                maybe_timestamp(sc, "timestamp_tcp_setup")
            )
        )
        if sc.tls_established:
            with open("test_output_flowdetails.txt", "a") as text_file:
                text_file.write("Branch 17\n")
            parts.append(
                (
                    "Server conn. TLS handshake",
                    maybe_timestamp(sc, "timestamp_tls_setup")
                )
            )

    if req is not None and req.timestamp_start:
        with open("test_output_flowdetails.txt", "a") as text_file:
            text_file.write("Branch 18\n")
        parts.append(
            (
                "First request byte",
                maybe_timestamp(req, "timestamp_start")
            )
        )
        parts.append(
            (
                "Request complete",
                maybe_timestamp(req, "timestamp_end")
            )
        )

    if resp is not None and resp.timestamp_start:
        with open("test_output_flowdetails.txt", "a") as text_file:
            text_file.write("Branch 19\n")
        parts.append(
            (
                "First response byte",
                maybe_timestamp(resp, "timestamp_start")
            )
        )
        parts.append(
            (
                "Response complete",
                maybe_timestamp(resp, "timestamp_end")
            )
        )

    if parts:
        with open("test_output_flowdetails.txt", "a") as text_file:
            text_file.write("Branch 20\n")
        # sort operations by timestamp
        parts = sorted(parts, key=lambda p: p[1])

        text.append(urwid.Text([("head", "Timing:")]))
        text.extend(common.format_keyvals(parts, indent=4))

    return searchable.Searchable(text)
