import os
import sys
import socket
import ssl
import OpenSSL
from pathlib import Path
from symbolchain.BufferReader import BufferReader
from symbolchain.BufferWriter import BufferWriter

CERTIFICATE_DIRECTORY = os.getcwd() + "/cert"


class NodeDiscoveryPullPeers:
    def __init__(self):
        self.version = 0
        self.public_key = ""
        self.network_generation_hash_seed = ""
        self.roles = 0
        self.port = 0
        self.network_identifier = 0
        self.host = ""
        self.friendly_name = ""

    def __str__(self):
        return "\n".join(
            [
                f"                     version: {self.version}",
                f"                  public key: {self.public_key}",
                f"network generation hash seed: {self.network_generation_hash_seed}",
                f"                       roles: {self.roles}",
                f"                        port: {self.port}",
                f"          network_identifier: {self.network_identifier}",
                f"                        host: {self.host}",
                f"               friendly_name: {self.friendly_name}",
            ]
        )


class SymbolPeerClient:
    def __init__(self, host, port, certificate_directory):
        (self.node_host, self.node_port) = (host, port)
        self.certificate_directory = Path(certificate_directory)
        self.timeout = 10

        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.ssl_context.load_cert_chain(
            self.certificate_directory / "node.full.crt.pem",
            keyfile=self.certificate_directory / "node.key.pem",
        )

    def _send_socket_request(self, packet_type, parser):
        try:
            with socket.create_connection(
                (self.node_host, self.node_port), self.timeout
            ) as sock:
                with self.ssl_context.wrap_socket(sock) as ssock:
                    self._send_simple_request(ssock, packet_type)
                    return parser(self._read_packet_data(ssock, packet_type))
        except socket.timeout as ex:
            raise ConnectionRefusedError from ex

    @staticmethod
    def _send_simple_request(ssock, packet_type):
        writer = BufferWriter()
        writer.write_int(8, 4)
        writer.write_int(packet_type, 4)
        ssock.send(writer.buffer)

    def _read_packet_data(self, ssock, packet_type):
        read_buffer = ssock.read()

        if 0 == len(read_buffer):
            raise ConnectionRefusedError(
                f"socket returned empty data for {self.node_host}"
            )

        size = BufferReader(read_buffer).read_int(4)

        while len(read_buffer) < size:
            read_buffer += ssock.read()

        reader = BufferReader(read_buffer)
        size = reader.read_int(4)
        actual_packet_type = reader.read_int(4)

        if packet_type != actual_packet_type:
            raise ConnectionRefusedError(
                f"socket returned packet type {actual_packet_type} but expected {packet_type}"
            )

        return reader

    def get_node_discovery_pull_peers(self):
        packet_type = 0x113
        return self._send_socket_request(
            packet_type, self._node_discovery_pull_peers_response
        )

    @staticmethod
    def _node_discovery_pull_peers_response(reader):
        node_discovery_pull_peers_list = []

        while not reader.eof:
            node_discovery_pull_peers = NodeDiscoveryPullPeers()
            reader.read_int(4)
            node_discovery_pull_peers.version = reader.read_int(4)
            node_discovery_pull_peers.public_key = reader.read_hex_string(32)
            node_discovery_pull_peers.network_generation_hash_seed = (
                reader.read_hex_string(32)
            )
            node_discovery_pull_peers.roles = reader.read_int(4)
            node_discovery_pull_peers.port = reader.read_int(2)
            node_discovery_pull_peers.network_identifier = reader.read_int(1)
            host_length = reader.read_int(1)
            friendly_name_length = reader.read_int(1)
            node_discovery_pull_peers.host = reader.read_string(host_length)
            node_discovery_pull_peers.friendly_name = reader.read_string(
                friendly_name_length
            )
            node_discovery_pull_peers_list.append(node_discovery_pull_peers)

        return node_discovery_pull_peers_list


def main(argv):
    port = 7900
    if 0 == len(argv):
        print("Arguments are too short")
        return 1
    elif 3 <= len(argv):
        if not argv[2].isdigit():
            print("Argument is not digit")
            return 1
        port = argv[2]

    peer_client = SymbolPeerClient(argv[1], port, CERTIFICATE_DIRECTORY)
    node_discovery_pull_peers_peer_list = peer_client.get_node_discovery_pull_peers()
    for node_discovery_pull_peers_peer in node_discovery_pull_peers_peer_list:
        print(node_discovery_pull_peers_peer)
        print()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as ex:
        print(ex)
