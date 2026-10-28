"""Isolated downstream UDP peer, not part of runtime image."""
import socket
import threading
from pyrad import dictionary, packet

secret = b'remote-test-secret'
d = dictionary.Dictionary('/tests/downstream.dictionary')


def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', port))
    while True:
        raw, addr = s.recvfrom(4096)
        request = packet.AuthPacket(packet=raw, secret=secret, dict=d)
        response = request.CreateReply()
        response.code = packet.AccountingResponse if request.code == packet.AccountingRequest else packet.AccessAccept
        s.sendto(response.ReplyPacket(), addr)

threading.Thread(target=serve, args=(1813,), daemon=True).start()
serve(1812)
