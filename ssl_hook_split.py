#!/bin/env python
import re
import os
import zlib
import sys

RE_IP = re.compile("\\w+: (0x[\\dA-F]+), address: ([\\d\\.]+), port: (\\d+), familiy: (\\d+)")
RE_DATA = re.compile("(\\w+): (0x[\\dA-F]+), time: (\\d+), req: 0x([\\dA-F]+), got: 0x([\\dA-F]+)")

class Connection:
    def __init__(self):
        self.family = "UNKNOWN"
        self.sock_ip = "UNKNOWN"
        self.peer_ip = "UNKNOWN"
        self.packets = {}

def auto_ungzip(data):
    if not b": gzip" in data:
        return data
    try:
        sep = b"\r\n\r\n"
        start = data.index(sep)
        if start == -1:
            return data
        odata = data[start + len(sep):]
        ndata = zlib.decompress(odata, 32 + zlib.MAX_WBITS)
        print("success")
        return data[:start + len(sep)] + ndata
    except Exception as e:
        print(e)
        return data


def read_connections(fname):
    with open(fname, "rb") as io:
        results = {}
        while True:
            line = ""
            while True:
                c = io.read(1)
                assert(c)
                if c[0] == 0xA:
                    break
                line += chr(c[0])

            if line.startswith("end"):
                break
            if line.startswith("fail"):
                raise ValueError(line)
            if line.startswith("module"):
                continue
            if line.startswith("fd_peer") or line.startswith("fd_sock"):
                m = RE_IP.match(line)
                assert(m)
                cid = m.group(1)
                address = m.group(2)
                port = m.group(3)
                family = m.group(4)
                if cid not in results:
                    results[cid] = Connection()
                c = results[cid]
                if line.startswith("fd_peer"):
                    c.peer_ip = f"{address}_{port}"
                else:
                    c.sock_ip = f"{address}_{port}"
                continue
            if line.startswith("read") or line.startswith("write"):
                m = RE_DATA.match(line)
                assert(m)
                direction = m.group(1)
                cid = m.group(2)
                time = int(m.group(3))
                requested = int(m.group(4), 16)
                received = int(m.group(5), 16)
                data = io.read(received)
                assert(len(data) == received)
                newline = io.read(1)
                assert(newline == b"\n")
                if cid not in results:
                    results[cid] = Connection()
                c = results[cid]
                key = (time, len(c.packets), direction)
                c.packets[key] = list(data)
                continue
            raise ValueError(f"Unknown type: {line}");
        for con in results.values():
            last_direction = ""
            last_packet = []
            for key in list(con.packets.keys()):
                direction = key[2]
                value = con.packets[key]
                if last_direction == direction:
                    last_packet.extend(value)
                    del con.packets[key]
                else:
                    last_direction = direction
        return results


def write_connections(connections, dname):
    os.makedirs(dname, exist_ok=True)
    for cid, c in connections.items():
        family, sock, peer = c.family, c.sock_ip, c.peer_ip
        fname = f"{dname}/{cid}-{family}-{sock}-{peer}.txt"
        with open(fname, "wb") as io:
            for (time, i, direction), value in c.packets.items():
                if direction == "read":
                    io.write(b"\n<" + b"=" * 120 + b">\n")
                    io.write(auto_ungzip(bytes(value)))
src = sys.argv[1]
dst = sys.argv[2] if 2 in sys.argv else src.replace(".txt", "")
cons = read_connections(src)
write_connections(cons, dst)
