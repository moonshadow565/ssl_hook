#!python
from __future__ import annotations
from typing import IO, Literal, Mapping, Callable, Tuple
from time import sleep
import re
import sys
import miniamf.amf0
import miniamf.amf3

RE_IP = re.compile("^(\\w+): (0x[\\dA-F]+), address: ([\\d\\.]+), port: (\\d+), familiy: (\\d+)$")
RE_DATA = re.compile("^(\\w+): (0x[\\dA-F]+), time: (\\d+), req: (0x[\\dA-F]+), got: (0x[\\dA-F]+)$")

class ProcessBuffer:
    # Internal storage for async buffer
    data: bytes

    # Initialize async buffer
    def __init__(self, processor, *args, **kwargs) -> None:
        self.data = b''
        self.processor = processor(self, *args, **kwargs)

    # Get results from associated processor
    def __call__(self, data: bytes):
        self.push(data)
        while a := next(self.processor):
            yield a

    # Push data to async buffer
    def push(self, data: bytes):
        #print("Pushing: ", len(data))
        self.data = self.data + data

    # Pull data from async buffer
    def pull(self, n: int) -> bytes:
        #print("Pulling:", n)
        result = self.data[:n]
        self.data = self.data[n:]
        return result

    # Read bytes from buffer
    def read_exact(self, n: int):
        while len(self.data) < n:
            yield
        return self.pull(n)

    # Read a line from buffer
    def read_line(self, encoding: str = 'ascii', terminator = 0x0A):
        i = 0
        while True:
            while len(self.data) <= i:
                yield
            if self.data[i] ==terminator:
                return self.pull(i + 1)[:-1].decode(encoding)
            i += 1

    # Read int from buffer
    def read_int(self, n: int, byteorder: Literal["little", "big"]):
        result = yield from self.read_exact(n)
        return int.from_bytes(result, byteorder)

def process_rtmp(ProcessBuffer: ProcessBuffer):
    # Header dict
    ctx_headers: Mapping[int, Tuple[int, int, int]] = {}
    # Stream dict
    ctx_streams: Mapping[int, bytearray] = {}
    # Chunk size
    ctx_chunk_size = 128

    # Process the handshake
    for _ in range(1):
        handshake = yield from ProcessBuffer.read_exact(1 + 0x600 + 0x600)
        assert handshake[0] == 0x03

    while True:
        # Get packed flag
        flag = yield from ProcessBuffer.read_int(1, 'little')

        # Unpack flag bits
        channel = flag & 0x3f
        header_type = flag >> 6

        # Read extended channel
        match channel:
            case 0:
                channel = yield from ProcessBuffer.read_int(1, 'little')
                channel += 64
            case 1:
                channel = yield from ProcessBuffer.read_int(2, 'little')
                channel += 64
            case _:
                pass

        # If we recieve full update or if the channel is not already inited, reset it to zero
        if header_type == 0 or channel not in ctx_headers:
            ctx_headers[channel] = (0, 0, 0)

        # Reuse old header parts
        msg_len, msg_type, msg_stream_id = ctx_headers[channel]

        # Header types 2,1,0 have a timestamp
        if header_type <= 2:
            timestamp = yield from ProcessBuffer.read_int(3, 'big')
            # Header type 1, 0 have msg length and type
            if header_type <= 1:
                msg_len = yield from ProcessBuffer.read_int(3, 'big')
                msg_type = yield from ProcessBuffer.read_int(1, 'little')
                # Header type 0 has a msg stream id
                if header_type <= 0:
                    msg_stream_id = yield from ProcessBuffer.read_int(4, 'little')
                # TODO: figure if extended timestamp contributes to msg len
                # if timestamp == 0xFF_FF_FF:
                #     msg_len -= 4
            if timestamp == 0xFF_FF_FF:
                timestamp = yield from ProcessBuffer.read_int(4, 'big')

        # Backup the header
        ctx_headers[channel] = (msg_len, msg_type, msg_stream_id)

        # Process message
        msg_buffer = ctx_streams.setdefault(channel, bytearray())    

        # Push data into buffer 
        msg_chunk = yield from ProcessBuffer.read_exact(min(max(msg_len - len(msg_buffer), 0), ctx_chunk_size))
        msg_buffer.extend(msg_chunk)

        # If we dont have enough data yet return nothing
        if len(msg_buffer) < msg_len:
            continue

        # Pull data out of the msg buffer and return it
        msg_data = bytes(msg_buffer[:msg_len])
        del ctx_streams[channel]

        # Process message
        match msg_type:
            # Ignore: incomplete, abort, ack, user ctl, win ack size, set peer bw
            case -1 | 2 | 3 | 4 | 5 | 6:
                pass
            # Parse: set chunk size
            case 1:
                ctx_chunk_size = int.from_bytes(msg_data[:4], 'big', False)
            # Parse: amf3/flex msg
            case 0x11:
                yield list(miniamf.amf0.Decoder(msg_data[12:], strict=False))
            # Parse: amf0 invoke
            case 0x14:
                yield list(miniamf.amf0.Decoder(msg_data, strict=False))
            # Unsuported: flex_stream_send, flex_shared_obj, amf0_shared_object, amf0_data, others...
            case 0xf | 0x10 | 0x12 | 0x13 | _:
                raise ValueError(f"Unsuported msg type: 0x{msg_type:02x}")

def process_hook(ProcessBuffer: ProcessBuffer):
    fd_peer = {}
    fd_sock = {}
    while True:
        line = yield from ProcessBuffer.read_line()
        line = line.strip()
        match line.split(':')[0]:
            case 'end' | 'module':
                pass
            case 'fd_sock':
                op, fid, addr, port, family = RE_IP.match(line).groups()
                op, fid, addr, port, family = op, int(fid, 16), addr, int(port), int(family)
                fd_sock[fid] = f"{addr}:{port}"
            case 'fd_peer':
                op, fid, addr, port, family = RE_IP.match(line).groups()
                op, fid, addr, port, family = op, int(fid, 16), addr, int(port), int(family)
                fd_peer[fid] = f"{addr}:{port}"
            case 'read' | 'write':
                op, fid, time, req, got = RE_DATA.match(line).groups()
                op, fid, time, req, got = op, int(fid, 16), int(time), int(req, 16), int(got, 16)
                sock = fd_sock.get(fid, 'UNK')
                peer = fd_peer.get(fid, 'UNK')
                data = yield from ProcessBuffer.read_exact(got)
                assert len(data) == got
                newline = yield from ProcessBuffer.read_exact(1)
                assert newline == b'\n'
                yield (op, fid, time, sock, peer, data)
            case _:
                raise ValueError("hook error: " + line)

def read_rtmp_from_hook(source: IO, delay: float):
    prerunner = ProcessBuffer(process_hook)
    runners = {}
    while True:
        chunk = source.read(0x1000)
        if not chunk:
            if not delay:
                return
            sleep(delay)
        for (op, fid, time, sock, peer, data) in prerunner(chunk):
            key = (fid, op)
            if not key in runners:
                if not len(data) in {1, 0x601, 0xC01} or data[0] != 0x03:
                    runners[key] = None
                else:
                    runners[key] = ProcessBuffer(process_rtmp)
            if runner := runners[key]:
                for result in runner(data):
                    print(f"{hex(fid)} - {sock} {'<' if op[0] == 'r' else '>'} {peer}")
                    print(result)

# File or - for stdin
file = sys.stdin.buffer
if len(sys.argv) > 1 or sys.argv[1] == '-':
    file = open(sys.argv[1], 'rb')
# Delay in float seconds to sleep for watching file changes(0 to disable watching for changes)
delay = 0
if len(sys.argv) > 2 and sys.argv[2] != '0':
    delay = float(sys.argv[2])
read_rtmp_from_hook(file, delay)
