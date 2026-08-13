#!/usr/bin/env python3
"""Standard-library interoperability test for example/ftp_async.c."""

import ftplib
import hashlib
import sys
import time


HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
SOURCE = sys.argv[2] if len(sys.argv) > 2 else None
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 2121
NAME = "netfast_async_ftp.bin"
SIZE = int(sys.argv[4]) if len(sys.argv) > 4 else 512 * 1024
BLOCK_SIZE = 256 * 1024
PATTERN = bytes(range(256))


class PatternReader:
    def __init__(self, size):
        self.remaining = size
        self.offset = 0
        self.digest = hashlib.sha256()

    def read(self, requested):
        length = min(requested, self.remaining)
        if not length:
            return b""
        start = self.offset % len(PATTERN)
        data = (PATTERN * ((start + length + 255) // 256))[start:start + length]
        self.digest.update(data)
        self.offset += length
        self.remaining -= length
        return data


class HashSink:
    def __init__(self):
        self.length = 0
        self.digest = hashlib.sha256()

    def __call__(self, data):
        self.length += len(data)
        self.digest.update(data)


def speed_text(size, elapsed):
    mib_s = size / (1024 * 1024) / elapsed
    return f"{mib_s:.2f} MiB/s ({mib_s * 8 / 1024:.3f} Gibit/s)"


def main():
    ftp = ftplib.FTP(timeout=3600, source_address=(SOURCE, 0) if SOURCE else None)
    ftp.connect(HOST, PORT)
    ftp.login("netfast", "netfast")

    source = PatternReader(SIZE)
    started = time.monotonic()
    ftp.storbinary(f"STOR {NAME}", source, blocksize=BLOCK_SIZE)
    upload_elapsed = time.monotonic() - started

    received = HashSink()
    started = time.monotonic()
    ftp.retrbinary(f"RETR {NAME}", received, blocksize=BLOCK_SIZE)
    download_elapsed = time.monotonic() - started
    size = ftp.size(NAME)
    ftp.quit()

    if (received.length != SIZE or size != SIZE or
            received.digest.digest() != source.digest.digest()):
        raise RuntimeError(
            f"FTP payload or SIZE reply mismatch: expected={SIZE}, "
            f"received={received.length}, SIZE={size}, "
            f"upload_sha256={source.digest.hexdigest()}, "
            f"download_sha256={received.digest.hexdigest()}, "
            f"upload={upload_elapsed:.3f}s/{speed_text(SIZE, upload_elapsed)}, "
            f"download={download_elapsed:.3f}s/"
            f"{speed_text(received.length, download_elapsed)}")
    print(f"FTP async interoperability PASS: {SIZE} bytes "
          f"sha256={source.digest.hexdigest()}")
    print(f"upload:   {upload_elapsed:.3f}s, {speed_text(SIZE, upload_elapsed)}")
    print(f"download: {download_elapsed:.3f}s, {speed_text(SIZE, download_elapsed)}")


if __name__ == "__main__":
    main()
