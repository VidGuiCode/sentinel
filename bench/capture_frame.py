#!/usr/bin/env python3
"""Capture a drawn Sentinel frame from a true pty.

Sentinel is a curses tool: it draws nothing unless stdout is a terminal
with a size above zero. `docker run -t` under a shell with no terminal
gives a pty of size 0x0. So plain smoke tests catch an empty screen
and wrongly read it as a pass.

This code makes a pty with a set size, runs the target, drains output
for some seconds, and turns the ANSI stream into a plain text grid.
Then the last visible frame can be checked. Use it for draw smoke
tests and to check that permission-cut panels show a reason, not blank.

Limit: the replay skips terminal scroll. So the caught grid can sit one
row off from what the tool wrote. Rows that changed across frames can
show old parts. Check that content is present ("does this panel state
why it is empty?"). Do not check exact row and column spots.

Usage:
    python3 bench/capture_frame.py [--rows 45] [--cols 160] [--duration 8]
                                   [--out frame.txt] -- python3 sentinel-monitor.py
"""
import argparse
import errno
import fcntl
import os
import re
import select
import signal
import struct
import sys
import termios
import time

# Cover enough ANSI/VT100 codes to replay a curses screen.
CSI_RE = re.compile(rb'\x1b\[([0-9;?]*)([a-zA-Z])')


class Screen:
    """Small VT100 grid: cursor moves, erase codes, and text."""

    def __init__(self, rows, cols):
        self.rows = rows
        self.cols = cols
        self.grid = [[' '] * cols for _ in range(rows)]
        self.cy = 0
        self.cx = 0
        self._pending = b''

    def _put(self, ch):
        if 0 <= self.cy < self.rows and 0 <= self.cx < self.cols:
            self.grid[self.cy][self.cx] = ch
        self.cx += 1
        if self.cx >= self.cols:
            self.cx = self.cols - 1

    def _erase_display(self, mode):
        if mode in (2, 3):
            self.grid = [[' '] * self.cols for _ in range(self.rows)]
        elif mode == 0:
            for x in range(self.cx, self.cols):
                self.grid[self.cy][x] = ' '
            for y in range(self.cy + 1, self.rows):
                self.grid[y] = [' '] * self.cols

    def _erase_line(self, mode):
        if mode == 0:
            for x in range(self.cx, self.cols):
                self.grid[self.cy][x] = ' '
        elif mode == 1:
            for x in range(0, min(self.cx + 1, self.cols)):
                self.grid[self.cy][x] = ' '
        elif mode == 2:
            self.grid[self.cy] = [' '] * self.cols

    def feed(self, data):
        # An escape code can split across two pty reads. Hold the cut
        # tail. Do not draw it as text.
        data = self._pending + data
        self._pending = b''
        i = 0
        n = len(data)
        while i < n:
            b = data[i:i + 1]
            if b == b'\x1b':
                tail = data[i:]
                m = CSI_RE.match(data, i)
                if m:
                    params, final = m.group(1), m.group(2)
                    nums = [int(p) for p in params.split(b';') if p.isdigit()]
                    self._csi(final, nums)
                    i = m.end()
                    continue
                # ESC ( B / ESC ) 0 - charset selection, three bytes.
                if len(tail) >= 3 and tail[1:2] in (b'(', b')'):
                    i += 3
                    continue
                # A cut code at the read edge: hold it.
                if len(tail) < 8 and (len(tail) < 2 or tail[1:2] in (b'[', b'(', b')')):
                    self._pending = tail
                    return
                i += 2  # unsupported / malformed escape
                continue
            if b == b'\r':
                self.cx = 0
            elif b == b'\n':
                self.cy = min(self.cy + 1, self.rows - 1)
            elif b == b'\b':
                self.cx = max(0, self.cx - 1)
            elif b >= b' ':
                # Decode one UTF-8 shape (box and braille glyphs).
                length = 1
                c = b[0]
                if c >= 0xF0:
                    length = 4
                elif c >= 0xE0:
                    length = 3
                elif c >= 0xC0:
                    length = 2
                try:
                    self._put(data[i:i + length].decode('utf-8', 'replace'))
                except Exception:
                    self._put('?')
                i += length
                continue
            i += 1

    def _csi(self, final, nums):
        if final == b'H' or final == b'f':
            self.cy = (nums[0] - 1) if nums else 0
            self.cx = (nums[1] - 1) if len(nums) > 1 else 0
            self.cy = max(0, min(self.cy, self.rows - 1))
            self.cx = max(0, min(self.cx, self.cols - 1))
        elif final == b'A':
            self.cy = max(0, self.cy - (nums[0] if nums else 1))
        elif final == b'B':
            self.cy = min(self.rows - 1, self.cy + (nums[0] if nums else 1))
        elif final == b'C':
            self.cx = min(self.cols - 1, self.cx + (nums[0] if nums else 1))
        elif final == b'D':
            self.cx = max(0, self.cx - (nums[0] if nums else 1))
        elif final == b'G':
            self.cx = max(0, min((nums[0] - 1) if nums else 0, self.cols - 1))
        elif final == b'J':
            self._erase_display(nums[0] if nums else 0)
        elif final == b'K':
            self._erase_line(nums[0] if nums else 0)
        # SGR/color (m) and mode set/reset (h/l) leave the text grid alone.

    def text(self):
        return '\n'.join(''.join(row).rstrip() for row in self.grid)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rows', type=int, default=45)
    parser.add_argument('--cols', type=int, default=160)
    parser.add_argument('--duration', type=float, default=8)
    parser.add_argument('--out', default=None)
    parser.add_argument('--keys', default='',
                        help='keys to send after the UI settles, '
                             'example: "d" opens the diagnostics overlay')
    parser.add_argument('--keys-at', type=float, default=None,
                        help='seconds into the run to send --keys '
                             '(default: 60%% of duration)')
    parser.add_argument('cmd', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    cmd = args.cmd[1:] if args.cmd and args.cmd[0] == '--' else args.cmd
    if not cmd:
        parser.error('no command given')

    master_fd, slave_fd = os.openpty()
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ,
                struct.pack('HHHH', args.rows, args.cols, 0, 0))

    pid = os.fork()
    if pid == 0:  # child
        os.setsid()
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        os.close(master_fd)
        os.close(slave_fd)
        env = dict(os.environ, TERM=os.environ.get('TERM', 'xterm-256color'),
                   LINES=str(args.rows), COLUMNS=str(args.cols))
        os.execvpe(cmd[0], cmd, env)
        os._exit(127)

    os.close(slave_fd)
    screen = Screen(args.rows, args.cols)
    start = time.time()
    deadline = start + args.duration
    keys_at = args.keys_at if args.keys_at is not None else args.duration * 0.6
    keys_sent = not args.keys
    while time.time() < deadline:
        if not keys_sent and time.time() - start >= keys_at:
            keys_sent = True
            try:
                os.write(master_fd, args.keys.encode())
            except OSError:
                pass
        r, _, _ = select.select([master_fd], [], [], 0.2)
        if not r:
            continue
        try:
            chunk = os.read(master_fd, 65536)
        except OSError as exc:
            if exc.errno in (errno.EIO, errno.EBADF):
                break
            raise
        if not chunk:
            break
        screen.feed(chunk)

    # Quit clean, so curses restores the terminal. Then wait for the end.
    try:
        os.write(master_fd, b'q')
        time.sleep(0.4)
    except OSError:
        pass
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            break
        for _ in range(20):
            wpid, _status = os.waitpid(pid, os.WNOHANG)
            if wpid:
                break
            time.sleep(0.05)
        else:
            continue
        break
    try:
        os.close(master_fd)
    except OSError:
        pass

    out = screen.text()
    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write(out + '\n')
    sys.stdout.write(out + '\n')
    # A frame with almost no shapes means the tool never drew.
    non_blank = sum(1 for line in out.splitlines() if line.strip())
    sys.stderr.write(f'\n[capture_frame] non-blank lines: {non_blank}\n')
    return 0 if non_blank > 3 else 1


if __name__ == '__main__':
    sys.exit(main())
