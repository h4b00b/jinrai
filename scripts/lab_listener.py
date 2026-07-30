#!/usr/bin/env python3
"""A local TCP sink for measuring jinrai's L4 modes against a lab target.

Usage: lab_listener.py <port> <seconds> <hold|close|backlog> [backlog]

  hold     accept and retain every connection (exercises the connection table the
           way the connect flood intends)
  close    accept and immediately close our end (a fast drain, so the measurement
           reflects jinrai's pacing rather than this script's accept throughput)
  backlog  bind and listen, then do nothing: the kernel completes every handshake
           into the accept queue with zero work in this process. The most robust
           instrument for measuring the CLIENT's descriptor behaviour, because no
           Python scheduling delay can be mistaken for the target misbehaving.
           Only valid while the expected connection count stays under the backlog.

Prints a progress timeline and a total to stderr.
"""
import socket
import sys
import time


def main():
    port = int(sys.argv[1])
    secs = float(sys.argv[2])
    mode = sys.argv[3]
    hold = mode == "hold"
    backlog = int(sys.argv[4]) if len(sys.argv) > 4 else 4096

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(backlog)
    s.setblocking(False)
    print("LISTENING port=%d backlog=%d mode=%s" % (port, backlog, mode),
          file=sys.stderr, flush=True)

    if mode == "backlog":
        # Never call accept(): the kernel finishes each handshake and parks the
        # connection in the accept queue. Nothing this process does can perturb
        # the client's timing.
        time.sleep(secs)
        print("TOTAL accepted=0 (kernel backlog only)", file=sys.stderr, flush=True)
        return

    held = []
    n = 0
    start = time.time()
    end = start + secs
    mark = start + 0.5
    while time.time() < end:
        try:
            # Drain everything pending before yielding, so a slow accept loop
            # cannot be mistaken for the client under-delivering.
            while True:
                c, _ = s.accept()
                n += 1
                if hold:
                    held.append(c)
                else:
                    c.close()
        except BlockingIOError:
            time.sleep(0.0002)
        except OSError as e:
            print("ACCEPT ERR %s" % e, file=sys.stderr, flush=True)
            time.sleep(0.001)
        now = time.time()
        if now > mark:
            print("t+%.1f accepted=%d open=%d" % (now - start, n, len(held)),
                  file=sys.stderr, flush=True)
            mark = now + 0.5
    print("TOTAL accepted=%d" % n, file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
