import sys
import time
from Malwaric.modules import colors

def info(message, duration=0.5):
    frames = [
        "●",
        "◐",
        "○",
        "◑",
    ]
    end_time = time.time() + duration
    while time.time() < end_time:
        for frame in frames:
            for dots in range(1, 4):
                sys.stdout.write(f"{colors.red}\r[{frame}]{colors.normal} {message}{'.'*dots}")
                sys.stdout.flush()
                time.sleep(0.3)
    sys.stdout.write("Done\n")