import asyncio as aio
import shutil
import os
import sys

# Adapted from https://stackoverflow.com/questions/510357/python-read-a-single-character-from-the-user
class Getch:
    def __init__(self):
        import tty

    def __call__(self):
        import tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

async def getch():
    q = aio.Queue()
    loop = aio.get_event_loop()
    aio.ensure_future(q.put(Getch()()), loop=loop)
    return (await q.get())

def get_terminal_size():
    size = shutil.get_terminal_size()
    return {
        "lines": size.lines,
        "columns": size.columns
    }

def word_wrap(ln, w):
    while ln:
        sp = ln.rfind(' ', 0, w)

        if sp == -1:
            # bad-break the line
            sp = min(len(ln), w)
            nsp = sp
        else:
            nsp = sp+1

        left = ln[0:sp]
        ln = ln[nsp:]

        if len(left) + 1 + len(ln) <= w:
            left = left + ' ' + ln
            ln = ''

        yield left

async def ux_show_story(msg, escape=None):
    # show a big long string, and wait for XY to continue
    # - returns character used to get out (X or Y)
    # - can accept other chars to 'escape' as well.
    # - accepts a stream or string
    top = 0
    while 1:
        size = get_terminal_size()
        H = size['lines']
        W = size['columns']
        ch = None
        lines = []

        for ln in msg.split('\n'):
            if len(ln) > W:
                lines.extend(word_wrap(ln, W))
            else:
                # ok if empty string, just a blank line
                lines.append(ln)
                
        # trim blank lines at end, add our own marker
        while not lines[-1]:
            lines = lines[:-1]
        
        # redraw
        os.system('clear')

        y=0
        for ln in lines[top:top+H]:
            print(ln)

        # wait to do something
        ch = await getch()
        if escape and (ch == escape or ch in escape):
            # allow another way out for some usages
            return ch
        elif ch == 'U':     # scroll up
            top = max(0, top-1)
        elif ch == 'D':     # scroll dn
            top = min(len(lines)-2, top+1)
