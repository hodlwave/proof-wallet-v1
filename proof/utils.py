import os
import subprocess
from binascii import hexlify
from tempfile import NamedTemporaryFile
from proof.ux import ux_show_story
from proof.wallet import Wallet
from os import listdir
from os.path import isfile, join

YELLOW_COLOR = 191
GREEN_COLOR = 118
RED_COLOR = 160

fg = lambda text, color: "\33[38;5;" + str(color) + "m" + text + "\33[0m"
bg = lambda text, color: "\33[48;5;" + str(color) + "m" + text + "\33[0m"

def color_text(text, color, formatter):
    return formatter(text, color)

def format_rolls(arr):
    return " ".join(arr)

def pprint_entropy(data):
    """
    Transforms raw bytes into a more human-readable form
    """
    out = ""
    for i in range(len(data) // 4):
        out += data[4*i: 4*i + 4].decode()
        out += "" if i == len(data) // 4 - 1 else " "
    return out

def generate_qr(data):
    # create temp files
    tmp1 = NamedTemporaryFile()
    tmp2 = NamedTemporaryFile()
    # write raw data to file 1
    with open(tmp1.name, 'w') as f1:
        f1.write(data)
    # write ANSII qr code from file 1 to file 2
    cmd = f"qrencode --read-from={tmp1.name} --output={tmp2.name} --type=ANSI"
    outcode = os.system(cmd)
    # read qr data and return
    with open(tmp2.name, 'r') as f2:
        out = f2.read()
    tmp1.delete
    tmp2.delete
    return out

async def scan_qr():
    """
    Async utility for scanning a qr code using zbarcam.
    Returns the scanned data as a string
    """
    cmd = ["zbarcam", "--raw", "--nodisplay"]
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ""):
        popen.stdout.close()
        popen.wait()
        return stdout_line.rstrip('\n')

def is_complete(w):
    return len(w.cosigners) + 1 == w.n

def get_all_wallets():
    path = Wallet.get_dir()
    wallet_files = [f for f in listdir(path) if isfile(join(path, f))]
    return list(map(lambda f: Wallet.load(f), wallet_files))

async def choose_from(msg_renderer, options, confirm = '\r', undo = 'u'):
    """
    Async utility for choosing from among multiple options (keys),
    with a provided story, confirmation & undo keys
    """
    chosen = None
    while True:
        ch = await ux_show_story(msg_renderer(chosen), None,  options + [confirm, undo])
        if ch in options:
            chosen = ch
        elif ch == undo and chosen is not None: # reset chosen
            chosen = None
        elif chosen is not None: # user is confirming choice
            return chosen    

async def choose_from_list(msg_prefix, options, _next = 'n', prev = 'p', confirm = '\r', back = 'x'):
    """
    Async utility that lets you choose from a list of items passed
    in. The list is rendered with an arrow pointing to the currently
    selected item, and the user presses confirm to make his selection.
    The msg_prefix is informational text rendered above the item list.

    Returns the numeric index selected.
    """
    selected = 0
    pointer = " --> "
    helptext = f"Press '{_next}' to go to the next element, '{prev}' to "
    helptext += f"go to the previous element, '{back}' to go exit this menu, and "
    helptext += "[ENTER] to make the desired selection."
    while True:
        msg = f"{msg_prefix}\n\n{helptext}" + "\n\n"
        for i, opt in enumerate(options):
            prefix = pointer if i == selected else len(pointer) * " "
            msg += prefix + options[i] + "\n"
        ch = await ux_show_story(msg, None, [_next, prev, confirm, back])
        if ch == _next and selected < len(options) - 1:
            selected += 1
        elif ch == prev and selected > 0:
            selected -= 1
        elif ch == confirm:
            return selected
        if ch == back:
            return None

async def import_data_warning(data):
    msg = f"""Proof Wallet: Import Data Warning

You have scanned a QR code that represents the following data:

{data}

Press [Enter] to confirm that this is the data you wanted to import. \
Press 'x' to abort this import.
"""
    ch = await ux_show_story(msg, None, ['\r', 'x'])
    if ch == '\r':
        return True
    return False
