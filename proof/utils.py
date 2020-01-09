import os
from binascii import hexlify
from tempfile import NamedTemporaryFile
from proof.ux import ux_show_story

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
    tmp1= NamedTemporaryFile()    
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
