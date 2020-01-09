import sys
import asyncio as aio
import subprocess
from proof.actions import *

def is_installed(program):
    return subprocess.call(["which", program]) == 0

async def intro():
    """
    Main control flow
    """
    ch = await network_select()
    if ch == 'q':
        sys.exit(0)
    network = {
        '1': "mainnet",
        '2': "testnet",
        '3': "regtest"
    }[ch]

    # Ensure all software dependencies are installed
    deps_installed = False
    deps = ['bitcoind', 'bitcoin-cli', 'qrencode', 'zbarcam', 'zbarimg']
    while not deps_installed:
        d = dict(map(lambda x: (x, is_installed(x)), deps))
        deps_installed = all(d.values())
        await diagnostic_report(d)

    await home(network)
    
loop = aio.get_event_loop()
loop.run_until_complete(intro())
loop.close()
