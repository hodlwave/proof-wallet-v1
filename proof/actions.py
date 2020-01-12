import asyncio as aio
import subprocess
import sys
import os
from hashlib import sha256
from binascii import hexlify

from proof.ux import ux_show_story
from proof.wallet import Wallet, Cosigner
from proof.utils import *
from crypto.mnemonic import Mnemonic
from crypto import bip32

async def network_select():
    msg = """\
Welcome to Proof Wallet,
the dedicated PSBT multisig UI for Bitcoin Core.

Choose a network:
(1) Mainnet
(2) Testnet
(3) Regtest
"""
    return await ux_show_story(msg, None, ['1','2','3','q'])

async def diagnostic_report(d):
    """ 
    Diplays a diagnostic report showing whether
    all of the software dependencies are installed
    """    
    msg = "Diagnostic Report\n\n"
    msg += "All of the following programs must be installed (✔) on your computer before you can use Proof Wallet.\n\n"
    for k, v in d.items():
        msg += f"{k}: {'✔' if v else 'X'}\n"
    msg += "\nOnce all the programs are installed, press ENTER to proceed."
    return await ux_show_story(msg, None, ['\r'])
    
async def home(network):
    while True:
        msg = "Proof Wallet: Home\n\n"
        msg += "1) Create wallet\n"
        msg += "2) Load wallet\n"
        msg += "3) Exit\n"
        ch = await ux_show_story(msg, None, ['1', '2', '3', '4'])
        if ch == '1':
            await create_wallet(network)
        elif ch == '2':
            await load_wallet(network)
        else:
            sys.exit(0)

async def choose_policy():
    """
    Interaction for getting M and N from user
    """
    title = "Proof Wallet: Choose multisig policy"
    def m_msg_renderer(M):
        return f"""{title}

How many signatures (M) should be required to spend bitcoins from this wallet?

Choose a number from 1 to 9, and press [Enter], or [u] to undo.

{"Choice: " + M if M is not None else ""}
"""
    
    M = int(await choose_from(m_msg_renderer, ['1', '2', '3', '4', '5', '6', '7', '8', '9']))
    def n_msg_renderer(N):
        return f"""{title}

You have selected the number of required signatures, M = {M}

How many total signers (N) will this wallet consist of?

Choose a number from {M} to 9, and press [Enter], or [u] to undo.

NOTE: N must be greater than or equal to M.

{"Choice: " + N if N is not None else ""}
"""
    N = None
    N_choices = list(map(str, range(M, 10)))
    while N is None or N < M:
        N = int(await choose_from(n_msg_renderer, N_choices))
    return M, N

async def roll_dice():
    """
    Interaction for generating >= 256 bits of entropy
    with casino dice
    """
    N = 10 # total rolls needed
    rolls = []
    while True:
        msg = "Proof Wallet: Dice Entropy\n\n"
        msg += f"Roll a casino grade dice at least {N} times. "
        msg += f"Press 1-6 to roll, [d] to move on (only after {N} rolls!) and [q] to quit at any time\n\n"

        # Draw previous rows
        finished_chunks = (len(rolls) // 10)
        for i in range(finished_chunks):
            start, end = 10 * i, 10 * i + 10
            msg += f"Rolls {start + 1} through {end}\n"
            msg += format_rolls(rolls[start:end])
            msg += "\n\n"

        # Draw last row
        remaining = rolls[finished_chunks * 10:]
        msg += f"Rolls {finished_chunks * 10 + 1} through {finished_chunks * 10 + 10}\n"
        msg += "" if len(remaining) == 0 else format_rolls(remaining)

        ch = await ux_show_story(msg, None, ['1', '2', '3', '4', '5', '6', 'd', 'q'])
        if ch in ['1', '2', '3', '4', '5', '6']:
            rolls.append(ch)
        elif ch == 'd' and len(rolls) < N:
            continue
        elif ch == 'd' and len(rolls) >= N:
            return list(map(int, rolls))

async def get_computer_entropy():
    """
    Interaction for getting entropy from the computer,
    either directly or manually entering (if on Machine #2)
    """
    title = "Proof Wallet: Computer Entropy\n\n"
    msg = title
    msg += "Do you want to\n"
    msg += "1) Generate entropy directly from this computer\n"
    msg += "2) Manually enter entropy generated from the other Proof Wallet computer?"
    ch = await ux_show_story(msg, None, ['1', '2'])
    if ch == '1':
        return hexlify(sha256(os.urandom(256)).digest())
    digits = []
    hex_chars = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    escape_chars = ['u', '\r']
    ch = '*'
    while True:
        msg = title
        msg += "Enter the entropy generated from the other Proof Wallet computer below.\n\n"
        msg += "You should only have to enter 16 groups of 4 characters, "
        msg += "specifically digits {0, 1, 2, 3, 4, 5, 6, 7, 8, 9} and letters {a, b, c, d, e, f}.\n\n"
        msg += "Don't worry about entering spaces, and press 'u' to undo if you make a mistake.\n\n"
        msg += "Press [Enter] after you enter the last character correctly.\n\n"
        for i in range(len(digits) // 4 + 1):
            msg += "".join(digits[4*i : 4*i + 4])
            msg += " "
        ch = await ux_show_story(msg, None, hex_chars + escape_chars)
        if ch in hex_chars and len(digits) < 64:
            digits.append(ch)
        if ch == 'u' and len(digits) > 0:
            digits.pop()            
        elif ch == '\r' and len(digits) == 64:
            return bytes("".join(digits), "utf-8")

async def export_xpub(xpub):
    while True:
        msg = "The following QR code encodes your wallet's root xpub. "
        msg += "Scan it with your phone and transfer it to your online watch-only-wallet.\n\n"
        msg += "If the QR code appears broken, try maximizing your terminal window, zooming out and pressing [ENTER]. "
        msg += "When you've finished scanning the QR code, press 'x' to go back to the last menu.\n\n"
        msg += xpub + "\n\n"
        msg += generate_qr(xpub)
        ch = await ux_show_story(msg, None, ["\r", "x"])
        if ch == 'x':
            return

async def sensitive_data_warning():
    msg = "Proof Wallet: Sensitive Info Warning\n\n"
    msg += "The following screen displays sensitive private key data that could be used by an attaker to "
    msg += "steal your bitcoin.\n\nPerform all of the following security steps to minimize "
    msg += "the chance that your private key data is leaked over any side-channel:\n"
    msg += "* TODO: Copy Glacier Protocol Setup Protocol steps (Section VI)"
    msg += "\n\nPress [Enter] once you are ready to proceed"
    await ux_show_story(msg, None, ["\r"])

async def create_wallet(network):
    title = "Proof Wallet: Create Wallet\n\n"

    # ask user for desired M and N
    M, N = await choose_policy()
    
    msg = title
    # roll dice > N times
    rolls = await roll_dice()
    computer_entropy = await get_computer_entropy()
    # get additional entropy from os
    dice_entropy = sha256(bytes(rolls)).digest()
    # xor dice & computer entropy to generate wallet xprv
    combined_entropy = bytes([a ^ b for a, b in zip(computer_entropy, dice_entropy)])
    # save wallet, export xpub via QR
    Mnem = Mnemonic()
    mnemonic = Mnem.to_mnemonic(combined_entropy)
    seed = Mnem.to_seed(mnemonic)
    xprv = Mnem.to_hd_master_key(seed, network)

    await sensitive_data_warning()
    
    msg = title
    msg += f"Policy: {M} of {N} (M of N)\n\n"
    msg += "Dice rolls\n\n"
    for i in range(len(rolls) // 10 + 1):
        msg += f"Rolls {10*i + 1} to {10*i + 10}: "
        msg += format_rolls(map(str, rolls[10*i : 10*i + 10]))
        msg += "\n"
    msg += "\nComputer entropy\n" + pprint_entropy(computer_entropy)
    msg += "\n\n24 Word Mnemonic\n" + mnemonic
    msg += "\n\nIf this is the first computer in the Proof Wallet protocol, you should "
    msg += "enter the above dice rolls and computer-generated entropy into the second machine "
    msg += "to ensure that the same wallet mnemonic phrase is generated. If a different phrase "
    msg += "is generated, you should first try to repeat the process, and if that doesn't work, "
    msg += "STOP this process (press [q]), and seek help from a knowledgable party.\n\n"
    msg += "If both mnemonics match, you can proceed to export the root xpub on the following screen by pressing [Enter]"
    ch = await ux_show_story(msg, None, ['q', '\r'])
    if ch == 'q':
        sys.exit(0)
    # export root xpub via qr
    w = Wallet(mnemonic, [], M, N, network)
    await export_xpub(w.xpub)
    w.save()
    msg = f"""{title}\
The wallet skeleton data has been saved locally on this computer. \
Once you've constructed all {N} (i.e. N) of your multisignature wallets and \
exported their xpubs, you can load this wallet in the 'Load Wallet' \
menu and import the other {N-1} (i.e. N-1) xpubs to finalize this wallet.

Note that this wallet will be listed as {w.name} in the 'Load Wallet' \
menu.

Press [Enter] to return to the home menu.
"""
    return await ux_show_story(msg, None, ['\r'])

async def finalize_wallet(w):
    title = "Proof Wallet: Finalize Wallet"
    # import N xpubs flow
    cosigner_xpubs = []
    while True:
        num_remaining = w.n - len(cosigner_xpubs) - 1
        warning = "\tYou have not yet imported any cosigner xpubs.\n" if len(cosigner_xpubs) == 0 else ""
        cosigner_str = "\tcosigner | xpub\n" if len(cosigner_xpubs) > 0 else ""
        for (cosigner_fp, cosigner_xpub) in cosigner_xpubs:
            cosigner_str += f"\t{cosigner_fp} | {cosigner_xpub}\n"

        # check if wallet is complete
        if num_remaining == 0:
            # regenerate wallet with xpubs
            cosigners = list(map(lambda x: Cosigner(x[0], x[1]), cosigner_xpubs))
            w_updated = Wallet(w.mnemonic, cosigners, w.m, w.n, w.network)
            w_updated.save()
            msg = f"""{title}

{w.name} has now been finalized with the following cosigners:

{cosigner_str}\

You can now use this wallet to receive bitcoin and sign PSBTs.

Press [Enter] to return to the home menu.
"""
            return await ux_show_story(msg, None, ['\r'])
        # wallet is not yet complete
        msg = f"""{title}

This wallet has {w.n} total signers, so you have {num_remaining} xpubs \
left to import. The following list shows the cosigner xpubs you have imported so far:

{warning}{cosigner_str}\

Press [ENTER] to initiate the qr code scanner.
"""
        await ux_show_story(msg, None, ['\r'])
        xpub = await scan_qr()
        # TODO: perform validations on xpub
        if await import_data_warning(xpub):
            fp = bip32.fingerprint(xpub)
            cosigner_xpubs.append((fp, xpub))

async def view_receive_addresses(w):
    title = "Proof Wallet: View Receive Addresses\n\n"
    start = 0
    N = 20
    while True:
        external = w.deriveaddresses(start, start + N - 1, 0)
        internal = w.deriveaddresses(start, start + N - 1, 1)
        msg = title
        msg += f"Displaying receive and change addresses from index {start} to {start + N - 1}. "
        msg += f"Press 'n' to view the next set of {N} addresses and 'p' for the "
        msg += f"previous set of {N} addresses. Press 'x' to go back to the previous menu.\n\n"

        # display receive addreses
        msg += "Derivation | Receive Address\n"
        for i, addr in enumerate(external):
            msg += f"m/0/{str(i + start)} | "
            msg += f"{color_text(addr, GREEN_COLOR, fg)}\n"

        # display change addreses
        msg += f"\nDerivation | Change Address\n"
        for i, addr in enumerate(internal):
            msg += f"m/1/{str(i + start)} | "
            msg += f"{color_text(addr, YELLOW_COLOR, fg)}\n"

        ch = await ux_show_story(msg, None, ['n', 'p', 'x'])
        if ch == 'n':
            start = start + N
        elif ch == 'p' and start > 0:
            start = start - N
        elif ch == 'x':
            return

async def wallet_menu(w):
    header = f"""Proof Wallet: Wallet Menu

Wallet Name: {w.name}
Policy: {w.m} of {w.n}
Network: {w.network}
Highest hardened derivation path: {"'m/'"}

"""
    while True:
        if is_complete(w):
            msg = f"""{header}\
What would you like to do?
1) Export xpub
2) View receive addresses
3) Sign PSBT
4) Go back
"""
            ch = await ux_show_story(msg, None, ['1', '2', '3', '4'])
            if ch == '1':
                await export_xpub(w.xpub)
            elif ch == '2':
                await view_receive_addresses(w)
            elif ch == '3':
                await sign_psbt(w)
            else:
                return
        else:
            msg = f"""{header}\
What would you like to do?
1) Export xpub
2) Add cosigners to finalize wallet
3) Go back
"""
            ch = await ux_show_story(msg, None, ['1', '2', '3'])
            if ch == '1':
                await export_xpub(w.xpub)
            elif ch == '2':
                await finalize_wallet(w)
                # reload wallet in case it has been finalized
                w = Wallet.load(w.name)
            else:
                return

async def load_wallet(network):
    title = "Proof Wallet: Load Wallet"
    # choose wallet to finalize
    msg_prefix = f"{title}\n\nChoose a {network} wallet to load"
    wallets = list(filter(lambda w: w.network == network, get_all_wallets()))
    wallet_names = list(map(lambda w: w.name + " " + ("[FINALIZED]" if is_complete(w) else "[NOT FINALIZED]"), wallets))
    idx = await choose_from_list(msg_prefix, wallet_names)
    if idx == None: # user wants to go back
        return
    w = wallets[idx]
    return await wallet_menu(w)

async def sign_psbt(w):
    # import psbt in chunks via QR code
    psbt_raw_lst = []
    while True:
        psbt_str = ""
        for part in psbt_raw_lst:
            psbt_str += f"\t{part}\n\n"
        msg = f"""Proof Wallet: Sign PSBT [Import]

Import the incomplete Base64 encoded PSBT via QR code. If the PSBT is too large \
to fit in a single QR code, you can import the data chunk-by-chunk with multiple \
QR codes. Ensure that each QR code you import has the intended data before confirming.

Controls:
[Enter] --  activate the QR scanner to import the next piece of data
'd'     -- decode the PSBT once the data has been imported completely
'u'     -- undo the last imported piece of data.
'x'     -- abort this import altogether

Below are the individual PSBT chunks you have imported so far:

{"You have not yet imported any parts of a PSBT" if len(psbt_raw_lst) == 0 else psbt_str}
"""
        ch = await ux_show_story(msg, None, ['\r', 'd', 'u', 'x'])
        if ch == '\r':
            chunk = await scan_qr()
            psbt_raw_lst.append(chunk)
        elif ch == 'd' and len(psbt_raw_lst) > 0:
            break
        elif ch == 'u' and len(psbt_raw_lst) > 0:
            psbt_raw_lst.pop()
        else:
            return

    # perform validations on psbt
    psbt_raw = "".join(psbt_raw_lst)
    psbt_validation = validate_psbt(psbt_raw, w)
    # display result of validations
    success = len(psbt_validation["error"]) == 0
    success_str = "SUCCESSFUL" if success else "NOT SUCCESSFUL"
    SUCCESS_COLOR = GREEN_COLOR if success else RED_COLOR
    validation_result = color_text(f"PSBT validation was {success_str}", SUCCESS_COLOR, bg)
    if success:
        summary = "Successful validations:\n"
        for successful_validation in psbt_validation["success"]:
            summary += f"* {color_text(successful_validation, GREEN_COLOR, fg)}\n"
        if len(psbt_validation["warning"]) > 0:
            summary += "\nValidation warnings:\n"
            for warning in psbt_validation["warning"]:
                summary += f"* {warning}\n"
    else:
        summary = "Validation error:\n"
        summary += f"* {psbt_validation['error'][0]}"
    msg = f"""Proof Wallet: Sign PSBT [Validate]

The following are the results of the internal validations performed on the \
PSBT you imported for the given wallet {w.name}. Press [Enter] to proceed and \
'x' to abort.

{validation_result}

{summary}
"""
    ch = await ux_show_story(msg, None, ['\r', 'x'])
    if not success or ch == 'x':
        return

    # display transaction summary and allow user to sign

    # export signed psbt in chunks via QR code
    return
