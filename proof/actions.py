import asyncio as aio
import subprocess
import sys
import os
from hashlib import sha256
from binascii import hexlify
from decimal import Decimal

from proof.ux import ux_show_story
from proof.wallet import Wallet, Cosigner
from proof.trie import Trie
from proof.utils import *
from proof.constants import *
from crypto.mnemonic import Mnemonic
from crypto import bip32

# In-memory cache of wallets
WALLETS_GLOBAL = []

async def network_select():
    """Select the Bitcoin network to use for the given session."""
    msg = """\
Welcome to Proof Wallet,
the dedicated PSBT multisig UI for Bitcoin Core.

Choose a network:
(1) Mainnet
(2) Testnet
(3) Regtest
"""
    return await ux_show_story(msg, ['1','2','3','q'])

async def diagnostic_report(d):
    """Diagnostic report showing whether Proof Wallet dependencies are on the path"""
    msg = "Diagnostic Report\n\n"
    msg += "All of the following programs must be installed (✔) on your computer before you can use Proof Wallet.\n\n"
    for k, v in d.items():
        msg += f"{k}: {'✔' if v else 'X'}\n"
    msg += "\nOnce all the programs are installed, press ENTER to proceed."
    return await ux_show_story(msg, ['\r'])

async def home(network):
    """Proof Wallet home menu"""
    for w in get_all_wallets():
        WALLETS_GLOBAL.append(w)
    while True:
        msg = "Proof Wallet: Home\n\n"
        msg += "1) Create wallet\n"
        msg += "2) Load wallet\n"
        msg += "3) Restore wallet\n"
        msg += "4) Exit\n"
        ch = await ux_show_story(msg, ['1', '2', '3', '4'])
        if ch == '1':
            await create_wallet(network)
        elif ch == '2':
            await load_wallet(network)
        elif ch == '3':
            await restore_wallet(network)
        else:
            sys.exit(0)

async def choose_policy():
    """Interaction for getting M and N from user"""
    title = "Proof Wallet: Choose multisig policy"
    msg_prefix = f"""{title}

How many total signers (N) will this wallet consist of?
"""
    choices = ['2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15']
    idx = await choose_from_list(msg_prefix, choices)
    if idx == None: # user wants to go back
        return None
    N = int(choices[idx])

    msg_prefix = f"""{title}
You have selected the number of total participants in the quorum, N = {N}

How many signatures (M) should be required to spend bitcoins from this wallet?\
"""
    choices = list(map(str, range(1, N+1)))
    idx = await choose_from_list(msg_prefix, choices)
    if idx == None: # user wants to go back
        return
    M = int(choices[idx])

    return M, N

async def roll_dice():
    """Interaction for generating >= 256 bits of entropy with casino dice"""
    MINIMUM_ROLLS_REQUIRED = 100
    rolls = []

    while True:
        ROLLS_ROWS = len(rolls) // ROLLS_PER_ROW
        rolls_str = ""
        for i in range(ROLLS_ROWS + 1):
            rolls_str += format_rolls_row(rolls, i, ROLLS_NUM_COLS, ROLLS_PER_ROW, ROLLS_PER_COL)

        msg = f"""Proof Wallet: Dice Entropy

Create entropy by rolling a casino grade dice at least {MINIMUM_ROLLS_REQUIRED} times.

Controls:
[1, 2, 3, 4, 5, 6] -- roll dice
'u'                -- undo last dice roll
'x'                -- exit wallet creation
[Enter]            -- finish dice rolls and proceed (only after {MINIMUM_ROLLS_REQUIRED} rolls)

{rolls_str}
"""
        ch = await ux_show_story(msg, ['1', '2', '3', '4', '5', '6', '\r', 'x', 'u'])
        if ch in ['1', '2', '3', '4', '5', '6']:
            rolls.append(ch)
        elif ch == '\r' and len(rolls) < MINIMUM_ROLLS_REQUIRED:
            continue
        elif ch == '\r' and len(rolls) >= MINIMUM_ROLLS_REQUIRED:
            return rolls
        elif ch == 'u' and len(rolls) > 0:
            rolls.pop()
        elif ch == 'x':
            return None

async def get_computer_entropy():
    """
    Interaction for getting entropy from the computer.

    The user can get entropy from the computer (Machine #1) or
    directly enter the entropy generated on Machine #1 to verify
    the validity of the operations on Machine #2.
    """
    title = "Proof Wallet: Computer Entropy\n\n"
    while True:
        msg = title
        msg += "Do you want to\n"
        msg += "1) Generate entropy directly from this computer\n"
        msg += "2) Manually enter entropy generated from the other Proof Wallet computer?\n"
        msg += "3) Cancel wallet creation process and return to the home menu"
        ch = await ux_show_story(msg, ['1', '2', '3'])
        if ch == '1':
            return hexlify(sha256(os.urandom(256)).digest())
        elif ch == '3':
            return None
        elif ch == '2':
            digits = []
            escape_chars = ['u', '\r']
            ch = '*'
            while True:
                entropy_str = ""
                for i in range(len(digits) // 4 + 1):
                    entropy_str += "".join(digits[4*i : 4*i + 4])
                    entropy_str += " "
                msg = f"""{title}
Enter the entropy generated from the other Proof Wallet computer below.

You should only have to enter 16 groups of 4 characters, specifically digits \
0, 1, 2, 3, 4, 5, 6, 7, 8, 9 and letters 'a', 'b', 'c', 'd', 'e', 'f'.

Controls
[0-9, a-f] -- enter character entropy
[Enter]    -- confirm entropy and proceed to next menu
'u'        -- undo last character
'x'        -- go back

{entropy_str}
"""
                ch = await ux_show_story(msg, HEX_CHARS + escape_chars)
                if ch in HEX_CHARS and len(digits) < 64:
                    digits.append(ch)
                elif ch == 'u' and len(digits) > 0:
                    digits.pop()
                elif ch == '\r' and len(digits) == 64:
                    return bytes("".join(digits), "utf-8")
                else:
                    continue

async def choose_bip39_words():
    """Interaction for selecting a BIP39 mnemonic phrase."""

    # build Trie of bip39 wordlist
    curdir = os.path.dirname(__file__)
    f =  open(f"{curdir}/../crypto/english.txt", "r", encoding="utf-8")
    wordlist = [w.strip() for w in f.readlines()]
    trie = Trie()
    for word in wordlist:
        trie.add(word)
    # choose 24 words to create a complete mnemonic
    mnemonic = []
    cur = trie
    prefix = ""
    while len(mnemonic) < 24: # escape when the mnemonic is complete
        msg_prefix = f"""Proof Wallet: Restore Wallet

Selected words: {" ".join(mnemonic)}

Choose word #{len(mnemonic) + 1}:
"""
        options = []
        items = list(cur.children.items())
        for c, child_trie in items:
            # child trie contains one word
            # child trie contains multiple direct children
            # child trie contains multiple indirect
            suffix = c
            tmp = child_trie
            while tmp.word_finished == False and len(tmp.children.items()) == 1:
                next_char, tmp_child = list(tmp.children.items())[0]
                suffix += next_char
                tmp = tmp_child
            if not tmp.word_finished: # multiple possible prefixes
                options.append( (prefix + suffix + "*", c, False) )
            elif len(tmp.children) == 0: # word is finished and no other prefixes below
                options.append( (prefix + suffix, c, True) )
            else: # word is finished and there are other prefixes
                options.append( (prefix + suffix, c, True) )
                options.append( (prefix + suffix + "*", c, False) )
        idx = await choose_from_list(msg_prefix, list(map(lambda x: x[0], options)))
        if idx is None and cur.parent is not None: # go up a level
            cur = cur.parent
            prefix = prefix[:-1]
        elif idx is None and len(mnemonic) > 0: # remove last chosen word
            mnemonic.pop()
            cur = trie
            prefix = ""
        elif idx is None: # return to last menu
            return None
        else:
            chosen_str, c, finished = options[idx]
            child_trie = cur.children[c]
            prefix += c
            while child_trie.word_finished == False and len(child_trie.children.items()) == 1:
                next_char, child_trie = list(child_trie.children.items())[0]
                prefix += next_char
            if finished:
                mnemonic.append(prefix)
                cur = trie
                prefix = ""
            else:
                cur = child_trie
    return " ".join(mnemonic)

async def export_xpub(xpub):
    """
    Interaction for exporting xpub via QR code.

    Parameters:
        xpub (str): The wallet xpub
    """
    while True:
        msg = f"""Proof Wallet: Export xpub

The QR below is your master public key. Scan and transfer it to your \
watch-only-wallet as well as any other cosigner's in your multisignature \
quorum.

Controls
[Enter] -- Reload this window (zoom out and press this if the QR code looks broken
'x'     -- Go back to the wallet menu

Displayed data: {xpub}\n\n
{generate_qr(xpub)}
"""
        ch = await ux_show_story(msg, ["\r", "x"])
        if ch == 'x':
            return

async def restore_wallet(network):
    """Restore a wallet from a saved BIP39 phrase."""

    # ask user for desired M and N
    policy = await choose_policy()
    if policy is None: # user canceled selection
        return
    M, N = policy

    Mnem = Mnemonic()
    # Warn user about private key data on-screen
    if not await sensitive_data_warning():
        return
    mnemonic = await choose_bip39_words() # have user input their mnemonic
    if mnemonic is None: # user canceled wallet restoration
        return
    elif Mnem.check(mnemonic) == False:
        msg = f"""Proof Wallet: Restore Wallet

The 24 BIP39 words you selected do not form a valid mnemonic.

Press [Enter] return to the home menu.
"""
        return await ux_show_story(msg, '\r')

    msg = f"""Proof Wallet: Restore Wallet

Policy: {M} of {N} (M of N)

24 Word Mnemonic
{mnemonic}

You can now proceed to this wallet's menu where you'll be able to export its extended \
public key and finalize it by importing cosigner extended public keys.

Controls
'x'     -- Abort wallet creation process
[Enter] -- Go to wallet menu
"""
    ch = await ux_show_story(msg, ['x', '\r'])
    if ch == 'x':
        return
    w = Wallet(mnemonic, [], M, N, network)
    WALLETS_GLOBAL.append(w)
    return await wallet_menu(w)

async def create_wallet(network):
    """Create a new wallet with user-supplied entropy."""

    # ask user for desired M and N
    policy = await choose_policy()
    if policy is None: # user canceled selection
        return
    M, N = policy

    # Warn user about private key data on-screen
    if not await sensitive_data_warning():
        return

    # roll dice > N times
    rolls = await roll_dice()
    if rolls is None:
        return
    rolls_ints = list(map(int, rolls))

    computer_entropy = await get_computer_entropy()
    if computer_entropy is None:
        return
    # get additional entropy from os
    dice_entropy = sha256(bytes(rolls_ints)).digest()
    # xor dice & computer entropy to generate wallet xprv
    combined_entropy = bytes([a ^ b for a, b in zip(computer_entropy, dice_entropy)])
    # generate mnemonic from entropy
    Mnem = Mnemonic()
    mnemonic = Mnem.to_mnemonic(combined_entropy)
    seed = Mnem.to_seed(mnemonic)
    xprv = Mnem.to_hd_master_key(seed, network)

    ROLLS_ROWS = len(rolls) // ROLLS_PER_ROW
    rolls_str = ""
    for i in range(ROLLS_ROWS + 1):
        rolls_str += format_rolls_row(rolls, i, ROLLS_NUM_COLS, ROLLS_PER_ROW, ROLLS_PER_COL)

    msg = f"""Proof Wallet: Create Wallet

Policy: {M} of {N} (M of N)

Dice rolls\n
{rolls_str}
Computer entropy
{pprint_entropy(computer_entropy)}

Mnemonic
{display_mnemonic(mnemonic)}

If this is the first computer in the Proof Wallet protocol, you should \
enter the above dice rolls and computer-generated entropy into the second machine \
to ensure that the same wallet mnemonic phrase is generated. If a different phrase \
is generated, you should first try to repeat the process, and if that doesn't work, \
abort this process immediately and seek help from a knowledgable party.

If both mnemonics match, you can proceed to this wallet's menu where you'll be able \
to export its extended public key and finalize it by importing cosigner extended public \
keys.

Controls
'x'     -- Abort wallet creation process
[Enter] -- Go to wallet menu
"""
    ch = await ux_show_story(msg, ['x', '\r'])
    if ch == 'x':
        return
    w = Wallet(mnemonic, [], M, N, network)
    WALLETS_GLOBAL.append(w)
    return await wallet_menu(w)

async def finalize_wallet(w):
    """Finalize a multisig wallet by adding cosigner xpubs/fingerprints."""

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
            msg = f"""{title}

{w.name} has now been finalized with the following cosigners:

{cosigner_str}\

You can now use this wallet to receive bitcoin and sign PSBTs.

Press [Enter] to go to the wallet menu.
"""
            await ux_show_story(msg, ['\r'])
            # update the wallet in WALLETS_GLOBAL
            idx = list(map(lambda w: w.name, WALLETS_GLOBAL)).index(w.name)
            WALLETS_GLOBAL[idx] = w_updated
            return w_updated

        # wallet is not yet complete
        msg = f"""{title}

This wallet has {w.n} total signers, so you have {num_remaining} xpubs \
left to import. The following list shows the cosigner xpubs you have imported so far:

{warning}{cosigner_str}\

Controls:
[Enter] -- initiate the qr code scanner
'x'     -- abort finalize wallet process
"""
        ch = await ux_show_story(msg, ['\r', 'x'])
        if ch == 'x':
            return w
        xpub = await scan_qr()
        if not is_valid_xpub(xpub, w.network):
            msg = f"""{title}

Import Error
The data you attempted to import {xpub} is not a valid extended \
public key.

Controls:
[Enter] -- retry the import
'x'     -- abort finalize wallet process
"""
            ch = await ux_show_story(msg, ['\r', 'x'])
            if ch == '\r':
                continue
            return
        if await import_data_warning(xpub):
            derived_fingerprint = bip32.fingerprint(xpub)
            input_fingerprint = ""
            while True:
                msg = f"""{title}

If the cosigner you imported is from another Proof Wallet or has \
no hardened derivation (i.e. it's derivation is 'm'), the cosigner \
fingerprint will be derived automatically. Otherwise manually enter \
the {FINGERPRINT_LENGTH} digit fingerprint using the numeric and hex keys.

Controls:
[Enter]    -- Use derived fingerprint if input buffer is empty else confirm manual input
[0-9, a-f] -- enter manual digits of fingerprint
'u'        -- undo last manual digit

Derived fingerprint: {derived_fingerprint}
Input fingerprint: {input_fingerprint}
"""
                ch = await ux_show_story(msg, ['\r', 'u'] + HEX_CHARS)
                if ch == '\r' and input_fingerprint == "":
                    cosigner_xpubs.append((derived_fingerprint, xpub))
                    break
                elif ch == '\r' and len(input_fingerprint) == FINGERPRINT_LENGTH:
                    cosigner_xpubs.append((input_fingerprint, xpub))
                    break
                elif ch in HEX_CHARS and len(input_fingerprint) < FINGERPRINT_LENGTH:
                    input_fingerprint += ch
                elif ch == 'u':
                    input_fingerprint = input_fingerprint[:-1]

async def view_receive_addresses(w):
    """Show receive addresses for a given wallet."""
    title = "Proof Wallet: View Receive Addresses"
    start = 0
    N = 10
    while True:
        external = w.deriveaddresses(start, start + N - 1, 0)
        internal = w.deriveaddresses(start, start + N - 1, 1)

        # display receive addreses
        addr_str = "Derivation | Receive Address\n"
        for i, addr in enumerate(external):
            addr_str += f"m/0/{str(i + start)} | "
            addr_str += f"{color_text(addr, GREEN_COLOR, fg)}\n"

        # display change addreses
        addr_str += f"\nDerivation | Change Address\n"
        for i, addr in enumerate(internal):
            addr_str += f"m/1/{str(i + start)} | "
            addr_str += f"{color_text(addr, YELLOW_COLOR, fg)}\n"

        msg = f"""{title}

Addresses {start} to {start + N - 1}

{addr_str}

Controls
'n' -- Next {N} addresses
'p' -- Previous {N} addresses
'x' -- Go back to wallet menu
"""
        ch = await ux_show_story(msg, ['n', 'p', 'x'])
        if ch == 'n':
            start = start + N
        elif ch == 'p' and start > 0:
            start = start - N
        elif ch == 'x':
            return

async def show_mnemonic(w):
    """Display BIP39 mnemonic phrase for wallet."""

    # Warn user about private key data onscreen
    if not await sensitive_data_warning():
        return

    desc = f"You have chosen to view your mnemonic phrase containing sensitive private key data."
    msg = f"""Proof Wallet: Show mnemonic

{display_mnemonic(w.mnemonic)}

Controls
[Enter] -- Go back to wallet menu
"""
    return await ux_show_story(msg, ['\r'])

async def wallet_menu(w):
    """Wallet home menu."""
    header = f"""Proof Wallet: Wallet Menu

Wallet Name: {w.name}
Fingerprint: {w.fingerprint}
Policy: {w.m} of {w.n}
Network: {w.network}
Highest hardened derivation path: {"'m'"}

"""
    while True:
        if is_complete(w):
            cosigner_info = ""
            for cosigner in w.cosigners:
                cosigner_info += f"{cosigner.fingerprint}    | {cosigner.xpub}\n"
            msg = f"""{header}\
Cosigners:
fingerprint | extended public key
{cosigner_info}
What would you like to do?
1) Export xpub
2) View receive addresses
3) Sign PSBT
4) Show mnemonic
5) Save Wallet
6) Go back
"""
            ch = await ux_show_story(msg, ['1', '2', '3', '4', '5', '6'])
            if ch == '1':
                await export_xpub(w.xpub)
            elif ch == '2':
                await view_receive_addresses(w)
            elif ch == '3':
                await sign_psbt(w)
            elif ch == '4':
                await show_mnemonic(w)
            elif ch == '5':
                if await save_wallet_confirm(w):
                    w.save()
            else:
                return
        else:
            msg = f"""{header}\
What would you like to do?
1) Export xpub
2) Add cosigners to finalize wallet
3) Show mnemonic
4) Save Wallet
5) Go back
"""
            ch = await ux_show_story(msg, ['1', '2', '3', '4', '5'])
            if ch == '1':
                await export_xpub(w.xpub)
            elif ch == '2':
                w = await finalize_wallet(w)
            elif ch == '3':
                await show_mnemonic(w)
            elif ch == '4':
                if await save_wallet_confirm(w):
                    w.save()
            else:
                return

async def load_wallet(network):
    """Load a wallet from the cache for the given network."""
    title = "Proof Wallet: Load Wallet"
    # choose wallet to finalize
    msg_prefix = f"{title}\n\nChoose a {network} wallet to load"
    wallets = list(filter(lambda w: w.network == network, WALLETS_GLOBAL))
    wallet_names = list(map(lambda w: w.name + " " + ("[FINALIZED]" if is_complete(w) else "[NOT FINALIZED]"), wallets))
    idx = await choose_from_list(msg_prefix, wallet_names)
    if idx == None: # user wants to go back
        return
    w = wallets[idx]
    return await wallet_menu(w)

async def display_psbt(w, psbt, analyze_result):
    """
    Display a PSBT in user-friendly format and ask user to sign.

    Parameters:
        w            (Wallet): wallet that can sign the given PSBT
        psbt           (dict): python dict loaded from bitcoin-cli decodepsbt RPC call
        analyze_result (dict): python dict loaded from bitcoin-cli analyzepsbt RPC call

    Returns:
        '\r': confirmation that user intends to sign psbt
        'x' : user cancels menu / rejects signing psbt
    """
    tx = psbt[PSBT_TX]
    txid = tx[PSBT_TX_TXID]
    num_vin = len(tx[PSBT_TX_VIN])
    num_vout = len(tx[PSBT_TX_VOUT])

    fee = Decimal(psbt[PSBT_FEE]).quantize(SATOSHI_PLACES)
    fee_rate_raw = Decimal(analyze_result[ANALYZE_ESTIMATED_FEERATE]).quantize(SATOSHI_PLACES)
    fee_rate = round(FEE_RATE_MULTIPLIER * fee_rate_raw, 1) # convert and round BTC/kB to sat/byte
    vsize = analyze_result[ANALYZE_ESTIMATED_VSIZE]

    # Render transaction inputs
    def parse_input(psbt, idx):
        txid = psbt[PSBT_TX][PSBT_TX_VIN][idx][PSBT_TX_TXID]
        vout = psbt[PSBT_TX][PSBT_TX_VIN][idx][PSBT_TX_VOUT]
        addr = psbt[PSBT_INPUTS][idx][PSBT_WITNESS_UTXO][PSBT_SCRIPTPUBKEY][PSBT_ADDRESS]
        amount = Decimal(psbt[PSBT_INPUTS][idx][PSBT_WITNESS_UTXO][PSBT_AMOUNT]).quantize(SATOSHI_PLACES)
        return (txid, vout, addr, amount)
    inputs = list(map(lambda i: parse_input(psbt, i), range(num_vin)))
    inputs_str = f"Inputs ({num_vin})\n"
    for txin, vout, addr, amount in inputs:
        txid_formatted = txin[:10] + "..." + txin[-10:]
        addr_colored = color_text(addr, GREEN_COLOR, fg)
        inputs_str += f"{txid_formatted}:{vout}\t{addr_colored}\t{amount}\n"

    # Render transaction outputs
    def parse_output(psbt, idx):
        change = PSBT_BIP32_DERIVS in psbt[PSBT_OUTPUTS][idx]
        [addr] = psbt[PSBT_TX][PSBT_TX_VOUT][idx][PSBT_SCRIPTPUBKEY][PSBT_TX_ADDRESSES]
        value = Decimal(psbt[PSBT_TX][PSBT_TX_VOUT][idx][PSBT_TX_VALUE]).quantize(SATOSHI_PLACES)
        return (addr, value, change)
    outputs = list(map(lambda i: parse_output(psbt, i), range(num_vout)))
    outputs_str = f"Outputs ({num_vout})\n"
    for addr, value, change in outputs:
        addr_colored = color_text(addr, YELLOW_COLOR, fg) if change else addr
        outputs_str += f"{addr_colored}\t{value}\n"
    msg = f"""Proof Wallet: Sign PSBT [View & Sign]

Transaction ID: {txid}
Virtual size: {vsize} vbyte
Fee (total): {fee}
Fee (rate): {fee_rate} sat/byte


{inputs_str}
{outputs_str}

Press [Enter] to sign the transaction and proceed to the QR code export step.
Press 'x' to abort the signing process and return to the Wallet Menu.
"""
    return await ux_show_story(msg, ["\r", 'x'])

async def export_psbt(psbt):
    """Exports a base64 encoded psbt in a batch of QR codes."""

    CHUNK_SIZE = 200 # don't display a QR code larger than CHUNK_SIZE bytes
    chunked = [
        # get chunk of bytes, convert to base64 bytes and decode to string
        psbt[i: i + CHUNK_SIZE]
        for i in range(0, len(psbt), CHUNK_SIZE)
    ]
    i = 0
    while True:
        msg = f"""Proof Wallet: Sign PSBT [Export]

The following QR code is part {i+1}/{len(chunked)} of the PSBT you signed. \
You should scan each part with your phone and transfer them to a watch-only-wallet, \
where you can recombine the parts and combine them with other PSBTs you've \
signed, finalize the transaction, and broadcast it to the Bitcoin network.

Controls:
'n' -- view next QR code
'p' -- view previous QR code
'x' -- go back Wallet menu

{chunked[i]}\n\n
{generate_qr(chunked[i])}
"""
        ch = await ux_show_story(msg, ['n', 'p', 'x'])
        if ch == 'n' and i < len(chunked) - 1:
            i += 1
        elif ch == 'p' and i > 0:
            i -= 1
        elif ch == 'x':
            return

async def sign_psbt(w):
    """
    Interaction for wallet to sign psbt.

    Includes import psbt in a batch of QR codes, performing automated
    validations on the imported data, displaying a summarized view of
    the transaction for the user to evaluate / sign.

    Parameters:
        w (Wallet): the wallet that would perform the signing role
    """

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
        ch = await ux_show_story(msg, ['\r', 'd', 'u', 'x'])
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
    validation_result = f"PSBT validation was {color_text(success_str, SUCCESS_COLOR, bg)}"
    summary = ""
    if success:
        if len(psbt_validation["warning"]) > 0:
            summary += "\nWarnings:\n"
            for warning in psbt_validation["warning"]:
                summary += f"* {color_text(warning, ORANGE_COLOR, fg)}\n"
        summary += "\nSuccesses:\n"
        for successful_validation in psbt_validation["success"]:
            summary += f"* {color_text(successful_validation, GREEN_COLOR, fg)}\n"
    else:
        summary += "Error:\n"
        summary += f"* {psbt_validation['error'][0]}"
    msg = f"""Proof Wallet: Sign PSBT [Validate]

The following are the results of the internal validations performed on the \
PSBT you imported for the given wallet {w.name}. Press [Enter] to proceed and \
'x' to abort.

{validation_result}

{summary}
"""
    ch = await ux_show_story(msg, ['\r', 'x'])
    if not success or ch == 'x':
        return

    # display transaction summary and allow user to sign
    psbt = psbt_validation["psbt"]
    analyze_result = psbt_validation["analyze_result"]
    ch = await display_psbt(w, psbt, analyze_result)
    if ch == 'x':
        return

    # sign the psbt
    psbt_processed = w.walletprocesspsbt(
        psbt_raw,
        psbt_validation["importmulti_lo"],
        psbt_validation["importmulti_hi"]
    )

    # export signed psbt in chunks via QR code
    await export_psbt(psbt_processed["psbt"])
