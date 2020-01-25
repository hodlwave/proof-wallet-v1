import os
import subprocess
import re
from binascii import hexlify, unhexlify
from hashlib import sha256
from tempfile import NamedTemporaryFile
from proof.ux import ux_show_story
from proof.wallet import Wallet
from proof.bitcoind import BitcoindAdapter
from os import listdir
from os.path import isfile, join
from proof.constants import *

fg = lambda text, color: "\33[38;5;" + str(color) + "m" + text + "\33[0m"
bg = lambda text, color: "\33[48;5;" + str(color) + "m" + text + "\33[0m"

def color_text(text, color, formatter):
    return formatter(text, color)

def format_rolls(arr):
    return " ".join(arr)

def format_rolls_row(rolls, row, ROLLS_NUM_COLS, ROLLS_PER_ROW, ROLLS_PER_COL):
    """
    Render dice rolls row based on grid dimensions
    """
    result = ""
    for col in range(ROLLS_NUM_COLS): # render each column's header
        start = ROLLS_PER_ROW * row + ROLLS_PER_COL * col
        end = start + ROLLS_PER_COL
        result += f"Rolls {start + 1} through {end}\t"

    result += "\n" # newline

    for col in range(ROLLS_NUM_COLS): # render each column's rolls
        start = ROLLS_PER_ROW * row + ROLLS_PER_COL * col
        end = start + ROLLS_PER_COL
        result += format_rolls(rolls[start:end]) + "\t"

    result += "\n\n" # two newlines for legibility
    return result

def pprint_entropy(data):
    """
    Transforms raw bytes into a more human-readable form
    """
    out = ""
    for i in range(len(data) // 4):
        out += data[4*i: 4*i + 4].decode()
        out += "" if i == len(data) // 4 - 1 else " "
    return out

def display_mnemonic(mnemonic):
    words = mnemonic.split(" ")
    result = ""
    for i, word in enumerate(words):
        curlen = len(word)
        result += f"{' ' if i < 9 else ''}{str(i+1)}. {word}\n"
    return result

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

async def choose_from_list(msg_prefix, options):
    """
    Async utility that lets you choose from a list of items passed
    in. The list is rendered with an arrow pointing to the currently
    selected item, and the user presses confirm to make his selection.
    The msg_prefix is informational text rendered above the item list.

    Returns the numeric index selected.
    """
    selected = 0
    pointer = " --> "
    controls = """Controls:
[Enter] -- make selection
'n'     -- next item in list
'p'     -- previous item in list
'x'     -- go back
"""
    while True:
        msg = f"{msg_prefix}\n\n{controls}\n\n"
        for i, opt in enumerate(options):
            prefix = pointer if i == selected else len(pointer) * " "
            msg += prefix + options[i] + "\n"
        ch = await ux_show_story(msg, None, ['n', 'p', '\r', 'x'])
        if ch == 'n' and len(options) > 0:
            selected = (selected + 1) % len(options)
        elif ch == 'p' and len(options) > 0:
            selected = (selected - 1) % len(options)
        elif ch == '\r' and len(options) > 0:
            return selected
        elif ch == 'x':
            return None

async def import_data_warning(data):
    desc = f"You have scanned a QR code that represents the following data:\n\n{data}"
    return await ux_confirm(desc)

async def save_wallet_confirm(w):
    desc = f"You have chosen to save {w.name} (containing private key data) to the computer's filesystem."
    return await ux_confirm(desc)

async def ux_confirm(desc):
    msg = f"""Proof Wallet: Confirmation

{desc}

Are you sure you want to do this?

[Enter] -- Yes
'x'     -- No
"""
    ch = await ux_show_story(msg, None, ['\r', 'x'])
    if ch == '\r':
        return True
    return False

def wallet_fingerprints(w):
    """
    Returns the set of fingerprints for every signatory
    of the wallet.
    """
    out = set(map(lambda w: w.fingerprint, w.cosigners))
    out.add(w.fingerprint)
    return out

def is_valid_xpub(xpub, network):
    adapter = BitcoindAdapter(network)
    desc = f"pk({xpub})"
    try:
        adapter.bitcoin_cli_checkoutput("getdescriptorinfo", desc)
        return True
    except subprocess.CalledProcessError:
        return False

def validate_psbt(psbt_raw, w):
    """
    ******************************************************************
    ********************  SECURITY CRITICAL  *************************
    ******************************************************************

    Validates that the psbt is safe to sign based on an exhaustive list
    of invariants for the provided wallet.

    Keyword arguments:
    psbt_raw -- the base64 encoded psbt string
    w        -- the prospective signing Wallet
    """
    response = {
        "success": [],
        "warning": [],
        "error": [],
        "psbt": None,
        "importmulti_lo": None,
        "importmulti_hi": None,
        "analyze_result": None
    }
    try:
        # attempt to decode psbt
        psbt = w.decodepsbt(psbt_raw)
        # attempt to analyze psbt (should always succeed if decode succeeds)
        response["analyze_result"] = w.analyzepsbt(psbt_raw)

        pattern = "^m/([01])/(0|[1-9][0-9]*)$" # match m/{change}/{idx} and prevent leading zeros
        response["success"].append("The provided base64 encoded input is a valid PSBT.")

        fps = set(wallet_fingerprints(w))

        # GENERAL VALIDATIONS
        if len(psbt[PSBT_INPUTS]) < 1:
            response["error"].append(f"PSBT 'inputs' array is empty")
            return response
        if len(psbt[PSBT_OUTPUTS]) < 1:
            response["error"].append(f"PSBT 'outputs' array is empty")
            return response

        # INPUTS VALIDATIONS
        for i, _input in enumerate(psbt[PSBT_INPUTS]):
            # Ensure input spends a witness UTXO
            if PSBT_NON_WITNESS_UTXO in _input or PSBT_WITNESS_UTXO not in _input:
                response["error"].append(f"Tx input {i} doesn't spend the expected segwit utxo.")
                return response

            # Ensure input contains BIP32 derivations
            if PSBT_BIP32_DERIVS not in _input:
                response["error"].append(f"Tx input {i} does not contain bip32 derivation metadata.")
                return response

            # Get the set of master fingerprints in the input's BIP32 derivations; ensure
            # they are consistent with the wallet's fingerprints
            input_fps = set(map(lambda deriv: deriv[PSBT_BIP32_MASTER_FP], _input[PSBT_BIP32_DERIVS]))
            if fps != input_fps:
                response["error"].append(f"Tx input {i} does not have our set of wallet fingerprints.")
                return response

            # Ensure the witness utxo is the expected type: witness_v0_scripthash
            scriptpubkey_type = _input[PSBT_WITNESS_UTXO][PSBT_SCRIPTPUBKEY][PSBT_TYPE]
            if scriptpubkey_type != PSBT_WSH_TYPE:
                response["error"].append(f"Tx input {i} contains an incorrect scriptPubKey type: {scriptpubkey_type}.")
                return response

            # Ensure input contains a witness script
            if PSBT_WITNESS_SCRIPT not in _input:
                response["error"].append(f"Tx input {i} doesn't contain a witness script")
                return response

            # Ensure that the witness script hash equals the scriptPubKey
            witness_script = _input[PSBT_WITNESS_SCRIPT][PSBT_HEX]
            witness_script_hash = hexlify(sha256(unhexlify(witness_script)).digest()).decode()
            scriptPubKeyParts = _input[PSBT_WITNESS_UTXO][PSBT_SCRIPTPUBKEY][PSBT_ASM].split(" ")

            # Ensure the scriptPubKey is the expected format: "0 WITNESS_SCRIPT_HASH"
            # Probably already validated in Bitcoin Core given the type but be extra cautious
            if len(scriptPubKeyParts) != 2:
                response["error"].append(f"Tx input {i} has an unexpected scriptPubKey")
                return response
            if scriptPubKeyParts[0] != "0":
                response["error"].append(f"Tx input {i} has an unsupported scriptPubKey version: {scriptPubKeyParts[0]}.")
                return response
            if witness_script_hash != scriptPubKeyParts[1]:
                response["error"].append(f"The hash of the witness script for Tx input {i} does not match the provided witness UTXO scriptPubKey.")
                return response

            # Ensure that the actual address contained in the witness_utxo matches our
            # expectations given the BIP32 derivations provided
            actual_address = _input[PSBT_WITNESS_UTXO][PSBT_SCRIPTPUBKEY][PSBT_ADDRESS]

            # Ensure each public key comes from the same derivation path and this derivation path
            # abides by the proper format (enforced by regex)
            input_paths = set(map(lambda deriv: deriv[PSBT_BIP32_PATH], _input[PSBT_BIP32_DERIVS]))
            if len(input_paths) != 1:
                response["error"].append(f"Tx input {i} contains different bip32 derivation paths for multiple xpubs.")
                return response
            input_path = input_paths.pop()
            match_object = re.match(pattern, input_path)
            if match_object is None:
                response["error"].append(f"Tx input {i} contains an unsupported bip32 derivation path: {input_path}.")
                return response
            change, idx = map(int, match_object.groups())

            # Ensure expected address implied by metadata matches actual address supplied
            [expected_address] = w.deriveaddresses(idx, idx, change)
            if expected_address != actual_address:
                response["error"].append(f"Tx input {i} contains an incorrect address based on the supplied bip32 derivation metadata.")
                return response

            # Ensure sighash is not set at all or set correctly
            if PSBT_SIGHASH in _input and _input[PSBT_SIGHASH] != SIGHASH_ALL:
                response["error"].append(f"Tx input {i} specifies an unsupported sighash, '{_input[PSBT_SIGHASH]}'. The only supported sighash is {SIGHASH_ALL}")
                return response

            # Update limits for impormulti command
            if response["importmulti_lo"] is None or response["importmulti_lo"] > idx:
                response["importmulti_lo"] = idx
            if response["importmulti_hi"] is None or response["importmulti_hi"] < idx:
                response["importmulti_hi"] = idx

        response["success"].append("All input validations succeeded.")

        # OUTPUTS VALIDATIONS
        tx = psbt[PSBT_TX]
        change_indexes = []
        for i, output in enumerate(psbt[PSBT_OUTPUTS]):
            # Get the corresponding Tx ouput
            tx_out = tx[PSBT_TX_VOUT][i]
            if PSBT_BIP32_DERIVS not in output:
                # consider this output as not part of this wallet not an error or
                # warning as this could be a valid output spend
                continue

            # Get the set of master fingerprints in the output's BIP32 derivations; ensure
            # they are consistent with the wallet's fingerprints
            output_fps = set(map(lambda deriv: deriv[PSBT_BIP32_MASTER_FP], output[PSBT_BIP32_DERIVS]))
            if fps != output_fps:
                response["error"].append(f"Tx output {i} does not have our set of wallet fingerprints.")
                return response

            # Ensure we are spending change back to the proper output type: witness_v0_scripthash
            scriptpubkey_type = tx_out[PSBT_SCRIPTPUBKEY][PSBT_TYPE]
            if scriptpubkey_type != PSBT_WSH_TYPE:
                response["error"].append(f"Tx output {i} contains an incorrect scriptPubKey type: {scriptpubkey_type}.")
                return response

            # Ensure the scriptpubkey only contains 1 address (is this necessary?)
            if len(tx_out[PSBT_SCRIPTPUBKEY][PSBT_TX_ADDRESSES]) != 1:
                response["error"].append(f"Tx output {i} contains multiple addresses.")
                return response
            [actual_address] = tx_out[PSBT_SCRIPTPUBKEY][PSBT_TX_ADDRESSES]

            # Ensure each public key comes from the same derivation path and this derivation path
            # abides by the proper format (enforced by regex)
            output_paths = set(map(lambda deriv: deriv[PSBT_BIP32_PATH], output[PSBT_BIP32_DERIVS]))
            if len(output_paths) != 1:
                response["error"].append(f"Tx output {i} contains different bip32 derivation paths for multiple xpubs.")
                return response
            output_path = output_paths.pop()
            match_object = re.match(pattern, output_path)
            if match_object is None:
                response["error"].append(f"Tx output {i} contains an unsupported bip32 derivation path: {output_path}.")
                return response
            change, idx = map(int, match_object.groups())

            # Allow a user to spend change to an external address, but display a warning
            if change == 0:
                response["warning"].append(f"Tx output {i} spends change to an external receive address.")

            # Ensure the actual address in the Tx output matches the expected address given
            # the BIP32 derivation paths
            [expected_address] = w.deriveaddresses(idx, idx, change)
            if expected_address != actual_address:
                response["error"].append(f"Tx output {i} spends bitcoin to an incorrect address based on the supplied bip32 derivation metadata.")
                return response
            change_indexes.append(i) # change validations pass

        # Display a warning to the user if we can't recognize any change (suspicious)
        if len(change_indexes) == 0:
            response["warning"].append(f"""No change outputs were identified in this transaction. \
If you intended to send bitcoin back to your wallet as change, abort this signing process. \
If not, you can safely ignore this warning""")

        # Validations succeded!
        response["success"].append("All output validations succeeded.")
        response["psbt"] = psbt

    # Catches exceptions in decoding or analyzing PSBT
    except subprocess.CalledProcessError:
        response["error"].append("The provided base64 encoded input is NOT a valid PSBT.")
    # Catch any other unexpected exception that may occur
    except:
        response["error"].append("An unexpected error occurred during the PSBT validation process")
    return response
