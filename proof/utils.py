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

YELLOW_COLOR = 191
GREEN_COLOR = 2
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
        if ch == 'n':
            selected = (selected + 1) % len(options)
        elif ch == 'p':
            selected = (selected - 1) % len(options)
        elif ch == '\r':
            return selected
        elif ch == 'x':
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

def wallet_fingerprints(w):
    """
    Returns the set of fingerprints for every signatory
    of the wallet. Fingerprints are converted to lowercase
    consistent with Bitcoin Core
    """
    out = set(map(lambda w: w.fingerprint.lower(), w.cosigners))
    out.add(w.fingerprint.lower())
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
    Validates that the psbt is safe to sign based on
    a stringent set of criteria for the provided wallet.

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
        "importmulti_hi": None
    }
    try:
        # attempt to decode psbt
        psbt = w.decodepsbt(psbt_raw)
        pattern = "^m/([01])/(0|[1-9][0-9]*)$" # match m/{change}/{idx} and prevent leading zeros
        response["success"].append("The provided base64 encoded input is a valid PSBT.")
        # INPUTS VALIDATION
        fps = set(wallet_fingerprints(w))
        for i, _input in enumerate(psbt[PSBT_INPUTS]):
            if PSBT_NON_WITNESS_UTXO in _input or PSBT_WITNESS_UTXO not in _input:
                response["error"].append(f"Tx input {i} doesn't spend the expected segwit utxo.")
                return response
            if PSBT_BIP32_DERIVS not in _input:
                response["error"].append(f"Tx input {i} does not contain bip32 derivation metadata.")
                return response
            input_fps = set(map(lambda deriv: deriv[PSBT_BIP32_MASTER_FP], _input[PSBT_BIP32_DERIVS]))
            if fps != input_fps:
                response["error"].append(f"Tx input {i} does not have our set of wallet fingerprints.")
                return response
            if PSBT_SCRIPTPUBKEY not in _input[PSBT_WITNESS_UTXO]:
                response["error"].append(f"Tx input {i} does not have a scriptPubKey.")
                return response
            scriptpubkey_type = _input[PSBT_WITNESS_UTXO][PSBT_SCRIPTPUBKEY][PSBT_TYPE]
            if scriptpubkey_type != PSBT_WSH_TYPE:
                response["error"].append(f"Tx input {i} contains an incorrect scriptPubKey type: {scriptpubkey_type}.")
                return response
            # ensure psbt has a witness script and that the scriptPubKey is the hash of the witness script
            if PSBT_WITNESS_SCRIPT not in _input:
                response["error"].append(f"Tx input {i} doesn't contain a witness script")
                return response
            witness_script = _input[PSBT_WITNESS_SCRIPT][PSBT_HEX]
            witness_script_hash = hexlify(sha256(unhexlify(witness_script)).digest()).decode()
            scriptPubKeyParts = _input[PSBT_WITNESS_UTXO][PSBT_SCRIPTPUBKEY][PSBT_ASM].split(" ")
            if len(scriptPubKeyParts) != 2:
                response["error"].append(f"Tx input {i} has an unexpected scriptPubKey")
                return response
            if scriptPubKeyParts[0] != "0":
                response["error"].append(f"Tx input {i} has an unsupported scriptPubKey version: {scriptPubKeyParts[0]}.")
                return response
            if witness_script_hash != scriptPubKeyParts[1]:
                response["error"].append(f"The hash of the witness script for Tx input {i} does not match the provided witness UTXO scriptPubKey.")
                return response
            actual_address = _input[PSBT_WITNESS_UTXO][PSBT_SCRIPTPUBKEY][PSBT_ADDRESS]
            # verify bip32_derivs path invariants
            input_paths = set(map(lambda deriv: deriv[PSBT_BIP32_PATH], _input[PSBT_BIP32_DERIVS]))
            if len(input_paths) > 1: # |_input_paths| can't be zero because already asserted fingerprint set is nonempty
                response["error"].append(f"Tx input {i} contains multiple DIFFERENT bip32 derivation paths.")
                return response
            input_path = input_paths.pop()
            match_object = re.match(pattern, input_path)
            if match_object is None:
                response["error"].append(f"Tx input {i} contains an unsupported bip32 derivation path: {input_path}.")
                return response
            change, idx = map(int, match_object.groups())
            # Update limits for impormulti command
            if response["importmulti_lo"] is None or response["importmulti_lo"] > idx:
                response["importmulti_lo"] = idx
            if response["importmulti_hi"] is None or response["importmulti_hi"] < idx:
                response["importmulti_hi"] = idx
            [expected_address] = w.deriveaddresses(idx, idx, change)
            if expected_address != actual_address:
                response["error"].append(f"Tx input {i} contains an incorrect address based on the supplied bip32 derivation metadata.")
                return response
            # check sighash
            if PSBT_SIGHASH in _input and _input[PSBT_SIGHASH] != SIGHASH_ALL:
                response["error"].append(f"Tx input {i} specifies an unsupported sighash, '{_input[PSBT_SIGHASH]}'. The only supported sighash is {SIGHASH_ALL}")
                return response
        response["success"].append("All input validations succeeded.")

        # OUTPUTS VALIDATION
        tx = psbt[PSBT_TX]
        change_indexes = []
        for i, output in enumerate(psbt[PSBT_OUTPUTS]):
            tx_out = tx[PSBT_TX_VOUT][i]
            if PSBT_BIP32_DERIVS not in output:
                # consider this output as not part of this wallet not an error or
                # warning as this could be a valid output spend
                continue
            output_fps = set(map(lambda deriv: deriv[PSBT_BIP32_MASTER_FP], output[PSBT_BIP32_DERIVS]))
            if fps != output_fps:
                response["error"].append(f"Tx output {i} does not have our set of wallet fingerprints.")
                return response
            scriptpubkey_type = tx_out[PSBT_SCRIPTPUBKEY][PSBT_TYPE]
            if scriptpubkey_type != PSBT_WSH_TYPE:
                response["error"].append(f"Tx output {i} contains an incorrect scriptPubKey type: {scriptpubkey_type}.")
                return response
            [actual_address] = tx_out[PSBT_SCRIPTPUBKEY][PSBT_TX_ADDRESSES]
            # verify bip32_derivs path invariants
            output_paths = set(map(lambda deriv: deriv[PSBT_BIP32_PATH], output[PSBT_BIP32_DERIVS]))
            if len(output_paths) > 1: # |output_paths| can't be zero because already asserted fingerprint set is nonempty
                response["error"].append(f"Tx output {i} contains multiple DIFFERENT bip32 derivation paths.")
                return response
            output_path = output_paths.pop()
            match_object = re.match(pattern, output_path)
            if match_object is None:
                response["error"].append(f"Tx output {i} contains an unsupported bip32 derivation path: {output_path}.")
                return response
            change, idx = map(int, match_object.groups())
            if change == 0:
                response["warning"].append(f"Tx output {i} spends change to an external receive address.")
            [expected_address] = w.deriveaddresses(idx, idx, change)
            if expected_address != actual_address:
                response["error"].append(f"Tx output {i} spends bitcoin to an incorrect address based on the supplied bip32 derivation metadata.")
                return response
            change_indexes.append(i) # change validations pass
        if len(change_indexes) == 0:
            response["warning"].append(f"No change outputs were identified in this Tx. If you intended to send change back to your wallet, you should abort this signing process.")
        response["success"].append("All output validations succeeded.")
        response["psbt"] = psbt
    except subprocess.CalledProcessError:
        response["error"].append("The provided base64 encoded input is NOT a valid PSBT.")
    except:
        response["error"].append("An unexpected error occurred during the PSBT validation process")
    return response
