import json
import os
import subprocess
from proof.bitcoind import BitcoindAdapter
from crypto.mnemonic import Mnemonic
from crypto import bip32

class Cosigner:
    """
    Class to hold cosigner fingerprint and xpub

    Attributes:
        fingerprint (str): the cosigner fingerprint associated with their master public key
        xpub        (str): the cosigner xpub at the highest hardened derivation
    """
    def __init__(self, fingerprint, xpub):
        self.fingerprint = fingerprint
        self.xpub = xpub

class Wallet:
    """
    Class representing a basic multisignature p2wsh wallet with private key data for
    one signer. Includes useful wallet methods that function via Bitcoin Core's RPC
    commands.

    Attributes:
        mnemonic   (str): the BIP39 mnemonic for the wallet's signer
        cosigners  (str): the wallet's cosigner public key data
        m          (int): the minimum number signatures required to spend bitcoin
        n          (int): the total number of signatures in this wallet
        network    (str): the blockchain this wallet uses; one of {"mainnet", "testnet", "regtest"}
        name       (str): (optional) name of this wallet
    """
    def __init__(self, mnemonic, cosigners, m, n, network="mainnet", name=None):
        self.network = network
        # ensure bitcoind running
        self.adapter.ensure_bitcoind_running()

        self.mnemonic = mnemonic
        self.cosigners = cosigners
        self.m = m
        self.n = n
        self.name = f"wallet-{self.fingerprint}" if name is None else name

        # create wallet
        self.createwallet()

    @property
    def xprv(self):
        """Derives the signer's xprv"""
        M = Mnemonic()
        seed = M.to_seed(self.mnemonic)
        return M.to_hd_master_key(seed, self.adapter.network)

    @property
    def xpub(self):
        """Derives the signer's xpub"""
        desc = f"pk({self.xprv})"
        out = self.adapter.bitcoin_cli_json("getdescriptorinfo", desc)
        pubdesc = out['descriptor'] # 'pk(XPUB)#checksum'
        return pubdesc[3:-10] # slice off 'pk(' prefix and ')#checksum' suffix

    @property
    def fingerprint(self):
        """Derives the signer's bip32 fingerprint"""
        return bip32.fingerprint(self.xpub)

    @property
    def adapter(self):
        """Retrieves an adapter for interfacing with Bitcoin Core"""
        return BitcoindAdapter(self.network)

    @staticmethod
    def get_dir():
        """Gets the directory where this wallet can be saved to"""
        _dir = os.getenv("HOME") + "/.proof"
        if not os.path.isdir(_dir):
            os.makedirs(_dir)
        return _dir

    @property
    def wallet_path(self):
        """Gets the path where this wallet would be if saved to the filesystem"""
        return Wallet.get_dir() + "/" + self.name

    def save(self):
        """Saves this wallet to the filesystem as a json file"""
        data = json.dumps(self, default=lambda o: o.__dict__)
        with open(self.wallet_path, 'w') as f:
            f.write(data)

    @classmethod
    def load(cls, name):
        """Loads the wallet with the given name from the filesystem"""
        path = cls.get_dir() + "/" + name
        with open(path, 'r') as f:
            d = json.loads(f.read())
            cosigners_raw = d["cosigners"]
            cosigners = list(map(
                lambda x: Cosigner(x["fingerprint"], x["xpub"]),
                cosigners_raw
            ))
            return cls(d["mnemonic"], cosigners, d["m"], d["n"], d["network"], d["name"])

    def createwallet(self):
        """Creates wallet in Bitcoin Core (idempotent)"""
        # list wallets (return if already loaded)
        wallets = self.adapter.bitcoin_cli_json("listwallets")
        if self.name in wallets:
            return
        try:
            # try loading the wallet if it already exists
            return self.adapter.bitcoin_cli_json("loadwallet",  self.name)
        except subprocess.CalledProcessError:
            # create wallet with private keys disabled
            self.adapter.bitcoin_cli_checkoutput("createwallet", self.name, "false")

    def wsh_descriptor(self, change = 0):
        """Gets the wallet's wsh Bitcion Core descriptor"""
        # create descriptor without checksum
        desc = "wsh(sortedmulti(" + str(self.m) + ","
        desc += "[" + self.fingerprint + "]"
        desc += self.xprv + "/" # define derivation as m/change/idx
        desc += str(change) + "/*,"
        for i, cosigner in enumerate(self.cosigners):
            desc += "[" + cosigner.fingerprint + "]"
            desc += cosigner.xpub + "/"
            desc += str(change) + "/*,"
        # drop last comma and close parens
        desc = desc[:-1] + "))"
        # getdescriptorinfo and append checksum
        out = self.adapter.bitcoin_cli_json("getdescriptorinfo", desc)
        return desc + "#" + out["checksum"]

    def importmulti(self, start, end):
        """Imports private key data for external and internal addresses over the given range into Bitcoin Core"""
        res = {}
        for change in {0, 1}:
            desc = self.wsh_descriptor(change)
            arg = [{
                "desc": desc,
                "internal": True if change == 1 else False,
                "range": [start, end],
                "timestamp": "now",
                "keypool": False,
                "watchonly": False
            }]
            res[change] = self.adapter.bitcoin_cli_json(f"-rpcwallet={self.name}", "importmulti", json.dumps(arg))
        return res

    def deriveaddresses(self, start, end, change=0):
        """Derives wallet addresses based on the requested parameters"""
        desc = self.wsh_descriptor(change)
        return self.adapter.bitcoin_cli_json("deriveaddresses", desc, json.dumps([start, end]))

    def decodepsbt(self, psbt):
        """Tries to decode a base64 encoded psbt"""
        return self.adapter.bitcoin_cli_json("decodepsbt", psbt)

    def analyzepsbt(self, psbt):
        """Tries to analyze a base64 encoded psbt"""
        return self.adapter.bitcoin_cli_json("analyzepsbt", psbt)

    def walletprocesspsbt(self, psbt, importmulti_lo=None, importmulti_hi=None):
        """
        Tries to process (sign) a base64 encoded psbt.

        First imports the specified key data given the supplied range.

        Parameters:
            psbt           (str): base64 encoded psbt
            importmulti_lo (int): lower bound for importing scripts into Bitcoin Core  
            importmulti_hi (int): upper bound for importing scripts into Bitcoin Core
        """
        if importmulti_lo is not None and importmulti_hi is not None:
            # import the descriptors necessary to process the provided psbt
            self.importmulti(importmulti_lo, importmulti_hi)
        return self.adapter.bitcoin_cli_json(f"-rpcwallet={self.name}", "walletprocesspsbt", psbt)
