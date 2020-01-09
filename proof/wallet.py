import json
import os
from proof.bitcoind import BitcoindAdapter
from crypto.mnemonic import Mnemonic
from crypto import bip32

class Cosigner:
    def __init__(self, fingerprint, xpub, derivation="/"):
        # master fingerprint of cosigner
        self.fingerprint = fingerprint
        # highest hardended derivation path
        self.derivation = derivation
        # account extended public key associated with highest hardened derivation
        self.xpub = xpub
        
class Wallet:
    def __init__(self, mnemonic, cosigners, m, n, network="mainnet", derivation = "/", name=None):
        self.network = network
        self.mnemonic = mnemonic
        self.cosigners = cosigners
        self.m = m
        self.n = n
        self.derivation = derivation
        self.name = f"wallet-{self.fingerprint}" if name is None else name

        # ensure bitcoind running
        self.adapter.ensure_bitcoind_running()
        # create wallet
        self.createwallet()
        
    @property
    def xprv(self):
        M = Mnemonic()
        seed = M.to_seed(self.mnemonic)
        return M.to_hd_master_key(seed, self.adapter.network)
        
    @property
    def xpub(self):
        desc = f"pk({self.xprv})"
        out = self.adapter.bitcoin_cli_json("getdescriptorinfo", desc)
        pubdesc = out['descriptor'] # 'pk(XPUB)#checksum'
        return pubdesc[3:-10] # slice off 'pk(' prefix and ')#checksum' suffix

    @property
    def fingerprint(self):
        return bip32.fingerprint(self.xpub)

    @property
    def adapter(self):
        return BitcoindAdapter(self.network)

    @staticmethod
    def get_dir():
        _dir = os.getenv("HOME") + "/.proof"
        if not os.path.isdir(_dir):
            os.makedirs(_dir)
        return _dir

    @property
    def wallet_path(self):
        return Wallet.get_dir() + "/" + self.name

    def save(self):
        data = json.dumps(self, default=lambda o: o.__dict__)
        with open(self.wallet_path, 'w') as f:
            f.write(data)

    @classmethod
    def load(cls, name):
        path = cls.get_dir() + "/" + name
        with open(path, 'r') as f:
            d = json.loads(f.read())
            cosigners_raw = d["cosigners"]
            cosigners = list(map(
                lambda x: Cosigner(x["fingerprint"], x["xpub"], x["derivation"]),
                cosigners_raw
            ))
            return cls(d["mnemonic"], cosigners, d["m"], d["network"], d["derivation"], d["name"])

    def createwallet(self):
        # list wallets (return if already exists)
        wallets = self.adapter.bitcoin_cli_json("listwallets")
        if self.name in wallets:
            return
        # create wallet with private keys disabled
        self.adapter.bitcoin_cli_checkoutput("createwallet", self.name, "false")

    def wsh_descriptor(self, change = 0):
        # create descriptor without checksum
        desc = "wsh(sortedmulti(" + str(self.m) + ","
        desc += "[" + self.fingerprint + "]"
        desc += self.xprv + self.derivation
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
        desc = self.wsh_descriptor(change)
        return self.adapter.bitcoin_cli_json("deriveaddresses", desc, json.dumps([start, end]))

    def decodepsbt(self, psbt):
        return self.adapter.bitcoin_cli_json("decodepsbt", psbt)
    
    def walletprocesspsbt(self, psbt):
        return self.adapter.bitcoin_cli_json(f"-rpcwallet={self.name}", "walletprocesspsbt", psbt)
