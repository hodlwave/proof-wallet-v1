from proof.bitcoind import BitcoindAdapter
from crypto.mnemonic import Mnemonic
from crypto import bip32

class Cosigner:
    def __init__(self, fingerprint, derivation, xpub):
        self.fingerprint = fingerprint
        self.derivation = derivation
        self.xpub = xpub
        
class Wallet:
    def __init__(self, mnemonic, cosigners, m, name=None, network="mainnet"):
        self.adapter = BitcoindAdapter(network)
        self.mnemonic = mnemonic
        self.cosigners = cosigners
        self.m = m
        self.name = f"wallet-{self.fingerprint}" if name is None else name

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
        
    def createwallet(self):
        # list wallets (return if already exists)
        wallets = self.adapter.bitcoin_cli_json("listwallets")
        if self.name in wallets:
            return
        # create wallet with private keys disabled
        self.adapter.bitcoin_cli_checkoutput("createwallet", self.name, "false")

    def decodepsbt(self, psbt):
        pass
    
    def importmulti(self, start, end):
        pass

    def walletprocesspsbt(self, psbt):
        pass
