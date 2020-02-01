# Proof Wallet

The goal of this project is to improve the user experience for bitcoin holders wishing to create a multisignature cold storage wallet by leveraging Bitcoin Core's wallet functionality.


<b>NOTE:</b> _Proof Wallet is currently in development and should not be used to secure mainnet bitcoins. Please test on testnet and regtest, and create an issue if you encounter any bugs._

## Motivation
Multisignature wallets are useful because - _properly executed_ - they can reduce the likelihood of losing bitcoin due to personal error or theft. If Alice creates a multisignature wallet with an M of N policy, she can lose any N - M of the private keys and still retain the ability to spend the bitcoins. Similarly, an adversary wishing to steal Alice's bitcoins would have to compromise at least M keys for the theft to be successful. In this way, multisig wallets improve security by adding redundancy and increasing the cost of theft.

[BIP 174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) or the "Partially Signed Bitcoin Transaction Format" (herein referred to as PSBT) is a standard that was created to support interfacing between the Bitcoin Protocol and offline private key signers such as hardware wallets. PSBT is particularly useful for multisignature wallets as it allows various signers to collaborate on signing and finalizing a given transaction. With PSBT users can gain the advantage of multisignature technology realized with different wallet implementations (hardware and software) holding keys stored in physically separate locations.

Under these circumstances, the risk of catastrophic loss due to any N-M wallet failures is reduced. Any additional wallet that bitcoin holders can utilize in this manner increases security and also reduces the risk of bugs in the other wallet implementations that could result in a catastrophic loss.

Proof Wallet intends to be an additional option bitcoin holders can utilize as part of their multisignature quorum. It was built to leverage the feature-rich and well-reviewed wallet functionality that Bitcoin Core offers while at the same time improving the overall user experience.

## Overview
Proof Wallet was heavily inspired by the principles outlined in the [Glacier Protocol](https://glacierprotocol.org/). To maximize the security of a Proof Wallet signatory in a multisig quorum, a user would create 2 eternally quarantined laptops (from different manufacturers) that boot Ubuntu from USBs. Using 2 laptops from different manufacturers is best practice as it minimizes the chance of malicious hardware or software corrupting the process in any way; at every step (wallet creation, deposits, withdrawls) this enables users to verify that the outputs on both machines are equivalent.

The actual Proof Wallet software is a thin wrapper around Bitcoin Core's RPC interface that aims to improve the overall user experience of running `bitcoin-cli` commands from the terminal. The wallet is a minimalistic terminal application dedicated to helping users create a multisignature wallet, finalizing the wallet by adding cosigner xpubs, displaying receive addresses, and enabling secure signing of PSBTs. In order to run, Proof Wallet also requires `bitcoind`, `bitcoin-cli`, `qrencode`, and `zbarcam` to be available on the computer's path; these are the same external dependencies that Glacier Protocol uses.

All wallet data that moves on and off the airgapped computer is transmitted via QR codes (either rendered directly within the terminal or captured by the webcam) from within the wallet. This data includes the wallet's xpub, cosigner xpubs, and unsigned and signed PSBTs.

In line with other modern hardware wallets, Proof Wallet utilizes BIP39 enabling convenient 24 word mnemonic backups that can be stored offline on paper or steel.

The Proof Wallet code was written to be as short as possible. Outside of Bitcoin Core, the only sensitive crypto operations are BIP39 - Proof Wallet uses the BIP reference implementation - and another ~100 lines of code to deserialize a BIP32 node and calculate its fingerprint (most of this code is taken verbatim from Peter Todd's [python-bitcoinlib](https://github.com/petertodd/python-bitcoinlib)). The other security-relevant code is a single python function (`validate_psbt`) that ensures that the PSBT is safe for the user to sign, and the Wallet class that constructs the JSON RPC commands issued to Bitcoin Core. 

Most of the code is window dressing that makes it easier for non-technical users to take advantage of the powerful multisig functionality available in Bitcoin Core.

## Features

* Supports mainnet, testnet, and regtest Bitcoin networks
* Minimal external dependencies. Proof Wallet relies on the same external dependencies as the Glacier Protocol
  * Bitcoin Core -- for wallet functionality
  * qrencode     -- for generating QR codes from raw data
  * zbar         -- for scanning QR code data using the computer's camera
* _All_ data is passed to and from the airgapped machine via QR codes. Since PSBT files are effectively unbounded in size (i.e. they can get really large), Proof Wallet natively implements batching so that transaction data can be imported and exported in chunks. Extended public keys are also moved on and off the machine via QR codes.
* Secure entropy generation. Proof Wallet private keys derive additive security from two sources of entropy similar to the Glacier Protocol:
  * Dice rolls: a user must enter at least 100 dice rolls (the equivalent of ~256 bits of entropy) to generate a wallet. Casino dice are _highly_ recommended for this task as they are fairer than other retail dice.
  * Computer generated entropy derived from /dev/urandom
  * Additionally, Proof Wallet can - and is recommended to - be run on two separate airgapped devices simultaneously to verify that the same actions always result in the same outputs. During the wallet creation process, this means that Alice can generate entropy from Computer #1, manually input the entropy into Computer #2, and verify that this results in the same BIP 39 mnemonic on both computers. This process reduces the risk that either computer is infected with malware that affects key generation.
* BIP 39 support. Proof Wallet uses the reference implementation of BIP 39 to generate a mnemonic phrase. Unlike Glacier Protocol, Proof Wallet supports HD wallets as defined by BIP 32.
* Wallet restore functionality so that private key data need not be persisted to electronic media; instead the user can restore their wallet from the 24 word mnemonic each time he intends to view his deposit addresses or sign a transaction.
* Users can view all external and internal (change) addresses associated with the p2wsh multisignature wallet to maximize the security of depositing funds.
* Users can _optionally_ choose to persist the wallet (containing private key data) to the filesystem if that is permissible under their threat model

## Security Tradeoffs
The Glacier Protocol was a major inspiration for Proof Wallet's design decisions; it is generally regarded as the most secure way to store bitcoin: at each step of the protocol, it stresses risk elimination over risk reduction and offers numerous desirable security properties that Proof Wallet tries to maintain; these include:
  * Open source software stack (Ubuntu, Bitcoin Core, Proof Wallet)
  * Airgapped execution on eternally quarantined hardware
  * Deterministic key generation from multiple sources of entropy
  * Correctness verification using duplicate enviornments
  * General purpose hardware instead of hardware wallets (effectively removing supply chain risk)
  * Low bandwidth communication to and from quarantined hardware (QR codes)

Despite its high security bar, few bitcoin holders use Glacier Protocol. Some reasons for this may include:
  * Discounting and / or ignorance of security risks
  * Fear of making a mistake
  * Qualms about the user experience (warranted or not)
	* Necessity for handling individual private keys
	* Address reuse
	* No BIP 39 or HD wallet (BIP 32) support
	* Monolithic - no way to interoperate with other hardware or software wallets

Proof Wallet makes a few security tradeoffs versus Glacier Protocol with the aim of bridging some of the UX issues described above. These include:
  * **Larger codebase**: glacierscript.py is 861 lines of code while Proof Wallet is currently ~2000 lines. Most of the difference comes from Proof Wallet's user interface that features simple menus and in-terminal QR code import/export that some users may feel makes for a friendlier experience.
  * **Optional storage on electronic media**: Proof Wallet allows users to optionally store private keys directly on device; under some threat models, this might be an acceptable tradeoff for users to make for a better user experience. If not, a user can restore a previously created wallet before every use.
  * **Minimal crypto operations outside of Bitcoin Core**: Proof Wallet performs a select few security critical operations outside of Bitcoin Core to enable large usability improvements. These are:
	* **BIP 39**: The reference implementation of BIP 39 is used to convert entropy to a BIP 39 mnemonic phrase. This is desirable because backing up a 24 word seed has now become a standard user experience common to most popular wallets.
	* **BIP 32 extended key -> BIP 32 fingerprint calculation**: In order to fulfill the requirements of the PSBT format, Proof Wallet must calculate the wallet's BIP 32 fingerprint. This involves performing a hash160 on the key bytes of a deserialized xpub. The code for decoding the Base58 encoded xpub was taken from Peter Todd's python-bitcointools. Users can easily reference BIP32 itself to verify the accuracy of the few other lines of code.
	* **PSBT safety check**: in order to make the code as short and secure as possible, Proof Wallet utilizes a very narrow part of the PSBT standard. Specifically, a user creates a cosigner in a p2wsh multisignature wallet; Proof Wallet only signs transactions that contain the wallet's inputs. Proof Wallet does not implement BIP 32 child key derivation so relative to the master private key ("m"), the only valid external receives addresses are at **m/0/&ast;** and the only valid change addresses are at **m/1/&ast;**. This simplicity makes it straightforward to validate whether a PSBT is safe for the user to sign. The function that performs this task (`validate_psbt`) is well commented, easily auditable and can be found in `proof/utils.py`.

Many users may find these tradeoffs acceptable for the improvements in user experience they offer; others may not. A nice feature of Proof Wallet is that it can interoperate with other PSBT compliant wallets. If a user wants to enjoy some specific security properties Glacier Protocol offers while also using some other PSBT-compliant wallet, Proof Wallet may be a good choice. Proof Wallet arguably improves on Glacier's security assumptions in at least 1 respect. During the deposit and withdrawl steps of Glacier Protocol, a user has on his person all the means of spending (which is to say losing and/or getting stolen) his bitcoin at that very time and place. A great advantage of PSBT multisig is that it provides a standard to interactively process an incomplete transaction at different times and places until the transaction is complete and ready to be finalized / broadcast to the network. With a quorum of Proof Wallets or a heterogeneous quorum of PSBT-compliant wallets, there never has to be a single point of failure during the deposit or withdrawal process. This seems like a very desirable security feature to have. Further, a multisignature quorum consisting of different wallets may reduce the risk that a security flaw in one wallet results in a catastrophic loss of funds.

## Codebase Summary
```
main.py -- wallet entrypoint

crypto/
	bip32.py -- deserializes a BIP 32 xpub and calculates its fingerprint
	mnemonic.py -- abbreviated reference implementation of BIP 39; adds version bits for testnet & regtest
	english.txt -- BIP 39 wordlist

proof/
	actions.py -- interactive menus
	bitcoind.py -- adapter for Bitcoin Core's JSON RPC interface (adapted from glacierscript.py)
	constants.py -- various constants used throughout Proof Wallet
	trie.py -- a basic Trie implementation for storing and traversing BIP 39 words
	utils.py -- utility functions and the security-critical validate_psbt()
	ux.py -- user interaction primitives
	wallet.py -- a basic p2wsh multisignature wallet that maintains a policy, one cosigner's private data, public data for the other cosigners and methods for utilizing Bitcoin Core's RPC interface (e.g. computes receive addresses and signs PSBTs)
```

## Improvements
* Comprehensive unit testing. Refactor code as much as possible into pure functions to improve testability
* Simulated integration testing of the interactive actions
* Use best practices for getting keyboard input from the user in proof/ux.py. This code was hacked together.
* Render QR codes so they fit on screen without the user having to resize the terminal
* Code review from python3 experts that understand best practices
* Security review by security experts
