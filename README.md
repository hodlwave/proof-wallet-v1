# Proof Wallet

## Overview
The goal of this project is to improve the user experience for bitcoin holders wishing to create a multisignature cold storage wallet that leverages the Bitcoin Core wallet functionality. Multisignature wallets are useful because - _properly executed_ - they can reduce the likelihood of losing bitcoin due to personal error or theft. 

If Alice creates a multisignature wallet with an M of N policy, she can lose any N - M of the private keys and still retain the ability to spend the bitcoins. Similarly, an adversary wishing to steal Alice's bitcoins would have to compromise at least M wallet signatories for the theft to be successful. In this way, multisig wallets improve security by adding redundancy and increasing the cost of theft.

[BIP 174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) or the "Partially Signed Bitcoin Transaction Format" (herein referred to as PSBT) is a standard that was created to support interfacing between the Bitcoin Protocol and offline private key signers such as hardware wallets. PSBT is particularly useful for multisignature wallets as it allows various signers to collaborate on signing and finalizing a given transaction. With PSBT users can gain the advantage of multisignature technology realized with different wallet implementations (hardware and software) holding keys stored in physically separate locations.

Under these circumstances, the risk of catastrophic loss due to any M-N wallet failures is reduced. Any additional wallet that bitcoin holders can utilize in this manner increases security and also reduces the risk of bugs in the other wallet implementations resulting in a catastrophic loss.

Proof Wallet is intended to be additional option bitcoin holders can utilize as part of the multisignature quorum. It was built to leverage the feature-rich and well-reviewed wallet functionality that Bitcoin Core offers while at the same time improving the overall user experience. The interface users interact with is a terminal application.

Proof Wallet was heavily inspired by the principles outlined in the [Glacier Protocol](https://glacierprotocol.org/).

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
  * Additionally, Proof Wallet can - and is recommended to - be run on two separate airgapped devices simultaneously two verify that the same actions always result in the same outputs. During the wallet creation process, this means that Alice can generate entropy from Computer #1, manually input the entropy into Computer #2, and verify that this results in the same BIP 39 mnemonic. This process reduces the risk that either computer is infected with malware that affects key generation.
* BIP 39 support. Proof Wallet uses the reference implementation of BIP 39 to generate a mnemonic phrase. Unlike Glacier Protocol, Proof Wallet supports HD wallets as defined by BIP 32.
* Wallet restore functionality so that private key data need not be persisted to electronic media; instead the user can restore their wallet from the 24 word mnemonic each time he intends to sign a transaction.
* Users can view all external and internal (change) addresses associated with the p2wsh multisignature wallet to maximize the security of depositing funds.
* Users can _optionally_ choose to persist the wallet (containing private key data) to the filesystem if that is permissible under their threat model
