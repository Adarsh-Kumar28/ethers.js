"use strict";

import { getAddress } from "@ethersproject/address";
import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
import { ExternallyOwnedAccount, Signer, TypedDataDomain, TypedDataField, TypedDataSigner } from "@ethersproject/abstract-signer";
import { arrayify, Bytes, BytesLike, concat, hexDataSlice, isHexString, joinSignature, SignatureLike } from "@ethersproject/bytes";
import { hashMessage, _TypedDataEncoder } from "@ethersproject/hash";
import { defaultPath, HDNode, entropyToMnemonic, Mnemonic } from "@ethersproject/hdnode";
import { keccak256 } from "@ethersproject/keccak256";
import { defineReadOnly, resolveProperties } from "@ethersproject/properties";
import { randomBytes } from "@ethersproject/random";
import { SigningKey } from "@ethersproject/signing-key";
import { decryptJsonWallet, decryptJsonWalletSync, encryptKeystore, ProgressCallback } from "@ethersproject/json-wallets";
import { computeAddress, recoverAddress, serialize, UnsignedTransaction } from "@ethersproject/transactions";
import { Wordlist } from "@ethersproject/wordlists";
import LitJsSdk from "lit-js-sdk";
import { Logger } from "@ethersproject/logger";
import { version } from "./_version";
const logger = new Logger(version);

function isAccount(value: any): value is ExternallyOwnedAccount {
    return (value != null && isHexString(value.privateKey, 32) && value.address != null);
}

function hasMnemonic(value: any): value is { mnemonic: Mnemonic } {
    const mnemonic = value.mnemonic;
    return (mnemonic && mnemonic.phrase);
}

export class Wallet extends Signer implements ExternallyOwnedAccount, TypedDataSigner {

    readonly address: string;
    readonly provider: Provider;

    // Wrapping the _signingKey and _mnemonic in a getter function prevents
    // leaking the private key in console.log; still, be careful! :)
    readonly _signingKey: () => SigningKey;
    readonly _mnemonic: () => Mnemonic;

    constructor(privateKey: BytesLike | ExternallyOwnedAccount | SigningKey, provider?: Provider) {
        super();

        if (isAccount(privateKey)) {
            const signingKey = new SigningKey(privateKey.privateKey);
            defineReadOnly(this, "_signingKey", () => signingKey);
            defineReadOnly(this, "address", computeAddress(this.publicKey));

            if (this.address !== getAddress(privateKey.address)) {
                logger.throwArgumentError("privateKey/address mismatch", "privateKey", "[REDACTED]");
            }

            if (hasMnemonic(privateKey)) {
                const srcMnemonic = privateKey.mnemonic;
                defineReadOnly(this, "_mnemonic", () => (
                    {
                        phrase: srcMnemonic.phrase,
                        path: srcMnemonic.path || defaultPath,
                        locale: srcMnemonic.locale || "en"
                    }
                ));
                const mnemonic = this.mnemonic;
                const node = HDNode.fromMnemonic(mnemonic.phrase, null, mnemonic.locale).derivePath(mnemonic.path);
                if (computeAddress(node.privateKey) !== this.address) {
                    logger.throwArgumentError("mnemonic/address mismatch", "privateKey", "[REDACTED]");
                }
            } else {
                defineReadOnly(this, "_mnemonic", (): Mnemonic => null);
            }


        } else {
            if (SigningKey.isSigningKey(privateKey)) {
                /* istanbul ignore if */
                if (privateKey.curve !== "secp256k1") {
                    logger.throwArgumentError("unsupported curve; must be secp256k1", "privateKey", "[REDACTED]");
                }
                defineReadOnly(this, "_signingKey", () => (<SigningKey>privateKey));

            } else {
                // A lot of common tools do not prefix private keys with a 0x (see: #1166)
                if (typeof(privateKey) === "string") {
                    if (privateKey.match(/^[0-9a-f]*$/i) && privateKey.length === 64) {
                        privateKey = "0x" + privateKey;
                    }
                }

                const signingKey = new SigningKey(privateKey);
                defineReadOnly(this, "_signingKey", () => signingKey);
            }

            defineReadOnly(this, "_mnemonic", (): Mnemonic => null);
            defineReadOnly(this, "address", computeAddress(this.publicKey));
        }

        /* istanbul ignore if */
        if (provider && !Provider.isProvider(provider)) {
            logger.throwArgumentError("invalid provider", "provider", provider);
        }

        defineReadOnly(this, "provider", provider || null);
    }

    get mnemonic(): Mnemonic { return this._mnemonic(); }
    get privateKey(): string { return this._signingKey().privateKey; }
    get publicKey(): string { return this._signingKey().publicKey; }

    getAddress(): Promise<string> {
        return Promise.resolve(this.address);
    }

    connect(provider: Provider): Wallet {
        return new Wallet(this, provider);
    }

    signTransaction(transaction: TransactionRequest): Promise<string> {
        return resolveProperties(transaction).then((tx) => {
            if (tx.from != null) {
                if (getAddress(tx.from) !== this.address) {
                    logger.throwArgumentError("transaction from address mismatch", "transaction.from", transaction.from);
                }
                delete tx.from;
            }

            const toSign = keccak256(serialize(<UnsignedTransaction>tx));
            console.log("toSign");
            console.log(toSign);
            const signature = this._signingKey().signDigest(toSign);
            console.log("LitActions");
            const response = this.runLitAction(toSign);
            console.log(response);
            console.log("signature");
            console.log(signature);
            return serialize(<UnsignedTransaction>tx, signature);
        });
    }

    private runLitAction = async (toSign: string) => {
        const litActionCode = `
            const go = async () => {
                const sigShare = await LitActions.signEcdsa({ toSign, publicKey, sigName });
            };
            go();
        `;

        console.log("1", toSign);
        // you need an AuthSig to auth with the nodes
        // normally you would obtain an AuthSig by calling LitJsSdk.checkAndSignAuthMessage({chain})
        // const authSig = {
        //     // sig: "0x2bdede6164f56a601fc17a8a78327d28b54e87cf3fa20373fca1d73b804566736d76efe2dd79a4627870a50e66e1a9050ca333b6f98d9415d8bca424980611ca1c",
        //     sig: "0x4153949906b0434dd574fead4a68eb6e4a6c21acfc819f401ef2c0dc12cd2f8c3b4169a414bdd2f30dd9fbd3c2aa31f551987940b57c6404a143603c82f924ed1b",
        //     derivedVia: "web3.eth.personal.sign",
        //     // signedMessage: "localhost wants you to sign in with your Ethereum account:\n0x0b1C5E9E82393AD5d1d1e9a498BF7bAAC13b31Ee\n\nThis is a key for Partiful\n\nURI: https://localhost/login\nVersion: 1\nChain ID: 1\nNonce: 1LF00rraLO4f7ZSIt\nIssued At: 2022-06-03T05:59:09.959Z",
        //     signedMessage: "localhost wants you to sign in with your Ethereum account:\n0x0b1C5E9E82393AD5d1d1e9a498BF7bAAC13b31Ee\n\nThis is a key for Partiful\n\nURI: https://localhost/login\nVersion: 1\nChain ID: 1\nNonce: ucYkVYkiTOFVHcGfn\nIssued At: 2022-10-22T07:46:08.333Z\nExpiration Time: 2022-10-29T07:45:45.334Z",
        //     address: "0x0b1C5E9E82393AD5d1d1e9a498BF7bAAC13b31Ee",
        // };

        console.log("authSign");
        const authSig = await LitJsSdk.checkAndSignAuthMessage({ chain: "ethereum" });
        console.log(authSig);
        console.log("litNodeClient");
        const litNodeClient = new LitJsSdk.LitNodeClient({ litNetwork: "serrano" });
        console.log("connecting...");
        await litNodeClient.connect();
        console.log("done");
        let utf8Encode = new TextEncoder();
        const toSignBytes = utf8Encode.encode(toSign);
        console.log("toSignBytes");
        console.log(toSignBytes);
        const results = await litNodeClient.executeJs({
            code: litActionCode,
            authSig,
            jsParams: {
                toSign: toSignBytes,
                publicKey: "0x043d50a0f3d14b433803636ca8e8709994e523831e5876b0f5fd941ebbc4aee30a07440facbe3d43118053969f1a25039d6d9c5889ed04af7e1d15d65e9d92b5ab",
                sigName: "sig1",
            },
        });
        console.log("results: ", results);
    };

    async signMessage(message: Bytes | string): Promise<string> {
        return joinSignature(this._signingKey().signDigest(hashMessage(message)));
    }

    async _signTypedData(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>): Promise<string> {
        // Populate any ENS names
        const populated = await _TypedDataEncoder.resolveNames(domain, types, value, (name: string) => {
            if (this.provider == null) {
                logger.throwError("cannot resolve ENS names without a provider", Logger.errors.UNSUPPORTED_OPERATION, {
                    operation: "resolveName",
                    value: name
                });
            }
            return this.provider.resolveName(name);
        });

        return joinSignature(this._signingKey().signDigest(_TypedDataEncoder.hash(populated.domain, types, populated.value)));
    }

    encrypt(password: Bytes | string, options?: any, progressCallback?: ProgressCallback): Promise<string> {
        if (typeof(options) === "function" && !progressCallback) {
            progressCallback = options;
            options = {};
        }

        if (progressCallback && typeof(progressCallback) !== "function") {
            throw new Error("invalid callback");
        }

        if (!options) { options = {}; }

        return encryptKeystore(this, password, options, progressCallback);
    }


    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options?: any): Wallet {
        let entropy: Uint8Array = randomBytes(16);

        if (!options) { options = { }; }

        if (options.extraEntropy) {
            entropy = arrayify(hexDataSlice(keccak256(concat([ entropy, options.extraEntropy ])), 0, 16));
        }

        const mnemonic = entropyToMnemonic(entropy, options.locale);
        return Wallet.fromMnemonic(mnemonic, options.path, options.locale);
    }

    static fromEncryptedJson(json: string, password: Bytes | string, progressCallback?: ProgressCallback): Promise<Wallet> {
        return decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new Wallet(account);
        });
    }

    static fromEncryptedJsonSync(json: string, password: Bytes | string): Wallet {
        return new Wallet(decryptJsonWalletSync(json, password));
    }

    static fromMnemonic(mnemonic: string, path?: string, wordlist?: Wordlist): Wallet {
        if (!path) { path = defaultPath; }
        return new Wallet(HDNode.fromMnemonic(mnemonic, null, wordlist).derivePath(path));
    }
}

export function verifyMessage(message: Bytes | string, signature: SignatureLike): string {
    return recoverAddress(hashMessage(message), signature);
}

export function verifyTypedData(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>, signature: SignatureLike): string {
    return recoverAddress(_TypedDataEncoder.hash(domain, types, value), signature);
}
