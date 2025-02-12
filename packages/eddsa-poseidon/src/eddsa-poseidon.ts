import {
    Base8,
    Fr,
    Point,
    addPoint,
    inCurve,
    mulPointEscalar,
    packPoint,
    subOrder,
    unpackPoint
} from "@zk-kit/baby-jubjub"
import {
    BigNumber,
    BigNumberish,
    F1Field,
    isHexadecimal,
    isStringifiedBigint,
    leBigintToBuffer,
    leBufferToBigint,
    scalar
} from "@zk-kit/utils"
import { poseidon5 } from "poseidon-lite/poseidon5"
import blake from "./blake"
import { Signature } from "./types"
import * as utils from "./utils"

/**
 * Hashes the 32-byte private key using Blake1, prunes the lower 32 bytes
 * of the buffer and converts it to a little-endian integer.
 * This function is used to obtain the secret scalar to be used as
 * the input of the private key in the circuits, since the circuit only
 * performs a fixed-base scalar multiplication.
 * For more info about these steps: {@link https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5}.
 * @param privateKey - The private key used for generating the public key.
 * @returns The secret scalar to be used to calculate public key.
 */
export function deriveSecretScalar(privateKey: BigNumberish): string {
    // Convert the private key to buffer.
    privateKey = utils.checkPrivateKey(privateKey)

    let hash = blake(privateKey)

    hash = hash.slice(0, 32)
    hash = utils.pruneBuffer(hash)

    return scalar.shiftRight(leBufferToBigint(hash), BigInt(3)).toString()
}

/**
 * Derives a public key from a given private key using the
 * {@link https://eips.ethereum.org/EIPS/eip-2494|Baby Jubjub} elliptic curve.
 * This function utilizes the Baby Jubjub elliptic curve for cryptographic operations.
 * The private key should be securely stored and managed, and it should never be exposed
 * or transmitted in an unsecured manner.
 * @param privateKey - The private key used for generating the public key.
 * @returns The derived public key.
 */
export function derivePublicKey(privateKey: BigNumberish): Point<string> {
    const s = deriveSecretScalar(privateKey)

    const publicKey = mulPointEscalar(Base8, BigInt(s))

    // Convert the public key values to strings so that it can easily be exported as a JSON.
    return [publicKey[0].toString(), publicKey[1].toString()]
}

/**
 * Signs a message using the provided private key, employing Poseidon hashing and
 * EdDSA with the Baby Jubjub elliptic curve.
 * @param privateKey - The private key used to sign the message.
 * @param message - The message to be signed.
 * @returns The signature object, containing properties relevant to EdDSA signatures, such as 'R8' and 'S' values.
 */
export function signMessage(privateKey: BigNumberish, message: BigNumberish): Signature<string> {
    // Convert the private key to buffer.
    privateKey = utils.checkPrivateKey(privateKey)

    // Convert the message to big integer.
    message = utils.checkMessage(message)

    const hash = blake(privateKey)

    const sBuff = utils.pruneBuffer(hash.slice(0, 32))
    const s = leBufferToBigint(sBuff)
    const A = mulPointEscalar(Base8, scalar.shiftRight(s, BigInt(3)))

    const msgBuff = leBigintToBuffer(message)

    const rBuff = blake(Buffer.concat([hash.slice(32, 64), msgBuff]))

    const Fr = new F1Field(subOrder)
    const r = Fr.e(leBufferToBigint(rBuff))

    const R8 = mulPointEscalar(Base8, r)
    const hm = poseidon5([R8[0], R8[1], A[0], A[1], message])
    const S = Fr.add(r, Fr.mul(hm, s))

    // Convert the signature values to strings so that it can easily be exported as a JSON.
    return {
        R8: [R8[0].toString(), R8[1].toString()],
        S: S.toString()
    }
}

/**
 * Verifies an EdDSA signature using the Baby Jubjub elliptic curve and Poseidon hash function.
 * @param message - The original message that was be signed.
 * @param signature - The EdDSA signature to be verified.
 * @param publicKey - The public key associated with the private key used to sign the message.
 * @returns Returns true if the signature is valid and corresponds to the message and public key, false otherwise.
 */
export function verifySignature(message: BigNumberish, signature: Signature, publicKey: Point): boolean {
    if (
        !utils.isPoint(publicKey) ||
        !utils.isSignature(signature) ||
        !inCurve(signature.R8) ||
        !inCurve(publicKey) ||
        BigInt(signature.S) >= subOrder
    ) {
        return false
    }

    // Convert the message to big integer.
    message = utils.checkMessage(message)

    // Convert the signature values to big integers for calculations.
    const _signature: Signature<bigint> = {
        R8: [BigInt(signature.R8[0]), BigInt(signature.R8[1])],
        S: BigInt(signature.S)
    }
    // Convert the public key values to big integers for calculations.
    const _publicKey: Point<bigint> = [BigInt(publicKey[0]), BigInt(publicKey[1])]

    const hm = poseidon5([signature.R8[0], signature.R8[1], publicKey[0], publicKey[1], message])

    const pLeft = mulPointEscalar(Base8, BigInt(signature.S))
    let pRight = mulPointEscalar(_publicKey, scalar.mul(hm, BigInt(8)))

    pRight = addPoint(_signature.R8, pRight)

    // Return true if the points match.
    return Fr.eq(BigInt(pLeft[0]), pRight[0]) && Fr.eq(pLeft[1], pRight[1])
}

export function packPublicKey(publicKey: Point): string {
    if (!utils.isPoint(publicKey) || !inCurve(publicKey)) {
        throw new Error("Invalid public key")
    }

    // Convert the public key values to big integers for calculations.
    const _publicKey: Point<bigint> = [BigInt(publicKey[0]), BigInt(publicKey[1])]

    const packedPublicKey = packPoint(_publicKey)

    if (packedPublicKey === null) {
        throw new Error("Invalid public key")
    }

    return packedPublicKey.toString()
}

export function unpackPublicKey(publicKey: BigNumber): Point<string> {
    if (
        typeof publicKey !== "bigint" &&
        (typeof publicKey !== "string" || !isStringifiedBigint(publicKey)) &&
        (typeof publicKey !== "string" || !isHexadecimal(publicKey))
    ) {
        throw new TypeError("Invalid public key type")
    }

    const unpackedPublicKey = unpackPoint(BigInt(publicKey))

    if (unpackedPublicKey === null) {
        throw new Error("Invalid public key")
    }

    return [unpackedPublicKey[0].toString(), unpackedPublicKey[1].toString()]
}

export class EdDSAPoseidon {
    privateKey: BigNumberish
    secretScalar: string
    publicKey: Point
    packedPublicKey: string

    constructor(privateKey: BigNumberish) {
        this.privateKey = privateKey
        this.secretScalar = deriveSecretScalar(privateKey)
        this.publicKey = derivePublicKey(privateKey)
        this.packedPublicKey = packPublicKey(this.publicKey) as string
    }

    signMessage(message: BigNumberish): Signature<string> {
        return signMessage(this.privateKey, message)
    }

    verifySignature(message: BigNumberish, signature: Signature): boolean {
        return verifySignature(message, signature, this.publicKey)
    }
}
