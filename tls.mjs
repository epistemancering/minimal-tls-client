import * as net from "net"

const signatureKey = (/**@type {ArrayBuffer}*/ key) => {
    return crypto.subtle.importKey("raw", key, { name: "hmac", hash: "sha-384" }, false, ["sign"])
}

const signIdentifier = async (/**@type {CryptoKey}*/ key, /**@type {number}*/ length, /**@type {number[]}*/ identifier, /**@type {number[]}*/ digest) => {
    return (await crypto.subtle.sign("hmac", key, Uint8Array.from([0, length, identifier.length + 6, 116, 108, 115, 49, 51, 32, ...identifier, digest.length, ...digest, 1]))).slice(0, length)
}

const aesOptions = (/**@type {Uint8Array}*/ iv, /**@type {number}*/ previous, /**@type {number[]}*/ additional) => {
    return {
        name: "aes-gcm",
        iv: iv.map((byte, index) => {
            return (previous / 256 ** (11 - index)) ^ byte
        }),
        additionalData: Uint8Array.from(additional)
    }
}

export default /**Create a TLS connection. @type {(options: net.NetConnectOpts, listener: (response: number[]) => void) => Promise<(request: Uint8Array) => void>}*/ async (/**Will be passed to `net.createConnection`.*/ options, /**Handle decrypted responses.*/ listener) => {
    const netSocket = net.createConnection(options)
    const keyPair = await crypto.subtle.generateKey({ name: "ecdh", namedCurve: "P-256" }, false, ["deriveBits"])
    const handshakeMessages = [1, 0, 0, 141, 3, 4, ...Array.from(crypto.getRandomValues(new Uint8Array(32))), 0, 0, 2, 19, 2, 1, 0, 0, 98, 0, 10, 0, 4, 0, 2, 0, 23, 0, 13, 0, 4, 0, 2, 8, 4, 0, 43, 0, 3, 2, 3, 4, 0, 51, 0, 71, 0, 69, 0, 23, 0, 65, ...Array.from(new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey)))]
    netSocket.write(Uint8Array.from([22, 3, 4, 0, 145, ...handshakeMessages]))
    let /**@type {Uint8Array}*/ encryptionIV
    let /**@type {CryptoKey}*/ encryptionKey
    let requestsEncrypted = 0

    const encryptWrite = async (/**@type {number[]}*/ request) => {
        const requestLength = request.length + 16
        const additionalData = [23, 3, 3, requestLength / 256, requestLength]
        netSocket.write(Uint8Array.from([...additionalData, ...Array.from(new Uint8Array(await crypto.subtle.encrypt(aesOptions(encryptionIV, requestsEncrypted, additionalData), encryptionKey, Uint8Array.from(request))))]))
    }

    await new Promise(async (resolve) => {
        let lastResponse = Promise.resolve()
        let responsesDecrypted = 0
        let /**@type {CryptoKey | undefined}*/ derivedKey
        let decryptionIV = new Uint8Array
        let /**@type {CryptoKey | undefined}*/ decryptionKey
        let /**@type {CryptoKey | undefined}*/ cTraffic

        const changeKeys = async (/**@type {number}*/ first, /**@type {number}*/ last, /**@type {ArrayBuffer}*/ digest) => {
            const typedDerived = /**@type {CryptoKey}*/(derivedKey)
            const handshakeDigest = Array.from(new Uint8Array(digest))
            const sTraffic = await signatureKey(await signIdentifier(typedDerived, 48, [115, 32, first, last, 32, 116, 114, 97, 102, 102, 105, 99], handshakeDigest))
            decryptionIV = new Uint8Array(await signIdentifier(sTraffic, 12, [105, 118], []))
            decryptionKey = await crypto.subtle.importKey("raw", await signIdentifier(sTraffic, 32, [107, 101, 121], []), "aes-gcm", false, ["decrypt"])
            cTraffic = await signatureKey(await signIdentifier(typedDerived, 48, [99, 32, first, last, 32, 116, 114, 97, 102, 102, 105, 99], handshakeDigest))
            encryptionIV = new Uint8Array(await signIdentifier(cTraffic, 12, [105, 118], []))
            encryptionKey = await crypto.subtle.importKey("raw", await signIdentifier(cTraffic, 32, [107, 101, 121], []), "aes-gcm", false, ["encrypt"])
        }

        for await (let responses of netSocket) {
            while (responses[0]) {
                const responseEnd = 256 * responses[3] + responses[4] + 5

                lastResponse = (async () => {
                    const encryptedResponse = responses[0] === 23
                    let responseContent = responses.slice(5, responseEnd)
                    await lastResponse

                    if (encryptedResponse) {
                        const decryptedResponse = new Uint8Array(await crypto.subtle.decrypt(aesOptions(decryptionIV, responsesDecrypted++, [23, 3, 3, responseContent.length / 256, responseContent.length]), /**@type {CryptoKey}*/(decryptionKey), responseContent))
                        responseContent = decryptedResponse.slice(0, -1)

                        if (decryptedResponse[decryptedResponse.length - 1] === 23) {
                            listener(Array.from(responseContent))
                        } else {
                            handshakeMessages.push(...Array.from(responseContent))

                            if (responseContent[0] === 20) {
                                const handshakeDigest = await crypto.subtle.digest("sha-384", Uint8Array.from(handshakeMessages))

                                await encryptWrite([
                                    20,
                                    0,
                                    0,
                                    48,
                                    ...Array.from(new Uint8Array(await crypto.subtle.sign("hmac", await signatureKey(await signIdentifier(/**@type {CryptoKey}*/(cTraffic), 48, [102, 105, 110, 105, 115, 104, 101, 100], [])), handshakeDigest))),
                                    22
                                ])

                                derivedKey = await signatureKey(await crypto.subtle.sign("hmac", await signatureKey(await signIdentifier(/**@type {CryptoKey}*/(derivedKey), 48, [100, 101, 114, 105, 118, 101, 100], [56, 176, 96, 167, 81, 172, 150, 56, 76, 217, 50, 126, 177, 177, 227, 106, 33, 253, 183, 17, 20, 190, 7, 67, 76, 12, 199, 191, 99, 246, 225, 218, 39, 78, 222, 191, 231, 111, 101, 251, 213, 26, 210, 241, 72, 152, 185, 91])), new ArrayBuffer(48)))
                                await changeKeys(97, 112, handshakeDigest)
                                responsesDecrypted = 0
                                resolve(undefined)
                            }
                        }
                    } else if (!derivedKey) {
                        handshakeMessages.push(...Array.from(responseContent))

                        derivedKey = await signatureKey(await crypto.subtle.sign(
                            "hmac",
                            await signatureKey(new Uint8Array([21, 145, 218, 197, 203, 191, 3, 48, 164, 168, 77, 233, 199, 83, 51, 14, 146, 208, 31, 10, 136, 33, 75, 68, 100, 151, 47, 214, 104, 4, 158, 147, 229, 47, 43, 22, 250, 217, 34, 253, 192, 88, 68, 120, 66, 143, 40, 43])),
                            await crypto.subtle.deriveBits(
                                {
                                    name: "ecdh",
                                    public: await crypto.subtle.importKey("raw", responseContent.slice(58), { name: "ecdh", namedCurve: "P-256" }, false, [])
                                },
                                keyPair.privateKey
                            )
                        ))

                        await changeKeys(104, 115, await crypto.subtle.digest("sha-384", Uint8Array.from(handshakeMessages)))
                    }
                })()

                responses = responses.slice(responseEnd)
            }
        }
    })

    return (request) => {
        encryptWrite([...Array.from(request), 23])
        ++requestsEncrypted
    }
}