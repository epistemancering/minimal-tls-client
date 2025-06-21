import * as https from "https"
import tls from "./tls.mjs"
import pfx from "./pfx.js"
/**@import * as net from "net"*/

const httpsServer = https.createServer(
    { pfx: Buffer.from(pfx, "base64") },
    (request, response) => {
        response.end("success")
    }
).listen(
    undefined,
    async () => {
        (await tls(
            { port: /**@type {net.AddressInfo}*/(httpsServer.address()).port },
            (response) => {
                console.log(String.fromCharCode(...response))
                process.exit()
            }
        ))(new TextEncoder().encode("GET / HTTP/1.1\r\nhost:\r\n\r\n"))
    }
)