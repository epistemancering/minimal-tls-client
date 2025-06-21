# minimal TLS client
This library demonstrates a typed TLS client with no `import` other than [`net`](https://nodejs.org/api/net.html). **This implementation is not secure!** If you need a TLS client in production, use [Node's built-in `tls` module](https://nodejs.org/api/tls.html).
```javascript
import tls from "./tls.mjs"

(async () => {
    const tlsRequest = await tls(
        { port: 443 },
        (response) => {
            console.log(String.fromCharCode(...response))
        }
    )

    const textEncoder = new TextEncoder
    tlsRequest(textEncoder.encode("hello,"))
    tlsRequest(textEncoder.encode("server!"))
})()
```
## installation
Download `tls.mjs`
## usage
`tls` exports a function that creates a TLS connection. It accepts options to pass to `net.createConnection` and a response handler, and it returns a function that sends requests.
## test
1. Create a file named `pfx.js` that exports your TLS credentials as a string
1. Download `test.js`
1. Run `node test`