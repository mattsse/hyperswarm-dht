#!/usr/bin/env node
const stdin = process.openStdin();
const dht = require('@hyperswarm/dht')
const crypto = require('crypto')

stdin.on('data', function (chunk) {
    const addr = chunk.toString().trim()

    const node = dht({
        ephemeral: true,
        bootstrap: [addr]
    })

    const topic = crypto.randomBytes(32)

    // announce a port
    node.announce(topic, {port: 12345}, function (err) {
        if (err) throw err

        // try and find it
        node.lookup(topic)
            .on('data', console.log)
            .on('end', function () {
                // unannounce it and shutdown
                node.unannounce(topic, {port: 12345}, function () {
                    node.destroy()
                    process.exit(1)
                })
            })
    })
});
