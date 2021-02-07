#!/usr/bin/env node
const dht = require('@hyperswarm/dht')

// in order to bootstrap we start an
// ephemeral node with empty bootstrap array
// and then call listen on it
const bs = dht({
    ephemeral: true,
    bootstrap: []
})

bs.listen(function () {
    const { address, port } = bs.address()
    console.log(`${address}:${port}`)
})
