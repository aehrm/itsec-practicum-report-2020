# Hiding off-topic data in legit Bitcoin transactions: Source Code

Implementation as described in: A. Ehrmanntraut, “Evaluating the effect on countermeasures preventing the inclusion of off-topic data into Bitcoin's blockchain”, Report, 2020.

This set of programs generates “legit” transaction containing arbitrary off-topic data as payload.
Similar to vanity address generation, by a brute-force procedure, the payload is encoded in the first most significant bits of public addresses (partial preimages), which are embedded in the transactions.
This additionally generates private keys corresponding to the public parts, and thus provide proof for the “legitimacy” of the public addresses in question.

* `hidedata` performs the preparation and the partial preimage loop and outputs suitable keypairs;
* `buildtx` then constructs the transactions from these keypairs,with assistance from the RPC interface of the Bitcoin daemon.
* `parsedata` allows for the reconstruction of the included data by giving as input the hash ofthe transaction containing the metadata


## Usage

```
$ ./hidedata -h
Usage: ./hidedata -s <strategy> [-X <strategy-option>] [-n <prefix-length>] [-f <file>|-] [-i <data>]

Parameter:
-s <strategy>          Use specified Strategy to hide supplied data. One of "p2pk", "p2pkh",
                       "p2sh".
-X <strategy-option>   Supply additional options to specified strategy. Option string is in the
                       form <key>=<value>. Strategy "p2sh" is the only one accepting options,
                       and requires a 33-byte or 65-byte long public key via -Xpubkey=<hexstr>.
-n <prefix-length>     Use prefixes of specified bitlength.
-i <data>              Hide following data, interpreted literal.
-f <file>|-            Read data to hide from file. If "-" was specified, data is read from
                       standard input.
```

Given specific script type (resp. inclusion strategy), `hidedata` generates keypairs by brute-force search such that the most significant bits of the public address correspond to the specified input data.
Output is a JSON-serialized object printed to stdout, to be passed on to `buildtx`.

In the case of P2SH keypairs, to each keypair the private part corresponds to a nonce value, and public address the hash of following redeem script: `PUSHDATA(20) <nonce> OP_DROP PUSHDATA(<pubkey length>) <pubkey> OP_CHECKSIGVERIFY`. The placeholder `<pubkey>` corresponds to the pubkey given by `-Xpubkey=<hexstr>`.

```
$ ./buildtx -h
Usage: ./buildtx [-f <file>|-] [-F <fee>] [-R <rpcurl>]

Parameter:
-f <file>|-            Read keypairs from specified JSON file. If "-" was specified,
                       data is read from standard input.
-F <fee>               Construct transaction with specified fee in sat/byte.
-R <rpcurl>            Use specified bitcoind deamon endpoint, in the form
                       http://user:password@ipaddr:port/
```

`buildtx` reads the JSON-encoded keypairs generated by `hidedata` in the previous step and generates a (chain) of transactions, with tx outputs holding the specified keypairs.
Writes hex-serialized transactions to stdout, with one transaction per line.

In order to fund the transactions, communication with the RPC interface of the Bitcoin daemon is necessary. (Specifically, `fundrawtransaction` and `signrawtransaction` is invoked.)

Note that the chain construction differs from Figure 4.1 given in the report: 
* chronologically first transaction does contain no payload-holding outputs, 
* chronologically last transaction does only contain a single Null Data metadata-holding output,
* order of the payload-holding outputs follows the *logical* order of the transactions, not the chronological order.


```
$ ./parsedata -h
Usage: ./parsedata [-f <file>|-] [-r <txhash>] [-R <rpcurl>]

Parameter:
-f <file>|-            Offline mode. Read transactions from file, line by line.
                       If "-" was specified, data is read from standard input.
-r <txhash>            Online mode. Communicates with the bitcoind RPC daemon.
                       Extracts data starting with specified head tx, successively
                       fetching relevant tx's from the deamon.
-R <rpcurl>            Use specified bitcoind deamon endpoint, in the form
                       http://user:password@ipaddr:port/
```

`parsedata` performs a reconstruction of the payload embedded in transactions, and outputs the payload to stdout.
The program peforms in either offline or online mode.
In offline mode, the program reads hex-serialized transactions, line by line, from the specified input.
In online mode, the program takes as input the hash of the head transaction (i.e. the one holding metadata, resp. the last one generated in the previous step).
Communicating with the RPC interface of the Bitcoin daemon, relevant transactions are fetched automatically.
(Note: this invokes `getrawtransaction`, and in general, requires the `-txindex` option of the daemon enabled.)

## Example

```bash
# start the daemon in regtest mode
$ bitcoind -txindex -regtest --rpcuser=user -rpcpassword=pass
# generate address and blocks
$ bitcoin-cli -regtest getnewaddress
2NCwxdmKcUnxwe1RKZoNvpscHgPNywbqEqA
$ bitcoin-cli -rpcuser=user -rpcpassword=pass -regtest generatetoaddress 10 2NCwxdmKcUnxwe1RKZoNvpscHgPNywbqEqA
# hides the picture in p2pk keypairs, within the 20 most significant bits of each pubkey 
$ ./hidedata -s p2ms -n 20 -f 204px-Tux.svg.png > tee pairs
$ cat pairs
{
  "metadata": {
     "method":      "p2ms",
     "data_len":    22137,
     "prefix_len":  20
  },
  "keypairs": [["0289504300b0bd600e46c8e108a9bc22a7c767b2b3f87d352aa5424b08c69c04d7", "732b6e1d7aef87e4d139d34f7e5b3f8e65f9f58aba44513b345c6ead00349e87"], ...],
}
$ ./buildtx -R 'http://user:pass@localhost:18443/' -f pairs > txs
Generated transaction
$ while read -r tx; do \
    bitcoin-cli -regtest -rpcpassword=pass -rpcuser=user sendrawtransaction $tx; \
    bitcoin-cli -rpcuser=user -rpcpassword=pass -regtest generatetoaddress 1 2NCwxdmKcUnxwe1RKZoNvpscHgPNywbqEqA; \
  done < txs
# tx hashes, each followed by block including that tx
f2ab5adeb41564de9dab2363910da2bb007469ab527d3cadf4b8147618b78f46
[
  "27d0b1a76f75d8a0d77b13cf1c4cb33458fea98e598eb98ebe3bd16cbdbcf1fb"
]
c9d7a7ff897d540e5bff45afa66c593e5636033968e219e536c55e642dd9dd74
[
  "66d5ae27f6617148bbe43136f364bc0b6fbb137dc6e19e96d95e182260fa4702"
]
...
6a3780e29b124f3d1c25ad78d37d4e0fcd7a65999832ca70c827aedd6a5b9a66
[
  "525dcb4ae96f7adc67a8cf48f6a931a6a6e72acba2066b15702654c038b5d386"
]
# parse embedded payload from head tx hash
$ ./parsedata -R 'http://user:pass@localhost:18443/' -r 6a3780e29b124f3d1c25ad78d37d4e0fcd7a65999832ca70c827aedd6a5b9a66 > parsed.png
Read 17 transactions
tx num: 15, prefix bits: 20, data length: 22137
$ diff -s 204px-Tux.svg.png parsed.png
Files 204px-Tux.svg.png and parsed.png are identical
```


## Building and Dependencies

* Build by invoking `make`.
* Required dependencies: openssl>=1.1, gmp>=6.2, curl>=7.71.
