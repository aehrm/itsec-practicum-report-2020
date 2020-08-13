# Evaluating the effect on countermeasures preventing the inclusion of off-topic data into Bitcoin's blockchain

[[PDF](report.pdf)]

**Abstract:**

Blockchain-based cryptocurrencies use the blockchain data structure as persistent, distributed, append-only, and timestamped ledger.
These properties make blockchains attractive to use as storage for data that is not related to the payment processing itself.
In the case of Bitcoin's blockchain, recent studies show that this inclusion of off-topic data has already been executed in practice.
In fact, arguably objectionable content is already stored on Bitcoin's blockchain;
this potentially illegal content has the possibility to put participants of the network at legal risk, imposing a threat to the entire network.

To overcome this risk, possible countermeasures were discussed. This paper analyzes a countermeasure by Seeg, which exploits the one-way property of the address generation.
This type of countermeasure can be identified as maximally strong with respect to principles that can be considered compatible with the philosophy of Bitcoin, motivating an evaluation of the strength of this countermeasure.
By performing a brute-force exponential-time inversion on the address generation, an implementation of a circumvention is obtained.

The economic cost for executing this brute-force circumvention can be considered as a reasonable upper bound on the effectiveness of the countermeasure.
Hence, using publicly available benchmark figures, we estimate the cost of the circumvention, to assess the effectiveness of any approach attempting to prevent off-topic inclusions while adhering to the (social) principles of Bitcoin.
