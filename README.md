# fuzi_q
## Over the net fuzzing of QUIC servers or clients.

Fuzi_q started from the testsuite of [picoquic](https://github.com/private-octopus/picoquic).
Picoquic is an implementation of QUIC written in C, and there is always
the suspicion that memory errors lurk somewhere in the C code. Sure, the code went
through multiple rounds of interop testing, and the internal test suites
is extensive, but there is always the risk of some rarely used code path
escaping testing and hiding some bug. The recommended solution is to "fuzz the
code", but encryption goes in the way. QUIC protocol messages are encrypted,
so catching them in transit and fuzzing them mostly tests the crypto code, and
not much else. To pass though decryption, the messages should be fuzzed before they
are encrypted and sent. Fuzi_q does that by instrumenting the Picoquic stack.

Fuzi_q hooks into the Picoquic stack, catching messages just before they would
be encrypted and fuzzing them. It tries to do that intelligently. For each connection,
Fuzi_q determines an encryption point, such as "the initial messages ave been
processed", or "the handshake is confirmed", or "the connection is closing".
The connection progresses up to that state, and then packets are fuzzed.

The fuzzing itself is based on knowledge of the QUIC protocol. The fuzzer
might modify QUIC frames, or insert randomly chosen QUIC frames in the packets.
The procedures implemented in the initial version are simple, there is clearly
room for more sophistication. Suggestions are welcome.

Fuzi_q can be used as a client to test a QUIC server, or as a server to test
a QUIC client.

A list of bugs surfaced using Fuzi_Q is available on
[this wiki page](https://github.com/private-octopus/fuzi_q/wiki/Bugs-found-using-Fuzi_Q).

The Fuzi_q code uses Picoquic, which itself relies on
[Picotls](https://github.com/h2o/picotls) and on OpenSSL libraries.
To build Fuzi_q, first build Picoquic, then install code from the
[Fuzi_q repo](https://github.com/private-octopus/fuzi_q), and simply do:
```
cmake .
make
```
This will build the executable `fuzi_q` and the test program `fuzi_qt`,
which can be used to verify you installation.

Starting `fuzi_q -h` displays a list of parameters.

The distribution includes a Visual Studio solution `fuzi_q_vs.sln` for
building on Windows._
