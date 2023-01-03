# rPGP Working Examples

A list of non-contrived working examples of the Rust rPGP library to help others attempting to use this library.

Please see the [rPGP](https://github.com/rpgp/rpgp) repo and the [crate documentation](https://docs.rs/pgp/0.9.0/pgp/) for more specific information on Friedel Ziegelmayer's work.

Each example will typically include:
 - A README.md file with a description of the example
 - A secret message to be encrypted. This might be hard coded or read from a file, or passed in as a command line argument.
 - An encryption process, and a decryption process.
 - Some trivial output to show that the encryption and decryption worked.

By non-contrived, I mean that the examples will not take shortcuts that preclude them from being applicable to actual use.

I found this to be a pain point in the existing examples and tests included with the library, so I wanted to provide some examples that are more applicable to real world use cases.

Each example presented is from a real world use case that is paired down to the bare minimum to demonstrate the use of the library.

This may make it appear to be doing things that are unnecessary in the context of the example, but it is done to demonstrate the practical uses of the library.