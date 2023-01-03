# Using Existing Keys

This example shows how to use existing keys to encrypt and decrypt messages.

When run, the program will:
- Encrypt a string, and save the encrypted string to a file.
- Read in that file, and decrypt the message it contains.
- Print both strings for the user to verify that they match.

There are two companion python scripts to prove that this example will work with unrelated PGP libraries.

Running the `pgp_decrypter.py` will decrypt and print the message contained in the "encrypted_message.txt" file created by the "pgp_example" program.

Running the `pgp_encrypter.py` will create an "encrypted_message.txt" file. Commenting out the line in `main.rs` that calls the `encrypt_message()` with the python generated "encrypted_message.txt" and then running the program will decrypt and print out the message from the script, which you will be able to see, is different from the Rust message.
