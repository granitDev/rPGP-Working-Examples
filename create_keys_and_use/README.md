# Create and Use PGP Keys

This example shows how to create and use PGP keys to encrypt and decrypt messages.

When run, the program will:
- Create a new PGP key pair and keep them in memory
- Pass the public key to the `encrypt_message()` function, returning an encrypted string
- Use the private key to decrypt the message and print it out

The keys are converted to ASCII armored format, this is not strictly necessary for the encryption and decryption to work, but it is useful for many applications.