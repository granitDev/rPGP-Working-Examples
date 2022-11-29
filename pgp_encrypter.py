from lib2to3.pgen2 import token
import pgpy

def main():
    encrypted_msg_file = "encrypted_message.txt"
    public_key_file = "./key_files/pub.asc"
    secret_msg = "Secret message from python encoder script"

    pubkey, _ = pgpy.PGPKey.from_file(public_key_file)
    message = pgpy.PGPMessage.new(secret_msg)
    armored_msg = pubkey.encrypt(message)
    print(armored_msg, file=open(encrypted_msg_file, 'w'))


if __name__ == "__main__":
    main()