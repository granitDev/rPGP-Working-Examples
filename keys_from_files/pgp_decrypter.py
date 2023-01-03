from lib2to3.pgen2 import token
import pgpy


pgp_msg_file = "p1_armored_message.txt"


def main():
    privkey, _ = pgpy.PGPKey.from_file('./key_files/person_two/sec.asc')
    crypt_msg = pgpy.PGPMessage.from_file(pgp_msg_file)
    msg = privkey.decrypt(crypt_msg).message
    print(msg)


if __name__ == "__main__":
    main()