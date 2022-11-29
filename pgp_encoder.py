from lib2to3.pgen2 import token
import pgpy


# This function is absolutely aweful and is only here
# because of the known limitations of requests library
# def get_token_from_payload(encrypted_payload):
#     ep_file = open("ep.pgp", "w")
#     ep_file.write(encrypted_payload)
#     ep_file.close()
#     privkey, _ = pgpy.PGPKey.from_file('private.key')
#     message = pgpy.PGPMessage.from_file("ep.pgp")
#     token_string = privkey.decrypt(message).message
#     return json.loads(token_string)

pgp_msg_file = "p1_armored_message.txt"
# pgp_msg_file = "ep.pgp"

def main():
    privkey, _ = pgpy.PGPKey.from_file('./key_files/person_two/sec.asc')
    crypt_msg = pgpy.PGPMessage.from_file(pgp_msg_file)
    msg = privkey.decrypt(crypt_msg).message
    print(msg)




    # server_pubkey, _ = pgpy.PGPKey.from_blob(server_pubkey_armored)
    # payload = pgpy.PGPMessage.new(json.dumps(auth_user))
    # encrypted_req['payload'] = str(server_pubkey.encrypt(payload))




if __name__ == "__main__":
    main()