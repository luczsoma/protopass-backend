import srp
import base64
import binascii



class Client:

    def regdata(username, password):
        salt, vkey = srp.create_salted_verification_key(username, password)

        print("salt:", salt)
        print("vkey:", vkey)
        print()

        result = {}
        result['salt'] = base64.b64encode(salt).decode('utf-8')
        result['verifier'] = binascii.hexlify(vkey).decode('utf-8')
        return result

    def login(username, password):
        usr = srp.User(username, password)
        uname, A = usr.start_authentication()

        result = {}
        result['username'] = username
        result['clientChallenge'] = binascii.hexlify(A).decode('utf-8')

        print(result)

        salt = input("Ender salt: ")
        print(salt)
        server_challenge = input("Server challenge: ")
        print(server_challenge)

        M = usr.process_challenge(base64.b64decode(salt), binascii.unhexlify(server_challenge))

        result = {}
        result['clientProof'] = binascii.hexlify(M).decode('utf-8')

        print(result)