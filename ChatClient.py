#!/usr/bin/env python
from __future__ import print_function
import argparse
from collections import defaultdict
from datetime import datetime as dt
import google
import messages_pb2 as proto
import random
import socket
import sys
import threading
import time
import cryptography
import os
import signal
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, hmac, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


registered = False
listen_port = 0
chat_users = {}
username = ""
password = ""
PIECE_SIZE = 1

session_identity_key = None
pre_keys = []

PREKEY_SIZE = 100

TCP_BUFFER_SIZE = 65535
SERVER_PUB_KEY = "server.pub"

ip = None
port = None

kdf_sending_chain = {}
kdf_receiving_chain = {}
identity_keys = {}

logged_in = False

def main():
    global username
    global password
    global ip
    global port
    os.setpgrp()
    parser = argparse.ArgumentParser(description='Chat client for Netowrk Security class.')
    parser.add_argument('-sip', help='The server this client should connect to.', type=str, nargs='?', default='127.0.0.1')
    parser.add_argument('-sp', help='The port this client should connect to.', type=int, nargs='?', default=4590)
    parser.add_argument('-U', help='Username to register with the chat server.', type=str, nargs='?')
    parser.add_argument('-p', help='Password to be used to login.', type=str, nargs='?')
    args = parser.parse_args(sys.argv[1:])
    ip = args.sip
    port = args.sp
    username = args.U
    me = username
    password = args.p

    message_handler_therad = threading.Thread(target=incoming_message_handler_thread)
    message_handler_therad.start()
    if username != None and password != None and ip != None and port != None:
        threading.Thread(target=login_thread, args=(username, password)).start()
    else:
        print("Please register or login after server connection is complete.")
    # Spawn shell for messages
    while True:
        print("+> ", end='')
        cmd = raw_input()
        cmd = cmd.split(" ", 1)
        if cmd[0] == "help":
            print("Commands: help list exit msg/send signup signin/login signout/logout")
            print("help: prints this help page.")
            print("list: lists the users connected to the server at this point of time.")
            print("exit: exits the application.")
            print("signup: <username> <password> registers a user associated to the password supplied on the server connected to.")
            print("login/signin: <username> <password> login with a username password.")
            print("msg/send: <username required> sends a message to the username supplied, given the user is logged into the server.")
            print("logout/signout: signs the user out of the server logged into.")
            print("connect: <server ip> <server port> connect to the server on the ip port. Does not log in.")
        elif cmd[0] == "list":
            threading.Thread(target=server_list_thread, args=(False,)).start()
        elif cmd[0] == "connect":
            if len(cmd) != 2:
                print("Please supply the right number of parameters!!")
            params = cmd[1].split(" ", 1)
            if len(params) != 2:
                print("Please supply the right number of parameters!!")
            else:
                ip, port = params
        elif cmd[0] == "exit":
            guess_ill_die()
            return
        elif cmd[0] == "msg" or cmd[0] == "send":
            if len(cmd) != 2:
                print("Please supply the right number of parameters!!")
            params = cmd[1].split(" ", 1)
            if len(params) != 2:
                print("Please supply the right number of parameters!!")
            else:
                threading.Thread(target=send_message_thread, args=(cmd[1],)).start()
        elif cmd[0] == "signup":
            if len(cmd) != 2:
                print("Please supply the right number of parameters!!")
            params = cmd[1].split(" ", 1)
            if len(params) != 2:
                print("Please supply the right number of parameters!!")
            threading.Thread(target=signup_thread, args=(cmd[1],)).start()
        elif cmd[0] == "logout" or cmd[0] == "signout":
            threading.Thread(target=logout_thread).start()
        elif cmd[0] == "login" or cmd[0] == "signin":
            if len(cmd) != 2:
                print("Please supply the right number of parameters!!")
            params = cmd[1].split(" ", 1)
            if len(params) != 2:
                print("Please supply the right number of parameters!!")
            else:
                username, password = params
                threading.Thread(target=login_thread, args=(username, password)).start()
        else:
            print("Invalid command!!")

def guess_ill_die():
    print("Cleaning up...")
    if logged_in:
        t = threading.Thread(target=logout_thread)
        t.start()
        t.join()
    os.killpg(0, signal.SIGKILL)

def fetch_identity(identity_pubkey):
    tls_state = setup_tls_with_server()
    if tls_state == None:
        return
    server_request = proto.ServerPacket()
    identity_pubkey.replace(" ", "")
    server_request.identityRequest.identityKey = identity_pubkey
    send_tls_packet(tls_state, server_request)
    client_packet = proto.ClientPacket()
    decrypted_packet = get_tls_packet(tls_state)
    if decrypted_packet == None:
        return
    client_packet.ParseFromString(decrypted_packet)
    identity_response = client_packet.identityResponse
    if identity_response.success:
        print("Successful identity lookup!!")
        visited = []
        for ik, user in identity_keys.items():
            if user == identity_response.username:
                if ik != identity_response.identityKey:
                    # Identity key updated, delete old kdf chain.
                    del kdf_sending_chain[identity_response.username]
                    del kdf_receiving_chain[identity_response.username]
                    visited.append(ik)
                else:
                    # We just fetched an IK for a user we already had, this shouldn't be possible.
                    print("Weird pkf, but ok.")
        for ik in visited:
            # Delete old ik associated to this identity.
            del identity_keys[ik]
        # Save the new ik to this username
        identity_keys[identity_response.identityKey] = identity_response.username
        chat_users[identity_response.username] = (identity_response.userIP, identity_response.port)
    else:
        print("Failed to fetch identity for:", identity_pubkey)
    tls_state[0].close()
    return identity_response

def fetch_prekey(username):
    tls_state = setup_tls_with_server()
    if tls_state == None:
        return
    server_request = proto.ServerPacket()
    username.replace(" ", "")
    server_request.prekeyRequest.username = username
    send_tls_packet(tls_state, server_request)
    client_packet = proto.ClientPacket()
    decrypted_packet = get_tls_packet(tls_state)
    if decrypted_packet == None:
        return
    client_packet.ParseFromString(decrypted_packet)
    prekey_response = client_packet.prekeyResponse
    if prekey_response.success:
        print("Successful fetch!!")
        chat_users[prekey_response.username] = (prekey_response.userIP, prekey_response.port)
    else:
        print("Failed fetching prekey for:", username)
    tls_state[0].close()
    return prekey_response

def logout_thread():
    global username
    global password
    global logged_in
    if not logged_in:
        print("Please be logged in to  logout :P")
        return
    logged_in = False
    tls_state = setup_tls_with_server()
    if tls_state == None:
        return
    server_request = proto.ServerPacket()
    server_request.logoutRequest.username = username
    server_request.logoutRequest.password = password
    send_tls_packet(tls_state, server_request)
    client_packet = proto.ClientPacket()
    decrypted_packet = get_tls_packet(tls_state)
    if decrypted_packet == None:
        return
    client_packet.ParseFromString(decrypted_packet)
    server_logout_response = client_packet.logoutResponse
    if server_logout_response.success:
        print("Signout successful!!")
    else:
        print("Signout failure!!")
    tls_state[0].close()

def signup_thread(args):
    if ip == None or port == None:
        print("Server information not provided!! Please set server info with connect command or check help.")
        return
    username, password = args.split(" ", 1)
    username.replace(" ", "") # No spaces in username.
    password.replace(" ", "") # No spaces in password.
    tls_state = setup_tls_with_server()
    if tls_state == None:
        return
    server_request = proto.ServerPacket()
    server_request.signupRequest.username = username
    server_request.signupRequest.password = password
    send_tls_packet(tls_state, server_request)
    client_packet = proto.ClientPacket()
    decrypted_packet = get_tls_packet(tls_state)
    if decrypted_packet == None:
        return
    client_packet.ParseFromString(decrypted_packet)
    server_signup_response = client_packet.signupResponse
    if server_signup_response.success:
        print("User", username, " signed up successfully!!")
    else:
        print("User", username, " signup FAILURE!!")
    tls_state[0].close()

def get_decrypted_message(message_request):
    # Check to see if theres a KDF chain associated to the given identity.
    if not identity_keys.has_key(message_request.identityKey):
        fetch_identity(message_request.identityKey)
    sender = identity_keys[message_request.identityKey]
    if not kdf_receiving_chain.has_key(sender):
        # First message from sender, calculate secrets and init state.
        ik_src = serialization.load_pem_public_key(
                str(message_request.identityKey),
                backend=default_backend())
        dh1 = session_identity_key.exchange(ec.ECDH(), ik_src)
        ephemeral_key = serialization.load_pem_public_key(
                str(message_request.senderEphemeral),
                backend=default_backend())
        # Need to lookup which OPK was used.
        match = False
        for opk in pre_keys:
            pem = opk.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
            if pem == message_request.preKey:
                match = True
                break
        if not match:
            print("Ephemeral used not found!!")
            return
        dh2 = opk.exchange(ec.ECDH(), ephemeral_key)
        pre_keys.remove(opk)
        kdf_receiving_chain[sender] = (dh1+dh2, 0)
    kdf_checkpoint = kdf_receiving_chain[sender]
    secret, chain_position = kdf_receiving_chain[sender]
    # Ratchet forward to the right chain position.
    while chain_position < message_request.chainPosition:
        # We'd want to save keys in case out of order messages arrive, but we don't care.
        hasher = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
        hasher.update(hex(0))
        hmac0 = hasher.finalize()
        chain_position += 1
        secret = hmac0
    if chain_position > message_request.chainPosition:
        # Invalid old messsage (maybe a replay)
        return sender, None
    # Gen ck(n+1)
    hasher = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
    hasher.update(hex(0))
    hmac0 = hasher.finalize()
    # Get hmac1 used to derive message keys.
    hasher = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
    hasher.update(hex(1))
    hmac1 = hasher.finalize()
    derived_random = HKDF(
            algorithm=hashes.SHA256(),
            length=80, # 32 message key, 32 hmac key, 16 IV
            salt=None,
            info=None,
            backend=default_backend()).derive(hmac1)
    symmetric_key_ephemeral = derived_random[0:32]
    hmac_key = derived_random[32:64]
    iv = derived_random[64:80]
    kdf_receiving_chain[sender] = (hmac0, chain_position+1)
    return sender, verify_and_decrypt(symmetric_key_ephemeral, hmac_key, iv, message_request.payload, message_request.oneDoesNotSimplyMAC)

def get_encrypted_message(dst, message):
    lookup = False
    ephemeral_key = None
    # Lookup state with dst
    if not kdf_sending_chain.has_key(dst):
        # Need to fetch identity key and prekey from server.
        prekey_response = fetch_prekey(dst)
        ik_dst = serialization.load_pem_public_key(
                str(prekey_response.identityKey),
                backend=default_backend())
        dh1 = session_identity_key.exchange(ec.ECDH(), ik_dst)
        opk_dst = serialization.load_pem_public_key(
                str(prekey_response.preKey),
                backend=default_backend())
        ephemeral_key = ec.generate_private_key(
                ec.SECP384R1(), default_backend())
        dh2 = ephemeral_key.exchange(ec.ECDH(), opk_dst)
        # chain_position = 0
        kdf_sending_chain[dst] = (dh1+dh2, 0)
        lookup = True
    # Now we have a KDF chain for the sender!
    kdf_checkpoint = kdf_sending_chain[dst]
    secret, chain_position = kdf_sending_chain[dst]
    # Gen ck(n+1)
    hasher = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
    hasher.update(hex(0))
    hmac0 = hasher.finalize()
    hasher = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
    hasher.update(hex(1))
    hmac1 = hasher.finalize()
    derived_random = HKDF(
            algorithm=hashes.SHA256(),
            length=80, # 32 message key, 32 hmac key, 16 IV
            salt=None,
            info=None,
            backend=default_backend()).derive(hmac1)
    symmetric_key_ephemeral = derived_random[0:32]
    hmac_key = derived_random[32:64]
    iv = derived_random[64:80]
    ct, cth = encrypt_and_hash(symmetric_key_ephemeral, hmac_key, iv, message)
    # Update KDF chain for next message.
    kdf_sending_chain[dst] = (hmac0, chain_position+1)
    client_packet = proto.ClientPacket()
    serialized_identity_public_key = session_identity_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    client_packet.messageRequest.identityKey = serialized_identity_public_key
    if ephemeral_key != None:
        serialized_ephemeral_key = ephemeral_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        client_packet.messageRequest.senderEphemeral = serialized_ephemeral_key
        client_packet.messageRequest.preKey = prekey_response.preKey
    client_packet.messageRequest.chainPosition = chain_position
    client_packet.messageRequest.payload = ct
    client_packet.messageRequest.oneDoesNotSimplyMAC = cth
    return client_packet

def send_message_thread(message_args):
    global me
    global PIECE_SIZE
    if not logged_in:
        print("Please login first!!")
        return
    part_counter = 0
    receiver, message = message_args.split(" ", 1)
    receiver.replace(" ", "")
    message.strip()
    # Fetch userlist for freshness, maybe someone logged out.
    if not server_list_thread(True):
        print("Unable to check freshness of the user, hoping for the best and sending a message!!")
    if not chat_users.has_key(receiver):
        print("User", receiver, "not registered with the server!!")
        return
    client_packet = get_encrypted_message(receiver, message)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Let's just assume our message is smaller than TCP_BUFFER_SIZE for now.
    sock.connect(chat_users[receiver])
    sock.send(client_packet.SerializeToString())
    message_response = proto.ClientPacket()
    message_response.ParseFromString(sock.recv(TCP_BUFFER_SIZE))
    if message_response.messageResponse.success:
        print("Message sent!!")
    else:
        print("Message send failure!!")
    sock.close()

def incoming_message_handler_thread():
    global listen_port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', 0))
    sock.listen(1)
    listen_port = sock.getsockname()[1]
    while True:
        recv = sock.accept()
        # print("Received", data, addr)
        threading.Thread(target=handle_incoming_message_thread, args=(recv,)).start()

def handle_incoming_message_thread(recv):
    conn, addr = recv
    client_packet = proto.ClientPacket()
    try:
        client_packet.ParseFromString(conn.recv(TCP_BUFFER_SIZE))
        message_request = client_packet.messageRequest
        sender, message = get_decrypted_message(message_request)
        print("Sender: ", sender, " says:", message)
        message_response = proto.ClientPacket()
        message_response.messageResponse.success = True
        conn.send(message_response.SerializeToString())
        return
    except google.protobuf.message.DecodeError:
        print("Received an invalid proto!!")

def server_list_thread(quiet):
    global chat_users
    server_packet = proto.ServerPacket()
    server_packet.listRequest.askForList = True
    tls_state = setup_tls_with_server()
    if tls_state == None:
        return
    send_tls_packet(tls_state, server_packet)
    try:
        data = get_tls_packet(tls_state)
        if data == None:
            tls_state[0].close()
            return False
        client_packet = proto.ClientPacket()
        client_packet.ParseFromString(data)
        users_active = []
        for user in client_packet.listResponse.connectedUsers:
            users_active.append(user.username)
            if not chat_users.has_key(user.username):
                chat_users[user.username] = ()
        for u in set(chat_users.keys()) - set(users_active):
            del chat_users[u]
        if not quiet:
             print("Users registered:", chat_users.keys())
    except socket.timeout:
        if not quiet:
            print("Failed to fetch list!! Please try again...")
            tls_state[0].close()
            return False
    except google.protobuf.message.DecodeError:
        if not quiet:
            print("Received an invalid proto as response!! Please try again...")
            tls_state[0].close()
            return False
    tls_state[0].close()


def send_tls_packet(tls_state, packet_to_encrypt):
    packet = proto.TLSPacket()
    packet.payload, packet.oneDoesNotSimplyMAC = encrypt_and_hash(tls_state[1], tls_state[2], tls_state[3], packet_to_encrypt.SerializeToString())
    tls_state[0].send(packet.SerializeToString())

def get_tls_packet(tls_state):
    packet = proto.TLSPacket()
    packet.ParseFromString(tls_state[0].recv(TCP_BUFFER_SIZE))
    return verify_and_decrypt(tls_state[1], tls_state[2], tls_state[3], packet.payload, packet.oneDoesNotSimplyMAC)

def login_thread(username, password):
    global listen_port
    global session_identity_key
    global pre_keys
    global logged_in
    session_identity_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend())
    serialized_identity_public_key = session_identity_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    server_packet = proto.ServerPacket()
    server_packet.loginRequest.username = username
    server_packet.loginRequest.password = password
    server_packet.loginRequest.identityKey = serialized_identity_public_key
    # Add N oneTimePreKeys.
    for i in range(PREKEY_SIZE):
        pk = ec.generate_private_key(
                ec.SECP384R1(), default_backend())
        pk_pub = pk.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        pre_keys.append(pk)
        server_packet.loginRequest.oneTimePreKeys.append(pk_pub)
    # Wait for listen port information
    while listen_port == 0:
        time.sleep(1)
    server_packet.loginRequest.port = listen_port
    tls_state = setup_tls_with_server()
    if tls_state == None:
        return
    send_tls_packet(tls_state, server_packet)
    try:
        data = get_tls_packet(tls_state)
        if data == None:
            print("Failed to register with Server!! Please try again...")
            return
        client_packet = proto.ClientPacket()
        client_packet.ParseFromString(data)
        if(client_packet.loginResponse.acknowledge):
            print("Registered with Server!")
            global registered
            registered = True
            tls_state[0].close()
        else:
            print("Received response from Server ACK was unset!!")
    except socket.timeout:
        print("Failed to register with Server!! Please try again...")
        logged_in = False
        tls_state[0].close()
    except google.protobuf.message.DecodeError:
        print("Received an invalid proto as response!! Please try again...")
        logged_in = False
        tls_state[0].close()
    logged_in = True
    tls_state[0].close()
    server_list_thread(True)

def encrypt_and_hash(aes_key, hmac_key, iv, plain_text):
    # Encrypt the plaintext.
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(256).padder()
    padded_plaintext = padder.update(plain_text) +  padder.finalize()
    cipher_text = encryptor.update(padded_plaintext) + encryptor.finalize()
    # Generate HMAC with HMAC key.
    hasher = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    hasher.update(cipher_text)
    hashed_cipher_text = hasher.finalize()
    return cipher_text, hashed_cipher_text

def verify_and_decrypt(aes_key, hmac_key, iv, cipher_text, hmac_provided):
    hasher = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    hasher.update(cipher_text)
    try:
        hasher.verify(hmac_provided)
    except:
        print("HMAC for Ciphertext verification failed!!")
        return None
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(256).unpadder()
    return unpadder.update(decrypted_padded_message) + unpadder.finalize()

def setup_tls_with_server():
    # Do TLS things
    # First verify that the Server is actually valid
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        test = sock.connect_ex((ip, port))
    except TypeError:
        print("Please supply a valid ip and port for the server!!")
        return None
    if test != 0:
        print("Server unreachable!! Please configure the right server and try again...")
        return None
    # Send Server SYN
    syn = proto.TLSSyn()
    # Generate DHPriv for the session.
    dhe_half = ec.generate_private_key(
            ec.SECP384R1(), default_backend())
    nonce1 = str(random.randint(1, 2**64)).rjust(20)
    # Load Server public key.
    try:
        with open(SERVER_PUB_KEY, "rb") as serialized_public:
            server_dh_half = serialization.load_pem_public_key(
                    serialized_public.read(),
                    backend=default_backend())
    except ValueError:
        print("Invalid PEM public key supplied!! Try again with a valid file.")
        guess_ill_die()
    except IOError:
        print(SERVER_PUB_KEY +" not found!! Please supply a valid file.")
        guess_ill_die()
    syn.clientDHHalf = dhe_half.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    secret = dhe_half.exchange(ec.ECDH(), server_dh_half)
    # Encrypt nonce by expanding secret to get AES and HMAC keys.
    # Entropy expanded into required keys.
    derived_random = HKDF(
            algorithm=hashes.SHA256(),
            length=80, # 32 message key, 32 hmac key, 16 IV
            salt=None,
            info=None,
            backend=default_backend()).derive(secret)
    symmetric_key_ephemeral = derived_random[0:32]
    hmac_key = derived_random[32:64]
    iv = derived_random[64:80]

    # Encrypt, HMAC and send it on the wire.
    ct, cth = encrypt_and_hash(symmetric_key_ephemeral, hmac_key, iv, nonce1)
    syn.encryptedNonce = ct
    syn.oneDoesNotSimplyMAC = cth
    tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_socket.connect((ip, port))
    tls_socket.send(syn.SerializeToString())

    # Receive SYNACK
    synack = proto.TLSSynAck()
    synack.ParseFromString(tls_socket.recv(TCP_BUFFER_SIZE))
    # Check if Nonce1 matches.
    plain_text = verify_and_decrypt(symmetric_key_ephemeral, hmac_key, iv, synack.encryptedNonces, synack.oneDoesNotSimplyMAC)
    if plain_text == None:
        print("Error setting up TLS connection with server, plain text decryption failed...")
        return
    received_nonce1 = plain_text[0:20]
    nonce2 = plain_text[20:40]
    if nonce1 != received_nonce1:
        print("ERROR SETTING UP TLS CONNECTION WITH SERVER!! NONCE FAILURE!!")
        return

    # Send ACK
    ack = proto.TLSAck()
    ct, cth = encrypt_and_hash(symmetric_key_ephemeral, hmac_key, iv, nonce2)
    ack.challengeNonce = ct
    ack.oneDoesNotSimplyMAC = cth
    tls_socket.send(ack.SerializeToString())

    # Return secret for comms and conn.
    return (tls_socket, symmetric_key_ephemeral, hmac_key, iv)

if __name__ == "__main__":
    main()
