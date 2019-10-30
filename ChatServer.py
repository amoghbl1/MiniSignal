#!/usr/bin/env python

import argparse
import google
import messages_pb2 as proto
import random
import socket
import sys
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, hmac, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cryptography

SERVER_LOGIN_REQUEST = "loginRequest"
SERVER_LIST_REQUEST = "listRequest"
SERVER_SIGNUP_REQUEST = "signupRequest"
SERVER_LOGOUT_REQUEST = "logoutRequest"
SERVER_PRE_KEY_REQUEST = "prekeyRequest"
SERVER_IDENTITY_REQUEST = "identityRequest"
TCP_BUFFER_SIZE = 65535
SERVER_PRIV_KEY = "server.priv"

registered_users = {}
identity_key_store = {}
pre_key_store = {}
password_store = {"user":"iiit123", "u1":"u1", "u2":"u2", "u3":"u3"}

def main():
    parser = argparse.ArgumentParser(description='Chat server for Network Security class.')
    parser.add_argument('-sip', help='The ip this server should run on.', type=str, nargs='?', default='127.0.0.1')
    parser.add_argument('-sp', help='The port this server should listen on.', type=int, nargs='?', default=4590)
    args = parser.parse_args(sys.argv[1:])
    server_ip = args.sip
    server_port = args.sp
    sock_addr = (server_ip, server_port)
    # Main opens connection to a socket and loops waiting for connections.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(sock_addr)
    sock.listen(1)
    print "Server listening on ", sock_addr
    while True:
        recv = sock.accept()
        # Let thread deal with the connection, wait for new connections.
        threading.Thread(target=socket_message_handler, args=(recv, )).start()

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
    except cryptography.encryption.InvalidSignature:
        print("HMAC for Ciphertext verification failed!!")
        return
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(cipher_text) + decryptor.finalize()
    unpadder = padding.PKCS7(256).unpadder()
    return unpadder.update(decrypted_padded_message) + unpadder.finalize()

def send_tls_packet(tls_state, packet_to_encrypt):
    packet = proto.TLSPacket()
    packet.payload, packet.oneDoesNotSimplyMAC = encrypt_and_hash(tls_state[1], tls_state[2], tls_state[3], packet_to_encrypt.SerializeToString())
    tls_state[0].send(packet.SerializeToString())

def get_tls_packet(tls_state):
    packet = proto.TLSPacket()
    packet.ParseFromString(tls_state[0].recv(TCP_BUFFER_SIZE))
    return verify_and_decrypt(tls_state[1], tls_state[2], tls_state[3], packet.payload, packet.oneDoesNotSimplyMAC)

def socket_message_handler(recv):
    # New connection received, do TLS things.
    conn, addr = recv
    syn = proto.TLSSyn()
    syn.ParseFromString(conn.recv(TCP_BUFFER_SIZE))
    # Load servers long term curve half.
    try:
        with open(SERVER_PRIV_KEY, "rb") as serialized_private:
            server_priv_key =  serialization.load_pem_private_key(
                    serialized_private.read(),
                    password=None,
                    backend=default_backend())
    except ValueError:
        print("Invalid PEM public key supplied!! Try again with a valid file.")
        return
    except IOError:
        print(SERVER_PRIV_KEY +" not found!! Please supply a valid file.")
        return
    try:
        client_dhe = serialization.load_pem_public_key(
                str(syn.clientDHHalf),
                backend=default_backend())
    except ValueError:
        print("Invalid DHE half suplied!!")
        return
    secret = server_priv_key.exchange(ec.ECDH(), client_dhe)
    derived_random = HKDF(
            algorithm=hashes.SHA256(),
            length=80, # 32 message key, 32 hmac key, 16 IV
            salt=None,
            info=None,
            backend=default_backend()).derive(secret)
    symmetric_key_ephemeral = derived_random[0:32]
    hmac_key = derived_random[32:64]
    iv = derived_random[64:80]

    # Verify SYN
    nonce1 = verify_and_decrypt(symmetric_key_ephemeral, hmac_key, iv, syn.encryptedNonce, syn.oneDoesNotSimplyMAC)

    # Send SYNACK
    synack = proto.TLSSynAck()
    nonce2 = str(random.randint(1, 2**64)).rjust(20)
    ct, cth = encrypt_and_hash(symmetric_key_ephemeral, hmac_key, iv, nonce1 + nonce2)
    synack.encryptedNonces = ct
    synack.oneDoesNotSimplyMAC = cth
    conn.send(synack.SerializeToString())

    # Verify ACK
    ack = proto.TLSAck()
    ack.ParseFromString(conn.recv(TCP_BUFFER_SIZE))
    received_nonce2 = verify_and_decrypt(symmetric_key_ephemeral, hmac_key, iv, ack.challengeNonce, ack.oneDoesNotSimplyMAC)
    if received_nonce2 != nonce2:
        print "ERROR SETTING UP TLS CONNECTION WITH SERVER!! NONCE FAILURE!!"
        return
    print "Established TLS session with ", addr

    tls_state = (conn, symmetric_key_ephemeral, hmac_key, iv)

    # Get TLS Packet to figure out request.
    data = get_tls_packet(tls_state)
    server_packet = proto.ServerPacket()
    try:
        server_packet.ParseFromString(data)
    except google.protobuf.message.DecodeError:
        print "Invalid packet received!!"
        return
    if(server_packet.HasField(SERVER_LOGIN_REQUEST)):
        handle_login(server_packet.loginRequest, addr, tls_state)
        conn.close()
    elif (server_packet.HasField(SERVER_LIST_REQUEST)):
        handle_list_thread(server_packet.listRequest, tls_state)
        conn.close()
    elif(server_packet.HasField(SERVER_SIGNUP_REQUEST)):
        handle_signup(server_packet.signupRequest, tls_state)
        conn.close()
    elif server_packet.HasField(SERVER_LOGOUT_REQUEST):
        handle_logout(server_packet.logoutRequest, tls_state)
        conn.close()
    elif server_packet.HasField(SERVER_PRE_KEY_REQUEST):
        handle_prekey_request(server_packet.prekeyRequest, tls_state)
        conn.close()
    elif server_packet.HasField(SERVER_IDENTITY_REQUEST):
        handle_identity_request(server_packet.identityRequest, tls_state)
        conn.close()
    else:
        print "Invalid client packet received!!"

def handle_prekey_request(prekeyRequest, tls_state):
    success = False
    client_packet = proto.ClientPacket()
    response = client_packet.prekeyResponse
    if registered_users.has_key(prekeyRequest.username):
        success = True
        response.username = prekeyRequest.username
        response.identityKey = identity_key_store[prekeyRequest.username]
        response.preKey = pre_key_store[prekeyRequest.username].pop()
        response.userIP, response.port = registered_users[prekeyRequest.username]
    response.success = success
    send_tls_packet(tls_state, client_packet)

def handle_identity_request(identityRequest, tls_state):
    success = False
    client_packet = proto.ClientPacket()
    response = client_packet.identityResponse
    for user, ik in identity_key_store.items():
        if ik == identityRequest.identityKey:
            response.identityKey = ik
            response.username = user
            response.userIP, response.port = registered_users[user]
            success = True
            break
    response.success = success
    send_tls_packet(tls_state, client_packet)

def handle_signup(signupRequest, tls_state):
    # Storing password in a dictionary, not written to disk, so any comprimise of
    # RAM is as bad as comprimising a salted hash, if we were to use such a system.
    print "Signup request:", signupRequest.username
    success = True
    if not password_store.has_key(signupRequest.username):
        password_store[signupRequest.username] = signupRequest.password
    else:
        success = False
    client_packet = proto.ClientPacket()
    client_packet.signupResponse.success = success
    send_tls_packet(tls_state, client_packet)

def handle_login(loginRequest, addr, tls_state):
    if not password_store.has_key(loginRequest.username):
        print "Unidentified username!!"
        return
    if password_store[loginRequest.username] != loginRequest.password:
        print "Unauthorized login for user:", loginRequest.username, "using", loginRequest.password
        return
    print "New connection from:", loginRequest.username, "listening at:", loginRequest.port
    registered_users[loginRequest.username] = (addr[0], loginRequest.port)
    identity_key_store[loginRequest.username] = loginRequest.identityKey
    pre_key_store[loginRequest.username] = []
    for prekey in loginRequest.oneTimePreKeys:
        pre_key_store[loginRequest.username].append(prekey)
    print "Got identity key:", identity_key_store[loginRequest.username]
    print "Got", len(pre_key_store[loginRequest.username]), "prekeys"
    client_packet = proto.ClientPacket()
    client_packet.loginResponse.acknowledge = True
    send_tls_packet(tls_state, client_packet)

def handle_logout(logoutRequest, tls_state):
    if not password_store.has_key(logoutRequest.username):
        print "Unidentified username!!"
        return
    if password_store[logoutRequest.username] != logoutRequest.password:
        print "Unauthorized logout for user:", logoutRequest.username, "using", logoutRequest.password
        return
    if not registered_users.has_key(logoutRequest.username):
        print "User", logoutRequest.username, "already logged out!!"
        return
    # delete things stored at login.
    del registered_users[logoutRequest.username]
    del identity_key_store[logoutRequest.username]
    del pre_key_store[logoutRequest.username]
    print "Successful logout!! Sending response..."
    client_packet = proto.ClientPacket()
    client_packet.logoutResponse.success = True
    send_tls_packet(tls_state, client_packet)

def handle_list_thread(listRequest, tls_state):
    global registered_users
    print "List request!!"
    client_packet = proto.ClientPacket()
    i = 0
    connectedUsers = client_packet.listResponse.connectedUsers
    for user, details in registered_users.iteritems():
        connectedUsers.add()
        connectedUsers[i].username = user
        connectedUsers[i].userIP = "TEEHEE"
        connectedUsers[i].listenPort = 0
        i = i + 1
    send_tls_packet(tls_state, client_packet)

if __name__ == "__main__":
    main()
