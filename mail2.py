import socket, threading, sqlite3, json, time, base64
import dns.resolver

#####################################
#### CRYPTO
#####################################

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key, load_ssh_public_key

def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    pvt_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    print(f"If needed, here are new generated private + public keys.\nYou can add this to 'config.py':\n   PRIVATE_KEY = {pvt_bytes}")
    print(f"and add this to your domain DNS, as a TXT record:\n   mail2server:<ip_of_your_server>;mail2pubkey:{pub_bytes}")
    print("Then restart the server.")

def sign(message, private_key):
    padding_instance = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    return base64.b64encode(private_key.sign(message.encode(), padding_instance, hashes.SHA256()))

def verify(message, signature, public_key):
    sig = base64.b64decode(signature)
    padding_instance = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    try:
        public_key.verify(sig, message.encode(), padding_instance, hashes.SHA256())
        return True
    except cryptography.exceptions.InvalidSignature:
        return False    

#####################################
#### UTILS
#####################################
def encode_json_message(j):
    data = json.dumps(j).encode()
    prefix = b"J" + len(data).to_bytes(4, byteorder="big")
    return prefix + data

def encode_text_message(t):
    t2 = t.encode()
    prefix = b"T" + len(t2).to_bytes(4, byteorder="big")
    return prefix + t2  

#####################################
#### DB
#####################################
class DB():
    def connect(self):
        self.db = sqlite3.connect("mail2.db", check_same_thread=False)
        self.db.execute('create table if not exists users(id integer primary key, login text unique, password text, dt timestamp default current_timestamp);')
        self.db.execute('create table if not exists mails(id integer primary key, _from text, _to text, content text, dt timestamp default current_timestamp);')
        print("db connected")

    def add_user(self, login, password):
        try:
            self.db.execute('insert into users(login, password) values(?, ?);', (login, password))
            self.db.commit()
            print(f"user {login=} added")
            return True
        except:
            return False

    def add_mail(self, _from, _to, content):
        self.db.execute('insert into mails(_from, _to, content) values(?, ?, ?);', (_from, _to , content))
        self.db.commit()
        print("mail delivered")

    def list_users(self):
        print("list of users:")
        for r in self.db.execute('select * from users'):
            print(r)

    def list_mails(self):
        print("list of mails:")
        for r in self.db.execute('select * from mails'):
            print(r)

#####################################
#### CLIENT
#####################################
class Client():
    def __init__(self, server):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((server, 555))
            self.connected = True
        except:
            print("ERROR, cannot connect mail server")
            self.connected = False

    def requires_connected(func):
        def wrapper(self, *args, **kwargs):
            if self.connected:
                return func(self, *args, **kwargs)
            else:
                print("(abandoned because not connected)")
        return wrapper

    @requires_connected
    def read_server_response(self):
        buf = self.socket.recv(5)
        data_type, data_size = buf[0:1], int.from_bytes(buf[1:], byteorder="big")
        buf = self.socket.recv(data_size)
        if data_type == b"J":  # JSON            
            data = json.loads(buf)
        elif data_type == b"B":  # BINARY
            data = buf
        elif data_type == b"T":  # TEXT
            data = buf.decode()
        return data

    @requires_connected
    def login(self, login, password):
        print(f"login to {login}...")
        self.socket.send(encode_json_message({"action": "login", "login": login, "password": password}))
        print(self.read_server_response())

    @requires_connected
    def send_mail(self, _to, content):
        print(f"sending email to {_to}...")
        self.socket.send(encode_json_message({"action": "send", "to": _to, "content": content}))
        print(self.read_server_response())

    @requires_connected
    def read_mails(self):
        print(f"reading mails...")
        self.socket.send(encode_json_message({"action": "read"}))
        j = self.read_server_response()
        if j["status"] == "success":
            for row in j["mails"]:
                print(row)
            print("(end of list)")
        else:
            print(j["message"])

    @requires_connected
    def close(self):
        self.socket.close()

    @requires_connected
    def add_user(self, login, password):
        print(f"adding new user...")
        self.socket.send(encode_json_message({"action": "adduser", "login": login, "password": password}))
        print(self.read_server_response())

#####################################
#### SERVER
#####################################
class Server():
    def __init__(self):
        try:
            from config import SERVER_DOMAIN, ADMIN_USER, PRIVATE_KEY
            self.server_domain = SERVER_DOMAIN            
            self.admin_user = ADMIN_USER
        except:
            print("The file 'config.py' is missing or incomplete. You can copy 'example_config.py' into 'config.py' and modify it.")
            generate_keys()
            exit()
            
        try:
            self.private_key = load_pem_private_key(PRIVATE_KEY, None, backend=default_backend())
        except:
            print("The PRIVATE_KEY from config.py could not be loaded.")
            generate_keys()
            exit()

        self.db = DB()
        self.db.connect()

    def find_server(self, domain):
        server = None
        for r in dns.resolver.resolve(domain, 'TXT'):
            txt = r.to_text()
            if txt[0] == '"':
                txt = txt[1: -1]
            if txt.startswith("mail2server:"):
                server, pubkey = txt.split(";")
                server, pubkey = server.split("mail2server:")[1], pubkey.split("mail2pubkey:")[1]
        return server, pubkey

    def send_text_response(self, connection, text):
        connection.send(encode_text_message(text))

    def send_json_response(self, connection, j):
        connection.send(encode_json_message(j))

    def client_listener(self, connection, address):
        print(f"New connection {connection=} {address=}")
        state = None
        session = None
        while True:
            # prefix
            try:
                buf = connection.recv(5)
            except ConnectionResetError:
                break
            if buf == b"":
                break
            data_type, data_size = buf[0:1], int.from_bytes(buf[1:], byteorder="big")
            if data_size > 1024 and session is None:
                send_text_response(connection, "ERROR, size too big without session, closing connection")
                break
            else:
                buf = connection.recv(data_size)
            if data_type == b"J":  # JSON            
                data = json.loads(buf)
            elif data_type == b"B":  # BINARY
                data = buf
            else:
                self.send_text_response(connection, "ERROR, bad prefix, closing connection")
                connection.close()
            
            # action
            if data["action"] == "login":
                if (data["login"] == self.admin_user["login"] and data["password"] == self.admin_user["password"]) or len(list(self.db.db.execute("select * from users where login=? and password=?", (data["login"], data["password"])))) > 0:
                    session = data["login"]
                    self.send_text_response(connection, f"OK, logged in, {data['login']}")
                else:
                    session = None
                    self.send_text_response(connection, f"ERROR, cannot log in, {data['login']}")
            elif data["action"] == "send":
                if session is None:
                    self.send_text_response(connection, "ERROR, not logged in, cannot send mail")
                else:
                    _from = session
                    content = data["content"]
                    to = data["to"]
                    domain = to.split("@")[1]
                    server, _ = self.find_server(domain)
                    print(f"Sending mail2 {_from=} {to=} {content=} using {server=}")
                    signature = sign(_from + to + content, self.private_key)

                    try:
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s2.connect((server, 555))
                        s2.send(encode_json_message({"action": "deliver", "from": session, "to": to, "content": content, "signature": signature}))
                        self.send_text_response(connection, "OK, mail sent")
                    except:
                        self.send_text_response(connection, f"ERROR, mail could not be delivered to {server=}")
            elif data["action"] == "read":
                if session:
                    L = list(self.db.db.execute("select * from mails where _to=?", (session, )))
                    self.send_json_response(connection, {"status": "success", "mails": L})
                else:
                    self.send_json_response(connection, {"status": "error", "message": "ERROR, cannot read mails (not logged in)"})
            elif data["action"] == "deliver":
                _to = data["to"]
                to_domain = _to.split("@")[1]
                if to_domain != self.server_domain:
                    self.send_text_response(connection, "ERROR, cannot deliver, recipient of your mail is not here")
                else:
                    _from = data["from"]
                    from_domain = _from.split("@")[1]
                    _, domain_pubkey = self.find_server(domain)
                    pubkey = load_ssh_public_key(domain_pubkey)
                    correctly_signed = verify(msg, data["signature"], pubkey)
                    if correctly_signed:
                        content = data["content"]
                        self.db.add_mail(_from, _to, content)
                        self.send_text_response(connection, "OK, mail delivered")
                    else:
                        self.send_text_response(connection, "ERROR, could not validate signature")
            elif data["action"] == "adduser":
                if session != self.admin_user["login"]:
                    self.send_text_response(connection, "ERROR, only admin can create a user")
                else:
                    res = self.db.add_user(data["login"], data["password"])
                    message = "OK, user added" if res else f"ERROR, cannot add user {data['login']} (already exists?)"
                    self.send_text_response(connection, message)
        
        print(f"Closing connection {connection=} {address=}")
        connection.close()

    def run(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('', 555))
        self.socket.listen(5)
        print(f"server started for {self.server_domain}, listening...")
        while True:
            connection, address = self.socket.accept()
            threading.Thread(target=self.client_listener, args=(connection, address)).start()

if __name__ == "__main__":
    s = Server()
    s.run()
