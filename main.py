import os
import pickle
import socket
import threading
import zipfile
import hashlib
import time
import math

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

def get_addr():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception as e:
        raise e

class Node:
    # constants
    DATA_FOLDER = 'data'
    MAX_RETRIES = 10
    KEYS_BIN_PATH = 'data/keys.bin'
    BALANCE_BIN_PATH = 'data/balance.bin'
    PEERS_BIN_PATH = 'data/peers.bin'
    TRANSACTION_BIN_PATH = 'data/transactions.bin'
    LEDGER_BIN_PATH = 'data/ledger.bin'
    MEMORYPOOL_BIN_PATH = 'data/memorypool.bin'
    MAX_ATTEMPTS = 999999999999999


    def __init__(self):
        if not os.path.exists(self.DATA_FOLDER):
            os.makedirs(self.DATA_FOLDER)
        # keys
        if not os.path.exists(self.KEYS_BIN_PATH):
            with open(self.KEYS_BIN_PATH, 'wb') as new_keys_bin:
                new_s_key = ec.generate_private_key(ec.SECP256R1())

                new_s_numbers = new_s_key.private_numbers()
                new_raw_s_key = new_s_numbers.private_value.to_bytes(32, byteorder="big")

                # Генерация публичного ключа
                new_p_key = new_s_key.public_key()
                new_p_numbers = new_p_key.public_numbers()
                new_raw_p_key = (
                        b"\x04" +
                        new_p_numbers.x.to_bytes(32, byteorder="big") +
                        new_p_numbers.y.to_bytes(32, byteorder="big")
                )
                pickle.dump((new_raw_p_key.hex(), new_raw_s_key.hex()), new_keys_bin)
        with open(self.KEYS_BIN_PATH, 'rb') as keys_bin:
            self.p_key, self.s_key = pickle.load(keys_bin)
        # balance
        if not os.path.exists(self.BALANCE_BIN_PATH):
            with open(self.BALANCE_BIN_PATH, 'wb') as new_balance_bin:
                pickle.dump(0, new_balance_bin)
        with open(self.BALANCE_BIN_PATH, 'rb') as balance_bin:
            self.balance = pickle.load(balance_bin)
        # addr
        self.addr = get_addr()
        # socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # ledger
        if not os.path.exists(self.LEDGER_BIN_PATH):
            with open(self.LEDGER_BIN_PATH, 'wb') as new_ledger_bin:
                pickle.dump([], new_ledger_bin)
        with open(self.LEDGER_BIN_PATH, 'rb') as ledger_bin:
            self.ledger = pickle.load(ledger_bin)
        # memorypool
        if not os.path.exists(self.MEMORYPOOL_BIN_PATH):
            with open(self.MEMORYPOOL_BIN_PATH, 'wb') as new_memorypool_bin:
                pickle.dump([], new_memorypool_bin)
        with open(self.MEMORYPOOL_BIN_PATH, 'rb') as memorypool_bin:
            self.memorypool = pickle.load(memorypool_bin)
            # peers
            if not os.path.exists(self.PEERS_BIN_PATH):
                print("Вы собираетесь создать первоначальный узел. Задать первоначальний баланс?(y/n): ", end="")
                respond = None
                while respond not in ["y", "n"]:
                    respond = input("")
                if respond == "y":
                    while True:
                        try:
                            self.balance = int(input("Введите сумму: "))
                            break
                        except ValueError:
                            continue
                # genesis block
                genesis_block = {"hash": None,
                              "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                              "time": str(int(time.time())),
                              "block_index": 0,
                              "height": 0,
                              "difficulty": 5,
                              "transactions": []} # генезис блок
                coinbase_transaction = {"tx_index": 0,
                                        "fee": 0,
                                        "inputs": [],
                                        "out": [{"value": self.balance,
                                                 "p_key": self.p_key,
                                                 "spent": False}]} # coinbase-транзакция
                genesis_block["transactions"].append(coinbase_transaction)
                self.ledger.append(genesis_block)
                with open(self.PEERS_BIN_PATH, 'wb') as new_peers_bin:
                    new_peers = [{"addr": self.addr,
                                  "p_key": self.p_key,
                                  "balance": self.balance}]
                    pickle.dump(new_peers, new_peers_bin)
                    print("Инициализирован первоначальный узел. Передайте эту копию другому пользователю")
                with zipfile.ZipFile('copy.zip', 'w') as zipf:
                    zipf.write('main.py')
                    zipf.write(self.PEERS_BIN_PATH, 'data/peers.bin')
                    zipf.write(self.LEDGER_BIN_PATH, 'data/ledger.bin')
            with open(self.PEERS_BIN_PATH, 'rb') as peers_bin:
                self.peers = pickle.load(peers_bin)
                self.peers = [peer for peer in self.peers if peer["addr"] != self.addr]
        # other
        self.max_retries = Node.MAX_RETRIES
        self.connections = 0
        self.is_mined = threading.Event()
        self.logs = []
        self.logs.append("Узел инициализирован")

    def bind(self):
        try:
            self.server_socket.bind(('0.0.0.0', 8080))
            self.server_socket.listen(10)
            self.logs.append("Узел запущен на порту 8080")
        except OSError as e:
            self.logs.append(f"Ошибка при привязке: {e}")
            self.server_socket.close()

    def wait(self):
        while True:
            try:
                conn, addr = self.server_socket.accept()
                self.connections += 1
                self.logs.append(f"Соединение №{self.connections} создано с {addr[0]}")
                thread = threading.Thread(target=self.handle_signal, args=(conn, addr[0]))
                thread.start()
            except OSError as e:
                self.logs.append(f"Ошибка при ожидании соединения: {e}")
                break

    def send_data(self, conn, data: bytes):
        data_length = len(data).to_bytes(4, byteorder='big')
        conn.sendall(data_length)
        conn.sendall(data)
        self.logs.append(f"Отправлен пакет данных размером {len(data)} байт")

    def receive_data(self, conn) -> bytes:
        data_length = int.from_bytes(conn.recv(4), byteorder='big')
        data = b''
        while len(data) < data_length:
            chunk = conn.recv(1024)
            if not chunk:
                raise ConnectionError("Соединение закрыто до завершения передачи данных")
            data += chunk
        self.logs.append(f"Получен пакет данных размером {data_length} байт")
        return data

    def validate_signature(self, transaction, sender):
        signature = transaction["inputs"]["signature"]
        out = transaction["out"]
        if out:
            p_key = sender["p_key"]
            x = int.from_bytes(bytes.fromhex(p_key)[1:33], byteorder="big")
            y = int.from_bytes(bytes.fromhex(p_key)[33:], byteorder="big")

            p_key = ec.EllipticCurvePublicNumbers(
                x=x,
                y=y,
                curve=ec.SECP256R1()
            ).public_key()

            try:
                p_key.verify(
                    bytes.fromhex(signature),
                    pickle.dumps(out),
                    ec.ECDSA(hashes.SHA256())
                )
                self.logs.append("Подпись верна!")
                return True
            except Exception as e:
                self.logs.append(f"Подпись недействительна: {e}")
                return False
        self.logs.append(f"Транзакция некорректна")
        return False

    def create_signature(self, out):
        s_key = ec.derive_private_key(
            int.from_bytes(bytes.fromhex(self.s_key), byteorder="big"),
            ec.SECP256R1()
        )

        transaction_data_bytes = pickle.dumps(out)
        signature = s_key.sign(transaction_data_bytes, ec.ECDSA(hashes.SHA256())).hex()

        return signature

    def mine_block(self, last_block):
        def notify(peer, last_block_hash, p_key):
            codeword = "block_mined"
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client_socket.connect((peer["addr"], 8080))
                client_socket.sendall(codeword.encode())
                respond = client_socket.recv(4)
                if int.from_bytes(respond, 'big') == 1:
                    self.send_data(client_socket, pickle.dumps((last_block_hash, p_key, elapsed_time)))
            except Exception as e:
                self.logs.append(f"Не удалось уведомить узел {peer['addr']}: {e}")
            finally:
                client_socket.close()

        transations = last_block["transactions"]
        hashes = [hashlib.sha256(pickle.dumps(transaction)).hexdigest() for transaction in transations]
        while len(hashes) != 1:
            merkel_tree = [hashes[i:i + 2] for i in range(0, len(hashes), 2)]
            hashes = [hashlib.sha256(leaves[0].encode() + leaves[1].encode()).hexdigest() for leaves in
                      merkel_tree]
        transaction_hash = hashes[0]
        timestamp = last_block["time"]
        previous_block_hash = last_block["previous_hash"]
        difficulty = last_block["difficulty"]
        nonce = 0
        self.logs.append("Начинат процесс добычи блока")
        start_time = time.time()
        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            if self.is_mined.is_set():
                return None, None
            last_block_hash = hashlib.sha256(
                previous_block_hash.encode() +
                transaction_hash.encode() +
                timestamp.encode() +
                str(nonce).encode()
            ).hexdigest()
            if last_block_hash[:difficulty] == difficulty * '0':
                self.logs.append(f"Хеш найден! Число - {nonce} Хеш - {last_block_hash}")
                elapsed_time = time.time() - start_time
                threads = [
                    threading.Thread(
                        target=notify,
                        args=(peer, last_block_hash, self.p_key)
                    )
                    for peer in self.peers
                ]

                for thread in threads:
                    thread.start()

                for thread in threads:
                    thread.join()
                return last_block_hash, elapsed_time
            nonce += 1
        self.logs.append("Не удалось получить хеш для блока после максимального числа попыток")

    def currency_transfer(self, amount, p_key):
        def process_transaction(peer, transaction, confirmations, lock, condition):
            codeword = "transaction"
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client_socket.connect((peer["addr"], 8080))

                client_socket.sendall(codeword.encode())

                self.send_data(client_socket, pickle.dumps(transaction))
                status = client_socket.recv(4)
                if status:
                    status = int.from_bytes(status, 'big')
                    with lock:
                        confirmations.append(status)
                        if len(confirmations) == len(self.peers):
                            if all(s == 1 for s in confirmations): # Транзакция подтверждена
                                client_socket.sendall("transaction_approved".encode())

                            else: # Транзакция неподтверждена
                                client_socket.sendall("transaction_disapproved".encode())
                        condition.notify_all()
            except Exception as e:
                self.logs.append(f"Транзакция не была обработана по {addr} изза: {e}")
            finally:
                client_socket.close()

        if amount > self.balance:
            self.logs.append("Недостаточно средств для транзакции")
            return

        if p_key == self.p_key:
            self.logs.append("Перевод средств на свой счёт невозможен")
            return

        last_block = self.ledger[-1]
        last_block_transactions = last_block["transactions"]
        if len(last_block_transactions) == 8 and not last_block["hash"]:
            self.logs.append("Во время добычи блока нельзя производить транзакции. Попробуйте снова, через некоторое время")
            return

        last_transaction = last_block_transactions[-1]
        last_transaction_out = last_transaction["out"]
        inputs = {"previous_out": []}
        for last_transaction_element in last_transaction_out:
            last_transaction_element["spent"] = True
            inputs["previous_out"].append(last_transaction_element)

        f = lambda x, y: 1 / (1 + math.log(math.fabs(x - y) + 1))

        out = []
        if amount == self.balance:
            f = lambda x: 1 / (1 + math.log(math.fabs(x) + 1))
            value = self.balance * (1 - f(self.balance))
            fee = amount-value

            out.append({"value": value,
                        "p_key": p_key,
                        "spent": False})
            amount = value
        else:
            change = (self.balance - amount) * (1 - f(self.balance, amount))
            fee = self.balance - change
            out = out + [{"value": amount,
                          "p_key": p_key,
                          "spent": False},
                         {"value": change,
                          "p_key": self.p_key,
                          "spent": False}]
        signature = self.create_signature(out)
        inputs["signature"] = signature
        transaction = {"tx_index": last_transaction["tx_index"] + 1,
                       "fee": fee,
                       "inputs": inputs,
                       "out": out}

        confirmations = []# 0 или 1

        lock = threading.Lock()
        condition = threading.Condition(lock)

        threads = [
            threading.Thread(
                target=process_transaction,
                args=(peer, transaction, confirmations, lock, condition)
            )
            for peer in self.peers
        ]

        for thread in threads:
            thread.start()

        with condition:
            condition.wait_for(lambda: len(confirmations) == len(self.peers))

        for thread in threads:
            thread.join()

        if all(s == 1 for s in confirmations):
            self.logs.append("Транзакция потдверждена другими узлами")

            last_block_transactions.append(transaction)

            for peer in self.peers:
                if peer["p_key"] == p_key:
                    peer["balance"] += amount
            self.balance -= amount+fee

            if len(last_block_transactions) == 8 and not last_block["hash"]:
                last_block_hash, elapsed_time = self.mine_block(last_block)
                if last_block_hash:
                    last_block["hash"] = last_block_hash
                    last_block_difficulty = last_block["difficulty"]
                    value = sum([transaction["fee"] for transaction in last_block_transactions])
                    coinbase_transaction = {"tx_index": 0,
                                            "fee": 0,
                                            "inputs": [],
                                            "out": [{"value": value,
                                                     "p_key": self.p_key,
                                                     "spent": False}]}
                    if elapsed_time > 600:
                        difficulty = last_block_difficulty - 1
                    elif elapsed_time < 600:
                        difficulty = last_block_difficulty + 1
                    block = {"hash": None,
                             "previous_hash": last_block["hash"],
                             "time": str(int(time.time())),
                             "block_index": last_block["block_index"] + 1,
                             "height": last_block["height"] + 1,
                             "difficulty": difficulty,
                             "transactions": [coinbase_transaction]}
                    self.ledger.append(block)
                    self.balance += value
                self.is_mined.clear()

    def add_new_peer(self, addr, conn):
        def announce_new_peer(peer, addr, p_key, balance):
            codeword = "new_peer_detection"
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client_socket.connect((peer["addr"], 8080))

                client_socket.sendall(codeword.encode())

                self.send_data(client_socket, pickle.dumps((addr, p_key, balance)))
            except Exception as e:
                self.logs.append(f"Транзакция не была обработана по {addr} изза: {e}")
            finally:
                client_socket.close()
        conn.sendall("new_peer".encode())

        personal_data_bytes = self.receive_data(conn)

        personal_data = pickle.loads(personal_data_bytes)

        p_key, balance = personal_data

        threads = [
            threading.Thread(
                target=announce_new_peer,
                args=(peer, addr, p_key, balance)
            )
            for peer in self.peers
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        self.peers.append({"addr": addr,
                           "p_key": p_key,
                           "balance": balance})
        self.logs.append(f"Принято соединение с новым узлом по адресу {addr}")

    def handle_signal(self, conn, addr):
        try:
            data = conn.recv(1024)
            if data:
                codeword = data.decode()
                if codeword == "check_connection":
                    conn.sendall("connection_successfully".encode())
                    self.logs.append(f"Обмен данными завершен с {addr}")

                    if addr not in [peer["addr"] for peer in self.peers]:
                        self.add_new_peer(addr, conn)

                    blocks_amount = len(self.ledger)
                    blocks_amount_bytes = blocks_amount.to_bytes(4, byteorder='big')
                    conn.sendall(blocks_amount_bytes)
                    blocks = self.ledger
                    for index, block in enumerate(blocks):
                        self.send_data(conn, pickle.dumps(block))
                        respond = conn.recv(4)
                        if int.from_bytes(respond, "big") == 1:
                            self.logs.append(f"Успешно отправлен блок №{index+1}")
                    self.logs.append(f"Отправлена копия бухгалтериской книжки к {addr}")
                elif codeword == "transaction":
                    transaction_bytes = self.receive_data(conn)
                    transaction = pickle.loads(transaction_bytes)
                    self.logs.append(f"Получена новая транзакция")
                    sender = next((peer for peer in self.peers if peer['addr'] == addr), None)
                    status = 0
                    if self.validate_signature(transaction, sender):
                        status = 1
                    conn.send(status.to_bytes(1, 'big'))
                    transaction_status = conn.recv(1024).decode()
                    if transaction_status == "transaction_approved":
                        last_block = self.ledger[-1]
                        last_block_transactions = last_block["transactions"]
                        last_block_difficulty = last_block["difficulty"]
                        last_transaction = last_block_transactions[-1]
                        last_transaction_out = last_transaction["out"]
                        for last_transaction_element in last_transaction_out:
                            last_transaction_element["spent"] = True
                        self.logs.append("Транзакция потдверждена другими узлами")
                        last_block_transactions.append(transaction)

                        if transaction["out"][0]["p_key"] == self.p_key:
                            self.logs.append("Баланс пополнен успешно")
                            self.balance += transaction["out"][0]["value"]
                        else:
                            for peer in self.peers:
                                if peer["p_key"] == transaction["out"][0]["p_key"]:
                                    peer["balance"] += transaction["out"][0]["value"]
                        for peer in self.peers:
                            if peer["addr"] == addr:
                                if len(transaction["out"]) == 1:
                                    peer["balance"] -= transaction["out"][0]["value"]
                                else:
                                    peer["balance"] -= transaction["out"][0]["value"] + transaction["fee"]

                        if len(last_block_transactions) == 8 and not last_block["hash"]:
                            last_block_hash, elapsed_time = self.mine_block(last_block)
                            if last_block_hash:
                                last_block["hash"] = last_block_hash
                                value = sum([transaction["fee"] for transaction in last_block_transactions])
                                coinbase_transaction = {"tx_index": 0,
                                                        "fee": 0,
                                                        "inputs": [],
                                                        "out": [{"value": value,
                                                                 "p_key": self.p_key,
                                                                 "spent": False}]}
                                if elapsed_time > 600:
                                    difficulty = last_block_difficulty - 1
                                elif elapsed_time < 600:
                                    difficulty = last_block_difficulty + 1

                                block = {"hash": None,
                                         "previous_hash": last_block["hash"],
                                         "time": str(int(time.time())),
                                         "block_index": last_block["block_index"]+1,
                                         "height": last_block["height"]+1,
                                         "difficulty": difficulty,
                                         "transactions": [coinbase_transaction]}
                                self.ledger.append(block)
                                self.balance += value
                elif codeword == "block_mined":
                    self.is_mined.set()
                    self.logs.append("Блок был добыт другим узлом сети. Удачи в следующий раз!")
                    respond = 1
                    conn.send(respond.to_bytes(1, 'big'))
                    mined_block_data_bytes = self.receive_data(conn)
                    mined_block_data = pickle.loads(mined_block_data_bytes)
                    last_block_hash, p_key, elapsed_time = mined_block_data
                    last_block = self.ledger[-1]
                    last_block_difficulty = last_block["difficulty"]
                    last_block_transactions = last_block["transactions"]
                    if last_block_hash:
                        last_block["hash"] = last_block_hash
                        value = sum([transaction["fee"] for transaction in last_block_transactions])
                        coinbase_transaction = {"tx_index": 0,
                                                "fee": 0,
                                                "inputs": [],
                                                "out": [{"value": value,
                                                         "p_key": p_key,
                                                         "spent": False}]}
                        if elapsed_time > 600:
                            difficulty = last_block_difficulty - 1
                        elif elapsed_time < 600:
                            difficulty = last_block_difficulty + 1
                        block = {"hash": None,
                                 "previous_hash": last_block["hash"],
                                 "time": str(int(time.time())),
                                 "block_index": last_block["block_index"] + 1,
                                 "height": last_block["height"] + 1,
                                 "difficulty": difficulty,
                                 "transactions": [coinbase_transaction]}
                        self.ledger.append(block)
                        for peer in self.peers:
                            if peer["p_key"] == p_key and peer["addr"] == addr:
                                peer["balance"] += value
                    else:
                        self.logs.append("Данные узла который нашёл блок не действительны")
                elif codeword == "new_peer_detection":
                    new_peer_data_bytes = self.receive_data(conn)
                    addr, p_key, balance = pickle.loads(new_peer_data_bytes)
                    if addr not in [peer["addr"] for peer in self.peers]:
                        self.peers.append({"addr": addr,
                                           "p_key": p_key,
                                           "balance": balance})

        except Exception as e:
            self.logs.append(f"Ошибка при обработке сигнала {addr}: {e}")
            raise e
        finally:
            conn.close()
            self.connections -= 1
            self.logs.append(f"Соединение с {addr} закрыто")

    def connect_to_peers(self):
        def send_signal(peer, lock, ledger_copies):
            codeword = "check_connection"
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client_socket.connect((peer["addr"], 8080))
                client_socket.sendall(codeword.encode())
                respond = client_socket.recv(1024)
                if respond.decode() == "connection_successfully":
                    self.logs.append(f"Соединение установлено с узлом {peer["addr"]}")

                    respond = client_socket.recv(1024)
                    if respond.decode() == "new_peer":
                        personal_data = (self.p_key, self.balance)
                        self.send_data(client_socket, pickle.dumps(personal_data))
                    blocks_amount = int.from_bytes(client_socket.recv(4), byteorder='big')
                    ledger_copy = []
                    for index in range(blocks_amount):
                        block_bytes = self.receive_data(client_socket)
                        block = pickle.loads(block_bytes)
                        ledger_copy.append(block)
                        respond = 1
                        client_socket.send(respond.to_bytes(1, "big"))
                    with lock:
                        ledger_copies.append(ledger_copy)
                else:
                    self.logs.append(f"Соединение не установлено так как узел ответил отрицательно")
            except Exception as e:
                self.logs.append(f"Узел с адресом {peer["addr"]} неактивен или не существует(ошибка: {e})")
            finally:
                client_socket.close()

        lock = threading.Lock()

        ledger_copies = []

        threads = [
            threading.Thread(
                target=send_signal,
                args=(peer, lock, ledger_copies)
            )
            for peer in self.peers
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        if ledger_copies:
            ledger_copies.append(self.ledger)
            self.ledger = max(ledger_copies, key=len)
            self.logs.append("Полученая копия бухгалтерской книги успешно установлена")

    def exit(self):
        with open('data/peers.bin', 'wb') as peers_bin:
            pickle.dump(self.peers, peers_bin)
        with open('data/balance.bin', 'wb') as balance_bin:
            pickle.dump(self.balance, balance_bin)
        with open('data/ledger.bin', 'wb') as ledger_bin:
            pickle.dump(self.ledger, ledger_bin)

if __name__ == "__main__":
    node = Node()
    node.bind()

    server_thread = threading.Thread(target=node.wait, daemon=True)
    server_thread.start()

    node.connect_to_peers()

    # Панель управления
    while True:
        command = input(">>> ").strip().lower()


        if command == "cls":
            os.system("cls")
        elif command == "logs":
            [print(log) for log in node.logs]
        elif command == "c_logs":
            node.logs.clear()
        elif command == "check_connection":
            node.connect_to_peers()
        elif command == "keys":
            print(f"your public key:\n{node.p_key}")
            print(f"your secret key:\n{node.s_key}")
        elif command == "addr":
            print(f"addr: {node.addr}")
        elif command == "peers":
            [print(f"addr: {peer["addr"]}\np_key:\n{peer["p_key"]}\nbalance: {peer["balance"]}") for peer in node.peers]
        elif command == "balance":
            print(f"balance: {node.balance} coins")
        elif "transfer" in command:
            command = command.split(' ')
            if len(command) == 3:
                try:
                    amount, addr = command[1:]
                    node.currency_transfer(int(amount), addr)
                except ValueError:
                    node.logs.append("Команда написана неверно")
        elif command == "ledger":
            for block in node.ledger:
                print(f"hash - {block["hash"]}")
                print(f"previous_hash - {block["previous_hash"]}")
                print(f"time - {block["time"]}")
                print(f"block_index - {block["block_index"]}")
                print(f"height - {block["height"]}")
                print(f"difficulty - {block["difficulty"]}")
                print(f"transactions:")
                if block["transactions"]:
                    for transaction in block["transactions"]:
                        print(f"  tx_index - {transaction["tx_index"]}")
                        print(f"  fee - {transaction["fee"]}")
                        print(f"  inputs - {transaction["inputs"]}")
                        print(f"  out - {transaction["out"]}")
        elif command == "exit":
            node.server_socket.close()
            print("Узел отключен")
            break

    node.exit()
