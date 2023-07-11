import json
import os
from datetime import datetime
import time
import matplotlib.pyplot as plt
from scapy.all import AsyncSniffer

class User:
    def __init__(self, username, password):
        self.username = username
        self.__password = password

    @staticmethod
    def login():
        username = input("Digite seu nome de usuário: ")
        password = input("Digite sua senha: ")

        # Verificar se o usuário já está cadastrado no arquivo de usuários
        if User.foi_registrado(username):
            user = User(username, password)
            print(f'Bem vindo {user.username}!')

            data_atual = datetime.today()

            hora_atual = datetime.now()
            
            with open('log.txt', 'a') as arquivo_log:
                arquivo_log.write(f'{username} fez login no dia {data_atual.day}/{data_atual.month}/{data_atual.year} as {hora_atual.hour}:{hora_atual.minute}:{hora_atual.second} \n')

            return user
        
        else:
            print("Usuário não cadastrado. Criando novo login...")
            return User.cria_novo_user()

    @staticmethod
    def foi_registrado(username):
        users = User.carrega_users()

        # Verificar se o usuário existe na lista de usuários
        for user in users:
            if user["username"] == username:
                return True

        return False

    @staticmethod
    def cria_novo_user():
        username = input("Digite um novo nome de usuário: ")
        password = input("Digite uma nova senha: ")

        users = User.carrega_users()

        novo_user = {"username": username, "password": password}
        users.append(novo_user)

        print(f'{username}, seu cadastro foi efetuado com sucesso. Faça o login novamente!')

        User.salva_users(users)

        return User(username, password)

    @staticmethod
    def carrega_users():
        users = []

        # Verificar se o arquivo de usuários existe
        if os.path.exists("users.txt"):
            with open("users.txt", "r") as file:
                try:
                    users = json.load(file)
                except json.JSONDecodeError:
                    pass

        return users

    @staticmethod
    def salva_users(users):
        with open("users.txt", "w") as file:
            json.dump(users, file)


class NetworkAnalyzer:
    def __init__(self):
        self._user = User.login()
        if self._user:
            self.username = self._user.username
            self.captured_packets = []
            self.sniffer = None
            self._start_time = 0
            self._end_time = 0
        else:
            raise TypeError("Falha no login. Impossível criar instância de NetworkAnalyzer.")


    def start_packet_capture(self):
        print('Começando a captura de pacotes!')
        self._start_time = time.time()

        def process_packet(packet):
            self.captured_packets.append(packet)

        self.sniffer = AsyncSniffer(prn=process_packet, store=False)
        self.sniffer.start()

    def stop_packet_capture(self):
        if self.sniffer is not None:
            print('Captura de pacotes finalizado!')
            self._end_time = time.time()
            self.sniffer.stop()
            self.sniffer = None

    def get_bandwidth(self):
        elapsed_time = self._end_time - self._start_time
        quantidade_pacotes = self.get_packet_count()
        bandwidth = quantidade_pacotes / elapsed_time
        print(f"A largura de banda da rede é: {round(bandwidth, 2)} pacotes/segundo")

    def get_packet_count(self):
        return len(self.captured_packets)

    def get_protocol_statistics(self):
        protocol_stats = {}

        for packet in self.captured_packets:
            protocol = packet.getlayer(0).name
            if protocol in protocol_stats:
                protocol_stats[protocol] += 1
            else:
                protocol_stats[protocol] = 1

        return protocol_stats

    def identify_anomalies(self):

        # Implemente a lógica para identificar e destacar eventos anômalos
        pass

    def generate_report(self):
        protocol_stats = self.get_protocol_statistics()

        protocols = list(protocol_stats.keys())
        count = list(protocol_stats.values())

        plt.figure(figsize=(8, 6))
        plt.bar(protocols, count)
        plt.xlabel("Protocolos")
        plt.ylabel("Contagem")
        plt.title("Estatísticas de Protocolos")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

    def filter_packets(self, criteria):
        # Filtrar captured_packets com base em critérios específicos
        pass

    def store_data(self):
        # Armazenar os dados relevantes, como informações de pacotes capturados e estatísticas de tráfego
        pass