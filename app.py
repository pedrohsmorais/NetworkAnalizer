import json
import os
from datetime import datetime
import time
import matplotlib.pyplot as plt
from scapy.all import AsyncSniffer, IP, ICMP
from scapy.sendrecv import sr1


class User:
    def __init__(self, username, password):
        self.username = username
        self.__password = password

    @staticmethod
    def login():
        username = input("Digite seu nome de usuário: ")
        password = input("Digite sua senha: ")

        if User.foi_registrado(username, password):
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
    def foi_registrado(username, password):
        users = User.carrega_users()

        for user in users:
            if user["username"] == username and user["password"] == password:
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
            self.use_shortcuts = 0
        else:
            raise TypeError("Falha no login. Impossível criar instância de NetworkAnalyzer.")


    def start_packet_capture(self):
        self.clear_terminal()
        print('\nComeçando a captura de pacotes!\n')
        self._start_time = time.time()

        def process_packet(packet):
            self.captured_packets.append(packet)

        self.sniffer = AsyncSniffer(prn=process_packet, store=False)
        self.sniffer.start()

    def stop_packet_capture(self):
        self.clear_terminal()
        if self.sniffer is not None:
            self._end_time = time.time()
            self.sniffer.stop()
            self.sniffer = None
            print('\nCaptura de pacotes finalizado!\n')
            if not self.use_shortcuts:
                choice = int(input('\nQuer usar os atalhos de comandos? Digite 1 para sim, ou 0 para não.\n'))
                if choice == 1:
                    self.use_shortcuts = 1
                    self.show_commands()
                else:
                    print('Atalhos desativados.')

    def get_bandwidth(self):
        self.clear_terminal()
        elapsed_time = self._end_time - self._start_time
        quantidade_pacotes = len(self.captured_packets)
        bandwidth = quantidade_pacotes / elapsed_time
        print('---------------------------------------------\n'
            f"A largura de banda da rede é: {round(bandwidth, 2)} pacotes/segundos\n"
            '---------------------------------------------\n'
            )

    def get_packet_count(self):
        self.clear_terminal()
        print('---------------------------------------------\n'
            f'A quantidade de pacotes capturados foram: {len(self.captured_packets)} pacotes.\n'
            '---------------------------------------------\n')

    def get_protocol_statistics(self):
        self.clear_terminal()
        self.protocol_stats = {}

        for packet in self.captured_packets:
            protocol = packet.getlayer(0).name
            if protocol in self.protocol_stats:
                self.protocol_stats[protocol] += 1
            else:
                self.protocol_stats[protocol] = 1
        print('---------------------------------------------\n'
            f'Protocolos existentes durante a captura de pacotes{self.protocol_stats}\n'
            '---------------------------------------------\n')

    def identify_anomalies(self, limite_pacotes=100, janela=10):
        self.clear_terminal()
        current_time = time.time()
        start_janela = current_time - janela

        quantidade_pacotes = [packet for packet in self.captured_packets if packet.time >= start_janela]

        if len(quantidade_pacotes) > limite_pacotes:
            print("Evento anômalo detectado!\n")
            print(f"Pacotes capturados no último intervalo de tempo: {len(quantidade_pacotes)}\n")
        else:
            print("Nenhum evento anômalo detectado.\n")

    def generate_report(self):
        self.clear_terminal()
        print('Preparando o gráfico.')

        protocols = list(self.protocol_stats.keys())
        count = list(self.protocol_stats.values())

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

    def get_ping(self):
        self.clear_terminal()
        packet = IP(dst="google.com") / ICMP()
        reply = sr1(packet, timeout=1, verbose=False)
        
        if reply:
            rtt = reply.time - packet.sent_time
            print('---------------------------------------------\n'
                f'O ping com o Google é de: {round(rtt * 1000, 2)} ms.\n'
                '---------------------------------------------\n')
        
    def get_capture_duration(self):
        self.clear_terminal()
        if self._start_time != 0 and self._end_time != 0:
            duration = self._end_time - self._start_time
            print('---------------------------------------------\n'
                f'A captura de pacotes durou {round(duration,2)} s.\n'
                '---------------------------------------------\n')
        else:
            print('Não conseguimos calcular o tempo. Tente novamente!')

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_commands(self):
        while self.use_shortcuts == 1:
            choice_command = int(input(f'Os atalhos a seguir estão disponiveis:\n'
                f'1 - get_bandwidth(), Usado para calcular a largura de banda da rede.\n'
                f'2 - get_packet_count(), Retorna a quantidade de pacotes.\n'
                f'3 - get_protocol_statistics(), Retorna a estatisticas de protocolos.\n'
                f'4 - identify_anomalies(), Identifica se existe alguam anomalia.\n'
                f'5 - generate_report(), Gera um gráfico cm os protocolos utilizados.\n'
                f'6 - get_ping(), Retorna o ping com o Google.\n'
                f'7 - get_capture_duration(), Retorna a duração da captura de pacotes.\n'
                f'0 - digite 0 para sair.\n'
                ))
            if choice_command == 1:
                self.get_bandwidth()
                self.show_commands()
            elif choice_command == 2:
                self.get_packet_count()
                self.show_commands()
            elif choice_command == 3:
                self.get_protocol_statistics()
                self.show_commands()
            elif choice_command == 4:
                self.identify_anomalies()
                self.show_commands()
            elif choice_command == 5:
                self.generate_report()
                self.show_commands()
            elif choice_command == 6:
                self.get_ping()
                self.show_commands()
            elif choice_command == 7:
                self.get_capture_duration()
                self.show_commands()
            elif choice_command == 0:
                print('Operação finalizada!')
                self.use_shortcuts = 0
        else:
            print('Os comandos a seguir estão disponiveis:\n'
                f'get_bandwidth(), Usado para calcular a largura de banda da rede.\n'
                f'get_packet_count(), Retorna a quantidade de pacotes.\n'
                f'get_protocol_statistics(), Retorna a estatisticas de protocolos.\n'
                f'identify_anomalies(), Identifica se existe alguam anomalia.\n'
                f'generate_report(), Gera um gráfico cm os protocolos utilizados.\n'
                f'get_ping(), Retorna o ping com o Google.\n'
                f'get_capture_duration(), Retorna a duração da captura de pacotes.\n')
            