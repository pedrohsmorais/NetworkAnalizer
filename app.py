import json
import os

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    @staticmethod
    def login():
        username = input("Digite seu nome de usuário: ")
        password = input("Digite sua senha: ")

        # Verificar se o usuário já está cadastrado no arquivo de usuários
        if User.foi_registrado(username):
            user = User(username, password)
            print(f'Bem vindo {user.username}!')
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
        
        print(f'Seu login foi criado. Bem vindo {username}!')

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

