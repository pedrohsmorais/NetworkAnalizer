# Network Analyzer

## Introdução

Este código Python implementa uma aplicação simples de análise de rede, permitindo a captura de pacotes, cálculos de largura de banda, estatísticas de protocolos, identificação de anomalias, geração de relatórios gráficos, e algumas outras funcionalidades. A aplicação requer autenticação de usuários para acessar as funcionalidades.

## Classes

### 1. `User`

- **Métodos Estáticos:**
  - `login()`: Realiza o login do usuário, solicita nome de usuário e senha, verifica se o usuário está registrado e retorna uma instância do usuário.
  - `foi_registrado(username, password)`: Verifica se um usuário com o nome de usuário e senha fornecidos já está registrado.
  - `cria_novo_user()`: Cria um novo usuário, solicita nome de usuário e senha, o registra e retorna uma nova instância do usuário.
  - `carrega_users()`: Carrega os usuários registrados a partir do arquivo `users.txt`.
  - `salva_users(users)`: Salva os usuários registrados no arquivo `users.txt`.
  
- **Construtor:**
  - `__init__(self, username, password)`: Inicializa uma instância de usuário com nome de usuário e senha.

### 2. `NetworkAnalyzer`

- **Construtor:**
  - `__init__(self)`: Inicializa uma instância do analisador de rede, realiza o login do usuário e configura variáveis relacionadas à captura de pacotes.

- **Métodos Públicos:**
  - `start_packet_capture()`: Inicia a captura de pacotes utilizando a biblioteca `scapy`.
  - `stop_packet_capture()`: Interrompe a captura de pacotes, exibe opções ao usuário e, se desejado, ativa atalhos de comandos.
  - `get_bandwidth()`: Calcula e exibe a largura de banda da rede com base nos pacotes capturados.
  - `get_packet_count()`: Exibe a quantidade de pacotes capturados.
  - `get_protocol_statistics()`: Calcula e exibe as estatísticas de protocolos presentes nos pacotes capturados.
  - `identify_anomalies(limite_pacotes=100, janela=10)`: Identifica se há anomalias com base em critérios predefinidos.
  - `generate_report()`: Gera e exibe um gráfico de barras com as estatísticas de protocolos.
  - `get_ping()`: Realiza um ping para o Google e exibe o tempo de resposta.
  - `get_capture_duration()`: Exibe a duração da captura de pacotes.
  - `clear_terminal()`: Limpa a tela do terminal para melhor apresentação.
  - `show_commands()`: Exibe os comandos disponíveis e permite a execução de atalhos de comandos.

## Fluxo de Execução

1. O programa inicia instanciando um `NetworkAnalyzer`.
2. O usuário é autenticado utilizando a classe `User`.
3. O usuário tem a opção de iniciar a captura de pacotes, interromper a captura, e utilizar várias funcionalidades, como cálculos de largura de banda, estatísticas de protocolos, identificação de anomalias, geração de relatórios gráficos, ping para o Google, entre outros.
4. O usuário pode escolher ativar atalhos de comandos para executar essas funcionalidades de maneira mais rápida.

## Considerações

- O código faz uso das bibliotecas `scapy` e `matplotlib`.
- A persistência dos usuários é feita em um arquivo JSON (`users.txt`).
- Algumas funcionalidades podem requerer privilégios administrativos para captura de pacotes ou execução de ping.

Este documento fornece uma visão geral do código e suas funcionalidades. Para um entendimento mais profundo, consulte os comentários no código-fonte.
