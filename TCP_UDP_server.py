#!/usr/bin/python3

'''
Servidor Socket Unificado: Suporta TCP ou UDP com POO e Type Hints

FUNCIONAMENTO:
==============
Este servidor permite criar um servidor de socket usando protocolo TCP ou UDP.

1. ENTRADA DO USUÁRIO:
   - Endereço: IP ou hostname para bind do servidor (padrão: 0.0.0.0)
     * Use '0.0.0.0' para aceitar conexões de qualquer interface de rede
     * Use 'localhost' ou '127.0.0.1' para conexões locais apenas
     * Use um IP específico para bind em interface específica

   - Porta: Número da porta (1-65535, padrão: 8080)
     * Portas < 1024 geralmente requerem privilégios de administrador

   - Protocolo: TCP ou UDP (padrão: TCP)
     * TCP: Orientado à conexão, confiável, mantém estado
     * UDP: Sem conexão, mais rápido, não garante entrega

2. FUNCIONAMENTO DO SERVIDOR:
   - TCP: Aceita conexões sequenciais, processa uma mensagem por conexão
   - UDP: Recebe datagramas continuamente de múltiplos clientes
   - Timeout: 5 minutos de inatividade encerra o servidor automaticamente
   - Logging: Todas as operações são registradas com timestamp

3. COMANDOS ESPECIAIS SUPORTADOS:
   - ping     → Responde "pong" (teste de conectividade)
   - time     → Retorna data/hora atual do servidor
   - help     → Lista comandos disponíveis
   - exit/quit → Encerra a conexão
   - Qualquer outra mensagem → Eco com informações do remetente

4. EXEMPLO DE USO:
   $ python3 server.py
   Endereço: 0.0.0.0        # Aceita de qualquer IP
   Porta: 8080              # Porta padrão
   Protocolo: TCP           # Protocolo TCP

5. PARA TESTAR:
   Em outro terminal, execute o cliente correspondente:
   $ python3 client.py
   URL: localhost:8080
   Protocolo: TCP

ARQUITETURA:
============
- Padrão Factory para criação de servidores
- Classe abstrata SocketServer define interface comum
- TCPServer e UDPServer implementam protocolos específicos
- MessageHandler processa lógica de negócio
- Logger registra todas as operações
- TimeoutHandler gerencia timeout de inatividade
'''

import socket
import sys
import signal
from typing import Tuple, Optional
from abc import ABC, abstractmethod
from enum import Enum
from datetime import datetime


class Protocol(Enum):
    """Enumeração para protocolos disponíveis"""
    TCP = "TCP"
    UDP = "UDP"


class TimeoutHandler:
    """Gerenciador de timeout da aplicação"""

    def __init__(self, timeout: int = 300) -> None:
        self.timeout = timeout
        signal.signal(signal.SIGALRM, self._timeout_callback)

    def _timeout_callback(self, signum: int, frame) -> None:
        raise Exception(
            f"\n>>> Servidor encerrado devido a inatividade: {self.timeout} segundos.\n")

    def start(self) -> None:
        """Inicia o timer de timeout"""
        signal.alarm(self.timeout)

    def stop(self) -> None:
        """Para o timer de timeout"""
        signal.alarm(0)

    def reset(self) -> None:
        """Reseta o timer de timeout"""
        signal.alarm(self.timeout)


class Logger:
    """Classe para logging de eventos do servidor"""

    @staticmethod
    def log(message: str) -> None:
        """Registra mensagem com timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")

    @staticmethod
    def log_connection(client_addr: Tuple[str, int], protocol: str) -> None:
        """Registra nova conexão"""
        Logger.log(f"Nova conexão {protocol}: {client_addr[0]}:{client_addr[1]}")

    @staticmethod
    def log_message(client_addr: Tuple[str, int], message: str) -> None:
        """Registra mensagem recebida"""
        Logger.log(f"Mensagem de {client_addr[0]}:{client_addr[1]} -> '{message}'")

    @staticmethod
    def log_error(error: str) -> None:
        """Registra erro"""
        Logger.log(f"ERRO: {error}")


class MessageHandler:
    """Classe para processar mensagens recebidas"""

    @staticmethod
    def process_message(message: str, client_addr: Tuple[str, int]) -> str:
        """
        Processa mensagem e gera resposta

        Args:
            message: Mensagem recebida do cliente
            client_addr: Endereço do cliente

        Returns:
            Resposta a ser enviada ao cliente
        """
        message = message.strip()

        # Comandos especiais
        if message.lower() in ['exit', 'quit']:
            return "Servidor: Conexão encerrada. Até logo!"

        if message.lower() == 'ping':
            return "Servidor: pong"

        if message.lower() == 'time':
            return f"Servidor: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        if message.lower() == 'help':
            return ("Servidor: Comandos disponíveis:\n"
                   "  ping - Testa conexão\n"
                   "  time - Retorna hora do servidor\n"
                   "  help - Mostra esta mensagem\n"
                   "  exit/quit - Encerra conexão")

        # Resposta padrão (eco da mensagem)
        return f"Servidor: Recebi '{message}' de {client_addr[0]}:{client_addr[1]}"


class SocketServer(ABC):
    """Classe abstrata base para servidores de socket"""

    BUFFER_SIZE: int = 1024

    def __init__(self, host: str, port: int, timeout_handler: TimeoutHandler) -> None:
        self.host = host
        self.port = port
        self.timeout_handler = timeout_handler
        self.socket: Optional[socket.socket] = None
        self.running: bool = False
        self.message_handler = MessageHandler()
        self.logger = Logger()

    @abstractmethod
    def setup_socket(self) -> None:
        """Configura o socket do servidor"""
        pass

    @abstractmethod
    def handle_client(self) -> None:
        """Trata comunicação com cliente"""
        pass

    def start(self) -> None:
        """Inicia o servidor"""
        try:
            self.setup_socket()
            self.running = True
            self.logger.log(f"Servidor {self.__class__.__name__.replace('Server', '')} iniciado em {self.host}:{self.port}")
            self.logger.log("Aguardando conexões... (Ctrl+C para encerrar)")

            self.timeout_handler.start()
            self.run()

        except KeyboardInterrupt:
            self.logger.log("\nServidor interrompido pelo usuário")
        except Exception as e:
            self.logger.log_error(str(e))
        finally:
            self.stop()

    @abstractmethod
    def run(self) -> None:
        """Loop principal do servidor"""
        pass

    def stop(self) -> None:
        """Encerra o servidor"""
        self.running = False
        self.timeout_handler.stop()
        if self.socket:
            self.socket.close()
        self.logger.log("Servidor encerrado")


class TCPServer(SocketServer):
    """Servidor TCP que aceita múltiplas conexões sequenciais"""

    def setup_socket(self) -> None:
        """Configura socket TCP"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)  # Até 5 conexões na fila
        except socket.error as e:
            self.logger.log_error(f"Falha ao configurar socket TCP: {e}")
            sys.exit(1)

    def run(self) -> None:
        """Loop principal TCP - aceita conexões"""
        while self.running:
            try:
                self.handle_client()
                self.timeout_handler.reset()
            except socket.error as e:
                self.logger.log_error(f"Erro no socket: {e}")
                break

    def handle_client(self) -> None:
        """Aceita e processa conexão TCP"""
        if not self.socket:
            return

        try:
            # Aceita nova conexão
            client_socket, client_addr = self.socket.accept()
            self.logger.log_connection(client_addr, "TCP")

            try:
                # Recebe dados
                data = client_socket.recv(self.BUFFER_SIZE)
                if data:
                    message = data.decode('utf-8')
                    self.logger.log_message(client_addr, message)

                    # Processa mensagem
                    response = self.message_handler.process_message(message, client_addr)

                    # Envia resposta
                    client_socket.sendall(response.encode('utf-8'))
                    self.logger.log(f"Resposta enviada para {client_addr[0]}:{client_addr[1]}")

            finally:
                client_socket.close()

        except socket.error as e:
            self.logger.log_error(f"Erro ao processar cliente: {e}")


class UDPServer(SocketServer):
    """Servidor UDP que recebe mensagens"""

    def setup_socket(self) -> None:
        """Configura socket UDP"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
        except socket.error as e:
            self.logger.log_error(f"Falha ao configurar socket UDP: {e}")
            sys.exit(1)

    def run(self) -> None:
        """Loop principal UDP - recebe datagramas"""
        while self.running:
            try:
                self.handle_client()
                self.timeout_handler.reset()
            except socket.error as e:
                self.logger.log_error(f"Erro no socket: {e}")
                break

    def handle_client(self) -> None:
        """Recebe e processa datagrama UDP"""
        if not self.socket:
            return

        try:
            # Recebe datagrama
            data, client_addr = self.socket.recvfrom(self.BUFFER_SIZE)
            self.logger.log_connection(client_addr, "UDP")

            if data:
                message = data.decode('utf-8')
                self.logger.log_message(client_addr, message)

                # Processa mensagem
                response = self.message_handler.process_message(message, client_addr)

                # Envia resposta
                self.socket.sendto(response.encode('utf-8'), client_addr)
                self.logger.log(f"Resposta enviada para {client_addr[0]}:{client_addr[1]}")

        except socket.error as e:
            self.logger.log_error(f"Erro ao processar mensagem: {e}")


class ServerFactory:
    """Factory para criar servidores apropriados"""

    @staticmethod
    def create_server(
        protocol: Protocol,
        host: str,
        port: int,
        timeout_handler: TimeoutHandler
    ) -> SocketServer:
        """
        Cria instância do servidor apropriado

        Args:
            protocol: Protocolo a ser utilizado (TCP ou UDP)
            host: Endereço de bind do servidor
            port: Porta do servidor
            timeout_handler: Gerenciador de timeout

        Returns:
            Instância de SocketServer (TCPServer ou UDPServer)
        """
        if protocol == Protocol.TCP:
            return TCPServer(host, port, timeout_handler)
        elif protocol == Protocol.UDP:
            return UDPServer(host, port, timeout_handler)
        else:
            raise ValueError(f"Protocolo inválido: {protocol}")


class ServerApplication:
    """Aplicação principal do servidor"""

    def __init__(self) -> None:
        self.timeout_handler = TimeoutHandler(timeout=300)  # 5 minutos

    def _get_user_input(self) -> Tuple[str, int, Protocol]:
        """
        Solicita informações do usuário

        Returns:
            Tupla contendo (host, port, protocol)
        """
        print("=" * 50)
        print("    Servidor Socket Unificado (TCP/UDP)")
        print("=" * 50)
        print()
        print("DICAS:")
        print("  - Use '0.0.0.0' para aceitar de qualquer IP (padrão)")
        print("  - Use 'localhost' ou '127.0.0.1' para conexões locais")
        print("  - Use um IP específico para interface específica")
        print()

        # Host/Endereço
        host_input = input('Endereço do servidor (host ou IP) [Padrão: 0.0.0.0]: ').strip()
        if not host_input:
            host = '0.0.0.0'
        else:
            host = host_input

        # Validar endereço
        if not self._is_valid_host(host):
            print(f"Aviso: '{host}' pode não ser um endereço válido. Continuando mesmo assim...")

        # Porta
        port_input = input('Porta do servidor [Padrão: 8080]: ').strip()
        if not port_input:
            port = 8080
        else:
            try:
                port = int(port_input)
                if port < 1 or port > 65535:
                    print("Porta fora do intervalo válido (1-65535)! Usando porta padrão 8080")
                    port = 8080
            except ValueError:
                print("Porta inválida! Usando porta padrão 8080")
                port = 8080

        # Protocolo
        while True:
            protocol_input = input('Protocolo (TCP/UDP) [Padrão: TCP]: ').strip().upper()
            if not protocol_input:
                protocol_input = 'TCP'

            try:
                protocol = Protocol(protocol_input)
                break
            except ValueError:
                print("Protocolo inválido! Use TCP ou UDP.")

        return host, port, protocol

    def _is_valid_host(self, host: str) -> bool:
        """
        Valida se o endereço fornecido é válido

        Args:
            host: Endereço a ser validado

        Returns:
            True se válido, False caso contrário
        """
        # Aceita endereços comuns
        if host in ['localhost', '0.0.0.0', '127.0.0.1']:
            return True

        # Tenta validar como IPv4
        try:
            parts = host.split('.')
            if len(parts) == 4:
                return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            pass

        # Se não é IP, assume que é hostname válido
        # (não fazemos lookup DNS aqui para não travar)
        return len(host) > 0 and not host.isspace()

    def run(self) -> None:
        """Executa a aplicação"""
        host, port, protocol = self._get_user_input()

        server = ServerFactory.create_server(
            protocol=protocol,
            host=host,
            port=port,
            timeout_handler=self.timeout_handler
        )

        server.start()
        sys.exit(0)


def main() -> None:
    """Função principal"""
    app = ServerApplication()
    app.run()


if __name__ == '__main__':
    main()
