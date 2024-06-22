import nmap
import requests
import vuldb  # Adicione a biblioteca vuldb
import sqlite3  # Adicione a biblioteca sqlite3

# Funções para varredura Nmap e análise de vulnerabilidade

def nmap_scan(target, port_range):
    scanner = nmap.PortScanner()
    scan_args = f"-sV -A {target} -p {port_range}"
    try:
        scan_result = scanner.scan(scan_args)
        return scan_result
    except Exception as e:
        print(f"Erro durante a varredura Nmap: {e}")
        return None


def analyze_vulnerability_with_gemini(host, port, service, service_version):
    gemini_api_key = "SEU_CHAVE_API_AQUI"
    url = "https://api.gemini.ai/v1/vulnerabilities/search"
    payload = {
        "host": host,
        "port": port,
        "service": service,
        "service_version": service_version
    }
    headers = {
        "Authorization": f"Bearer {gemini_api_key}"
    }
    try:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            vulnerability_info = response.json()["data"]
            return vulnerability_info
        else:
            print(f"Erro ao consultar API Gemini: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão com API Gemini: {e}")
        return None


def analyze_vulnerability_with_vuldb(host, port, service, service_version):
    vuldb_client = vuldb.Client()
    vulnerability_info = vuldb_client.query(
        q=f"nvd:{service_version} and service:{service}",
        host=host,
        port=port
    )
    if vulnerability_info:
        return vulnerability_info[0]
    else:
        return None


# Função para salvar resultados no banco de dados

def save_results_to_db(scan_result, db_path):
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    # Crie as tabelas se não existirem
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_date TEXT NOT NULL
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            host_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            mac_address TEXT,
            hostname TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS services (
            service_id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service_name TEXT,
            service_version TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts(host_id)
        );
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            cve_id TEXT,
            summary TEXT,
            cvss_score FLOAT,
            exploit_link TEXT,
            risk_level TEXT,
            FOREIGN KEY (service_id) REFERENCES services(service_id)
        );
    """)

    # Inserir dados do scan
    scan_id = cursor.execute("INSERT INTO scans (target, scan_date) VALUES (?, ?)", (target, datetime.datetime.now().isoformat())).lastrowid
    cursor.execute("INSERT INTO hosts (
