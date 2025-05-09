#Logica principal
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from tqdm import tqdm
import os



class WebScanner:
    def __init__(self, target_url):
        self.session = requests.Session()
        self.session.timeout = 10
        self.max_threads = min(5, os.cpu_count() * 2)
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.lock = Lock()

    def check_sql_injection(self):
        """ Testa formularios por SQL Injection básico """
        forms = self.get_forms()
        for form in forms:
            payload = "' OR  1=1 --"
            response = self.submit_form(form, payload)
            if "error in your SQL syntax" in response.text:
                with self.lock:
                    self.vulnerabilities.append(("SQL Injection", form.action))
                    
    def check_xss(self):
        """Testa por XSS refletido"""
        forms = self.get_forms()
        for form in forms:
            payload = "<script>alert('XSS')</script>"
            response = self._submit_form(form, payload)
            if payload in response.text:
                with self.lock:
                    self.vulnerabilities.append(("XSS", form.action))
    
    def check_directories(self):
        """Buscar diretórios ocultos usando wordlist"""
        with open("wordlist.txt", "r") as f:
            wordlist = [line.strip() for line in f]

        for dir_path in wordlist:
            url = urljoin(self.target_url, dir_path)
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                with self.lock:
                    self.vulnerabilities.append(("Directory exposto", url))
    
    def check_cors(self):
        """Verificar cofingurações inseguras de CORS"""
        headers = {
            "Origin": "http://evil.com",
            "Access-Control-Request-Method": "GET",
        }
        response = self.session.options(self.target_url, headers=headers)

        if "evil.com" in response.headers.get("Access-Control-Allow-Origin", ""):
            with self.lock:
                self.vulnerabilities.append(("Cors misconfiguration", self.target_url))

    def get_forms(self):
        """Extrai formulário html da página"""
        response = self.session.get(self.target_url)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    
    def submit_form(self, form, payload):
        """Submete o formulário com o payload"""
        action = form.attrs.get("action", "")
        url = urljoin(self.target_url, action)
        inputs = form.find_all("input")
        data = {input.attrs["name"]: payload for input in inputs if "name" in input.attrs}
        return self.session.post(url, data=data)
    
    def generate_report(self):
        """Gerar um relatório de vulnerabilidades"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Relatório de Vulnerabilidades</title>
            <style>
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; }
                tr:nth-child(even) { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>Relatório para {{ target }}</h1>
            <table>
                <tr><th>Tipo</th><th>Local</th><th>Severidade</th></tr>
                {% for vuln in vulns %}
                <tr>
                    <td>{{ vuln[0] }}</td>
                    <td>{{ vuln[1] }}</td>
                    <td style="color: {% if 'SQL' in vuln[0] %}red{% else %}orange{% endif %}">
                        {% if 'SQL' in vuln[0] %}Alta{% else %}Média{% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """
        
        from jinja2 import Template
        report = Template(html_template).render(
            target=self.target_url,
            vulns=self.vulnerabilities
        )
        
        with open("report.html", "w") as f:
            f.write(report)

    def run_scan(self):
        """executar todas as verificações"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            #submete as tarefas em paralelo
            futures = [
                executor.submit(self.check_sql_injection),
                executor.submit(self.check_xss),
                executor.submit(self.check_directories),
                executor.submit(self.check_cors)
            ]

            #aguarda a conclusão de todas as tarefas
            for future in tqdm(futures, desc="Scanning", unit="test"):
                try:
                    future.result(timeout=30)  # Timeout por teste
                except Exception as e:
                    print(f"\n[!] Teste falhou: {str(e)[:100]}...")

if __name__ == "__main__":
        target = input("Digite a URL alvo: (ex: http://testhphp.vulnweb.com): ")
        if not target.startswith("http"):
            target = "http://" + target

        scanner = WebScanner(target)
        scanner.run_scan()

        print("\n[+] Vulnerabilidades encontradas:")
        for vuln in sorted(scanner.vulnerabilities):
            print(f"- {vuln[0]:<25} em {vuln[1]}")

        scanner.generate_report()
        print("\n[+] Relatório gerado como 'report.html'")