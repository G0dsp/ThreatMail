import base64
import webbrowser
import os
import requests
import readline  # Para autocompletado de archivos en Unix/Linux
import re       # Expresiones regulares
import time     # Para esperar en la API de urlscan
import whois    # pip install python-whois
from requests.exceptions import RequestException
from colorama import Fore, Style, init  # Para salida en colores

# Inicializar colorama
init(autoreset=True)

# Configuración de autocompletado de archivos
def complete(text, state):
    return [x for x in os.listdir() if x.startswith(text)][state]

readline.set_completer(complete)
readline.parse_and_bind('tab: complete')

# ------------------------------------------------------------------------
#                           FUNCIONES AUXILIARES
# ------------------------------------------------------------------------

def extract_domain(url):
    if "@" in url:
        url = url.split("@")[-1]
    if url.startswith("http://") or url.startswith("https://"):
        url = url.split("://", 1)[1]
    url = url.split('/')[0]
    parts = url.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return url

def decode_base64_to_txt(encoded_file, txt_file):
    with open(encoded_file, 'r', encoding='utf-8') as f:
        base64_content = f.read()
    # Eliminamos caracteres que no sean parte de la codificación base64
    base64_content = ''.join([c for c in base64_content if c.isalnum() or c in ['+', '/', '=']])
    decoded_bytes = base64.b64decode(base64_content)
    with open(txt_file, 'wb') as output_file:
        output_file.write(decoded_bytes)
    print(f"El archivo ha sido decodificado y guardado en {txt_file}\n")

def check_email_security_fields(txt_file):
    with open(txt_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    dkim_pass = arc_pass = spf_pass = False
    spf_domain = dkim_domain = from_domain = None
    
    for line in lines:
        if "dkim=pass" in line.lower():
            dkim_pass = True
        if "arc=pass" in line.lower():
            arc_pass = True
        if "spf=pass" in line.lower():
            spf_pass = True
        if "spfdomain=" in line.lower():
            spf_domain = line.split('spfdomain=')[-1].split()[0].strip()
        if "dkdomain=" in line.lower():
            dkim_domain = line.split('dkdomain=')[-1].split()[0].strip()
        if "fromdomain=" in line.lower():
            from_domain = line.split('fromdomain=')[-1].split()[0].strip(');')
    
    results = {
         "dkim_pass": dkim_pass,
         "arc_pass": arc_pass,
         "spf_pass": spf_pass,
         "spf_domain": spf_domain,
         "dkim_domain": dkim_domain,
         "from_domain": from_domain
    }
    
    # Imprimir resultados de autenticación aquí (solo se imprime una vez)
    print("Resultados de autenticación:")
    print(f"- DKIM Pass: {dkim_pass}")
    print(f"- ARC Pass: {arc_pass}")
    print(f"- SPF Pass: {spf_pass}")
    if not (spf_domain and dkim_domain and from_domain):
        print("No se encontraron todos los dominios para comparar.")
    else:
        domains_match = (spf_domain == dkim_domain == from_domain)
        print(f"Dominios coinciden: {domains_match}")
    return results

def extract_from_and_domain(txt_file):
    from_line = None
    domain = None
    with open(txt_file, 'r', encoding='utf-8') as f:
        content = f.read()
    lines = content.splitlines()
    for line in lines:
        if 'From:' in line and '@' in line:
            from_line = line
            break
    if from_line:
        match = re.search(r'<([^@]+@[\w\.-]+)>', from_line)
        if match:
            email = match.group(1)
            domain = email.split('@')[-1]
        else:
            match = re.search(r'@([\w\.-]+)', from_line)
            if match:
                domain = match.group(1)
    return from_line, domain

def extract_subject(txt_file):
    with open(txt_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    subject_line = None
    for line in lines:
        if line.lower().startswith("subject:"):
            subject_line = line.strip()
            break
    return subject_line

def extract_html_from_eml(txt_file, html_file):
    with open(txt_file, 'r', encoding='utf-8') as f:
        content = f.read()
    html_start = content.find('<html')
    html_end = content.find('</html>') + len('</html>')
    if html_start != -1 and html_end != -1:
        html_content = content[html_start:html_end]
        with open(html_file, 'w', encoding='utf-8') as html_output:
            html_output.write(html_content)
        print(f"\nParte HTML guardada en {html_file}")
        webbrowser.get('firefox').open(f'file://{os.path.abspath(html_file)}')
    else:
        print("No se encontró contenido HTML en el archivo.")

def extract_urls_from_text(txt_file):
    with open(txt_file, 'r', encoding='utf-8') as f:
        content = f.read()
    urls = re.findall(r'https?://[^\s\'"]+', content)
    return urls

def extract_smtp_mailfrom(txt_file):
    smtp_mailfrom = None
    with open(txt_file, 'r', encoding='utf-8') as f:
        for line in f:
            if "smtp.mailfrom" in line.lower():
                parts = line.split("=")
                if len(parts) > 1:
                    smtp_mailfrom = parts[1].strip()
                    break
    return smtp_mailfrom

def check_forwarding(txt_file):
    with open(txt_file, 'r', encoding='utf-8') as f:
        content = f.read()
    if re.search(r'(?i)(fwd:|fw:|forwarded|reenviado)', content):
        return "REENVIADO"
    return "no se encuentra forwarding"

def get_whois_creation_date(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        return creation.strftime("%Y-%m-%d %H:%M:%S") if creation else "[NO DATA]"
    except Exception:
        return "[NO DATA]"

# ------------------------------------------------------------------------
#                CONSULTA A VIRUS TOTAL
# ------------------------------------------------------------------------

def search_domain_virustotal(domain, vt_api_key):
    domain_clean = extract_domain(domain)
    url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {'apikey': vt_api_key, 'domain': domain_clean}
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            print(f"\nResultados en VirusTotal para {domain_clean}:")
            categories = data.get('categories', 'No disponible')
            print(f"   - Categorías: {Fore.GREEN}{categories}")
            reputation = data.get('reputation', 'No disponible')
            print(f"   - Reputación: {Fore.GREEN}{reputation}")
            if 'positives' in data and 'total' in data:
                positives = data['positives']
                total = data['total']
                print(f"   - Puntuación: {Fore.GREEN}{positives}/{total}")
        else:
            print(f"No se encontraron resultados para {domain_clean} en VirusTotal.")
    except RequestException as e:
        print(f"Error al conectar con VirusTotal: {e}")

# ------------------------------------------------------------------------
#                      NUEVA LÓGICA PARA URLSCAN
# ------------------------------------------------------------------------

def format_urlscan_result(scan_result):
    page_info = scan_result.get("page", {})
    task_info = scan_result.get("task", {})
    verdicts_info = scan_result.get("verdicts", {}).get("overall", {})

    formatted_result = {
        "Page URL": page_info.get("url"),
        "Domain": page_info.get("domain"),
        "IP Address": page_info.get("ip"),
        "Asn Info": page_info.get("asn"),
        "Country": page_info.get("country"),
        "Screenshot URL": task_info.get("screenshotURL"),
        "Malicious": verdicts_info.get("malicious"),
        "Score": verdicts_info.get("score"),
        "Tags": task_info.get("tags"),
        "Visibility": task_info.get("visibility"),
    }
    return formatted_result

def scan_domain_with_urlscan(domain_url, output_file, urlscan_api_key=None):
    scan_url = "https://urlscan.io/api/v1/scan/"
    payload = {"url": domain_url, "visibility": "public"}
    headers = {"Content-Type": "application/json"}
    if urlscan_api_key:
        headers["API-Key"] = urlscan_api_key

    # Se deja que esta función imprima sus propios mensajes
    print(f"Solicitando escaneo a urlscan para {domain_url}...")
    try:
        response = requests.post(scan_url, json=payload, headers=headers)
        if response.status_code == 200:
            data = response.json()
            result_uuid = data.get("uuid")
            if not result_uuid:
                print("No se obtuvo UUID del escaneo en urlscan.")
                return
            # Esperar a que finalice el escaneo
            time.sleep(10)
            result_url = f"https://urlscan.io/api/v1/result/{result_uuid}"
            final_response = requests.get(result_url, headers=headers)
            if final_response.status_code == 200:
                final_data = final_response.json()
                formatted_data = format_urlscan_result(final_data)
                print("\n--- Resultados finales de urlscan.io ---")
                for k, v in formatted_data.items():
                    print(f"{k}: {v}")
                screenshot_url = formatted_data.get("Screenshot URL")
                if screenshot_url:
                    img_response = requests.get(screenshot_url)
                    if img_response.status_code == 200:
                        with open(output_file, "wb") as f:
                            f.write(img_response.content)
                        print(f"Captura guardada en {output_file}")
                    else:
                        print("No se pudo descargar la captura desde la URL final.")
                else:
                    print("No se encontró la URL de la captura en el resultado final.")
            else:
                print(f"Error al obtener resultado final de urlscan: {final_response.status_code}")
        else:
            print(f"Error en la solicitud a urlscan, código: {response.status_code}")
    except RequestException as e:
        print(f"Error al conectar con urlscan: {e}")

# ------------------------------------------------------------------------
#               FUNCIÓN PRINCIPAL PARA IMPRIMIR EL INFORME
# ------------------------------------------------------------------------

def print_report(txt_file, from_line, domain_from_header, vt_api_key, urlscan_api_key):
    print("===========================================")
    print("               ANÁLISIS                  ")
    print("===========================================")
    print()
    
    # Sección: Análisis del correo
    print("-------------------------------------------")
    print("Análisis del correo:")
    print("-------------------------------------------")
    # Insertamos aquí los resultados de autenticación (solo se imprime una vez)
    check_email_security_fields(txt_file)
    print()  # Espacio extra
    
    print(f"Contenido del campo 'From': {from_line if from_line else 'No encontrado'}")
    print()
    smtp_mailfrom = extract_smtp_mailfrom(txt_file)
    print(f"Contenido del campo 'smtp.Mailfrom': {smtp_mailfrom if smtp_mailfrom else ''}")
    print()
    print(f"Dominio extraído del campo 'From': {domain_from_header if domain_from_header else 'No encontrado'}")
    print()
    forwarding_result = check_forwarding(txt_file)
    forwarding_bool = "TRUE" if forwarding_result == "REENVIADO" else "FALSE"
    print(f"Revisión correo reenviado campo 'Forwarding' : [{forwarding_bool}]")
    print()
    
    # Sección: Análisis de dominio
    print("-------------------------------------------")
    print("Análisis de dominio:")
    print("-------------------------------------------")
    if domain_from_header:
        print(f"Dominio del remitente: {domain_from_header}")
        print(f'Google Search: https://www.google.com/search?q={domain_from_header}')
        print()
        print(f"IBM X-Force: https://exchange.xforce.ibmcloud.com/url/{domain_from_header}")
        print()
        print(f"Talos Intelligence: https://www.talosintelligence.com/reputation_center/lookup?search={domain_from_header}")
        print()
    else:
        print("No se pudo extraer el dominio del remitente.")
    print("Virus Total:")
    if domain_from_header:
        search_domain_virustotal(domain_from_header, vt_api_key)
    else:
        print("No se pudo extraer el dominio para VirusTotal.")
    print()
    print("Información de Whois:")
    if domain_from_header:
        creation_date = get_whois_creation_date(domain_from_header)
        print(f"Fecha de creación: {creation_date}")
    else:
        print("Fecha de creación: [NO DATA]")
    print()
    
    # Sección: Análisis URL (urlscan)
    print("-------------------------------------------")
    print("Análisis URL (urlscan):")
    print("-------------------------------------------")
    if domain_from_header:
        domain_url = "https://" + domain_from_header
        print(f"Se solicitará captura y análisis de: {domain_url}")
        print()
        safe_url = re.sub(r'\W+', '', domain_from_header)
        screenshot_file = f"screenshot_{safe_url}.png"
        scan_domain_with_urlscan(domain_url, screenshot_file, urlscan_api_key)
    else:
        print("No se pudo determinar el dominio para la captura.")
    print()
    
    # Sección: URLs encontradas en el EML
    print("-------------------------------------------")
    print("Todas las URLs encontradas en el EML:")
    urls = extract_urls_from_text(txt_file)
    if urls:
        for url in urls:
            print(f"- {url}")
    else:
        print("- [URLS]")
    print()
    print("-------------------------------------------")
    print()
    
    # Sección: Conclusión
    print("Conclusión:")
    print("Fin de ejecución")
    print()

# ------------------------------------------------------------------------
#                           PUNTO DE ENTRADA
# ------------------------------------------------------------------------

if __name__ == "__main__":
    eml_file = input("Introduce el nombre del archivo .eml: ")
    txt_file = "mail.txt"
    html_file = "mail.html"
    
    # API keys y credenciales (reemplaza con las tuyas)
    vt_api_key = "XXXXX"
    urlscan_api_key = "XXXXX"
    
    # 1. Decodificar el archivo y guardar en txt
    decode_base64_to_txt(eml_file, txt_file)
    
    # 2. Extraer el 'From' y el dominio del remitente
    from_line, domain_from_header = extract_from_and_domain(txt_file)
    
    # 3. Imprimir informe final
    print_report(txt_file, from_line, domain_from_header, vt_api_key, urlscan_api_key)
    
    # 4. Extraer la parte HTML y abrir en Firefox
    extract_html_from_eml(txt_file, html_file)

