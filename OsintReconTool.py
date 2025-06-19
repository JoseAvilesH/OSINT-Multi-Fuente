"""
OSINT Recon Tool v1.1
Autor: Jose Aviles
Descripción:
Herramienta OSINT modular que utiliza WHOIS, Shodan (API gratuita)
y scraping en Google para encontrar correos relacionados a un dominio.

Uso: python osint_recon.py
"""

import socket
import json
import requests
import shodan
import whois
import re
from googlesearch import search
from bs4 import BeautifulSoup

# Configura tu API Key de Shodan
SHODAN_API_KEY = "TU_API_KEY_AQUI"

# Resolver dominio a IP
def obtener_ip(dominio):
    try:
        return socket.gethostbyname(dominio)
    except socket.gaierror:
        return None

# Consulta WHOIS del dominio
def consultar_whois(dominio):
    try:
        datos = whois.whois(dominio)
        return {
            'dominio': dominio,
            'registrante': datos.get('name'),
            'correos': datos.get('emails'),
            'fecha_registro': str(datos.get('creation_date')),
            'fecha_expiracion': str(datos.get('expiration_date'))
        }
    except Exception as e:
        return {'error': str(e)}

# Consulta Shodan con IP
def consultar_shodan(ip):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        resultado = api.host(ip)
        return {
            'ip': ip,
            'puertos': resultado.get('ports', []),
            'organizacion': resultado.get('org'),
            'sistema_operativo': resultado.get('os'),
            'servicios': resultado.get('data', [])
        }
    except shodan.APIError as e:
        return {
            'error': str(e),
            'sugerencia': 'Verifica tu API Key o prueba con una IP pública conocida como scanme.shodan.io'
        }

# Buscar correos públicos desde Google
def buscar_correos_google(dominio):
    correos_encontrados = set()
    consulta = f'"@{dominio}" site:{dominio}'

    try:
        resultados = search(consulta, num_results=10, lang="es")
        for url in resultados:
            try:
                html = requests.get(url, timeout=5).text
                texto = BeautifulSoup(html, "html.parser").get_text()
                encontrados = re.findall(rf"[a-zA-Z0-9_.+-]+@{re.escape(dominio)}", texto)
                correos_encontrados.update(encontrados)
            except Exception:
                continue
    except Exception as e:
        print(f"Error en la búsqueda de correos: {e}")
    
    return list(correos_encontrados)

# Mostrar resultados WHOIS
def mostrar_whois(data):
    print("\n[ WHOIS ]")
    if 'error' in data:
        print(f"Error: {data['error']}")
        return
    print(f"Dominio: {data['dominio']}")
    print(f"Registrante: {data.get('registrante', 'No disponible')}")
    print(f"Correos: {data.get('correos', 'No disponibles')}")
    print(f"Fecha de registro: {data.get('fecha_registro', 'Desconocida')}")
    print(f"Fecha de expiración: {data.get('fecha_expiracion', 'Desconocida')}")

# Mostrar resultados Shodan
def mostrar_shodan(data):
    print("\n[ SHODAN ]")
    if 'error' in data:
        print(f"Error: {data['error']}")
        if 'sugerencia' in data:
            print(f"Sugerencia: {data['sugerencia']}")
        return
    
    print(f"IP: {data['ip']}")
    print(f"Organización: {data.get('organizacion', 'Desconocida')}")
    print(f"Sistema operativo: {data.get('sistema_operativo', 'Desconocido')}")
    print(f"Puertos abiertos: {', '.join(map(str, data.get('puertos', [])))}")

    print("\nServicios detectados:")
    for servicio in data.get('servicios', []):
        puerto = servicio.get('port')
        producto = servicio.get('product', 'Desconocido')
        ciudad = servicio.get('location', {}).get('city')
        pais = servicio.get('location', {}).get('country_name')
        hostnames = servicio.get('hostnames', [])
        waf = servicio.get('http', {}).get('waf') if 'http' in servicio else None

        print(f"- Puerto {puerto}: {producto}")
        if waf:
            print(f"  WAF: {waf}")
        if ciudad and pais:
            print(f"  Ubicación: {ciudad}, {pais}")
        if hostnames:
            print(f"  Hostnames: {', '.join(hostnames)}")

# Mostrar resumen final
def mostrar_resumen(whois_data, shodan_data, correos):
    print("\n========== RESUMEN DE OSINT ==========")
    print(f"Correo WHOIS: {whois_data.get('correos') if whois_data.get('correos') else 'No disponible'}")
    print(f"Correos extraídos de Google: {correos if correos else 'No se encontraron'}")

    if 'error' not in shodan_data:
        print(f"Puertos abiertos: {shodan_data.get('puertos', [])}")
        print(f"Organización: {shodan_data.get('organizacion')}")
    else:
        print(f"Shodan: {shodan_data.get('error')}")

# Punto de entrada
def main():
    dominio = input("Introduce el dominio objetivo: ").strip()
    ip = obtener_ip(dominio)

    print(f"\nIP resuelta: {ip if ip else 'No se pudo resolver IP'}")

    whois_data = consultar_whois(dominio)
    mostrar_whois(whois_data)

    if ip:
        shodan_data = consultar_shodan(ip)
        mostrar_shodan(shodan_data)
    else:
        shodan_data = {'error': 'No se pudo resolver la IP'}

    correos = buscar_correos_google(dominio)
    mostrar_resumen(whois_data, shodan_data, correos)

if __name__ == "__main__":
    main()
