# OSINT-Multi-Fuente
# 🕵️ OSINT Recon Tool v1.1

**Autor:** Jose Aviles 
**Versión:** 1.1  
**Descripción:**  
Herramienta OSINT modular que permite recolectar información pública sobre un dominio, combinando consultas WHOIS, análisis con la API gratuita de Shodan y scraping de correos electrónicos desde resultados de Google.

---

## 🛠️ Funcionalidades

- Resolución de dominio a IP
- Consulta WHOIS del dominio
- Escaneo básico con SHODAN (requiere API Key)
- Scraping de correos desde páginas indexadas en Google

---

## 🔧 Requisitos

Instala los módulos necesarios:

```bash
pip install shodan python-whois googlesearch-python beautifulsoup4
