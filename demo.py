#!/usr/bin/env python3
"""Laboratorio local de la mini exposición del Grupo 4 (ISIS 3311).

Simula la entrega de un correo de phishing entre dos programas del mismo
computador. Nada sale de 127.0.0.1: el servidor, el destinatario, los dominios
(.example) y el contenido están fijos en este archivo.

El DNS es una tabla en memoria y no hay firma DKIM real. Es un modelo
simplificado para mostrar la lógica de SPF y DMARC, no una implementación
completa de esos estándares.

Solo usa la biblioteca estándar de Python.
"""
import argparse
import re
import smtplib
import socketserver
import sys
import threading
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

HOST = "127.0.0.1"
ORGANIZACION = "altoverde.example"
RECEPTOR = "mx.altoverde.example"
RELAY = "relay.correo-masivo.example"
IP_ATACANTE = "198.51.100.23"  # Rango reservado para documentación (RFC 5737).
IP_ORGANIZACION = "192.0.2.10"  # Rango reservado para documentación (RFC 5737).
BUZON = Path(__file__).resolve().parent / "buzon"
ULTIMO = BUZON / "ultimo.eml"
TEXTO_ENLACE = "https://portal.altoverde.example/verificar"
DESTINO_ENLACE = "https://altoverde.example.portal-verificar.example/login"
HOMOGRAFO = "аltoverde.example"  # La primera letra es una "a" cirílica.

ESCENARIOS = {
    "suplantacion": {
        "sobre": "rebote@correo-masivo.example",
        "from": "soporte@altoverde.example",
    },
    "parecido": {
        "sobre": "rebote@altoverde-ayuda.example",
        "from": "soporte@altoverde-ayuda.example",
    },
}

COLOR = sys.stdout.isatty()


def pintar(texto, codigo):
    return f"\033[{codigo}m{texto}\033[0m" if COLOR else texto


def amarillo(texto):
    return pintar(texto, "1;33")


def rojo(texto):
    return pintar(texto, "1;31")


def titulo(texto):
    print("\n" + pintar(texto, "1;4"))


def dominio_de(direccion):
    return parseaddr(direccion)[1].rpartition("@")[2].lower()


def organizacional(dominio):
    """Devuelve las dos últimas etiquetas; basta para los dominios .example."""
    return ".".join(dominio.lower().split(".")[-2:])


def crear_dns(politica):
    return {
        "altoverde.example": {"spf": [IP_ORGANIZACION], "dmarc": politica},
        "correo-masivo.example": {"spf": [IP_ATACANTE], "dmarc": None},
        "altoverde-ayuda.example": {"spf": [IP_ATACANTE], "dmarc": "reject"},
    }


def evaluar(dns, sobre, remitente):
    """Calcula SPF y DMARC con la IP simulada del relay del atacante."""
    spf_pasa = IP_ATACANTE in dns.get(sobre, {}).get("spf", [])
    alineado = spf_pasa and organizacional(sobre) == organizacional(remitente)
    return {
        "spf": "pass" if spf_pasa else "fail",
        "dkim": "none",
        "dmarc": "pass" if alineado else "fail",
        "politica": dns.get(remitente, {}).get("dmarc") or "none",
        "sobre": sobre,
        "from": remitente,
    }


def crear_correo(escenario):
    datos = ESCENARIOS[escenario]
    correo = EmailMessage()
    correo["From"] = f'"Mesa de Servicios TI" <{datos["from"]}>'
    correo["To"] = "Rectoria <rectoria@altoverde.example>"
    correo["Reply-To"] = "<soporte@altoverde-ayuda.example>"
    correo["Subject"] = "URGENTE: su cuenta se suspende hoy"
    texto = (
        "Estimado usuario:\n\n"
        "Detectamos actividad inusual en su cuenta institucional.\n"
        "Para evitar la suspensión y la pérdida de su correo,\n"
        "verifique su identidad en las próximas 2 horas.\n\n"
        f"{TEXTO_ENLACE}\n\n"
        "Mesa de Servicios TI, Universidad Alto Verde\n"
    )
    correo.set_content(texto)
    html = (
        "<p>Estimado usuario:</p>"
        "<p>Detectamos actividad inusual en su cuenta institucional. "
        "Para evitar la suspensión y la pérdida de su correo, "
        "verifique su identidad en las próximas 2 horas.</p>"
        f'<p><a href="{DESTINO_ENLACE}">{TEXTO_ENLACE}</a></p>'
        "<p>Mesa de Servicios TI, Universidad Alto Verde</p>"
    )
    correo.add_alternative(html, subtype="html")
    return correo


def extraer_direccion(comando):
    encontrada = re.search(r"<([^>]*)>", comando)
    return encontrada.group(1) if encontrada else ""


class Receptor(socketserver.StreamRequestHandler):
    """Receptor SMTP mínimo: acepta o rechaza al terminar DATA."""

    def decir(self, linea):
        print(f"  {pintar('S:', '36')} {linea}", flush=True)
        self.wfile.write((linea + "\r\n").encode())

    def leer_datos(self):
        lineas = []
        while True:
            crudo = self.rfile.readline()
            if crudo in (b".\r\n", b".\n", b""):
                return b"".join(lineas)
            lineas.append(crudo[1:] if crudo.startswith(b"..") else crudo)

    def recibir(self, sobre):
        datos = self.leer_datos()
        print(f"  {pintar('C:', '35')} (cabeceras y cuerpo del mensaje)", flush=True)
        correo = message_from_bytes(datos, policy=policy.default)
        resultado = evaluar(self.server.dns, dominio_de(sobre), dominio_de(correo["From"]))
        self.server.resultado = resultado
        if resultado["dmarc"] == "fail" and resultado["politica"] == "reject":
            self.decir("550 5.7.1 Rechazado por politica DMARC del dominio del From")
            return
        autenticacion = (
            f"Authentication-Results: {RECEPTOR};\r\n"
            f" spf={resultado['spf']} smtp.mailfrom={resultado['sobre']};\r\n"
            f" dkim={resultado['dkim']};\r\n"
            f" dmarc={resultado['dmarc']} (p={resultado['politica']}) "
            f"header.from={resultado['from']}\r\n"
        )
        cabeceras = (
            f"Return-Path: <{sobre}>\r\n"
            f"Received: from {RELAY} ([{IP_ATACANTE}]) by {RECEPTOR}\r\n"
            f"{autenticacion}"
        ).encode()
        BUZON.mkdir(exist_ok=True)
        ULTIMO.write_bytes(cabeceras + datos)
        self.server.entregado = True
        self.decir("250 2.0.0 Entregado al buzon")

    def handle(self):
        self.decir(f"220 {RECEPTOR} ESMTP laboratorio")
        sobre = ""
        while True:
            crudo = self.rfile.readline()
            if not crudo:
                return
            linea = crudo.decode(errors="replace").rstrip("\r\n")
            print(f"  {pintar('C:', '35')} {linea}", flush=True)
            comando = linea.upper()
            if comando.startswith(("EHLO", "HELO")):
                self.decir(f"250 {RECEPTOR}")
            elif comando.startswith("MAIL FROM:"):
                sobre = extraer_direccion(linea)
                self.decir("250 2.1.0 Sobre recibido (no se verifica aun)")
            elif comando.startswith("RCPT TO:"):
                self.decir("250 2.1.5 Destinatario aceptado")
            elif comando == "DATA":
                self.decir("354 Envie el mensaje y termine con un punto")
                self.recibir(sobre)
            elif comando == "RSET":
                self.decir("250 2.0.0 Listo")
            elif comando == "QUIT":
                self.decir("221 Adios")
                return
            else:
                self.decir("502 Comando no soportado")


class Servidor(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def enviar(escenario, politica):
    datos = ESCENARIOS[escenario]
    ULTIMO.unlink(missing_ok=True)
    detalle = f" | p={politica} en {ORGANIZACION}" if escenario == "suplantacion" else ""
    titulo(f"Escenario: {escenario}{detalle}")
    print(f"  Sobre (MAIL FROM): {datos['sobre']}")
    print(f"  From visible:      {datos['from']}")
    titulo("Conversación SMTP (solo en 127.0.0.1)")
    with Servidor((HOST, 0), Receptor) as servidor:
        servidor.dns = crear_dns(politica)
        servidor.entregado = False
        servidor.resultado = None
        hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
        hilo.start()
        puerto = servidor.server_address[1]
        try:
            with smtplib.SMTP(HOST, puerto, local_hostname=RELAY, timeout=10) as cliente:
                cliente.send_message(
                    crear_correo(escenario),
                    from_addr=datos["sobre"],
                    to_addrs=["rectoria@altoverde.example"],
                )
        except smtplib.SMTPResponseException as error:
            if error.smtp_code != 550:
                raise
        finally:
            servidor.shutdown()
        resultado = servidor.resultado
        entregado = servidor.entregado
    titulo("Decisión del receptor")
    print(f"  spf={resultado['spf']}  dkim={resultado['dkim']}  dmarc={resultado['dmarc']}  p={resultado['politica']}")
    if entregado:
        print("  " + amarillo("ENTREGADO") + f": {ULTIMO.relative_to(Path.cwd()) if ULTIMO.is_relative_to(Path.cwd()) else ULTIMO}")
    else:
        print("  " + rojo("RECHAZADO") + ": nunca llegó al buzón")


class Enlaces(HTMLParser):
    def __init__(self):
        super().__init__()
        self.enlaces = []
        self.actual = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.actual = {"destino": dict(attrs).get("href", ""), "texto": ""}

    def handle_data(self, data):
        if self.actual is not None:
            self.actual["texto"] += data

    def handle_endtag(self, tag):
        if tag == "a" and self.actual is not None:
            self.enlaces.append(self.actual)
            self.actual = None


def analizar(ruta):
    if not ruta.exists():
        print("No hay correo en el buzón: el último envío fue rechazado o aún no se ha enviado.")
        return
    correo = message_from_bytes(ruta.read_bytes(), policy=policy.default)
    remitente = dominio_de(correo["From"])
    sobre = dominio_de(correo["Return-Path"])
    responder = dominio_de(correo["Reply-To"]) if correo["Reply-To"] else remitente
    autenticacion = " ".join(str(correo["Authentication-Results"]).split())
    valor = lambda clave: re.search(rf"{clave}=([\w-]+)", autenticacion).group(1)
    spf, dkim, dmarc, politica = valor("spf"), valor("dkim"), valor("dmarc"), valor(r"\(p")

    titulo("Identidad")
    print(f"  From visible: {amarillo(remitente)}")
    print(f"  Sobre:        {amarillo(sobre)}")
    print(f"  Responder a:  {amarillo(responder)}")

    titulo("Autenticación")
    relacion = "igual al From" if organizacional(sobre) == organizacional(remitente) else "no al From"
    print(f"  spf={spf}: autoriza a {sobre}, {relacion}")
    print(f"  dkim={dkim}: nadie firmó el mensaje")
    print(f"  dmarc={dmarc} (p={politica}): {'alineado con el From' if dmarc == 'pass' else 'sin alineación con el From'}")

    html = correo.get_body(preferencelist=("html",)).get_content()
    lector = Enlaces()
    lector.feed(html)
    titulo("Enlaces")
    externos = []
    for enlace in lector.enlaces:
        host = urlsplit(enlace["destino"]).hostname or ""
        real = organizacional(host)
        print(f"  Texto:        {enlace['texto']}")
        print(f"  Destino:      {enlace['destino']}")
        print(f"  Dominio real: {amarillo(real)}")
        if real != ORGANIZACION:
            externos.append(real)

    verificado = []
    if dmarc == "fail":
        verificado.append("El From no está autenticado (DMARC falla).")
    if organizacional(remitente) != ORGANIZACION:
        verificado.append(f"El remitente no es de la organización: {remitente}.")
    if organizacional(responder) != ORGANIZACION:
        verificado.append(f"Las respuestas irían fuera de la organización: {responder}.")
    for real in externos:
        verificado.append(f"El enlace lleva a un dominio ajeno: {real}.")

    cuerpo = correo.get_body(preferencelist=("plain",)).get_content().lower()
    asunto = str(correo["Subject"]).lower()
    indicios = []
    if "urgente" in asunto:
        indicios.append("Urgencia en el asunto.")
    if "estimado usuario" in cuerpo:
        indicios.append("Saludo genérico.")
    if "suspensión" in cuerpo and "2 horas" in cuerpo:
        indicios.append("Amenaza con plazo.")

    titulo("Veredicto")
    print("  " + amarillo("VERIFICADO"))
    for punto in verificado:
        print(f"    - {punto}")
    print("  INDICIO")
    for punto in indicios:
        print(f"    - {punto}")
    print("  " + rojo("NO DEMOSTRADO"))
    print("    - Quién lo envió. El correo prueba el engaño, no al autor.")


def revisar_dominio(dominio):
    titulo("Dominio")
    print(f"  Se ve así:  {dominio}")
    ajenos = [(i, c) for i, c in enumerate(dominio) if ord(c) > 127]
    for posicion, caracter in ajenos:
        print(f"  Posición {posicion}: {caracter!r} es {amarillo(f'U+{ord(caracter):04X}')}, no ASCII")
    print(f"  En DNS es:  {amarillo(dominio.encode('idna').decode())}")


def main():
    argumentos = argparse.ArgumentParser(description="Laboratorio local de phishing, solo 127.0.0.1")
    comandos = argumentos.add_subparsers(dest="comando", required=True)
    envio = comandos.add_parser("enviar")
    envio.add_argument("escenario", choices=ESCENARIOS)
    envio.add_argument("--politica", choices=("none", "reject"), default="none")
    analisis = comandos.add_parser("analizar")
    analisis.add_argument("archivo", nargs="?", type=Path, default=ULTIMO)
    dominio = comandos.add_parser("dominio")
    dominio.add_argument("nombre", nargs="?", default=HOMOGRAFO)
    opciones = argumentos.parse_args()
    if opciones.comando == "enviar":
        enviar(opciones.escenario, opciones.politica)
    elif opciones.comando == "analizar":
        analizar(opciones.archivo)
    else:
        revisar_dominio(opciones.nombre)


if __name__ == "__main__":
    main()
