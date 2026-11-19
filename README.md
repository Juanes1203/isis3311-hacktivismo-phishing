# Un correo basta · Hacktivismo, ingeniería social y phishing

Mini exposición del Grupo 4 · ISIS 3311 Ciberseguridad · Universidad de los Andes · 2026-20
David Elías Forero Cobos y Juan Esteban Jiménez Benavides

- **Presentación:** `index.html` (publicada con GitHub Pages). Se abre también con doble clic, sin internet.
- **Demo en vivo:** dentro de la misma página, diapositiva 15 (botón **Demo** o tecla **D**). No necesita terminal ni internet.
- **Versión de terminal (opcional):** `demo.py`, el mismo modelo en Python (instrucciones abajo).

## Controles de la presentación

| Tecla | Acción |
|---|---|
| → / Espacio | Siguiente diapositiva |
| iPad / celular | Desliza el dedo a la izquierda o derecha, toca los bordes o usa los botones ‹ › de abajo |
| ← | Anterior |
| N | Notas del presentador (quién habla, tiempos, puntos de control) |
| G | Índice, incluido el anexo de preguntas |
| D | Ir a la demo (laboratorio SMTP) |
| F | Pantalla completa |
| T / R | Pausar o reiniciar el cronómetro |
| 1–5, 0 | En la diapositiva 13, resaltar cada señal del correo |

## La demo en la página (diapositiva 15)

1. Elige el **From** que escribe el atacante: suplantación exacta o dominio parecido.
2. Elige la **política DMARC** de altoverde.example: `p=none`, `p=quarantine` o `p=reject`.
3. Pulsa **Enviar correo**. Un sobre animado va del atacante al receptor, se encienden SPF, DKIM y DMARC, y el correo cae en Bandeja, Spam o Rechazado. Abajo se ve la conversación SMTP.
4. **Analizar buzón** muestra el veredicto: verificado, indicio y no demostrado.

Los botones del **Guion** (1 a 4) hacen la secuencia completa de la exposición con un clic cada uno.

## Glosario rápido

| Término | Qué es |
|---|---|
| **SMTP** | Protocolo con el que los servidores se entregan el correo. No autentica al remitente. |
| **From** | Remitente visible. Lo escribe quien envía. |
| **Return-Path / MAIL FROM** | El "sobre": dirección técnica para entregar y rebotar. Es lo que revisa SPF. |
| **Reply-To** | A dónde van las respuestas. Puede ser otro dominio. |
| **SPF** | Lista de servidores que un dominio autoriza para enviar su correo. |
| **DKIM** | Firma digital que el dominio pone en cada mensaje. |
| **DMARC** | Exige que SPF o DKIM pasen con el mismo dominio del From (alineación). |
| **p=none / quarantine / reject** | Qué pide el dueño del dominio si DMARC falla: observar, mandar a spam o rechazar. |
| **250 / 550** | Códigos SMTP: 250 aceptado, 550 rechazado. |
| **Dominio registrado** | El que va justo antes de la primera `/`. Lo de la izquierda es subdominio. |
| **Homógrafo / xn--** | Letra de otro alfabeto que se ve igual. DNS la escribe en punycode (`xn--`). |
| **AiTM** | Proxy falso entre la víctima y el sitio real que copia la sesión, incluso con MFA por código. |
| **MFA / FIDO2 / passkeys** | Segundo factor. FIDO2 y passkeys solo funcionan en el dominio real. |
| **MITRE ATT&CK (T1566…)** | Catálogo público de técnicas de ataque con códigos. |
| **.example / 127.0.0.1** | Dominios reservados para ejemplos y la dirección de este mismo computador. |

### Cómo leer el resultado de la demo

| Resultado | Qué significa en el escenario |
|---|---|
| `spf=pass` | El servidor que envió está autorizado, pero por correo-masivo.example, no por Alto Verde. |
| `dkim=none` | Nadie firmó el mensaje. |
| `dmarc=fail` | Ni SPF ni DKIM coinciden con el dominio del From (altoverde.example): el From es falso. |
| `p=none` | Alto Verde solo pide observar, así que el correo llega igual. Con `p=reject` sale `550` y no llega. |

La diapositiva 24 (anexo) tiene este glosario dentro de la presentación.

## Todo es ficticio

Universidad Alto Verde y Colectivo Aguacero son inventados. Los dominios `.example` están reservados (RFC 2606) y las IP son de documentación (RFC 5737). Ningún correo sale del computador y no se captura ninguna credencial.

---

# Demo en terminal (opcional)

Simula la entrega de un correo de phishing entre dos programas de este Mac.
No necesita internet ni instalar nada. Corre con Python 3.9 o superior.

## Por qué es seguro

- El servidor solo escucha en `127.0.0.1` y se apaga al terminar cada comando.
- El destinatario, los dominios `.example` y el texto están fijos en `demo.py`.
- No hay página falsa ni se captura ninguna credencial.

## Qué es simulado

- El DNS es una tabla dentro de `demo.py`.
- La IP del atacante es fija, tomada de un rango reservado para documentación.
- No hay firma DKIM real; siempre sale `dkim=none`.

Dilo en la exposición: es un modelo simplificado de la lógica de SPF y DMARC.

## Guion (1 min 30 s, en la diapositiva 15)

Antes de la clase, abre la terminal, aumenta la letra con `Cmd +` y entra a la carpeta donde está `demo.py` (en el Mac de Juan Esteban):

```bash
cd ~/Desktop/PRESENTACION
```

La diapositiva 15 de la presentación tiene esta misma demo en el navegador; la terminal es opcional.

**1. El From es mentira y llega.** Señala que `MAIL FROM` y el `From` visible son distintos.

```bash
python3 demo.py enviar suplantacion --politica none
```

**2. Cambiamos una sola pieza.** Mismo correo, pero el dominio publica `p=reject`. Señala el `550`.

```bash
python3 demo.py enviar suplantacion --politica reject
```

**3. El atacante se adapta.** Usa un dominio parecido que sí controla, y DMARC pasa.

```bash
python3 demo.py enviar parecido
```

**4. Se analiza lo que llegó.** Lee en voz alta el veredicto.

```bash
python3 demo.py analizar
```

Si sobra tiempo, en la diapositiva del enlace puedes mostrar el homógrafo:

```bash
python3 demo.py dominio
```

## Si algo falla

Vuelve a la diapositiva 15. Tiene los mismos tres resultados, comprobados el 2026-11-10.
