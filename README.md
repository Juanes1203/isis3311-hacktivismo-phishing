# Un correo basta · Hacktivismo, ingeniería social y phishing

Mini exposición del Grupo 4 · ISIS 3311 Ciberseguridad · Universidad de los Andes · 2026-20
David Elías Forero Cobos y Juan Esteban Jiménez Benavides

- **Presentación:** `index.html` (publicada con GitHub Pages). Se abre también con doble clic, sin internet.
- **Demo en vivo:** `demo.py` (instrucciones abajo).

## Controles de la presentación

| Tecla | Acción |
|---|---|
| → / Espacio | Siguiente diapositiva |
| ← | Anterior |
| N | Notas del presentador (quién habla, tiempos, puntos de control) |
| G | Índice, incluido el anexo de preguntas |
| F | Pantalla completa |
| T / R | Pausar o reiniciar el cronómetro |
| 1–5, 0 | En la diapositiva 13, resaltar cada señal del correo |

La diapositiva 15 trae la misma demo de `demo.py` traducida a JavaScript, como respaldo si la terminal falla.

## Todo es ficticio

Universidad Alto Verde y Colectivo Aguacero son inventados. Los dominios `.example` están reservados (RFC 2606) y las IP son de documentación (RFC 5737). Ningún correo sale del computador y no se captura ninguna credencial.

---

# Demo en vivo

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

Si la terminal falla, la presentación (`index.html`, diapositiva 15) tiene la misma demo simulada en el navegador.

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
