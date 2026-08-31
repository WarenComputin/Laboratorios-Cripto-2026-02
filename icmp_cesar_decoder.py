#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║    ICMP Covert Channel — Decoder de Cifrado César            ║
║    Extrae el mensaje de un .pcapng y prueba las 26 llaves    ║
╚══════════════════════════════════════════════════════════════╝

Uso:
    python3 icmp_cesar_decoder.py <captura.pcapng> [ip_destino]

Ejemplos:
    python3 icmp_cesar_decoder.py captura.pcapng
    python3 icmp_cesar_decoder.py captura.pcapng 127.0.0.1

Funcionamiento:
  1. Lee el archivo .pcapng con Scapy.
  2. Filtra paquetes ICMP Echo Request (tipo 8) hacia la IP destino.
  3. Extrae el carácter cifrado del byte 0x00 del payload (56 bytes).
  4. Reconstruye la palabra cifrada en el orden de los paquetes (ICMP seq).
  5. Aplica todas las 26 rotaciones del cifrado César (k=0 … k=25).
  6. Puntúa cada candidato por frecuencia de letras (inglés + español).
  7. Imprime todas las combinaciones e indica en verde la más probable.

Dependencias:
    pip install scapy
"""

import sys
import os
import struct

# ─── Colores ANSI ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ─── Frecuencias de letras (%) ────────────────────────────────────────────────

# Inglés (referencia: Lewand, 2000)
FREQ_EN: dict[str, float] = {
    "A": 8.17, "B": 1.49, "C": 2.78, "D": 4.25, "E": 12.70,
    "F": 2.23, "G": 2.02, "H": 6.09, "I": 6.97, "J": 0.15,
    "K": 0.77, "L": 4.03, "M": 2.41, "N": 6.75, "O": 7.51,
    "P": 1.93, "Q": 0.10, "R": 5.99, "S": 6.33, "T": 9.06,
    "U": 2.76, "V": 0.98, "W": 2.36, "X": 0.15, "Y": 1.97,
    "Z": 0.07,
}

# Español (referencia: RAE / Llorente, 1965)
FREQ_ES: dict[str, float] = {
    "A": 11.53, "B": 2.21, "C": 4.02, "D": 5.86, "E": 13.68,
    "F": 0.69,  "G": 1.01, "H": 0.70, "I": 6.25, "J": 0.44,
    "K": 0.02,  "L": 4.97, "M": 3.16, "N": 6.71, "O": 8.68,
    "P": 2.51,  "Q": 0.88, "R": 6.87, "S": 7.98, "T": 4.63,
    "U": 3.93,  "V": 0.90, "W": 0.01, "X": 0.22, "Y": 0.90,
    "Z": 0.52,
}


# ─── Scapy ───────────────────────────────────────────────────────────────────
try:
    from scapy.all import rdpcap, IP, ICMP, Raw, conf
    conf.verb = 0
except ImportError:
    print("[!] Scapy no está instalado.")
    print("    Instálalo con: pip install scapy")
    sys.exit(1)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def caesar_decrypt(text: str, shift: int) -> str:
    """Decifra `text` con rotación César inversa de `shift` posiciones."""
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
        elif ch.islower():
            result.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
        else:
            result.append(ch)   # No es letra → se mantiene igual
    return "".join(result)


def score_text(text: str) -> float:
    """
    Puntúa el texto candidato comparando frecuencias observadas
    con las esperadas en inglés Y español, y devuelve el mejor score.

    Método: χ² negativo (menor divergencia → mayor puntaje).
    Un score más alto (menos negativo) indica mayor probabilidad
    de ser texto natural.
    """
    letters = [ch.upper() for ch in text if ch.isalpha()]
    if not letters:
        return float("-inf")

    total  = len(letters)
    counts = {}
    for ch in letters:
        counts[ch] = counts.get(ch, 0) + 1

    def chi2_neg(freq_table: dict) -> float:
        score = 0.0
        for letter, expected_pct in freq_table.items():
            observed_pct = (counts.get(letter, 0) / total) * 100.0
            score -= (observed_pct - expected_pct) ** 2
        return score

    return max(chi2_neg(FREQ_EN), chi2_neg(FREQ_ES))


def all_printable_alpha(text: str) -> bool:
    """Devuelve True si todos los caracteres son letras ASCII imprimibles."""
    return all(ch.isalpha() and ch.isascii() for ch in text)


# ─── Extracción desde PCAPNG ─────────────────────────────────────────────────

def extract_from_pcap(pcap_path: str, target_ip: str = "127.0.0.1") -> list[dict]:
    """
    Lee el archivo .pcapng y extrae los caracteres cifrados de los paquetes
    ICMP Echo Request (tipo 8) enviados a `target_ip`.

    Retorna lista de dicts con: seq, ip_id, icmp_id, char, byte, timestamp_us
    """
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[!] Error al leer el archivo: {e}")
        sys.exit(1)

    found = []

    for pkt in packets:
        # Filtro: debe tener capa IP e ICMP
        if IP not in pkt or ICMP not in pkt:
            continue

        # Filtro: solo Echo Request (tipo 8) hacia la IP destino
        if pkt[ICMP].type != 8:
            continue
        if pkt[IP].dst != target_ip:
            continue

        # Extraer payload: es la capa Raw después del encabezado ICMP
        raw_data = None
        if Raw in pkt:
            raw_data = bytes(pkt[Raw].load)
        else:
            # Fallback: tomar payload del ICMP directamente
            icmp_payload = bytes(pkt[ICMP].payload)
            if icmp_payload:
                raw_data = icmp_payload

        if raw_data is None or len(raw_data) < 1:
            continue

        # El carácter cifrado está en el primer byte del payload (offset 0x00)
        char_byte = raw_data[0]

        # Extraer timestamp si el payload tiene al menos 16 bytes (offset 0x08-0x0F)
        timestamp_us = None
        if len(raw_data) >= 16:
            try:
                timestamp_us = struct.unpack(">Q", raw_data[8:16])[0]
            except struct.error:
                pass

        # Solo aceptar caracteres ASCII imprimibles (0x20–0x7E)
        if 0x20 <= char_byte <= 0x7E:
            found.append({
                "seq"         : pkt[ICMP].seq,
                "ip_id"       : pkt[IP].id,
                "icmp_id"     : pkt[ICMP].id,
                "char"        : chr(char_byte),
                "byte"        : char_byte,
                "timestamp_us": timestamp_us,
                "payload_len" : len(raw_data),
            })

    # Ordenar por número de secuencia ICMP para garantizar el orden correcto
    found.sort(key=lambda p: p["seq"])
    return found


# ─── Programa principal ───────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        prog = sys.argv[0]
        print(f"\nUso    : python3 {prog} <captura.pcapng> [ip_destino]")
        print(f"Ejemplo: python3 {prog} captura.pcapng 127.0.0.1\n")
        sys.exit(1)

    pcap_path = sys.argv[1]
    target_ip = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"

    if not os.path.isfile(pcap_path):
        print(f"[!] No se encontró el archivo: {pcap_path!r}")
        sys.exit(1)

    # ── 1. Extraer paquetes ──────────────────────────────────────────────────
    sep = "═" * 68
    print(f"\n{sep}")
    print("  ICMP Covert Channel  ·  Decoder de Cifrado César")
    print(sep)
    print(f"  Archivo   : {pcap_path}")
    print(f"  Filtro    : ICMP Echo Request  →  {target_ip}")
    print(sep)

    records = extract_from_pcap(pcap_path, target_ip)

    if not records:
        print("\n[!] No se encontraron paquetes ICMP válidos en la captura.")
        print("    Verifica que el archivo sea el correcto y que la IP destino coincida.")
        sys.exit(1)

    encrypted = "".join(r["char"] for r in records)

    # ── 2. Mostrar tabla de extracción ──────────────────────────────────────
    print(f"\n  {'#':>3}  {'ICMP seq':>8}  {'IP ID':>7}  {'ICMP ID':>8}  "
          f"{'Byte':>6}  {'Char':>5}  Timestamp (µs)")
    print("  " + "─" * 64)
    for i, r in enumerate(records, start=1):
        ts_str = str(r["timestamp_us"]) if r["timestamp_us"] else "N/D"
        print(f"  {i:>3}  {r['seq']:>8}  0x{r['ip_id']:04X}  "
              f"0x{r['icmp_id']:04X}  "
              f"0x{r['byte']:02X}  "
              f"'{r['char']}'  {ts_str}")

    print(f"\n  Mensaje cifrado extraído : {BOLD}{encrypted}{RESET}")
    print(f"  Total de caracteres      : {len(encrypted)}\n")

    # ── 3. Calcular puntuaciones para los 26 desplazamientos ────────────────
    candidates = []
    for shift in range(26):
        plaintext = caesar_decrypt(encrypted, shift)
        score     = score_text(plaintext)
        all_alpha = all_printable_alpha(plaintext)
        candidates.append({
            "shift"    : shift,
            "plaintext": plaintext,
            "score"    : score,
            "all_alpha": all_alpha,
        })

    # La mejor opción: primero preferir texto 100% alfabético, luego mayor score
    best = max(
        candidates,
        key=lambda c: (int(c["all_alpha"]), c["score"])
    )

    # ── 4. Imprimir todas las combinaciones ─────────────────────────────────
    print(sep)
    print("  TODAS LAS COMBINACIONES DE DESCIFRADO CÉSAR  (k = 0 … 25)")
    print(sep)
    print(f"  {'Llave':>6}  │  {'Texto descifrado':<28}  │  {'Score':>9}  │  Nota")
    print("  " + "─" * 64)

    for c in candidates:
        shift     = c["shift"]
        plaintext = c["plaintext"]
        score     = c["score"]
        is_best   = (shift == best["shift"])
        alpha_tag = "solo letras" if c["all_alpha"] else ""

        if is_best:
            # Línea completa en verde y negrita
            line = (
                f"  k = {shift:>2}  │  {plaintext:<28}  │  {score:>9.2f}  │  "
                f"◄ MÁS PROBABLE  {alpha_tag}"
            )
            print(f"{GREEN}{BOLD}{line}{RESET}")
        else:
            dim_score = f"{DIM}{score:>9.2f}{RESET}"
            print(
                f"  k = {shift:>2}  │  {plaintext:<28}  │  {dim_score}  │  {alpha_tag}"
            )

    # ── 5. Resumen final ─────────────────────────────────────────────────────
    print("  " + "─" * 64)
    print()
    print(f"{GREEN}{BOLD}  ╔══════════════════════════════════════════════════════╗")
    print(f"  ║   RESULTADO MÁS PROBABLE                             ║")
    print(f"  ╠══════════════════════════════════════════════════════╣")
    print(f"  ║   Llave (k)       :  {best['shift']:<32} ║")
    print(f"  ║   Texto cifrado   :  {encrypted:<32} ║")
    print(f"  ║   Texto plano     :  {best['plaintext']:<32} ║")
    print(f"  ║   Score           :  {best['score']:<32.4f} ║")
    print(f"  ╚══════════════════════════════════════════════════════╝{RESET}")
    print()


if __name__ == "__main__":
    main()
