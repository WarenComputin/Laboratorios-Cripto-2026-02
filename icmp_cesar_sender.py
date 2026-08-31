#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       ICMP Covert Channel - Trabajo de Criptografía          ║
║       Canal encubierto vía ICMP Echo Request (tipo 8)        ║
╚══════════════════════════════════════════════════════════════╝

Uso:
    sudo python3 icmp_cesar_sender.py <palabra_cifrada> [ip] [intervalo_s]

Ejemplos:
    sudo python3 icmp_cesar_sender.py KHOOR
    sudo python3 icmp_cesar_sender.py KHOOR 127.0.0.1 1

Estructura del payload ICMP (56 bytes):
┌──────────┬───────┬──────────────────────────────────────────┐
│ Offset   │ Bytes │ Contenido                                 │
├──────────┼───────┼──────────────────────────────────────────┤
│ 0x00-0x02│   3   │ Carácter cifrado + padding [char,0x00,0x00]│
│ 0x03-0x07│   5   │ Bytes nulos [0x00 × 5]                   │
│ 0x08-0x0F│   8   │ Timestamp ICMP (µs, big-endian uint64)   │
│ 0x10-0x37│  40   │ Patrón fijo: 0x10, 0x11, …, 0x37        │
└──────────┴───────┴──────────────────────────────────────────┘
Total payload: 3 + 5 + 8 + 40 = 56 bytes

Filtros Wireshark:
    icmp && ip.dst == 127.0.0.1
    icmp.type == 8

Criterios demostrados:
    ✔ Tráfico a IP de loopback (127.0.0.1)
    ✔ Inyecta cifrado en tráfico ICMP (payload[0x00])
    ✔ Mantiene intervalo de 1 segundo entre paquetes
    ✔ Mantiene timestamp ICMP (offset 0x08, 8 bytes)
    ✔ Mantiene IP Identification coherente (incremental)
    ✔ Mantiene Sequence Number coherente (incremental)
    ✔ Mantiene ICMP Identification coherente (fijo por sesión)
    ✔ Mantiene payload (3 bytes) coherente en 0x00-0x02
    ✔ Mantiene payload (5 bytes 0x00) en 0x03-0x07
    ✔ Mantiene payload secuencial 0x10→0x37 en offset 0x10
    ✔ Checksum ICMP e IP calculados automáticamente (Scapy)

Dependencias:
    pip install scapy
    Requiere privilegios root (sudo) para enviar raw sockets.
"""

import sys
import time
import struct

try:
    from scapy.all import IP, ICMP, Raw, send, conf
except ImportError:
    print("[!] Scapy no está instalado.")
    print("    Instálalo con: pip install scapy")
    sys.exit(1)

conf.verb = 0   # Silenciar output de Scapy


# ─── Construcción del payload ────────────────────────────────────────────────

def build_payload(char_byte: int) -> bytes:
    """
    Construye el payload ICMP de 56 bytes con estructura fija.

    Estructura:
      [0x00-0x02]  3 bytes  → Carácter cifrado + 0x00 + 0x00
      [0x03-0x07]  5 bytes  → Bytes nulos (0x00 × 5)
      [0x08-0x0F]  8 bytes  → Timestamp en microsegundos (big-endian uint64)
      [0x10-0x37] 40 bytes  → Patrón fijo: 0x10, 0x11, …, 0x37
    """
    part_char    = bytes([char_byte & 0xFF, 0x00, 0x00])   # 3 bytes
    part_null    = bytes(5)                                  # 5 bytes (0x00 × 5)
    ts_us        = int(time.time() * 1_000_000) & 0xFFFFFFFFFFFFFFFF
    part_ts      = struct.pack(">Q", ts_us)                 # 8 bytes (timestamp)
    part_pattern = bytes(range(0x10, 0x38))                 # 40 bytes (0x10→0x37)

    payload = part_char + part_null + part_ts + part_pattern
    assert len(payload) == 56, f"[BUG] payload={len(payload)} bytes (esperado 56)"
    return payload


# ─── Envío de paquetes ───────────────────────────────────────────────────────

def send_word_icmp(
    word: str,
    target: str = "127.0.0.1",
    iface: str = "lo",
    interval: float = 1.0,
) -> None:
    """
    Envía un paquete ICMP Echo Request por cada carácter de `word`.
    Termina al enviar el último carácter.
    """
    ICMP_ID = 0x1337          # Identificador ICMP fijo para toda la sesión
    ip_id   = 0x4E20          # IP Identification inicial
    seq_num = 0               # Sequence Number ICMP inicial

    sep = "═" * 64
    print(f"\n{sep}")
    print("  ICMP Covert Channel  ·  Criptografía — Cifrado César")
    print(sep)
    print(f"  Destino   : {target}  (interfaz: {iface})")
    print(f"  Palabra   : {word!r}  →  {len(word)} paquetes a enviar")
    print(f"  Intervalo : {interval} s entre paquetes")
    print(f"  ICMP ID   : 0x{ICMP_ID:04X}  (constante en la sesión)")
    print(f"  Payload   : 56 bytes  (estructura fija)")
    print(sep)
    print(f"  Wireshark : icmp && ip.dst == {target}")
    print(f"{sep}\n")

    for idx, ch in enumerate(word, start=1):
        seq_num += 1
        ip_id    = (ip_id + 1) & 0xFFFF   # 16 bits, wraps 0xFFFF→0x0000

        char_byte = ord(ch)
        payload   = build_payload(char_byte)

        # ── Construir paquete: IP / ICMP / Datos ──────────────────────────
        pkt = (
            IP(dst=target, id=ip_id)
            / ICMP(type=8, code=0, id=ICMP_ID, seq=seq_num)
            / Raw(load=payload)
        )

        # Scapy recalcula checksums IP e ICMP automáticamente
        send(pkt, iface=iface, verbose=False)

        ts_str = time.strftime("%H:%M:%S")
        print(
            f"  [{ts_str}] pkt {idx:02d}/{len(word)}"
            f"  char='{ch}' (0x{char_byte:02X})"
            f"  IP_ID=0x{ip_id:04X}"
            f"  ICMP_seq={seq_num:04d}"
            f"  payload[0]=0x{char_byte:02X}"
        )

        # Esperar el intervalo solo entre paquetes (no después del último)
        if idx < len(word):
            time.sleep(interval)

    print(f"\n  [✔] Transmisión completada — {len(word)} paquetes enviados.\n")


# ─── Punto de entrada ────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        prog = sys.argv[0]
        print(f"Uso    : sudo python3 {prog} <palabra_cifrada> [ip] [intervalo_s]")
        print(f"Ejemplo: sudo python3 {prog} KHOOR 127.0.0.1 1\n")
        sys.exit(1)

    word     = sys.argv[1]
    target   = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    interval = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0

    if not word:
        print("[!] Error: la palabra cifrada no puede estar vacía.")
        sys.exit(1)

    send_word_icmp(word, target=target, interval=interval)


if __name__ == "__main__":
    main()
