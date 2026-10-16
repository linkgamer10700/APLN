#!/usr/bin/env python3
"""
===============================================================================
NIDS BIO-INSPIRADO (AIS) - CAPA DE PERCEPCION Y EXTRACCION DE CARACTERISTICAS
ENTREGABLE 7: EXTRACTOR DE FLUJOS PCAP A VECTOR ROBUSTO EN R^7
===============================================================================

Este script procesa capturas de tráfico crudo (.pcap) generadas con tcpdump,
agrega los paquetes a nivel de sesión/flujo (IP origen, puerto origen, IP destino,
puerto destino) y calcula las 7 dimensiones requeridas por el NIDS en CUDA:

1. puerto_destino: Puerto del servicio objetivo.
2. tamano_carga_bytes: Promedio del tamaño de paquete IP (payload + headers).
3. duracion_conexion_ms: Tiempo entre primer y último paquete (mínimo 1 ms).
4. peticiones_por_segundo: Cantidad de paquetes dividida por duración en segundos.
5. tasa_bytes_por_segundo: Suma de bytes dividida por duración en segundos.
6. conteo_banderas_tcp_criticas: Ocurrencias de banderas SYN o RST en TCP.
7. varianza_tiempo_llegada: Varianza estadística de IAT (Inter-Arrival Time) en ms.
===============================================================================
"""

import sys
import os
import time
import csv
import statistics
from collections import defaultdict, Counter
from scapy.all import PcapReader, IP, IPv6, TCP, UDP


class FlowAccumulator:
    """Acumulador ligero para estadísticas de flujo/sesión en memoria."""
    __slots__ = (
        'sport', 'dport', 'proto', 'count', 'total_bytes',
        'first_time', 'last_time', 'flags_count', 'iats'
    )

    def __init__(self, sport: int, dport: int, proto: str, first_time: float, pkt_len: int, flags_count: int):
        self.sport = sport
        self.dport = dport
        self.proto = proto
        self.count = 1
        self.total_bytes = pkt_len
        self.first_time = first_time
        self.last_time = first_time
        self.flags_count = flags_count
        self.iats = []

    def update(self, pkt_time: float, pkt_len: int, flags_count: int):
        self.count += 1
        self.total_bytes += pkt_len
        iat_ms = (pkt_time - self.last_time) * 1000.0
        if iat_ms < 0:
            iat_ms = 0.0
        self.iats.append(iat_ms)
        self.last_time = pkt_time
        self.flags_count += flags_count


def resolver_servicio_cliente(sport: int, dport: int):
    """
    Determina cual es el puerto de servicio (servidor/escucha) y cual el del cliente.
    En Linux y estandares de red, los puertos efimeros de clientes dinamicos son >= 32768.
    Los servicios escuchan en puertos reservados y bien conocidos (< 32768).
    Si ambos son < 32768 o ambos >= 32768, el menor es el puerto del servicio.
    """
    es_sport_efimero = (sport >= 32768)
    es_dport_efimero = (dport >= 32768)

    if es_sport_efimero and not es_dport_efimero:
        return sport, dport  # sport=cliente, dport=servicio
    elif es_dport_efimero and not es_sport_efimero:
        return dport, sport  # dport=cliente (respuesta), sport=servicio
    else:
        if sport <= dport:
            return dport, sport  # dport=cliente, sport=servicio
        else:
            return sport, dport  # sport=cliente, sport=servicio


def extraer_flujos_pcap(pcap_path: str, output_csv: str):
    print("=" * 80)
    print("   NIDS FEATURE EXTRACTOR - INGESTA DE TRAFICO REAL (.PCAP -> CSV 7D)   ")
    print("=" * 80)
    print(f"[*] Archivo PCAP de entrada : {pcap_path}")
    print(f"[*] Archivo CSV de salida   : {output_csv}")

    if not os.path.exists(pcap_path):
        print(f"\n[!] ERROR CRITICO: No existe el archivo de captura: '{pcap_path}'")
        sys.exit(1)

    file_size_mb = os.path.getsize(pcap_path) / (1024 * 1024)
    print(f"[*] Tamaño del archivo PCAP : {file_size_mb:.2f} MB")
    print("[*] Iniciando lectura con Scapy PcapReader (Streaming en memoria)...")

    flows = {}
    total_pkts = 0
    valid_pkts = 0
    t0 = time.time()
    last_log_time = t0

    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                total_pkts += 1

                # 1. Filtro estricto: Solo TCP o UDP
                is_tcp = TCP in pkt
                is_udp = UDP in pkt
                if not (is_tcp or is_udp):
                    continue

                if is_tcp:
                    trans = pkt[TCP]
                    proto = "TCP"
                    # Conteo estricto de banderas críticas SYN (0x02) y RST (0x04)
                    flags_val = int(trans.flags)
                    flags_criticas = (1 if (flags_val & 0x02) else 0) + (1 if (flags_val & 0x04) else 0)
                else:
                    trans = pkt[UDP]
                    proto = "UDP"
                    flags_criticas = 0

                # 2. Extracción de capa IP (v4 o v6)
                if IP in pkt:
                    ip_layer = pkt[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    pkt_len = len(ip_layer)
                elif IPv6 in pkt:
                    ip_layer = pkt[IPv6]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    pkt_len = len(ip_layer)
                else:
                    continue

                sport = int(trans.sport)
                dport = int(trans.dport)
                pkt_time = float(pkt.time)
                valid_pkts += 1

                # Determinar puerto logico de cliente (p_orig) y servicio (p_dest)
                p_cliente, p_servicio = resolver_servicio_cliente(sport, dport)

                # Clave canonica de sesion bidireccional (asocia paquetes de ida y vuelta)
                ep1 = (src_ip, sport)
                ep2 = (dst_ip, dport)
                if ep1 <= ep2:
                    flow_key = (ep1, ep2, proto)
                else:
                    flow_key = (ep2, ep1, proto)

                if flow_key not in flows:
                    flows[flow_key] = FlowAccumulator(
                        sport=p_cliente,
                        dport=p_servicio,
                        proto=proto,
                        first_time=pkt_time,
                        pkt_len=pkt_len,
                        flags_count=flags_criticas
                    )
                else:
                    flows[flow_key].update(pkt_time, pkt_len, flags_criticas)

                # Reporte de progreso cada 25,000 paquetes o cada 5 segundos
                if total_pkts % 25000 == 0:
                    now = time.time()
                    elapsed = now - t0
                    pps = total_pkts / max(elapsed, 0.001)
                    print(f"    -> [{elapsed:6.1f}s] {total_pkts:8d} paquetes leídos | "
                          f"{valid_pkts:8d} válidos (TCP/UDP) | {len(flows):6d} flujos activos ({pps:.0f} pkt/s)")

    except KeyboardInterrupt:
        print("\n[!] Proceso interrumpido por el usuario. Generando CSV con los flujos acumulados...")
    except Exception as e:
        print(f"\n[!] Advertencia durante la lectura del PCAP: {e}")

    total_time = time.time() - t0
    print(f"\n[+] Lectura completada en {total_time:.2f} s ({total_pkts} paquetes analizados, {len(flows)} flujos detectados).")
    print(f"[*] Calculando vectores multidimensionales en R^7 y exportando a '{output_csv}'...")

    # 3. Exportación al CSV con cabecera exacta
    fieldnames = [
        "id", "puerto_origen", "puerto_destino", "tamano_carga_bytes",
        "duracion_conexion_ms", "peticiones_por_segundo", "tasa_bytes_por_segundo",
        "conteo_banderas_tcp_criticas", "varianza_tiempo_llegada"
    ]

    with open(output_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)

        # Priorizar servicios con mayor densidad de trafico para que entren primero a los centroides Self
        service_counts = Counter(f.dport for f in flows.values())
        sorted_flows = sorted(flows.values(), key=lambda f: (-service_counts[f.dport], f.dport, -f.count))

        session_id = 1
        for flow in sorted_flows:
            # Dim 1: puerto_destino (servicio legitimo protegido)
            p_dest = flow.dport
            p_orig = flow.sport

            # Dim 2: tamano_carga_bytes (Promedio de carga por paquete)
            tamano_carga = int(round(flow.total_bytes / max(flow.count, 1)))

            # Dim 3: duracion_conexion_ms (Mínimo 1 ms)
            if flow.count == 1:
                duracion_ms = 1.0
            else:
                duracion_ms = (flow.last_time - flow.first_time) * 1000.0
            duracion_ms = max(1.0, duracion_ms)
            duracion_ms_int = int(round(duracion_ms))

            # Duración en segundos para cálculo de frecuencias (mínimo 0.001 s)
            duracion_seg = max(duracion_ms / 1000.0, 0.001)

            # Dim 4: peticiones_por_segundo
            peticiones_por_segundo = int(round(flow.count / duracion_seg))

            # Dim 5: tasa_bytes_por_segundo
            tasa_bytes_por_segundo = int(round(flow.total_bytes / duracion_seg))

            # Dim 6: conteo_banderas_tcp_criticas
            conteo_banderas = int(flow.flags_count)

            # Dim 7: varianza_tiempo_llegada (Inter-Arrival Time en ms)
            if len(flow.iats) < 2:
                var_iat = 0.0
            else:
                try:
                    var_iat = statistics.variance(flow.iats)
                except Exception:
                    var_iat = 0.0
            # Acotar a rango seguro int32 [0, 1000000] para evitar overflow por sesiones inactivas
            varianza_tiempo_llegada = max(0, min(int(round(var_iat)), 1000000))

            writer.writerow([
                session_id,
                p_orig,
                p_dest,
                tamano_carga,
                duracion_ms_int,
                peticiones_por_segundo,
                tasa_bytes_por_segundo,
                conteo_banderas,
                varianza_tiempo_llegada
            ])
            session_id += 1

    csv_size_kb = os.path.getsize(output_csv) / 1024.0
    print(f"[+] Archivo '{output_csv}' sobreescrito exitosamente.")
    print(f"    -> Total de Sesiones / Vectores generados : {session_id - 1}")
    print(f"    -> Tamaño del CSV generado              : {csv_size_kb:.2f} KB")
    print("=" * 80)


if __name__ == "__main__":
    pcap_input = "../trafico_servidor_raw.pcap"
    csv_output = "server_background_traffic.csv"

    if len(sys.argv) >= 2:
        pcap_input = sys.argv[1]
    if len(sys.argv) >= 3:
        csv_output = sys.argv[2]

    extraer_flujos_pcap(pcap_input, csv_output)
