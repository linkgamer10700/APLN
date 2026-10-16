import random
import csv

random.seed(42)

# 1. Generar server_background_traffic.csv (Línea base legítima)
with open('entregable_7/server_background_traffic.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow([
        "id", "puerto_origen", "puerto_destino", "tamano_carga_bytes",
        "duracion_conexion_ms", "peticiones_por_segundo", "tasa_bytes_por_segundo",
        "conteo_banderas_tcp_criticas", "varianza_tiempo_llegada"
    ])
    
    pkt_id = 1
    # 700 paquetes Web Legítimo (Pto 80)
    for _ in range(700):
        p_orig = random.randint(1024, 65535)
        p_dest = 80
        tam = random.randint(480, 520)
        dur = random.randint(110, 130)
        req = random.randint(13, 17)
        tasa = tam * req + random.randint(-100, 100)
        flags = random.choice([0, 1])
        var_t = random.randint(20, 30)
        writer.writerow([pkt_id, p_orig, p_dest, tam, dur, req, tasa, flags, var_t])
        pkt_id += 1

    # 400 paquetes DNS Legítimo (Pto 53)
    for _ in range(400):
        p_orig = random.randint(1024, 65535)
        p_dest = 53
        tam = random.randint(55, 65)
        dur = random.randint(4, 6)
        req = random.randint(2, 3)
        tasa = tam * req + random.randint(-10, 10)
        flags = 0
        var_t = random.randint(8, 12)
        writer.writerow([pkt_id, p_orig, p_dest, tam, dur, req, tasa, flags, var_t])
        pkt_id += 1

    # 400 paquetes API/REST Legítimo (Pto 8080)
    for _ in range(400):
        p_orig = random.randint(1024, 65535)
        p_dest = 8080
        tam = random.randint(1950, 2050)
        dur = random.randint(950, 1050)
        req = random.randint(2, 4)
        tasa = tam * req + random.randint(-150, 150)
        flags = random.choice([0, 1])
        var_t = random.randint(25, 35)
        writer.writerow([pkt_id, p_orig, p_dest, tam, dur, req, tasa, flags, var_t])
        pkt_id += 1

print("[+] Generado exitosamente: server_background_traffic.csv con 1500 paquetes base.")

# 2. Generar server_live_traffic.csv (Tráfico en vivo con mezcla Tri-Estado)
with open('entregable_7/server_live_traffic.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow([
        "id", "puerto_origen", "puerto_destino", "tamano_carga_bytes",
        "duracion_conexion_ms", "peticiones_por_segundo", "tasa_bytes_por_segundo",
        "conteo_banderas_tcp_criticas", "varianza_tiempo_llegada"
    ])
    
    live_packets = [
        # --- Tráfico Benigno / Self (Esperado: 0 - NORMAL) ---
        (101, 5501, 80, 502, 121, 15, 7530, 1, 26),
        (102, 5502, 80, 495, 118, 14, 6930, 0, 24),
        (103, 5503, 80, 510, 125, 16, 8160, 1, 28),
        (104, 5504, 53, 62, 5, 2, 124, 0, 10),
        (105, 5505, 53, 58, 4, 3, 174, 0, 9),
        (106, 5506, 8080, 1990, 1010, 3, 5970, 0, 29),
        (107, 5507, 8080, 2015, 995, 3, 6045, 1, 31),
        
        # --- Tráfico No Catalogado / Atípico (Esperado: 1 - CUARENTENA) ---
        (201, 8001, 3000, 800, 400, 8, 6400, 1, 30),     # Microservicio interno nuevo
        (202, 8002, 3306, 350, 600, 4, 1400, 0, 25),     # Monitoreo DB atípico
        (203, 8003, 80, 1100, 350, 8, 8800, 1, 45),      # Web payload no habitual
        (204, 8004, 8443, 600, 200, 5, 3000, 1, 35),     # HTTPS alternativo no clasificado
        
        # --- Anomalías y Ciberataques (Esperado: 2 - BLOQUEO) ---
        (301, 9001, 22, 64, 12, 2, 128, 18, 2),          # SSH Brute/Scan (SYN+RST ráfagas)
        (302, 9002, 80, 60, 4, 350, 21000, 180, 1),       # SYN Flood Masivo (Llegada determinista)
        (303, 9003, 8080, 4800, 2200, 45, 216000, 2, 15), # Buffer Overflow / Injection
        (304, 9004, 4444, 1200, 900, 3, 3600, 35, 1),    # Metasploit C2 Reverse Shell
        (305, 9005, 80, 54, 10, 95, 5130, 95, 2),        # TCP RST Teardown storm
        (306, 9006, 23, 70, 8, 3, 210, 22, 2),           # Telnet Reconnaissance Scan
        (307, 9007, 80, 80, 3, 500, 40000, 250, 0),       # High-Rate DoS Flood
    ]
    
    for pkt in live_packets:
        writer.writerow(pkt)

print("[+] Generado exitosamente: server_live_traffic.csv con 18 paquetes evaluables.")
