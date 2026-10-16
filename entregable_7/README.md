# Entregable 7: Ingesta de Datos Reales y Vector Robusto (NIDS Bio-Inspirado CUDA)

## 1. Visión General y Objetivos
Este entregable evoluciona el **Sistema Inteligente de Detección de Anomalías de Red (NIDS)** bio-inspirado basado en **Selección Negativa Artificial (AIS)** acelerado masivamente en **GPU mediante NVIDIA CUDA**, alcanzando grado de producción mediante:
1. **Expansión del Vector de Características (Feature Engineering)** de 4 a **7 dimensiones robustas**, capturando la física y semántica completa de los flujos de red.
2. **Eliminación de perfiles estáticos hardcodeados**: Implementación de un modelo **Data-Driven Self** que aprende dinámicamente los centroides y halos de tolerancia a partir de la línea base del servidor (`server_background_traffic.csv`).
3. **Censura Clonal Inmunocompetente en $\mathbb{R}^7$**: Generación aleatoria masiva de detectores Non-Self con eliminación de autorreactividad para erradicar falsos positivos.
4. **Evaluación Tri-Estado en Hardware GPU**: Clasificación de tráfico en tiempo real (`server_live_traffic.csv`) en **NORMAL (0)**, **CUARENTENA/SANDBOX (1)** y **BLOQUEO (2)**.
5. **Rigor Metodológico**: Control estricto de consistencia que aborta la ejecución si la línea base del servidor no está presente.

---

## 2. Relevancia Matemática y de Ciberseguridad del Vector Robusto (7D)

El hiperespacio se modela mediante el vector $\mathbf{x} \in \mathbb{R}^7$:

$$\mathbf{x} = \begin{bmatrix}
\text{puerto\_destino} \\
\text{tamano\_carga\_bytes} \\
\text{duracion\_conexion\_ms} \\
\text{peticiones\_por\_segundo} \\
\text{tasa\_bytes\_por\_segundo} \\
\text{conteo\_banderas\_tcp\_criticas} \\
\text{varianza\_tiempo\_llegada}
\end{bmatrix}$$

| Dimensión | Dominio | Relevancia en Ciberseguridad | Comportamiento Benigno (Self) | Comportamiento Malicioso (Ataque) |
|---|---|---|---|---|
| **1. Puerto Destino** | Discreto $[1, 65535]$ | Discrimina servicios bien conocidos (0-1023), registrados y efímeros/troyanos. | Concentrado en servicios autorizados (80, 443, 53, 8080). | Escaneo horizontal/vertical (Nmap SYN scan, puertos 22, 23, 4444). |
| **2. Tamaño Carga (B)** | Continuo $[0, 65535]$ | Cuantifica la densidad del payload. | Handshakes pequeños y respuestas HTTP balanceadas (500-1500 B). | Paquetes anómalos mínimos (40-64 B en floods) o masivos (> 4000 B en SQLi/Buffer Overflow). |
| **3. Duración Conexión (ms)** | Temporal $[1, \infty)$ | Mide la persistencia de la sesión TCP. | Sesiones proporcionales al servicio (100-1200 ms). | Efímeras en barridos (< 15 ms) o hiper-persistentes en Slowloris/Backdoors C2. |
| **4. Peticiones / Seg** | Frecuencia $[1, \infty)$ | Tasa instantánea de emisión; delata automatización volumétrica. | Cadencia humana moderada (1-20 req/s). | Picos masivos automatizados en DoS/DDoS (300-1000 req/s). |
| **5. Tasa Transferencia (B/s)** | Throughput $[0, \infty)$ | Relación física acoplada ($\text{Throughput} \approx \text{Payload} \times \text{Rate}$). | Consumo de ancho de banda proporcional al protocolo. | Exfiltración furtiva de datos o saturación por amplificación. |
| **6. Banderas TCP Críticas** | Protocolar $[0, 255]$ | Evalúa anomalías en máquinas de estados TCP (SYN / RST). | Máximo 1 SYN por sesión; RST solo en errores de socket. | Ráfagas de SYN sin ACK (SYN Flood) o tormentas RST para forzar teardowns. |
| **7. Varianza Llegada (Jitter ms)** | Temporal $[0, \infty)$ | Entropía del intervalo entre llegadas consecutivas ($IAT$). | Tráfico humano y orgánico: alta varianza (Poisson/Pareto con pausas naturales). | Tráfico por bots/scripts: varianza cuasi-nula (isocronía determinista de herramientas). |

---

## 3. Métrica Espacial y Geometría Inmune: Distancia Manhattan $L_1$ Calibrada

Para comparar vectores en $\mathbb{R}^7$, se implementa la métrica Manhattan ($L_1$), optimizada tanto en CPU como en los hilos de ejecución de la GPU (`__device__ distancia_l1_gpu`):

$$d_{L1\_calibrada}(\mathbf{p}, \mathbf{q}) = \sum_{i=1}^7 w_i |p_i - q_i|$$

### Calibración Dimensional
1. **Puerto de Red**: Al ser un identificador categórico de socket y no una magnitud lineal continua, una discrepancia de puerto entre servicios genera una penalización que evita que servicios con paquetes pequeños (como DNS port 53) absorban accidentalmente escaneos furtivos a SSH (port 22).
2. **Throughput (Bytes/seg)**: Se normaliza mediante escalamiento por potencia de dos ($/ 64$ o bit-shift `>> 6`), garantizando que la magnitud en bytes/s no domine destructivamente sobre las banderas TCP o la cadencia.
3. **Banderas Críticas (SYN/RST)**: Ponderación prioritaria ($w=5$), pues una sola bandera anómala en TCP es un síntoma de ataque de primer orden.

---

## 4. Pipeline de Aprendizaje y Clasificación Tri-Estado

```
[ server_background_traffic.csv ] (Línea Base Real)
               │
               ▼
   entrenar_perfil_self_csv()
   -> Computo de Centroides en R^7
               │
               ▼
[ Especies Self Benignas (Halo r_self = 120) ]
               │
               ▼
   Censura Clonal (Selección Negativa)
   -> 16,384 Linfocitos Candidatos generados
   -> Si dist(c, Self) <= (r_self + r_det) => Apoptosis (Eliminado)
               │
               ▼
[ Linfocitos Inmunocompetentes (Detectores Non-Self) ]
               │
               ▼  (cudaMemcpy HostToDevice)
   [ GPU VRAM: RTX 3060 Ti / CUDA Threads ]
               │
   evaluar_ecosistema_gpu<<<Bloques, 256>>>
               │
               ├─► dist <= r_det (100)               ──► ESTADO 2: BLOQUEO INMEDIATO (Anomalía)
               ├─► dist > r_det && dist_self <= r_self──► ESTADO 0: NORMAL (Permitido)
               └─► dist > r_det && dist_self > r_self ──► ESTADO 1: CUARENTENA / OBSERVACION (Zona Gris)
```

---

## 5. Instrucciones de Compilación y Ejecución

### Prerrequisitos
- Compilador NVIDIA CUDA (`nvcc` 12.0+)
- GPU NVIDIA con arquitectura compatible (ej. RTX 3060 Ti `sm_86`)

### Compilación con Makefile
```bash
cd entregable_7
make clean && make
```

### Ejecución
```bash
make run
```
O de forma manual:
```bash
./nids_entrenamiento_real [server_background_traffic.csv] [server_live_traffic.csv]
```

### Salidas Generadas
- **Consola**: Reporte tabulado de inspección dimensional en tiempo real.
- **`reporte_inspeccion.csv`**: Registro completo de auditoría forense con las 7 dimensiones y las decisiones operativas del NIDS.
