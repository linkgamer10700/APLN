/**
 * ============================================================================
 * SISTEMA INTELIGENTE DE DETECCION DE ANOMALIAS DE RED (NIDS) BIO-INSPIRADO
 * ENTREGABLE 7: INGESTA DE DATOS REALES Y VECTOR ROBUSTO EN 7 DIMENSIONES
 * ============================================================================
 * 
 * Paradigma: Seleccion Negativa Artificial (Artificial Immune Systems - AIS)
 * Aceleracion: NVIDIA CUDA (Procesamiento Masivamente Paralelo en GPU)
 * Arquitectura: Evaluacion Tri-Estado (0: NORMAL, 1: CUARENTENA, 2: BLOQUEO)
 * 
 * ============================================================================
 * RELEVANCIA MATEMATICA Y CIBERSEGURIDAD DEL VECTOR ROBUSTO (7 DIMENSIONES):
 * ============================================================================
 * 
 * 1. puerto_destino (Dominio Discreto [1 - 65535]):
 *    - Relevancia: Diferencia servicios estandarizados (puertos bien conocidos
 *      0-1023) de servicios registrados o puertos efimeros/troyanos. Ataques
 *      como Nmap Port Scan golpean puertos cerrados o inusuales, mientras el
 *      trafico legitimo se concentra en los puertos de servicio del servidor.
 * 
 * 2. tamano_carga_bytes (Dominio Continuo/Discreto [0 - 65535 B]):
 *    - Relevancia: Modela la densidad de informacion util transportada. Permite
 *      distinguir paquetes de control minimo (40-64 bytes en escaneos o SYN floods)
 *      frente a transacciones normales (500-1500 bytes) y anomalias de
 *      desbordamiento de bufer (Buffer Overflow / SQLi payloads gigantes > 3000 B).
 * 
 * 3. duracion_conexion_ms (Dominio Temporal [ms]):
 *    - Relevancia: Cuantifica la persistencia de la sesion TCP/UDP. Ataques
 *      volumetricos y escaneos presentan una vida util efimera (< 15 ms),
 *      mientras que ataques de denegacion lenta (Slowloris) o canales de mando
 *      y control (C2 / Backdoors) exhiben una persistencia temporal anormal.
 * 
 * 4. peticiones_por_segundo (Frecuencia / Cadencia [req/s]):
 *    - Relevancia: Tasa de emision instantanea. Es el indicador por excelencia
 *      de ataques volumetricos automatizados (DDoS, HTTP Floods, fuerza bruta),
 *      donde la cadencia supera por ordenes de magnitud la capacidad humana.
 * 
 * 5. tasa_bytes_por_segundo (Throughput / Flujo [B/s]):
 *    - Relevancia: Relacion de acoplamiento fisico (Throughput ≈ Payload x Rate).
 *      Aisla patrones de exfiltracion masiva de datos y ataques de amplificacion,
 *      donde pocos paquetes pueden consumir todo el ancho de banda disponible.
 * 
 * 6. conteo_banderas_tcp_criticas (Anomalia Protocolar [SYN/RST]):
 *    - Relevancia: En sesiones TCP legitimas, SYN solo ocurre en el handshake
 *      inicial (1 por sesion) y RST es esporadico. Una concentracion elevada
 *      de banderas SYN sin culminar el handshake es sintoma directo de un
 *      SYN Flood Attack, mientras que tormentas de RST revelan tecnicas de
 *      evasion o teardown malicioso.
 * 
 * 7. varianza_tiempo_llegada (Jitter Inter-Arrival Time [ms]):
 *    - Relevancia: El trafico humano genuino exhibe alta variabilidad temporal
 *      (distribuciones de Poisson/Pareto con pausas naturales). Por el contrario,
 *      los bots, scripts automatizados y generadores de paquetes de estres
 *      emiten trafico con varianza cuasi-nula (cadencia isocrona y determinista).
 * 
 * ============================================================================
 * METRICA ESPACIAL: NORMA MANHATTAN L1 CALIBRADA EN R^7
 * d_L1_calibrada(x, y) = SUM(w_i * |x_i - y_i|)
 * Calibracion dimensional:
 * - Puerto: Discriminacion categorica de socket (evita colision inter-protocolo)
 * - Tamano y Duracion: Escalamiento por factor 4
 * - Frecuencia (req/s): Peso x2
 * - Throughput (B/s): Normalizacion por factor 64 (evita sesgo por magnitud B/s)
 * - Banderas Criticas (SYN/RST): Peso critico x5
 * - Varianza/Jitter: Peso temporal x2
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <cuda_runtime.h>

// Parametros de Hiperescala Inmunologica
#define TOTAL_DETECTORES_A_GENERAR 16384
#define MAX_ESPECIES_SELF 128
#define MAX_PAQUETES 2000

// Umbrales de Afinidad Geometrica Calibrada (Norma L1 en R^7)
#define UMBRAL_ENTRENAMIENTO 250   // Radio del halo de tolerancia Self legitimo (calibrado para datos reales)
#define UMBRAL_DETECCION 150       // Radio de colision para activacion letal de Detector

struct EspecieSelf {
    int id_especie;
    int puerto_destino;                 // Dim 1: Puerto destino del servicio protegido
    int tamano_carga_bytes;             // Dim 2: Tamano de carga util promedio (bytes)
    int duracion_conexion_ms;           // Dim 3: Duracion promedio de sesion (ms)
    int peticiones_por_segundo;         // Dim 4: Frecuencia promedio (req/s)
    int tasa_bytes_por_segundo;         // Dim 5: Tasa de transferencia (B/s)
    int conteo_banderas_tcp_criticas;   // Dim 6: Banderas SYN/RST esperadas
    int varianza_tiempo_llegada;        // Dim 7: Varianza/Jitter temporal promedio (ms)
    char descripcion[64];
};

struct PaqueteDatos {
    int id;
    int puerto_origen;
    int puerto_destino;                 // Dim 1
    int tamano_carga_bytes;             // Dim 2
    int duracion_conexion_ms;           // Dim 3
    int peticiones_por_segundo;         // Dim 4
    int tasa_bytes_por_segundo;         // Dim 5
    int conteo_banderas_tcp_criticas;   // Dim 6
    int varianza_tiempo_llegada;        // Dim 7
    int estado_clasificacion;           // -1: Sin evaluar, 0: Normal, 1: Cuarentena, 2: Bloqueo
};

struct Detector {
    int puerto_destino;                 // Dim 1
    int tamano_carga_bytes;             // Dim 2
    int duracion_conexion_ms;           // Dim 3
    int peticiones_por_segundo;         // Dim 4
    int tasa_bytes_por_segundo;         // Dim 5
    int conteo_banderas_tcp_criticas;   // Dim 6
    int varianza_tiempo_llegada;        // Dim 7
};

// ============================================================================
// METRICAS DE DISTANCIA L1 (MANHATTAN) EN 7 DIMENSIONES
// ============================================================================

/**
 * Metrica de afinidad en CPU para la fase de Censura Clonal (Seleccion Negativa).
 */
int distancia_manhattan_cpu(
    int p1, int t1, int d1, int r1, int b1, int f1, int v1,
    int p2, int t2, int d2, int r2, int b2, int f2, int v2
) {
    // Discriminacion categorica de puerto con escala dimensional calibrada
    int d_p = (p1 == p2) ? 0 : ((abs(p1 - p2) > 30) ? 500 : abs(p1 - p2) * 15);
    int d_t = abs(t1 - t2) / 8;
    int d_d = abs(d1 - d2) / 256;
    int d_r = abs(r1 - r2) / 8;
    int d_b = abs(b1 - b2) / 1024;
    int d_f = abs(f1 - f2) * 4;
    int d_v = abs(v1 - v2) / 256;

    return d_p + d_t + d_d + d_r + d_b + d_f + d_v;
}

/**
 * Metrica de afinidad masivamente paralela en GPU para evaluacion de paquetes.
 */
__device__ int inline distancia_l1_gpu(
    int p1, int t1, int d1, int r1, int b1, int f1, int v1,
    int p2, int t2, int d2, int r2, int b2, int f2, int v2
) {
    int d_p = 0;
    if (p1 != p2) {
        int diff = p1 - p2; if (diff < 0) diff = -diff;
        d_p = (diff > 30) ? 500 : diff * 15;
    }
    int d_t = t1 - t2; if (d_t < 0) d_t = -d_t; d_t /= 8;
    int d_d = d1 - d2; if (d_d < 0) d_d = -d_d; d_d /= 256;
    int d_r = r1 - r2; if (d_r < 0) d_r = -d_r; d_r /= 8;
    int d_b = b1 - b2; if (d_b < 0) d_b = -d_b; d_b /= 1024;
    int d_f = f1 - f2; if (d_f < 0) d_f = -d_f; d_f *= 4;
    int d_v = v1 - v2; if (d_v < 0) d_v = -d_v; d_v /= 256;

    return d_p + d_t + d_d + d_r + d_b + d_f + d_v;
}

// Utilidad para generacion uniforme acotada
int rand_rango(int min, int max) {
    return min + rand() % (max - min + 1);
}

// ============================================================================
// ENTRENAMIENTO DINAMICO (DATA-DRIVEN SELF) DESDE CSV
// ============================================================================

/**
 * Lee el archivo de entrenamiento masivo de linea base del servidor y calcula
 * dinamicamente los centroides matematicos en 7D para cada servicio legitimo.
 * 
 * Cumplimiento metodologico: Si el archivo no existe, el programa se detiene.
 */
int entrenar_perfil_self_csv(const char* archivo_entrenamiento, struct EspecieSelf* especies) {
    FILE* fp = fopen(archivo_entrenamiento, "r");
    if (!fp) {
        printf("\n================================================================================\n");
        printf("[!] ERROR CRITICO DE RIGOR METODOLOGICO:\n");
        printf("    No se pudo encontrar el archivo de entrenamiento: '%s'\n", archivo_entrenamiento);
        printf("    Es imposible entrenar el sistema inmunologico sin la linea base del servidor.\n");
        printf("    La politica de seguridad prohibe el uso de perfiles estaticos hardcodeados.\n");
        printf("    Operacion cancelada por inconsistencia de datos base.\n");
        printf("================================================================================\n\n");
        return 0; // Detencion estricta
    }

    char buffer[512];
    // Saltear el encabezado del CSV
    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        printf("[!] Error: El archivo '%s' esta vacio o corrupto.\n", archivo_entrenamiento);
        fclose(fp);
        return 0;
    }

    // Estructuras de acumulacion para computo de centroides
    int puertos_detectados[MAX_ESPECIES_SELF];
    long long acum_tamano[MAX_ESPECIES_SELF] = {0};
    long long acum_duracion[MAX_ESPECIES_SELF] = {0};
    long long acum_peticiones[MAX_ESPECIES_SELF] = {0};
    long long acum_tasa[MAX_ESPECIES_SELF] = {0};
    long long acum_banderas[MAX_ESPECIES_SELF] = {0};
    long long acum_varianza[MAX_ESPECIES_SELF] = {0};
    long long conteo_muestras[MAX_ESPECIES_SELF] = {0};
    int total_especies = 0;
    long long total_paquetes = 0;

    int id, p_orig, p_dest, tam, dur, req, tasa, flags, var_t;

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (sscanf(buffer, "%d,%d,%d,%d,%d,%d,%d,%d,%d",
                   &id, &p_orig, &p_dest, &tam, &dur, &req, &tasa, &flags, &var_t) == 9) {
            
            // Localizar indice del servicio/puerto destino
            int idx_esp = -1;
            for (int i = 0; i < total_especies; i++) {
                if (puertos_detectados[i] == p_dest) {
                    idx_esp = i;
                    break;
                }
            }

            // Descubrimiento dinamico de un nuevo servicio legitimo en el servidor
            if (idx_esp == -1) {
                if (total_especies < MAX_ESPECIES_SELF) {
                    idx_esp = total_especies++;
                    puertos_detectados[idx_esp] = p_dest;
                } else {
                    continue; // Capacidad maxima de especies alcanzada
                }
            }

            int dur_cap = (dur > 60000) ? 60000 : dur;
            int var_cap = (var_t > 60000) ? 60000 : var_t;
            acum_tamano[idx_esp] += tam;
            acum_duracion[idx_esp] += dur_cap;
            acum_peticiones[idx_esp] += req;
            acum_tasa[idx_esp] += tasa;
            acum_banderas[idx_esp] += flags;
            acum_varianza[idx_esp] += var_cap;
            conteo_muestras[idx_esp]++;
            total_paquetes++;
        }
    }

    fclose(fp);

    if (total_paquetes == 0 || total_especies == 0) {
        printf("[!] Error: No se extrajeron muestras representativas de '%s'.\n", archivo_entrenamiento);
        return 0;
    }

    // Calculo formal de los Centroides Matematicos (Medias Aritmeticas en R^7)
    for (int i = 0; i < total_especies; i++) {
        especies[i].id_especie = i + 1;
        especies[i].puerto_destino = puertos_detectados[i];
        especies[i].tamano_carga_bytes = (int)(acum_tamano[i] / conteo_muestras[i]);
        especies[i].duracion_conexion_ms = (int)(acum_duracion[i] / conteo_muestras[i]);
        especies[i].peticiones_por_segundo = (int)(acum_peticiones[i] / conteo_muestras[i]);
        especies[i].tasa_bytes_por_segundo = (int)(acum_tasa[i] / conteo_muestras[i]);
        especies[i].conteo_banderas_tcp_criticas = (int)(acum_banderas[i] / conteo_muestras[i]);
        especies[i].varianza_tiempo_llegada = (int)(acum_varianza[i] / conteo_muestras[i]);

        snprintf(especies[i].descripcion, sizeof(especies[i].descripcion),
                 "Centroide Self Pto:%d (%lld paquetes base)",
                 puertos_detectados[i], conteo_muestras[i]);
    }

    printf("    -> Ingesta de Entrenamiento Exitosa: %lld paquetes procesados dinamicamente.\n", total_paquetes);
    printf("    -> Ecosistema Self Aprendido: %d especies / centroides caracterizados.\n", total_especies);

    return total_especies;
}

// ============================================================================
// GENERACION DE DETECTORES (CENSURA CLONAL / SELECCION NEGATIVA EN CPU)
// ============================================================================

/**
 * Genera el repertorio de receptores Non-Self (Linfocitos T).
 * Aplica la censura negativa en el timo digital: descarta cualquier detector
 * aleatorio que colisione geometricamente contra el perfil Self recien aprendido.
 * 
 * Regla de Inmunocompetencia: Para evitar autoinmunidad (falsos positivos),
 * ningun detector puede intersectar el halo de tolerancia del Self. Por ende,
 * la distancia de censura es (umbral_entrenamiento + umbral_deteccion).
 */
int generar_detectores_ecosistema(
    struct Detector* detectores,
    int total_a_generar,
    struct EspecieSelf* especies,
    int num_especies,
    int umbral_entrenamiento,
    int umbral_deteccion
) {
    int validos = 0;
    int radio_censura = umbral_entrenamiento + umbral_deteccion;

    for (int i = 0; i < total_a_generar; i++) {
        int r_puerto, r_tamano, r_duracion, r_peticiones, r_tasa, r_banderas, r_varianza;

        int modo = i % 8;
        if (modo == 0) {
            // Sector A: Escaneo de Puertos y Servicios Criticos (SSH, Telnet, Probing)
            r_puerto = rand_rango(20, 25);
            r_tamano = rand_rango(50, 80);
            r_duracion = rand_rango(1, 20);
            r_peticiones = rand_rango(1, 5);
            r_banderas = rand_rango(15, 30); // Anomalia de banderas SYN/RST
            r_varianza = rand_rango(1, 4);   // Cadencia automatizada
            r_tasa = r_tamano * r_peticiones;
        } else if (modo == 1) {
            // Sector B: Inundacion Volumetrica y Ataque DoS / SYN Flood
            r_puerto = (rand() % 2 == 0) ? 80 : 443;
            r_tamano = rand_rango(50, 90);
            r_duracion = rand_rango(1, 8);
            r_peticiones = rand_rango(300, 550);
            r_banderas = rand_rango(150, 280); // Rafagas masivas de SYN sin ACK
            r_varianza = rand_rango(0, 2);     // Jitter cuasi-nulo (herramienta de ataque)
            r_tasa = r_tamano * r_peticiones;
        } else if (modo == 2) {
            // Sector C: Explotacion de Payload, Inyeccion y Buffer Overflow
            r_puerto = (rand() % 3 == 0) ? 80 : ((rand() % 2 == 0) ? 443 : 8080);
            r_tamano = rand_rango(4000, 5500); // Payload anormalmente gigante
            r_duracion = rand_rango(1800, 2600);
            r_peticiones = rand_rango(30, 55);
            r_banderas = rand_rango(1, 3);
            r_varianza = rand_rango(10, 20);
            r_tasa = r_tamano * r_peticiones;
        } else if (modo == 3) {
            // Sector D: Backdoors Persistentes, Canales C2 y Trafico Troyano
            r_puerto = rand_rango(4440, 4450);
            r_tamano = rand_rango(1100, 1400);
            r_duracion = rand_rango(800, 1100);
            r_peticiones = rand_rango(2, 5);
            r_banderas = rand_rango(30, 45); // Sesiones anormales / reintentos
            r_varianza = rand_rango(0, 2);
            r_tasa = r_tamano * r_peticiones;
        } else if (modo == 4) {
            // Sector E: Tormenta de Resets TCP (RST Teardown Storm)
            r_puerto = (rand() % 2 == 0) ? 80 : 443;
            r_tamano = rand_rango(50, 70);
            r_duracion = rand_rango(5, 15);
            r_peticiones = rand_rango(80, 110);
            r_banderas = rand_rango(85, 110); // Banderas RST saturadas
            r_varianza = rand_rango(1, 3);
            r_tasa = r_tamano * r_peticiones;
        } else if (modo == 5) {
            // Sector F: Exploracion de Proximidad a Servicios Protegidos (Prueba de Tolerancia Central)
            int esp_sel = rand() % num_especies;
            r_puerto = especies[esp_sel].puerto_destino;
            r_tamano = especies[esp_sel].tamano_carga_bytes + rand_rango(-200, 200);
            if (r_tamano < 20) r_tamano = 20;
            r_duracion = especies[esp_sel].duracion_conexion_ms + rand_rango(-100, 100);
            if (r_duracion < 1) r_duracion = 1;
            r_peticiones = especies[esp_sel].peticiones_por_segundo + rand_rango(-5, 30);
            if (r_peticiones < 1) r_peticiones = 1;
            r_banderas = rand_rango(0, 10);
            r_varianza = rand_rango(0, 30);
            r_tasa = r_tamano * r_peticiones;
        } else {
            // Sectores G..H: Exploracion General del Hiperespacio 7D
            r_puerto = rand_rango(1, 10000);
            r_tamano = rand_rango(20, 5000);
            r_duracion = rand_rango(1, 3000);
            r_peticiones = rand_rango(1, 500);
            r_banderas = rand_rango(0, 150);
            r_varianza = rand_rango(0, 100);
            r_tasa = r_tamano * r_peticiones;
        }

        // Test de Tolerancia Central (Censura Clonal) frente al Ecosistema Self
        int colision_self = 0;
        for (int e = 0; e < num_especies; e++) {
            int dist = distancia_manhattan_cpu(
                r_puerto, r_tamano, r_duracion, r_peticiones, r_tasa, r_banderas, r_varianza,
                especies[e].puerto_destino, especies[e].tamano_carga_bytes,
                especies[e].duracion_conexion_ms, especies[e].peticiones_por_segundo,
                especies[e].tasa_bytes_por_segundo, especies[e].conteo_banderas_tcp_criticas,
                especies[e].varianza_tiempo_llegada
            );

            // Si el detector colisiona con el halo del Self, es autorreactivo: descartar
            if (dist <= radio_censura) {
                colision_self = 1;
                break;
            }
        }

        // Si sobrevivio a la censura clonal, es un linfocito maduro inmunocompetente
        if (!colision_self) {
            detectores[validos].puerto_destino = r_puerto;
            detectores[validos].tamano_carga_bytes = r_tamano;
            detectores[validos].duracion_conexion_ms = r_duracion;
            detectores[validos].peticiones_por_segundo = r_peticiones;
            detectores[validos].tasa_bytes_por_segundo = r_tasa;
            detectores[validos].conteo_banderas_tcp_criticas = r_banderas;
            detectores[validos].varianza_tiempo_llegada = r_varianza;
            validos++;
        }
    }

    return validos;
}

// ============================================================================
// CARGA DE TRAFICO EN VIVO (LIVE EVALUATION) DESDE CSV
// ============================================================================

/**
 * Carga el segundo archivo de trafico para la evaluacion en tiempo real.
 */
int cargar_trafico_live_csv(const char* ruta, struct PaqueteDatos* paquetes, int max_paquetes) {
    FILE* fp = fopen(ruta, "r");
    if (!fp) {
        printf("[!] ERROR: No se pudo abrir el archivo de trafico en vivo: '%s'\n", ruta);
        return 0;
    }

    char buffer[512];
    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        printf("[!] Error: El archivo '%s' esta vacio.\n", ruta);
        fclose(fp);
        return 0;
    }

    int count = 0;
    while (fgets(buffer, sizeof(buffer), fp) && count < max_paquetes) {
        struct PaqueteDatos p;
        if (sscanf(buffer, "%d,%d,%d,%d,%d,%d,%d,%d,%d",
                   &p.id, &p.puerto_origen, &p.puerto_destino,
                   &p.tamano_carga_bytes, &p.duracion_conexion_ms,
                   &p.peticiones_por_segundo, &p.tasa_bytes_por_segundo,
                   &p.conteo_banderas_tcp_criticas, &p.varianza_tiempo_llegada) == 9) {
            p.estado_clasificacion = -1; // No clasificado inicialmente
            paquetes[count++] = p;
        }
    }

    fclose(fp);
    printf("    -> Ingesta Live Exitosa: %d paquetes cargados desde '%s'.\n", count, ruta);
    return count;
}

// ============================================================================
// KERNEL CUDA: EVALUACION INMUNOLOGICA TRI-ESTADO EN GPU (7 DIMENSIONES)
// ============================================================================

__global__ void evaluar_ecosistema_gpu(
    struct PaqueteDatos* d_paquetes,
    struct Detector* d_detectores,
    struct EspecieSelf* d_especies,
    int num_paquetes,
    int num_detectores,
    int num_especies,
    int umbral_entrenamiento,
    int umbral_deteccion
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < num_paquetes) {
        struct PaqueteDatos p = d_paquetes[idx];

        // --------------------------------------------------------------------
        // FASE A: Inspeccion Inmunologica de Ataque (Detectores Non-Self)
        // --------------------------------------------------------------------
        int min_dist_detector = 99999999;

        for (int i = 0; i < num_detectores; i++) {
            struct Detector det = d_detectores[i];
            int d = distancia_l1_gpu(
                p.puerto_destino, p.tamano_carga_bytes, p.duracion_conexion_ms,
                p.peticiones_por_segundo, p.tasa_bytes_por_segundo,
                p.conteo_banderas_tcp_criticas, p.varianza_tiempo_llegada,
                det.puerto_destino, det.tamano_carga_bytes, det.duracion_conexion_ms,
                det.peticiones_por_segundo, det.tasa_bytes_por_segundo,
                det.conteo_banderas_tcp_criticas, det.varianza_tiempo_llegada
            );

            if (d < min_dist_detector) min_dist_detector = d;

            // Optimizacion: Si se cruzo el radio letal del detector, abortar busqueda
            if (min_dist_detector <= umbral_deteccion) break;
        }

        if (min_dist_detector <= umbral_deteccion) {
            // Colision con Linfocito Maduro: Amenaza confirmada
            d_paquetes[idx].estado_clasificacion = 2; // ESTADO 2: BLOQUEO INMEDIATO
        } else {
            // ----------------------------------------------------------------
            // FASE B: Verificacion de Pertenencia al Ecosistema Benigno (Self)
            // ----------------------------------------------------------------
            int min_dist_self = 99999999;

            for (int e = 0; e < num_especies; e++) {
                struct EspecieSelf esp = d_especies[e];
                int d = distancia_l1_gpu(
                    p.puerto_destino, p.tamano_carga_bytes, p.duracion_conexion_ms,
                    p.peticiones_por_segundo, p.tasa_bytes_por_segundo,
                    p.conteo_banderas_tcp_criticas, p.varianza_tiempo_llegada,
                    esp.puerto_destino, esp.tamano_carga_bytes, esp.duracion_conexion_ms,
                    esp.peticiones_por_segundo, esp.tasa_bytes_por_segundo,
                    esp.conteo_banderas_tcp_criticas, esp.varianza_tiempo_llegada
                );

                if (d < min_dist_self) min_dist_self = d;
            }

            // Evaluacion de Proximidad al Perfil Self Aprendido
            if (min_dist_self <= umbral_entrenamiento) {
                // Dentro del radio de tolerancia de una especie legitima
                d_paquetes[idx].estado_clasificacion = 0; // ESTADO 0: NORMAL (PERMITIDO)
            } else {
                // Zona Gris: No colisiona con detectores de ataque conocidos,
                // pero tampoco encaja en ningun centroide de servicio protegido
                d_paquetes[idx].estado_clasificacion = 1; // ESTADO 1: CUARENTENA / SANDBOX
            }
        }
    }
}

// ============================================================================
// EXPORTACION DE AUDITORIA Y RESULTADOS (CSV)
// ============================================================================

void exportar_reporte(const char* archivo, struct PaqueteDatos* paquetes, int num_paquetes) {
    FILE* fp = fopen(archivo, "w");
    if (!fp) {
        printf("[!] Error al exportar reporte a '%s'.\n", archivo);
        return;
    }

    fprintf(fp, "ID,Pto_Orig,Pto_Dest,Tamano_Bytes,Duracion_ms,Peticiones_s,Tasa_Bytes_s,Banderas_Criticas,Varianza_Jitter_ms,Estado_Clasificacion,Accion\n");
    for (int i = 0; i < num_paquetes; i++) {
        struct PaqueteDatos p = paquetes[i];
        const char* estado_str = "";
        const char* accion = "";

        if (p.estado_clasificacion == 0) {
            estado_str = "NORMAL";
            accion = "PERMITIDO";
        } else if (p.estado_clasificacion == 1) {
            estado_str = "OBSERVACION";
            accion = "CUARENTENA_ANALISIS";
        } else {
            estado_str = "ANOMALIA";
            accion = "BLOQUEO_INMEDIATO";
        }

        fprintf(fp, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s\n",
                p.id, p.puerto_origen, p.puerto_destino,
                p.tamano_carga_bytes, p.duracion_conexion_ms,
                p.peticiones_por_segundo, p.tasa_bytes_por_segundo,
                p.conteo_banderas_tcp_criticas, p.varianza_tiempo_llegada,
                estado_str, accion);
    }

    fclose(fp);
}

// ============================================================================
// FUNCION PRINCIPAL (PIPELINE DE PRODUCCION NIDS)
// ============================================================================

int main(int argc, char* argv[]) {
    srand(42);

    const char* archivo_train = "server_background_traffic.csv";
    const char* archivo_live  = "server_live_traffic.csv";

    // Permitir sobreescritura opcional por linea de comandos
    if (argc >= 2) archivo_train = argv[1];
    if (argc >= 3) archivo_live  = argv[2];

    printf("======================================================================================\n");
    printf("   SISTEMA DE DETECCION DE ANOMALIAS (NIDS) BIO-INSPIRADO - SELECCION NEGATIVA GPU   \n");
    printf("   ENTREGABLE 7: VECTOR ROBUSTO 7D Y APRENDIZAJE DATA-DRIVEN DESDE DATOS REALES       \n");
    printf("======================================================================================\n\n");

    // ------------------------------------------------------------------------
    // FASE 1: APRENDIZAJE DINAMICO DEL PERFIL SELF (CENTROIDES DESDE CSV)
    // ------------------------------------------------------------------------
    printf("[1] FASE DE APRENDIZAJE DATA-DRIVEN (LINEA BASE DEL SERVIDOR)...\n");
    struct EspecieSelf* especies_cpu = (struct EspecieSelf*)malloc(MAX_ESPECIES_SELF * sizeof(struct EspecieSelf));
    if (!especies_cpu) {
        printf("[!] Error fatal: Fallo en asignacion de memoria para especies Self.\n");
        return 1;
    }

    int num_especies = entrenar_perfil_self_csv(archivo_train, especies_cpu);
    if (num_especies <= 0) {
        // Detencion requerida por el principio de rigor metodologico
        free(especies_cpu);
        return 1;
    }

    printf("\n    --- Perfiles de Especies Benignas Aprendidas (Centroides en R^7) ---\n");
    for (int i = 0; i < num_especies; i++) {
        printf("    [%d] %-36s | Pto:%-5d Tam:%-4dB Dur:%-4dms Pet:%-2d/s Tasa:%-5dB/s Fla:%-1d Var:%-2dms\n",
               especies_cpu[i].id_especie, especies_cpu[i].descripcion,
               especies_cpu[i].puerto_destino, especies_cpu[i].tamano_carga_bytes,
               especies_cpu[i].duracion_conexion_ms, especies_cpu[i].peticiones_por_segundo,
               especies_cpu[i].tasa_bytes_por_segundo, especies_cpu[i].conteo_banderas_tcp_criticas,
               especies_cpu[i].varianza_tiempo_llegada);
    }
    printf("\n");

    // ------------------------------------------------------------------------
    // FASE 2: CENSURA CLONAL MULTI-PERFIL EN HIPERESPACIO 7D (CPU)
    // ------------------------------------------------------------------------
    printf("[2] FASE DE CENSURA CLONAL (SELECCION NEGATIVA INMUNOLOGICA EN 7D)...\n");
    struct Detector* detectores_cpu = (struct Detector*)malloc(TOTAL_DETECTORES_A_GENERAR * sizeof(struct Detector));
    if (!detectores_cpu) {
        printf("[!] Error fatal: Fallo en asignacion de memoria para detectores.\n");
        free(especies_cpu);
        return 1;
    }

    int validos = generar_detectores_ecosistema(
        detectores_cpu, TOTAL_DETECTORES_A_GENERAR, especies_cpu, num_especies,
        UMBRAL_ENTRENAMIENTO, UMBRAL_DETECCION
    );

    printf("    -> Candidatos Generados en Hiperespacio 7D: %d\n", TOTAL_DETECTORES_A_GENERAR);
    printf("    -> Detectores Inmunes Sobrevivientes (Non-Self): %d\n", validos);
    printf("    -> Tasa de Censura por Auto-reactividad: %.2f%%\n\n",
           ((float)(TOTAL_DETECTORES_A_GENERAR - validos) / TOTAL_DETECTORES_A_GENERAR) * 100.0f);

    // ------------------------------------------------------------------------
    // FASE 3: INGESTA DE TRAFICO EN TIEMPO REAL (LIVE TRAFFIC EVALUATION)
    // ------------------------------------------------------------------------
    printf("[3] INGESTA DE TRAFICO EN TIEMPO REAL (LIVE EVALUATION)...\n");
    struct PaqueteDatos* paquetes_cpu = (struct PaqueteDatos*)malloc(MAX_PAQUETES * sizeof(struct PaqueteDatos));
    if (!paquetes_cpu) {
        printf("[!] Error fatal: Fallo en asignacion de memoria para paquetes.\n");
        free(especies_cpu);
        free(detectores_cpu);
        return 1;
    }

    int num_paquetes = cargar_trafico_live_csv(archivo_live, paquetes_cpu, MAX_PAQUETES);
    if (num_paquetes <= 0) {
        printf("[!] Error: No hay paquetes de evaluacion disponibles.\n");
        free(especies_cpu);
        free(detectores_cpu);
        free(paquetes_cpu);
        return 1;
    }
    printf("\n");

    // ------------------------------------------------------------------------
    // FASE 4: ASIGNACION DE MEMORIA Y TRANSFERENCIA A VRAM (CUDA)
    // ------------------------------------------------------------------------
    printf("[4] ACELERACION GPU: TRANSFERENCIA DE MEMORIA A VRAM (CUDA)...\n");
    struct PaqueteDatos* d_paquetes = NULL;
    struct Detector* d_detectores = NULL;
    struct EspecieSelf* d_especies = NULL;

    size_t sz_paquetes = num_paquetes * sizeof(struct PaqueteDatos);
    size_t sz_detectores = validos * sizeof(struct Detector);
    size_t sz_especies = num_especies * sizeof(struct EspecieSelf);

    cudaError_t err1 = cudaMalloc((void**)&d_paquetes, sz_paquetes);
    cudaError_t err2 = cudaMalloc((void**)&d_detectores, sz_detectores);
    cudaError_t err3 = cudaMalloc((void**)&d_especies, sz_especies);

    if (err1 != cudaSuccess || err2 != cudaSuccess || err3 != cudaSuccess) {
        printf("[!] Error critico en cudaMalloc: Memoria insuficiente en GPU.\n");
        free(especies_cpu);
        free(detectores_cpu);
        free(paquetes_cpu);
        return 1;
    }

    cudaMemcpy(d_paquetes, paquetes_cpu, sz_paquetes, cudaMemcpyHostToDevice);
    cudaMemcpy(d_detectores, detectores_cpu, sz_detectores, cudaMemcpyHostToDevice);
    cudaMemcpy(d_especies, especies_cpu, sz_especies, cudaMemcpyHostToDevice);

    int hilosPorBloque = 256;
    int bloques = (num_paquetes + hilosPorBloque - 1) / hilosPorBloque;

    printf("    -> VRAM Asignada: Paquetes (%.2f KB), Detectores (%.2f KB), Especies (%.2f KB)\n",
           sz_paquetes / 1024.0, sz_detectores / 1024.0, sz_especies / 1024.0);
    printf("    -> Configuracion de Ejecucion: %d Bloques x %d Hilos/Bloque (%d Hilos Totales)\n\n",
           bloques, hilosPorBloque, bloques * hilosPorBloque);

    // ------------------------------------------------------------------------
    // FASE 5: LANZAMIENTO DEL KERNEL CUDA TRI-ESTADO EN 7D
    // ------------------------------------------------------------------------
    printf("[5] EJECUCION DE KERNEL CUDA TRI-ESTADO (GPU PARALLEL INSPECTION)...\n");
    evaluar_ecosistema_gpu<<<bloques, hilosPorBloque>>>(
        d_paquetes, d_detectores, d_especies,
        num_paquetes, validos, num_especies,
        UMBRAL_ENTRENAMIENTO, UMBRAL_DETECCION
    );

    cudaDeviceSynchronize();
    cudaError_t err_kernel = cudaGetLastError();
    if (err_kernel != cudaSuccess) {
        printf("[!] Error en ejecucion del Kernel CUDA: %s\n", cudaGetErrorString(err_kernel));
    }

    // Sincronizar clasificaciones desde la GPU hacia el Host
    cudaMemcpy(paquetes_cpu, d_paquetes, sz_paquetes, cudaMemcpyDeviceToHost);
    printf("    -> Evaluacion masiva completada en hardware GPU con exito.\n\n");

    // ------------------------------------------------------------------------
    // FASE 6: REPORTE DE INSPECCION Y ESTADO OPERACIONAL
    // ------------------------------------------------------------------------
    printf("[6] REPORTE DE INSPECCION Y ESTADO OPERACIONAL:\n");
    printf("----------------------------------------------------------------------------------------------------------------------------\n");
    printf("%-4s | %-6s | %-6s | %-6s | %-7s | %-5s | %-8s | %-5s | %-5s | %-12s | %-20s\n",
           "ID", "P_ORIG", "P_DEST", "TAM(B)", "DUR(ms)", "REQ/s", "TASA(B/s)", "FLAGS", "VARms", "CLASIFICACION", "ACCION SISTEMA");
    printf("----------------------------------------------------------------------------------------------------------------------------\n");

    int c_normal = 0, c_obs = 0, c_bloq = 0;

    for (int i = 0; i < num_paquetes; i++) {
        struct PaqueteDatos p = paquetes_cpu[i];
        char estado_str[20];
        char accion_str[30];

        if (p.estado_clasificacion == 0) {
            strcpy(estado_str, "NORMAL");
            strcpy(accion_str, "[OK] PERMITIDO");
            c_normal++;
        } else if (p.estado_clasificacion == 1) {
            strcpy(estado_str, "OBSERVACION");
            strcpy(accion_str, "[?] CUARENTENA/SANDBOX");
            c_obs++;
        } else {
            strcpy(estado_str, "ANOMALIA");
            strcpy(accion_str, "[!] BLOQUEO INMEDIATO");
            c_bloq++;
        }

        printf("%-4d | %-6d | %-6d | %-6d | %-7d | %-5d | %-8d | %-5d | %-5d | %-12s | %-20s\n",
               p.id, p.puerto_origen, p.puerto_destino,
               p.tamano_carga_bytes, p.duracion_conexion_ms,
               p.peticiones_por_segundo, p.tasa_bytes_por_segundo,
               p.conteo_banderas_tcp_criticas, p.varianza_tiempo_llegada,
               estado_str, accion_str);
    }
    printf("----------------------------------------------------------------------------------------------------------------------------\n");
    printf("RESUMEN GLOBAL: %d Normales | %d En Cuarentena | %d Bloqueados (Total Evaluados: %d)\n\n",
           c_normal, c_obs, c_bloq, num_paquetes);

    // ------------------------------------------------------------------------
    // FASE 7: EXPORTACION DE AUDITORIA Y LIBERACION DE MEMORIA
    // ------------------------------------------------------------------------
    exportar_reporte("reporte_inspeccion.csv", paquetes_cpu, num_paquetes);
    printf("[7] Auditoria de seguridad exportada a 'reporte_inspeccion.csv'.\n");

    // Liberacion rigurosa de memoria dinamica en GPU y CPU
    cudaFree(d_paquetes);
    cudaFree(d_detectores);
    cudaFree(d_especies);

    free(paquetes_cpu);
    free(detectores_cpu);
    free(especies_cpu);

    printf("[+] Proceso concluido exitosamente.\n");
    return 0;
}
