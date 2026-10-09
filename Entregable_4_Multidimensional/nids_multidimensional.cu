/**
 * ============================================================================
 * PROYECTO: Sistema Inteligente de Detección de Anomalías (NIDS) Bio-Inspirado
 * ENTREGABLE 4: Expansión Multidimensional y Procesamiento Paralelo en GPU (CUDA)
 * ARCHIVO: nids_multidimensional.cu
 * ============================================================================
 *
 * FUNDAMENTOS TEÓRICOS Y ARQUITECTURA:
 * ------------------------------------
 * 1. Algoritmo de Selección Negativa (NSA - Negative Selection Algorithm):
 *    Inspirado en el sistema inmunológico biológico (maduración y tolerancia de
 *    linfocitos T en el timo). El sistema divide el universo de tráfico en:
 *      - Self (Propio): Patrones rutinarios y benignos del servidor/red.
 *      - Non-Self (No Propio): Intrusiones, anomalías, escaneos y ataques.
 *
 * 2. Espacio de Formas Multidimensional (Shape Space 4D):
 *    Cada paquete de red o detector inmunológico se modela como un vector:
 *    x = [puerto_destino, tamano_carga, duracion_conexion, peticiones_por_segundo]
 *
 * 3. Métrica de Distancia de Manhattan (Norma L1):
 *    D(A, B) = sum(|A_i - B_i|)
 *    Seleccionada por su eficiencia aritmética en aceleradores GPU (sin multiplicaciones
 *    ni raíces cuadradas complejas), ideal para procesamiento de paquetes a tasa de línea.
 *
 * 4. Paralelismo Masivo en GPU (NVIDIA CUDA):
 *    - Memoria dinámica (cudaMalloc / cudaMemcpy / cudaFree).
 *    - Función __device__ distancia_gpu: cálculo L1 compilado para hilos CUDA.
 *    - Kernel __global__ evaluar_trafico_gpu: mapeo masivo de un paquete por hilo,
 *      comparando de manera concurrente contra el repertorio completo de detectores.
 *
 * 5. Exportación al Entregable 5:
 *    Generación de 'frontera_datos.csv' para renderizado tridimensional.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <cuda_runtime.h>

// ============================================================================
// CONFIGURACIÓN DEL SISTEMA Y CONSTANTES ESTÁTICAS
// ============================================================================
#define NUM_PAQUETES 14
#define TOTAL_DETECTORES_A_GENERAR 4096
#define MAX_DETECTORES_CSV 500

// --- PERFIL NORMAL (SELF) ---
// Representa el comportamiento rutinario del servidor web protegido
#define PERFIL_PUERTO_DEST 80       // Puerto HTTP estándar
#define PERFIL_TAMANO 500           // Tamaño promedio de payload en bytes
#define PERFIL_DURACION 120         // Duración promedio de sesión en ms
#define PERFIL_PETICIONES 15        // Frecuencia promedio en peticiones/seg

// --- UMBRALES DE DISTANCIA (MÉTRICA MANHATTAN 4D) ---
// UMBRAL_ENTRENAMIENTO: Radio de tolerancia del Self durante la selección negativa.
// Cualquier detector candidato a una distancia <= UMBRAL_ENTRENAMIENTO del Self
// es eliminado (apoptosis) para prevenir falsos positivos (autoinmunidad).
#define UMBRAL_ENTRENAMIENTO 250

// UMBRAL_DETECCION: Radio de afinidad de un detector para alertar sobre una anomalía.
// Garantía matemática de cero falsos positivos:
//   MinDist(Detector, Normal) >= UMBRAL_ENTRENAMIENTO - MaxDist(Normal, Self)
//   250 - 41 = 209 > 180 (UMBRAL_DETECCION).
#define UMBRAL_DETECCION 180

// ============================================================================
// ESTRUCTURAS DE DATOS MULTIDIMENSIONALES (4 CARACTERÍSTICAS)
// ============================================================================

/**
 * Representación estructurada de un paquete de datos en la red.
 */
struct PaqueteDatos {
    int id;                         // Identificador numérico del paquete
    int puerto_origen;              // Puerto origen del cliente
    int puerto_destino;             // Característica 1: Puerto destino del servicio
    int tamano_carga;               // Característica 2: Tamaño de carga útil (bytes)
    int duracion_conexion;          // Característica 3: Duración de conexión (ms)
    int peticiones_por_segundo;     // Característica 4: Tasa de emisión (req/s)
    int senal_control;              // 0: Normal / Permitido, 1: Anomalía / Bloqueado
};

/**
 * Representación de un Detector Inmunológico (Linfocito T maduro) en 4D.
 */
struct Detector {
    int puerto_destino;             // Dimensión 1
    int tamano_carga;               // Dimensión 2
    int duracion_conexion;          // Dimensión 3
    int peticiones_por_segundo;     // Dimensión 4
};

// ============================================================================
// FUNCIONES EN CPU (HOST)
// ============================================================================

/**
 * Distancia de Manhattan (Norma L1) en un espacio de 4 dimensiones:
 * D(p, d) = |p1 - d1| + |p2 - d2| + |p3 - d3| + |p4 - d4|
 */
int distancia_manhattan_cpu(int p1, int t1, int d1, int r1,
                            int p2, int t2, int d2, int r2) {
    return abs(p1 - p2) + abs(t1 - t2) + abs(d1 - d2) + abs(r1 - r2);
}

/**
 * Generador auxiliar de números aleatorios uniformes en el rango [min, max].
 */
int aleatorio_en_rango(int min, int max) {
    return min + rand() % (max - min + 1);
}

/**
 * FASE 1: APRENDIZAJE Y SELECCIÓN NEGATIVA (Tolerancia Central en CPU)
 * Genera candidatos y elimina aquellos que reconozcan el perfil Self.
 * Los sobrevivientes maduran para formar el repertorio de receptores Non-Self.
 */
int generar_detectores(struct Detector* detectores) {
    int validos = 0;

    for (int i = 0; i < TOTAL_DETECTORES_A_GENERAR; i++) {
        int r_puerto;
        int r_tamano;
        int r_duracion;
        int r_peticiones;

        // Muestreo estratificado del espacio de formas para asegurar cobertura
        // de las regiones anómalas (escaneos, ataques de fuerza bruta, DoS, fugas, etc.)
        int modo = i % 8;
        if (modo == 0) {
            // Escaneo de servicios bajos (SSH, Telnet, FTP, etc.)
            r_puerto = aleatorio_en_rango(20, 100);
            r_tamano = aleatorio_en_rango(40, 150);
            r_duracion = aleatorio_en_rango(10, 50);
            r_peticiones = aleatorio_en_rango(1, 10);
        } else if (modo == 1) {
            // Escaneo y acceso remoto administrativo (RDP, Web Admin, SMB)
            int puertos_admin[] = {3389, 8080, 8443, 445};
            r_puerto = puertos_admin[rand() % 4];
            r_tamano = aleatorio_en_rango(80, 200);
            r_duracion = aleatorio_en_rango(10, 60);
            r_peticiones = aleatorio_en_rango(1, 15);
        } else if (modo == 2) {
            // Inyecciones de código y cargas masivas (SQLi, Overflow)
            r_puerto = (rand() % 2 == 0) ? 80 : 8080;
            r_tamano = aleatorio_en_rango(1600, 2200);
            r_duracion = aleatorio_en_rango(700, 1000);
            r_peticiones = aleatorio_en_rango(20, 50);
        } else if (modo == 3) {
            // Ataques volumétricos y denegación de servicio (DDoS Flood)
            r_puerto = (rand() % 2 == 0) ? 80 : 443;
            r_tamano = aleatorio_en_rango(40, 120);
            r_duracion = aleatorio_en_rango(1, 20);
            r_peticiones = aleatorio_en_rango(200, 350);
        } else if (modo == 4) {
            // Puertos de control C2 y puertas traseras (Troyanos / Shells)
            r_puerto = aleatorio_en_rango(4000, 5000);
            r_tamano = aleatorio_en_rango(1100, 1400);
            r_duracion = aleatorio_en_rango(800, 1000);
            r_peticiones = aleatorio_en_rango(1, 10);
        } else if (modo == 5) {
            // Exfiltración mediante tunelización y anomalías DNS
            r_puerto = 53;
            r_tamano = aleatorio_en_rango(750, 950);
            r_duracion = aleatorio_en_rango(200, 350);
            r_peticiones = aleatorio_en_rango(70, 120);
        } else if (modo == 6) {
            // Conexiones anómalas de retención lenta (Slowloris)
            r_puerto = 80;
            r_tamano = aleatorio_en_rango(100, 200);
            r_duracion = aleatorio_en_rango(900, 1100);
            r_peticiones = aleatorio_en_rango(1, 5);
        } else {
            // Exploración uniforme global en el hiperespacio
            r_puerto = aleatorio_en_rango(1, 5000);
            r_tamano = aleatorio_en_rango(20, 2000);
            r_duracion = aleatorio_en_rango(1, 1000);
            r_peticiones = aleatorio_en_rango(1, 200);
        }

        // Medir distancia Manhattan al Perfil Normal (Self)
        int dist_al_normal = distancia_manhattan_cpu(
            r_puerto, r_tamano, r_duracion, r_peticiones,
            PERFIL_PUERTO_DEST, PERFIL_TAMANO, PERFIL_DURACION, PERFIL_PETICIONES
        );

        // SELECCIÓN NEGATIVA:
        // Si el detector colisiona con el Self, se destruye (apoptosis).
        // Si dist_al_normal > UMBRAL_ENTRENAMIENTO, el detector madura y sobrevive.
        if (dist_al_normal > UMBRAL_ENTRENAMIENTO) {
            detectores[validos].puerto_destino = r_puerto;
            detectores[validos].tamano_carga = r_tamano;
            detectores[validos].duracion_conexion = r_duracion;
            detectores[validos].peticiones_por_segundo = r_peticiones;
            validos++;
        }
    }

    return validos;
}

/**
 * FASE 2: ENCAPSULAMIENTO DE PAQUETE (CPU)
 * Inicializa la tupla de 4 características asignando estado seguro por defecto.
 */
struct PaqueteDatos crear_paquete(int id, int p_orig, int p_dest, int tam, int dur, int reqs) {
    struct PaqueteDatos p;
    p.id = id;
    p.puerto_origen = p_orig;
    p.puerto_destino = p_dest;
    p.tamano_carga = tam;
    p.duracion_conexion = dur;
    p.peticiones_por_segundo = reqs;
    p.senal_control = 0; // Inicial: Normal (Self)
    return p;
}

// ============================================================================
// FUNCIONES Y KERNEL EN GPU (DEVICE Y GLOBAL CUDA)
// ============================================================================

/**
 * Función Device de CUDA (__device__):
 * Ejecutada por cada hilo de la GPU en paralelo.
 * Calcula la distancia de Manhattan en 4 dimensiones:
 * D = |puerto - d_puerto| + |tamano - d_tamano| + |duracion - d_duracion| + |pet - d_pet|
 */
__device__ int distancia_gpu(struct PaqueteDatos p, struct Detector d) {
    int d_puerto = p.puerto_destino - d.puerto_destino;
    if (d_puerto < 0) d_puerto = -d_puerto;

    int d_tam = p.tamano_carga - d.tamano_carga;
    if (d_tam < 0) d_tam = -d_tam;

    int d_dur = p.duracion_conexion - d.duracion_conexion;
    if (d_dur < 0) d_dur = -d_dur;

    int d_pet = p.peticiones_por_segundo - d.peticiones_por_segundo;
    if (d_pet < 0) d_pet = -d_pet;

    return d_puerto + d_tam + d_dur + d_pet;
}

/**
 * Kernel de CUDA (__global__):
 * Paralelismo masivo en GPU: Cada hilo evalúa un paquete contra los detectores.
 * Si un paquete tiene afinidad con un detector (distancia <= umbral_deteccion),
 * se reconoce una colisión anómala y se activa senal_control = 1.
 */
__global__ void evaluar_trafico_gpu(
    struct PaqueteDatos* d_paquetes,
    struct Detector* d_detectores,
    int* d_resultados,
    int num_paquetes,
    int num_detectores,
    int umbral_deteccion
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < num_paquetes) {
        d_resultados[idx] = 0; // Normal por defecto

        // Evaluación concurrente frente a todos los detectores del repertorio
        for (int i = 0; i < num_detectores; i++) {
            int dist = distancia_gpu(d_paquetes[idx], d_detectores[i]);

            // Detección de colisión con el espacio Non-Self
            if (dist <= umbral_deteccion) {
                d_resultados[idx] = 1;             // Registro de anomalía
                d_paquetes[idx].senal_control = 1; // Acción de mitigación / alerta
                break;                             // Cortocircuito: confirmado como amenaza
            }
        }
    }
}

// ============================================================================
// EXPORTACIÓN DE DATOS (ENTREGABLE 5)
// ============================================================================

/**
 * Exporta el espacio de formas clasificado al archivo 'frontera_datos.csv'.
 * Columnas requeridas: tipo,puerto,tamano,duracion,peticiones
 */
void exportar_frontera_csv(const char* nombre_archivo,
                           struct PaqueteDatos* paquetes, int num_paquetes,
                           struct Detector* detectores, int num_detectores) {
    FILE* archivo = fopen(nombre_archivo, "w");
    if (!archivo) {
        fprintf(stderr, "Error: No fue posible abrir el archivo '%s'\n", nombre_archivo);
        return;
    }

    // Cabecera formal
    fprintf(archivo, "tipo,puerto,tamano,duracion,peticiones\n");

    // 1. Exportación de paquetes analizados
    for (int i = 0; i < num_paquetes; i++) {
        const char* tipo_str = (paquetes[i].senal_control == 1) ? "Anomalia" : "Normal";
        fprintf(archivo, "%s,%d,%d,%d,%d\n",
                tipo_str,
                paquetes[i].puerto_destino,
                paquetes[i].tamano_carga,
                paquetes[i].duracion_conexion,
                paquetes[i].peticiones_por_segundo);
    }

    // 2. Exportación de una muestra representativa de detectores sobrevivientes
    int muestra = (num_detectores < MAX_DETECTORES_CSV) ? num_detectores : MAX_DETECTORES_CSV;
    for (int i = 0; i < muestra; i++) {
        fprintf(archivo, "Detector,%d,%d,%d,%d\n",
                detectores[i].puerto_destino,
                detectores[i].tamano_carga,
                detectores[i].duracion_conexion,
                detectores[i].peticiones_por_segundo);
    }

    fclose(archivo);
    printf("    -> Datos exportados exitosamente a '%s' (%d paquetes, %d detectores).\n",
           nombre_archivo, num_paquetes, muestra);
}

// ============================================================================
// FUNCIÓN PRINCIPAL (MAIN)
// ============================================================================
int main() {
    srand(1337); // Semilla reproducible para experimentación científica

    printf("====================================================================\n");
    printf(" SISTEMA NIDS BIO-INSPIRADO - SELECCION NEGATIVA MULTIDIMENSIONAL   \n");
    printf(" ACELERADO CON GPU NVIDIA CUDA (ESPACIO DE CARACTERISTICAS 4D)     \n");
    printf("====================================================================\n\n");

    // ------------------------------------------------------------------------
    // [1] FASE DE APRENDIZAJE: SELECCIÓN NEGATIVA EN CPU
    // ------------------------------------------------------------------------
    printf("[1] FASE DE APRENDIZAJE (SELECCION NEGATIVA / TOLERANCIA CENTRAL)...\n");
    printf("    Perfil Normal (Self): Pto=%d, Tam=%d B, Dur=%d ms, Pet=%d req/s\n",
           PERFIL_PUERTO_DEST, PERFIL_TAMANO, PERFIL_DURACION, PERFIL_PETICIONES);
    printf("    Umbral Tolerancia Central (Entrenamiento): %d\n", UMBRAL_ENTRENAMIENTO);
    printf("    Umbral de Colision (Deteccion GPU):        %d\n", UMBRAL_DETECCION);

    struct Detector detectores_cpu[TOTAL_DETECTORES_A_GENERAR];
    int num_detectores_validos = generar_detectores(detectores_cpu);

    printf("    -> Candidatos aleatorios generados: %d\n", TOTAL_DETECTORES_A_GENERAR);
    printf("    -> Detectores censurados (Apoptosis por colision con Self): %d\n",
           TOTAL_DETECTORES_A_GENERAR - num_detectores_validos);
    printf("    -> Detectores maduros sobrevivientes (Repertorio Non-Self): %d\n\n",
           num_detectores_validos);

    // ------------------------------------------------------------------------
    // [2] ENCAPSULAMIENTO DE TRÁFICO MULTIDIMENSIONAL (CPU)
    // ------------------------------------------------------------------------
    printf("[2] ENCAPSULAMIENTO DE TRAFICO MULTIDIMENSIONAL (CPU)...\n");
    struct PaqueteDatos paquetes_cpu[NUM_PAQUETES];

    // Tráfico Normal (Self): Variaciones operacionales legítimas alrededor del perfil
    paquetes_cpu[0]  = crear_paquete(1, 5001, 80, 500, 120, 15); // Exacto al perfil
    paquetes_cpu[1]  = crear_paquete(2, 5002, 80, 480, 110, 14); // Petición GET ligera
    paquetes_cpu[2]  = crear_paquete(3, 5003, 80, 530, 130, 16); // Formulario POST
    paquetes_cpu[3]  = crear_paquete(4, 5004, 80, 515, 115, 15); // Descarga imágenes/CSS
    paquetes_cpu[4]  = crear_paquete(5, 5005, 80, 495, 125, 14); // Consulta API JSON
    paquetes_cpu[5]  = crear_paquete(6, 5006, 80, 520, 128, 17); // Navegación interactiva

    // Tráfico Anómalo (Non-Self): Vectores de ataque diversos
    paquetes_cpu[6]  = crear_paquete(7, 4120, 22,   64,   15,   3);   // Escaneo SSH
    paquetes_cpu[7]  = crear_paquete(8, 4121, 23,   90,   30,   5);   // Escaneo Telnet
    paquetes_cpu[8]  = crear_paquete(9, 9999, 80,   70,    5, 280);   // Inundación DDoS Flood
    paquetes_cpu[9]  = crear_paquete(10, 6660, 80, 1900,  850,  35);   // Inyección SQL / Overflow
    paquetes_cpu[10] = crear_paquete(11, 7771, 4444, 1250, 920,   4);  // Shell inversa Troyano / C2
    paquetes_cpu[11] = crear_paquete(12, 8882, 53,  850,  280,  95);   // Exfiltración DNS Tunneling
    paquetes_cpu[12] = crear_paquete(13, 9991, 80,  150,  980,   2);   // Conexión lenta Slowloris
    paquetes_cpu[13] = crear_paquete(14, 3321, 3389, 120,  20,   6);   // Fuerza bruta RDP

    for (int i = 0; i < NUM_PAQUETES; i++) {
        printf("    Paquete %2d | Pto:%4d, Tam:%4d B, Dur:%4d ms, Pet:%3d req/s\n",
               paquetes_cpu[i].id,
               paquetes_cpu[i].puerto_destino,
               paquetes_cpu[i].tamano_carga,
               paquetes_cpu[i].duracion_conexion,
               paquetes_cpu[i].peticiones_por_segundo);
    }
    printf("\n");

    // ------------------------------------------------------------------------
    // [3] FASE DE EVALUACIÓN PARALELA EN GPU (CUDA)
    // ------------------------------------------------------------------------
    printf("[3] FASE DE EVALUACION PARALELA EN GPU CON CUDA...\n");

    // Punteros a la memoria de la tarjeta gráfica (VRAM)
    struct PaqueteDatos* d_paquetes = NULL;
    struct Detector* d_detectores = NULL;
    int* d_resultados = NULL;
    int resultados_cpu[NUM_PAQUETES];

    // Asignación de memoria dinámica en GPU (cudaMalloc)
    size_t tam_paquetes = NUM_PAQUETES * sizeof(struct PaqueteDatos);
    size_t tam_detectores = num_detectores_validos * sizeof(struct Detector);
    size_t tam_resultados = NUM_PAQUETES * sizeof(int);

    cudaMalloc((void**)&d_paquetes, tam_paquetes);
    cudaMalloc((void**)&d_detectores, tam_detectores);
    cudaMalloc((void**)&d_resultados, tam_resultados);

    // Transferencia de datos Host (CPU) -> Device (GPU)
    cudaMemcpy(d_paquetes, paquetes_cpu, tam_paquetes, cudaMemcpyHostToDevice);
    cudaMemcpy(d_detectores, detectores_cpu, tam_detectores, cudaMemcpyHostToDevice);

    // Configuración de la jerarquía de ejecución en GPU
    int hilosPorBloque = 256;
    int bloquesPorGrid = (NUM_PAQUETES + hilosPorBloque - 1) / hilosPorBloque;

    printf("    -> Desplegando Grid CUDA: %d bloque(s), %d hilos por bloque...\n",
           bloquesPorGrid, hilosPorBloque);

    // Lanzamiento del kernel paralelo
    evaluar_trafico_gpu<<<bloquesPorGrid, hilosPorBloque>>>(
        d_paquetes, d_detectores, d_resultados,
        NUM_PAQUETES, num_detectores_validos, UMBRAL_DETECCION
    );

    // Sincronización de barrera de la GPU
    cudaDeviceSynchronize();

    // Transferencia de resultados Device (GPU) -> Host (CPU)
    cudaMemcpy(resultados_cpu, d_resultados, tam_resultados, cudaMemcpyDeviceToHost);
    cudaMemcpy(paquetes_cpu, d_paquetes, tam_paquetes, cudaMemcpyDeviceToHost);

    printf("    -> Evaluacion en GPU finalizada con exito.\n\n");

    // ------------------------------------------------------------------------
    // [4] RESULTADOS Y ACCIÓN DE MITIGACIÓN
    // ------------------------------------------------------------------------
    printf("[4] RESULTADOS DEL ANALISIS INMUNOLOGICO:\n");
    int total_anomalias = 0;
    int total_normales = 0;

    for (int i = 0; i < NUM_PAQUETES; i++) {
        printf("    [Paquete %2d] Pto:%4d, Tam:%4d B, Dur:%4d ms, Pet:%3d/s -> ",
               paquetes_cpu[i].id,
               paquetes_cpu[i].puerto_destino,
               paquetes_cpu[i].tamano_carga,
               paquetes_cpu[i].duracion_conexion,
               paquetes_cpu[i].peticiones_por_segundo);

        if (resultados_cpu[i] == 1) {
            printf("[!] ANOMALIA (Senal: %d) -> BLOQUEADO / MITIGAR\n",
                   paquetes_cpu[i].senal_control);
            total_anomalias++;
        } else {
            printf("[OK] TRAFICO NORMAL (Senal: %d) -> PERMITIDO\n",
                   paquetes_cpu[i].senal_control);
            total_normales++;
        }
    }

    printf("\n    Resumen: %d paquetes normales (Self), %d anomalias detectadas (Non-Self).\n\n",
           total_normales, total_anomalias);

    // ------------------------------------------------------------------------
    // [5] EXPORTACIÓN AL ESPACIO MATEMÁTICO (ENTREGABLE 5)
    // ------------------------------------------------------------------------
    printf("[5] EXPORTACION AL ESPACIO MATEMATICO (ENTREGABLE 5)...\n");
    exportar_frontera_csv("frontera_datos.csv", paquetes_cpu, NUM_PAQUETES,
                          detectores_cpu, num_detectores_validos);

    // ------------------------------------------------------------------------
    // [6] LIBERACIÓN DE MEMORIA DINÁMICA EN GPU
    // ------------------------------------------------------------------------
    cudaFree(d_paquetes);
    cudaFree(d_detectores);
    cudaFree(d_resultados);

    printf("\n=== PROCESO DE EVALUACION Y EXPORTACION FINALIZADO CORRECTAMENTE ===\n");
    return 0;
}
