#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <cuda_runtime.h>

#define TOTAL_DETECTORES_A_GENERAR 8192
#define NUM_ESPECIES 3
#define MAX_PAQUETES 1000

// Umbrales para la Métrica de Afinidad (Norma L1 4D)
#define UMBRAL_ENTRENAMIENTO 200   // Radio de pertenencia a una Especie Normal
#define UMBRAL_DETECCION 120       // Radio de colisión para confirmar Ataque

struct EspecieSelf {
    int id_especie;
    int puerto_destino;
    int tamano_carga;
    int duracion_conexion;
    int peticiones_por_segundo;
    char descripcion[50];
};

struct PaqueteDatos {
    int id;
    int puerto_origen;
    int puerto_destino;
    int tamano_carga;
    int duracion_conexion;
    int peticiones_por_segundo;
    int estado_clasificacion; // 0: Normal, 1: Cuarentena, 2: Bloqueado
};

struct Detector {
    int puerto_destino;
    int tamano_carga;
    int duracion_conexion;
    int peticiones_por_segundo;
};

int distancia_manhattan_cpu(int p1, int t1, int d1, int r1,
                            int p2, int t2, int d2, int r2) {
    return abs(p1 - p2) + abs(t1 - t2) + abs(d1 - d2) + abs(r1 - r2);
}

int rand_rango(int min, int max) {
    return min + rand() % (max - min + 1);
}

/**
 * Instancia el ecosistema con 3 especies benignas fundamentales.
 */
void inicializar_ecosistema(struct EspecieSelf* especies) {
    // Especie 1: Servidor Web HTTP/HTTPS
    especies[0].id_especie = 1;
    especies[0].puerto_destino = 80;
    especies[0].tamano_carga = 500;
    especies[0].duracion_conexion = 120;
    especies[0].peticiones_por_segundo = 15;
    strcpy(especies[0].descripcion, "Trafico Web Standard (HTTP/HTTPS)");

    // Especie 2: Servidor DNS Legítimo
    especies[1].id_especie = 2;
    especies[1].puerto_destino = 53;
    especies[1].tamano_carga = 60;
    especies[1].duracion_conexion = 5;
    especies[1].peticiones_por_segundo = 2;
    strcpy(especies[1].descripcion, "Resolucion DNS Legítima");

    // Especie 3: Transferencia Interna / API Pesada
    especies[2].id_especie = 3;
    especies[2].puerto_destino = 8080;
    especies[2].tamano_carga = 2000;
    especies[2].duracion_conexion = 1500;
    especies[2].peticiones_por_segundo = 2;
    strcpy(especies[2].descripcion, "Transferencia Interna / API REST");
}

int generar_detectores_ecosistema(struct Detector* detectores, struct EspecieSelf* especies, int num_espc) {
    int validos = 0;

    for (int i = 0; i < TOTAL_DETECTORES_A_GENERAR; i++) {
        int r_puerto, r_tamano, r_duracion, r_peticiones;
        
        int modo = i % 8;
        if (modo == 0) {
            // Sector Escaneo de Puertos y Servicios Críticos (SSH, Telnet)
            r_puerto = rand_rango(20, 100);
            r_tamano = rand_rango(30, 150);
            r_duracion = rand_rango(5, 50);
            r_peticiones = rand_rango(1, 10);
        } else if (modo == 1) {
            // Sector Inyecciones y Sobrecargas de Payload (SQLi, Overflow)
            r_puerto = rand_rango(75, 450);
            r_tamano = rand_rango(1500, 2500);
            r_duracion = rand_rango(500, 1500);
            r_peticiones = rand_rango(10, 50);
        } else if (modo == 2) {
            // Sector Inundación / Ataque de Denegación de Servicio (DoS / Flood)
            r_puerto = (rand() % 2 == 0) ? 80 : 443;
            r_tamano = rand_rango(40, 150);
            r_duracion = rand_rango(2, 20);
            r_peticiones = rand_rango(200, 400);
        } else if (modo == 3) {
            // Sector Conexiones Lentas / Backdoors persistentes
            r_puerto = rand_rango(4000, 5000);
            r_tamano = rand_rango(1000, 1500);
            r_duracion = rand_rango(500, 1500);
            r_peticiones = rand_rango(1, 10);
        } else if (modo == 4) {
            // RDP / DB Traffic Anomalies
            r_puerto = rand_rango(3000, 3500);
            r_tamano = rand_rango(200, 500);
            r_duracion = rand_rango(500, 1500);
            r_peticiones = rand_rango(1, 10);
        } else {
            // Exploración uniforme en todo el ecosistema
            r_puerto = rand_rango(1, 10000);
            r_tamano = rand_rango(10, 2500);
            r_duracion = rand_rango(1, 2000);
            r_peticiones = rand_rango(1, 300);
        }

        int colision_self = 0;

        // Comprobar la tolerancia central frente a cada Especie Benigna
        for (int e = 0; e < num_espc; e++) {
            int dist = distancia_manhattan_cpu(
                r_puerto, r_tamano, r_duracion, r_peticiones,
                especies[e].puerto_destino, especies[e].tamano_carga,
                especies[e].duracion_conexion, especies[e].peticiones_por_segundo
            );

            // Si se acerca peligrosamente a cualquier perfil normal, es autorreactivo
            if (dist <= UMBRAL_ENTRENAMIENTO) {
                colision_self = 1;
                break; 
            }
        }

        // Supervivencia exclusiva si respeta el espacio de TODO el ecosistema
        if (!colision_self) {
            detectores[validos].puerto_destino = r_puerto;
            detectores[validos].tamano_carga = r_tamano;
            detectores[validos].duracion_conexion = r_duracion;
            detectores[validos].peticiones_por_segundo = r_peticiones;
            validos++;
        }
    }
    return validos;
}

int cargar_trafico_sintetico(struct PaqueteDatos* paquetes) {
    int n = 0;
    
    // -- Especie 1 (Web) Cercanos --
    paquetes[n++] = (struct PaqueteDatos){101, 5501, 80, 480, 115, 14, -1};
    paquetes[n++] = (struct PaqueteDatos){102, 5502, 443, 520, 130, 16, -1};
    
    // -- Especie 2 (DNS) Cercanos --
    paquetes[n++] = (struct PaqueteDatos){201, 6001, 53, 58, 4, 2, -1};
    paquetes[n++] = (struct PaqueteDatos){202, 6002, 53, 65, 6, 3, -1};

    // -- Especie 3 (API/Transf) Cercanos --
    paquetes[n++] = (struct PaqueteDatos){301, 7001, 8080, 1950, 1450, 2, -1};
    
    // -- Cuarentena (Comportamientos grises / Nuevas aplicaciones no catalogadas) --
    // Ej: Un servicio interno nuevo en puerto 3000 con características atípicas pero benignas
    paquetes[n++] = (struct PaqueteDatos){401, 8001, 3000, 800, 400, 8, -1};
    paquetes[n++] = (struct PaqueteDatos){402, 8002, 3306, 300, 900, 5, -1}; // DB Traffic
    
    // -- Anomalías Críticas (Ataques obvios) --
    paquetes[n++] = (struct PaqueteDatos){901, 9001, 22, 64, 15, 2, -1};     // SSH Scan
    paquetes[n++] = (struct PaqueteDatos){902, 9002, 80, 60, 5, 250, -1};    // DDoS Flood
    paquetes[n++] = (struct PaqueteDatos){903, 9003, 4444, 1200, 800, 4, -1};// Trojan C2
    paquetes[n++] = (struct PaqueteDatos){904, 9004, 80, 2400, 1200, 40, -1};// Overflow

    return n;
}

/**
 * Lee el archivo CSV de entrada. Retorna la cantidad de paquetes procesados.
 */
int cargar_trafico_csv(const char* ruta, struct PaqueteDatos* paquetes) {
    FILE* fp = fopen(ruta, "r");
    if (!fp) {
        printf("[!] ADVERTENCIA: No se encontro '%s'.\n", ruta);
        printf("[!] Activando Mecanismo de Contingencia: Generando Trafico Sintetico en RAM.\n");
        return cargar_trafico_sintetico(paquetes);
    }

    char buffer[256];
    // Saltear el encabezado
    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        fclose(fp);
        return cargar_trafico_sintetico(paquetes);
    }

    int count = 0;
    while (fgets(buffer, sizeof(buffer), fp) && count < MAX_PAQUETES) {
        struct PaqueteDatos p;
        // Formato esperado: id,puerto_orig,puerto_dest,tamano,duracion,peticiones
        if (sscanf(buffer, "%d,%d,%d,%d,%d,%d",
                   &p.id, &p.puerto_origen, &p.puerto_destino,
                   &p.tamano_carga, &p.duracion_conexion, &p.peticiones_por_segundo) == 6) {
            p.estado_clasificacion = -1; // No clasificado inicialmente
            paquetes[count++] = p;
        }
    }

    fclose(fp);
    printf("    -> Ingesta desde CSV exitosa: %d paquetes procesados.\n", count);
    return count;
}

// ============================================================================
// FUNCIONES Y KERNEL EN GPU (CUDA)
// ============================================================================

__device__ int inline distancia_l1_gpu(int p1, int t1, int d1, int r1,
                                       int p2, int t2, int d2, int r2) {
    int d_puerto = p1 - p2; if (d_puerto < 0) d_puerto = -d_puerto;
    int d_tam    = t1 - t2; if (d_tam < 0) d_tam = -d_tam;
    int d_dur    = d1 - d2; if (d_dur < 0) d_dur = -d_dur;
    int d_pet    = r1 - r2; if (d_pet < 0) d_pet = -d_pet;
    
    return d_puerto + d_tam + d_dur + d_pet;
}

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
        
        // Fase A: Inspección Inmunológica (Verificar Peligro / Amenaza)
        int min_dist_detector = 9999999; // Infinito representativo
        for (int i = 0; i < num_detectores; i++) {
            int d = distancia_l1_gpu(
                p.puerto_destino, p.tamano_carga, p.duracion_conexion, p.peticiones_por_segundo,
                d_detectores[i].puerto_destino, d_detectores[i].tamano_carga,
                d_detectores[i].duracion_conexion, d_detectores[i].peticiones_por_segundo
            );
            if (d < min_dist_detector) min_dist_detector = d;
            
            // Optimización: Si se cruzó el umbral de detección letal, no buscar más
            if (min_dist_detector <= umbral_deteccion) break;
        }

        if (min_dist_detector <= umbral_deteccion) {
            // Riesgo Inminente: Colisión con linfocito (Detector)
            d_paquetes[idx].estado_clasificacion = 2; // ESTADO 2: BLOQUEO
        } else {
            // Fase B: Verificación de Especie Benigna (Asimilación Self)
            int min_dist_self = 9999999;
            for (int e = 0; e < num_especies; e++) {
                int d = distancia_l1_gpu(
                    p.puerto_destino, p.tamano_carga, p.duracion_conexion, p.peticiones_por_segundo,
                    d_especies[e].puerto_destino, d_especies[e].tamano_carga,
                    d_especies[e].duracion_conexion, d_especies[e].peticiones_por_segundo
                );
                if (d < min_dist_self) min_dist_self = d;
            }

            // Si está protegido por el halo de tolerancia de ALGUNA especie conocida
            if (min_dist_self <= umbral_entrenamiento) {
                d_paquetes[idx].estado_clasificacion = 0; // ESTADO 0: NORMAL
            } else {
                // Zona gris: No es un ataque conocido, pero tampoco es una especie catalogada
                d_paquetes[idx].estado_clasificacion = 1; // ESTADO 1: CUARENTENA
            }
        }
    }
}

// ============================================================================
// EXPORTACIÓN DE RESULTADOS
// ============================================================================
void exportar_reporte(const char* archivo, struct PaqueteDatos* paquetes, int num_paquetes) {
    FILE* fp = fopen(archivo, "w");
    if (!fp) {
        printf("[!] Error guardando %s\n", archivo);
        return;
    }

    fprintf(fp, "ID,Pto_Orig,Pto_Dest,Tamano,Duracion,Peticiones,Estado_Clasificacion,Accion\n");
    for (int i = 0; i < num_paquetes; i++) {
        struct PaqueteDatos p = paquetes[i];
        const char* accion = "";
        const char* estado_str = "";
        
        if (p.estado_clasificacion == 0) { 
            estado_str = "NORMAL"; accion = "PERMITIDO"; 
        } else if (p.estado_clasificacion == 1) { 
            estado_str = "OBSERVACION"; accion = "CUARENTENA_ANALISIS"; 
        } else { 
            estado_str = "ANOMALIA"; accion = "BLOQUEO_INMEDIATO"; 
        }

        fprintf(fp, "%d,%d,%d,%d,%d,%d,%s,%s\n",
                p.id, p.puerto_origen, p.puerto_destino, p.tamano_carga,
                p.duracion_conexion, p.peticiones_por_segundo, estado_str, accion);
    }
    fclose(fp);
}

int main() {
    srand(42);

    // 1. Configurar Ecosistema Benigno
    printf("[1] CARGANDO ECOSISTEMA BENIGNO (ESPECIES SELF)...\n");
    struct EspecieSelf especies_cpu[NUM_ESPECIES];
    inicializar_ecosistema(especies_cpu);
    
    for (int i = 0; i < NUM_ESPECIES; i++) {
        printf("    -> Especie %d: %s | Pto:%d Tam:%dB Dur:%dms Pet:%d/s\n",
               especies_cpu[i].id_especie, especies_cpu[i].descripcion,
               especies_cpu[i].puerto_destino, especies_cpu[i].tamano_carga,
               especies_cpu[i].duracion_conexion, especies_cpu[i].peticiones_por_segundo);
    }
    printf("\n");

    // 2. Aprendizaje y Tolerancia Central
    printf("[2] FASE DE APRENDIZAJE: CENSURA CLONAL MULTI-PERFIL...\n");
    struct Detector detectores_cpu[TOTAL_DETECTORES_A_GENERAR];
    int validos = generar_detectores_ecosistema(detectores_cpu, especies_cpu, NUM_ESPECIES);
    
    printf("    -> Detectores Candidatos Iniciales: %d\n", TOTAL_DETECTORES_A_GENERAR);
    printf("    -> Detectores Inmunes Sobrevivientes (Non-Self Global): %d\n\n", validos);

    // 3. Ingesta de Tráfico (CSV o Sintético)
    printf("[3] INGESTA DE TRAFICO DE RED...\n");
    struct PaqueteDatos paquetes_cpu[MAX_PAQUETES];
    int num_paquetes = cargar_trafico_csv("trafico_red.csv", paquetes_cpu);
    printf("\n");

    if (num_paquetes <= 0) {
        printf("[!] Error crítico: No hay paquetes para evaluar.\n");
        return 1;
    }

    // 4. Preparación CUDA (VRAM)
    printf("[4] ACELERACION GPU: EVALUACION TRI-ESTADO (CUDA)...\n");
    struct PaqueteDatos* d_paquetes;
    struct Detector* d_detectores;
    struct EspecieSelf* d_especies;

    size_t sz_paquetes = num_paquetes * sizeof(struct PaqueteDatos);
    size_t sz_detectores = validos * sizeof(struct Detector);
    size_t sz_especies = NUM_ESPECIES * sizeof(struct EspecieSelf);

    cudaMalloc((void**)&d_paquetes, sz_paquetes);
    cudaMalloc((void**)&d_detectores, sz_detectores);
    cudaMalloc((void**)&d_especies, sz_especies);

    cudaMemcpy(d_paquetes, paquetes_cpu, sz_paquetes, cudaMemcpyHostToDevice);
    cudaMemcpy(d_detectores, detectores_cpu, sz_detectores, cudaMemcpyHostToDevice);
    cudaMemcpy(d_especies, especies_cpu, sz_especies, cudaMemcpyHostToDevice);

    int hilosPorBloque = 256;
    int bloques = (num_paquetes + hilosPorBloque - 1) / hilosPorBloque;

    // 5. Lanzamiento del Kernel
    evaluar_ecosistema_gpu<<<bloques, hilosPorBloque>>>(
        d_paquetes, d_detectores, d_especies,
        num_paquetes, validos, NUM_ESPECIES,
        UMBRAL_ENTRENAMIENTO, UMBRAL_DETECCION
    );

    cudaDeviceSynchronize();

    // Recuperar clasificaciones
    cudaMemcpy(paquetes_cpu, d_paquetes, sz_paquetes, cudaMemcpyDeviceToHost);

    // 6. Presentación de Resultados en Consola
    printf("    -> Evaluacion paralela completa.\n\n");
    printf("[5] REPORTE DE INSPECCION Y ESTADO OPERACIONAL:\n");
    printf("--------------------------------------------------------------------------------------\n");
    printf("%-5s | %-6s | %-6s | %-6s | %-6s | %-12s | %-18s\n", 
           "ID", "PTO", "TAM(B)", "DUR(ms)", "REQ/s", "CLASIFICACION", "ACCION SISTEMA");
    printf("--------------------------------------------------------------------------------------\n");

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

        printf("%-5d | %-6d | %-6d | %-6d | %-6d | %-12s | %-18s\n",
               p.id, p.puerto_destino, p.tamano_carga, p.duracion_conexion, 
               p.peticiones_por_segundo, estado_str, accion_str);
    }
    printf("--------------------------------------------------------------------------------------\n");
    printf("RESUMEN GLOBAL: %d Normales | %d En Cuarentena | %d Bloqueados\n\n", c_normal, c_obs, c_bloq);

    // 7. Exportación Final y Liberación
    exportar_reporte("reporte_inspeccion.csv", paquetes_cpu, num_paquetes);
    printf("[6] Auditoria exportada exitosamente a 'reporte_inspeccion.csv'.\n");

    cudaFree(d_paquetes);
    cudaFree(d_detectores);
    cudaFree(d_especies);

    return 0;
}
