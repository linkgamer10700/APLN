#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

// CONFIGURACIÓN DEL SISTEMA
#define NUM_PAQUETES 5
#define TOTAL_DETECTORES_A_GENERAR 1024

// --- PERFIL NORMAL ---
#define PERFIL_PUERTO_DEST 80
#define PERFIL_TAMANO 500
#define UMBRAL_ENTRENAMIENTO 200 
#define UMBRAL_DETECCION 50      

// ESTRUCTURAS DE DATOS (Fusión Avance 1 y 2)
// Representación numérica de un paquete en la red para procesamiento rápido en GPU
struct PaqueteDatos {
    int puerto_origen;
    int puerto_destino;
    int tamano_carga;
    int senal_control; // 0: Tráfico Normal, 1: Alerta / Bloquear
};

// Detector (Célula Inmunológica T)
struct Detector {
    int puerto_destino;
    int tamano_carga;
};

// FASE 2: ENCAPSULAMIENTO (CPU)
struct PaqueteDatos encapsular_y_proteger(const char* mensaje_crudo, int p_origen, int p_destino) {
    struct PaqueteDatos paquete_nuevo;
    paquete_nuevo.puerto_origen = p_origen;
    paquete_nuevo.puerto_destino = p_destino;
    paquete_nuevo.tamano_carga = strlen(mensaje_crudo) * 20; 
    paquete_nuevo.senal_control = 0; 
    return paquete_nuevo;
}

// FASE 1: APRENDIZAJE / SELECCIÓN NEGATIVA (CPU)
int distancia_manhattan(int p_dest1, int tam1, int p_dest2, int tam2) {
    return abs(p_dest1 - p_dest2) + abs(tam1 - tam2);
}

int generar_detectores(struct Detector* detectores) {
    int validos = 0;
    for (int i = 0; i < TOTAL_DETECTORES_A_GENERAR; i++) {
        // Generar mutaciones aleatorias (puertos y tamaños)
        int r_puerto = rand() % 1000;
        int r_tamano = rand() % 1500;
        
        int distancia_al_normal = distancia_manhattan(r_puerto, r_tamano, PERFIL_PUERTO_DEST, PERFIL_TAMANO);
        
        // SELECCIÓN NEGATIVA: Si el detector está lejos del perfil normal, sobrevive (es Non-Self)
        // Si estuviera muy cerca del perfil normal (distancia < UMBRAL_ENTRENAMIENTO), se autodestruye para evitar falsos positivos.
        if (distancia_al_normal > UMBRAL_ENTRENAMIENTO) {
            detectores[validos].puerto_destino = r_puerto;
            detectores[validos].tamano_carga = r_tamano;
            validos++;
        }
    }
    return validos;
}

// FASE 3: EVALUACIÓN Y ACCIÓN (GPU CUDA)

// Función auxiliar ejecutada directamente dentro de la tarjeta gráfica (__device__)
__device__ int distancia_gpu(struct PaqueteDatos p, struct Detector d) {
    // Calculamos el valor absoluto manualmente para CUDA device
    int diff_puerto = p.puerto_destino - d.puerto_destino;
    if(diff_puerto < 0) diff_puerto = -diff_puerto;
    
    int diff_tam = p.tamano_carga - d.tamano_carga;
    if(diff_tam < 0) diff_tam = -diff_tam;
    
    return diff_puerto + diff_tam;
}

// Kernel de CUDA: Función principal que se ejecuta en paralelo en cientos o miles de hilos (__global__)
__global__ void evaluar_trafico_gpu(struct PaqueteDatos* d_paquetes, struct Detector* d_detectores, int* d_resultados, int num_paquetes, int num_detectores, int umbral) {
    // Identificador único del hilo en el grid completo
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    // Verificamos no salirnos del arreglo de paquetes
    if (idx < num_paquetes) {
        d_resultados[idx] = 0; // Inicialmente asumimos que es normal (0)
        
        // Cada hilo compara su paquete asignado contra TODOS los detectores sobrevivientes
        for (int i = 0; i < num_detectores; i++) {
            int dist = distancia_gpu(d_paquetes[idx], d_detectores[i]);
            
            // Si coincide con un detector de anomalías (distancia muy pequeña), es un ataque
            if (dist <= umbral) {
                d_resultados[idx] = 1; // 1 = Anomalía detectada
                d_paquetes[idx].senal_control = 1; // FASE 4: Acción (Mandamos señal de alerta/cierre de conexión)
                break; // No necesitamos revisar los demás detectores, ya sabemos que es malicioso
            }
        }
    }
}

// FUNCIÓN PRINCIPAL
int main() {
    srand(time(NULL));
    
    printf("   SISTEMA INTELIGENTE NIDS - ACELERADO CON CUDA GPU    \n");
    
    // 1. Fase de Aprendizaje (Generación de Detectores en CPU)
    printf("[1] FASE DE APRENDIZAJE (SELECCION NEGATIVA)...\n");
    struct Detector detectores_cpu[TOTAL_DETECTORES_A_GENERAR];
    int num_detectores_validos = generar_detectores(detectores_cpu);
    printf("    -> De %d detectores generados aleatoriamente,\n", TOTAL_DETECTORES_A_GENERAR);
    printf("    -> %d detectores maduraron y sobrevivieron (Perfil Non-Self).\n\n", num_detectores_validos);
    
    // 2. Simulación de Tráfico y Encapsulamiento (CPU)
    printf("[2] ENCAPSULAMIENTO DE TRAFICO ENTRANTE...\n");
    struct PaqueteDatos paquetes_cpu[NUM_PAQUETES];
    
    // Generamos Tráfico Normal (Similar al perfil esperado)
    paquetes_cpu[0] = encapsular_y_proteger("Hola, quiero ver la pagina web", 5001, 80);
    paquetes_cpu[1] = encapsular_y_proteger("Consulta a la base de datos", 5002, 80);
    paquetes_cpu[2] = encapsular_y_proteger("Navegacion segura y rutinaria", 5003, 80);
    
    // Generamos Tráfico Anómalo (Ataque, puertos raros, mucho tamaño)
    // Fuerza bruta con un payload enorme dirigido a un puerto extraño
    paquetes_cpu[3] = encapsular_y_proteger("SUPER MEGA PAYLOAD ATAQUE FUERZA BRUTA PARA COLAPSAR MEMORIA Y GENERAR OVERFLOW 1234567890", 9999, 4444); 
    // Intento de escaneo de puertos o conexión SSH
    paquetes_cpu[4] = encapsular_y_proteger("Intento de conexion maliciosa", 6666, 22);
    
    for(int i=0; i<NUM_PAQUETES; i++) {
        printf("    Paquete %d encapsulado -> Pto. Dest: %d, Tamano Carga: %d bytes\n", i + 1, paquetes_cpu[i].puerto_destino, paquetes_cpu[i].tamano_carga);
    }
    printf("\n");
    
    // 3. Fase de Evaluación (En GPU)
    printf("[3] FASE DE EVALUACION PARALELA EN GPU (CUDA)...\n");
    
    struct PaqueteDatos *d_paquetes;
    struct Detector *d_detectores;
    int *d_resultados;
    int resultados_cpu[NUM_PAQUETES];
    
    // Reservar memoria en VRAM de la GPU
    cudaMalloc((void**)&d_paquetes, NUM_PAQUETES * sizeof(struct PaqueteDatos));
    cudaMalloc((void**)&d_detectores, num_detectores_validos * sizeof(struct Detector));
    cudaMalloc((void**)&d_resultados, NUM_PAQUETES * sizeof(int));
    
    // Copiar datos de CPU a VRAM de GPU
    cudaMemcpy(d_paquetes, paquetes_cpu, NUM_PAQUETES * sizeof(struct PaqueteDatos), cudaMemcpyHostToDevice);
    cudaMemcpy(d_detectores, detectores_cpu, num_detectores_validos * sizeof(struct Detector), cudaMemcpyHostToDevice);
    
    // Definir configuración de ejecución CUDA (Hilos y Bloques)
    int hilosPorBloque = 256;
    int bloquesPorGrid = (NUM_PAQUETES + hilosPorBloque - 1) / hilosPorBloque;
    
    // LANZAMIENTO DEL KERNEL (Procesamiento paralelo masivo)
    evaluar_trafico_gpu<<<bloquesPorGrid, hilosPorBloque>>>(d_paquetes, d_detectores, d_resultados, NUM_PAQUETES, num_detectores_validos, UMBRAL_DETECCION);
    
    // Esperar a que todos los hilos de la GPU terminen
    cudaDeviceSynchronize();
    
    // Traer resultados de vuelta a la memoria RAM de la CPU
    cudaMemcpy(resultados_cpu, d_resultados, NUM_PAQUETES * sizeof(int), cudaMemcpyDeviceToHost);
    cudaMemcpy(paquetes_cpu, d_paquetes, NUM_PAQUETES * sizeof(struct PaqueteDatos), cudaMemcpyDeviceToHost); // Necesario para traer la senal_control actualizada
    
    // 4. Acción y Resultados Finales
    printf("    -> Evaluacion en GPU completada con exito.\n\n");
    
    printf("[4] RESULTADOS Y ACCION DEL SISTEMA INTELIGENTE:\n");
    for (int i = 0; i < NUM_PAQUETES; i++) {
        printf("    [Paquete %d] Pto. Dest: %4d, Tamano: %4d -> ", i + 1, paquetes_cpu[i].puerto_destino, paquetes_cpu[i].tamano_carga);
        
        if (resultados_cpu[i] == 1) {
            printf("[!] ANOMALIA DETECTADA! (Senal de Control: %d - Bloqueando Conexion)\n", paquetes_cpu[i].senal_control);
        } else {
            printf("[OK] TRAFICO NORMAL       (Senal de Control: %d - Conexion Permitida)\n", paquetes_cpu[i].senal_control);
        }
    }
    
    // Liberar memoria VRAM
    cudaFree(d_paquetes);
    cudaFree(d_detectores);
    cudaFree(d_resultados);

    printf("PROCESO FINALIZADO \n");
    
    return 0;
}
