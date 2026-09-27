#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define TOTAL_DETECTORES_A_GENERAR 10
#define LIMITE_VALOR_RED 1000

const int PERFIL_NORMAL = 500; 
const int UMBRAL_SIMILITUD = 100; 

int reacciona_a_normalidad(int valor_detector) {
    int diferencia = abs(valor_detector - PERFIL_NORMAL);
    if (diferencia <= UMBRAL_SIMILITUD) {
        return 1;
    }
    return 0;
}

int main() {
    int detectores_sobrevivientes[TOTAL_DETECTORES_A_GENERAR];
    int contador_validos = 0;
    
    srand(time(NULL));
    
    printf("Perfil Normal (Self): %d (Umbral: +/- %d)\n\n", PERFIL_NORMAL, UMBRAL_SIMILITUD);
    
    for (int i = 0; i < TOTAL_DETECTORES_A_GENERAR; i++) {
        int nuevo_detector = rand() % LIMITE_VALOR_RED;
        
        printf("Evaluando Detector %d (Valor: %d)... ", i + 1, nuevo_detector);
        
        if (reacciona_a_normalidad(nuevo_detector)) {
            printf("RECHAZADO (Provocaria falsa alarma)\n");
        } else {
            detectores_sobrevivientes[contador_validos] = nuevo_detector;
            contador_validos++;
            printf("APROBADO (Detector maduro guardado)\n");
        }
    }
    
    printf("\nResumen del Aprendizaje:\n");
    printf("De %d detectores generados, solo sobrevivieron %d.\n", TOTAL_DETECTORES_A_GENERAR, contador_validos);
    
    return 0;
}