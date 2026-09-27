#include <stdio.h>
#include <string.h>

struct CapaAplicacion {
    char mensaje[256];
};

struct CapaTransporte {
    int puerto_origen;
    int puerto_destino;
    int senal_control; 
};

struct PaqueteDatos {
    struct CapaTransporte cabecera;
    struct CapaAplicacion carga_util;
};

struct PaqueteDatos encapsular_y_proteger(const char* mensaje_crudo, int enviar_senal_cierre) {
    struct PaqueteDatos paquete_nuevo;
    
    strcpy(paquete_nuevo.carga_util.mensaje, mensaje_crudo);
    
    paquete_nuevo.cabecera.puerto_origen = 5000;
    paquete_nuevo.cabecera.puerto_destino = 80;
    
    if (enviar_senal_cierre == 1) {
        paquete_nuevo.cabecera.senal_control = 0; 
    } else {
        paquete_nuevo.cabecera.senal_control = 1; 
    }
    
    return paquete_nuevo;
}

int main() {
    printf("--- Iniciando Prototipo de Encapsulamiento ---\n\n");
    
    struct PaqueteDatos paquete1 = encapsular_y_proteger("Hola, este es un inicio de sesion", 0);
    printf("Paquete 1 Generado:\n");
    printf("- Datos: %s\n", paquete1.carga_util.mensaje);
    printf("- Cabecera -> Puerto Destino: %d | Senal: %d (Normal)\n\n", paquete1.cabecera.puerto_destino, paquete1.cabecera.senal_control);
    
    struct PaqueteDatos paquete2 = encapsular_y_proteger("ALERTA: Intento de fuerza bruta detectado", 1);
    printf("Paquete 2 Generado (Con señal de seguridad):\n");
    printf("- Datos: %s\n", paquete2.carga_util.mensaje);
    printf("- Cabecera -> Puerto Destino: %d | Senal: %d (CERRAR CONEXION)\n", paquete2.cabecera.puerto_destino, paquete2.cabecera.senal_control);

    return 0;
}