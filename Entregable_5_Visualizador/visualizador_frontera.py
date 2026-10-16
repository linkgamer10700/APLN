import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# Archivo de entrada exportado por el motor en C/CUDA
ARCHIVO_CSV = "frontera_datos.csv"
ARCHIVO_SALIDA_IMG = "frontera_nids_3d.png"


def cargar_datos(ruta_archivo):
    """
    Carga el archivo CSV con las coordenadas multidimensionales.
    Valida la existencia de las columnas requeridas sin usar librerías de ML.
    """
    if not os.path.exists(ruta_archivo):
        raise FileNotFoundError(
            f"No se encontró el archivo '{ruta_archivo}'. "
            "Asegúrate de compilar y ejecutar primero 'nids_multidimensional.cu'."
        )

    df = pd.read_csv(ruta_archivo)
    columnas_esperadas = {"tipo", "puerto", "tamano", "duracion", "peticiones"}
    
    if not columnas_esperadas.issubset(set(df.columns)):
        raise ValueError(
            f"El archivo CSV no contiene las columnas requeridas: {columnas_esperadas}. "
            f"Columnas encontradas: {list(df.columns)}"
        )

    return df


def graficar_espacio_formas(df):
    """
    Construye y despliega la visualización 3D del espacio de formas.
    Separa los datos en las 3 clases: Normal (Self), Anomalia (Non-Self) y Detector.
    """
    # 1. Separación de conjuntos de datos mediante filtrado booleano en Pandas
    df_detectores = df[df["tipo"] == "Detector"]
    df_normales = df[df["tipo"] == "Normal"]
    df_anomalias = df[df["tipo"] == "Anomalia"]

    # 2. Configuración de la figura 3D con Matplotlib
    fig = plt.figure(figsize=(13, 9), dpi=100)
    ax = fig.add_subplot(111, projection="3d")

    # Estilo general del lienzo
    fig.patch.set_facecolor("#f8f9fa")
    ax.set_facecolor("#f8f9fa")

    # 3. Graficado de Detectores Inmunes (Células T)
    # Marcadores semitransparentes que revelan la cobertura del espacio exterior y el vacío central
    if not df_detectores.empty:
        ax.scatter(
            df_detectores["puerto"],
            df_detectores["tamano"],
            df_detectores["duracion"],
            c="#b0b7bd",
            alpha=0.22,
            s=22,
            marker=".",
            depthshade=True,
            label=f"Detectores Inmunes Non-Self (n={len(df_detectores)})"
        )

    # 4. Graficado de Tráfico Normal (Self)
    # Puntos azules compactos ubicados en el perfil de tolerancia segura
    if not df_normales.empty:
        ax.scatter(
            df_normales["puerto"],
            df_normales["tamano"],
            df_normales["duracion"],
            c="#0066cc",
            s=90,
            marker="o",
            edgecolors="#002244",
            linewidth=1.2,
            alpha=0.95,
            depthshade=False,
            label=f"Self / Tráfico Normal (n={len(df_normales)})"
        )

    # 5. Graficado de Anomalías Detectadas (Non-Self)
    # Puntos rojos grandes y resaltados indicando colisiones con el repertorio inmune
    if not df_anomalias.empty:
        ax.scatter(
            df_anomalias["puerto"],
            df_anomalias["tamano"],
            df_anomalias["duracion"],
            c="#e60000",
            s=160,
            marker="^",
            edgecolors="#4a0000",
            linewidth=1.5,
            alpha=1.0,
            depthshade=False,
            label=f"Non-Self / Anomalías Detectadas (n={len(df_anomalias)})"
        )

    # 6. Etiquetas formales de los ejes científicos
    ax.set_xlabel("Puerto Destino (Servicio)", fontsize=11, fontweight="bold", labelpad=12)
    ax.set_ylabel("Tamaño de Carga Útil (Bytes)", fontsize=11, fontweight="bold", labelpad=12)
    ax.set_zlabel("Duración de Conexión (ms)", fontsize=11, fontweight="bold", labelpad=12)

    # 7. Título formal requerido
    ax.set_title(
        "Espacio de Formas NIDS: Frontera Self vs Non-Self",
        fontsize=15,
        fontweight="bold",
        pad=20,
        color="#1a1a1a"
    )

    # 8. Ajuste de vista tridimensional (Ángulo de elevación y azimut para máxima claridad)
    ax.view_init(elev=24, azim=48)

    # 9. Leyenda técnica y estética
    legend = ax.legend(
        loc="upper left",
        frameon=True,
        facecolor="#ffffff",
        edgecolor="#cccccc",
        framealpha=0.95,
        fontsize=10
    )
    legend.get_frame().set_boxstyle("Round,pad=0.5")

    # 10. Ajustes de rejilla y límites visuales
    ax.grid(True, linestyle="--", alpha=0.45)
    plt.tight_layout()

    # 11. Guardar copia en disco en alta resolución
    plt.savefig(ARCHIVO_SALIDA_IMG, dpi=300, bbox_inches="tight")
    print(f"[*] Visualización guardada en '{ARCHIVO_SALIDA_IMG}' (300 DPI).")

    # 12. Apertura interactiva (si hay servidor de ventanas disponible)
    try:
        if "DISPLAY" in os.environ or sys.platform == "win32" or sys.platform == "darwin":
            print("[*] Abriendo ventana interactiva de visualización 3D...")
            plt.show()
        else:
            print("[*] Entorno sin interfaz gráfica (Headless); gráfico generado en imagen.")
    except Exception as e:
        print(f"[!] Nota al desplegar ventana: {e}")


def main():
    print("=" * 70)
    print(" VISUALIZADOR CIENTÍFICO 3D - ESPACIO DE FORMAS NIDS (ENTREGABLE 5) ")
    print("=" * 70)

    try:
        df = cargar_datos(ARCHIVO_CSV)
        print(f"[*] Datos leídos exitosamente de '{ARCHIVO_CSV}'.")
        print(f"    Total de registros: {len(df)}")
        print(f"    - Paquetes Normales (Self):    {len(df[df['tipo'] == 'Normal'])}")
        print(f"    - Paquetes Anómalos (Non-Self): {len(df[df['tipo'] == 'Anomalia'])}")
        print(f"    - Detectores Muestreados:      {len(df[df['tipo'] == 'Detector'])}\n")

        graficar_espacio_formas(df)
        print("\n[✓] Proceso de visualización finalizado exitosamente.")
    except Exception as err:
        print(f"\n[ERROR] Ocurrió una falla durante la ejecución: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
