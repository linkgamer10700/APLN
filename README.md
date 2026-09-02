# Sistema inteligente de detección de anomalías mediante selección negativa y computación paralela.
## ¿Qué hace?

El sistema aprende cómo es el comportamiento normal de un conjunto de datos y genera "detectores" que representan comportamientos diferentes.

Cuando llega un dato nuevo:
- Si se parece al comportamiento normal → normal.
- Si es suficientemente diferente → anomalía.
La idea está inspirada en el sistema inmunológico, donde las células aprenden a reconocer lo propio (Self) y reaccionan ante lo que no pertenece al organismo (Non-Self).

## ¿Dónde lo aplicamos?

Como primera aplicación:

Detección de intrusiones en tráfico de red (NIDS).

> Por ejemplo:
> Tráfico normal
>       ↓
>   Aprendizaje
>       ↓
>  Detectores
>       ↓
> Nuevo tráfico
>       ↓
> ┌───────────────┐
> │ ¿Se parece a  │
> │ lo normal?    │
> └───────┬───────┘
>     Sí  │  No
>        ↓    ↓
>     NORMAL  ALERTA

## ¿Dónde está la IA?
En el Algoritmo de Selección Negativa, que genera y selecciona automáticamente los detectores.
No usamos modelos ya hechos. Implementamos el algoritmo nosotros mismos.

## ¿Dónde está el paralelismo?

La evaluación de miles o millones de posibles detectores puede hacerse simultáneamente:
Detectores
    ↓
┌──────┬──────┬──────┬──────┐
│CPU 1 │CPU 2 │CPU 3 │CPU 4 │
└──────┴──────┴──────┴──────┘
    ↓
Resultados


Utilizaríamos OpenMP en C para comparar la versión normal contra la versión paralela.

¿Qué vamos a medir?

Principalmente:

Qué tan bien detecta anomalías.
Falsos positivos y falsos negativos.
Tiempo de ejecución.
Speedup al utilizar varios núcleos.
Eficiencia del paralelismo.
Impacto de aumentar el número de detectores.
¿Por qué es un proyecto fuerte?

Porque combina:

IA bioinspirada + detección de anomalías + ciberseguridad + computación paralela + programación de bajo nivel, todo implementado desde cero.

Y lo más importante: si después deciden que no quieren cybersecurity, simplemente cambiamos los datos de entrada y mantenemos el mismo núcleo del proyecto. Por ejemplo, podría aplicarse a sensores industriales, transacciones financieras o secuencias biológicas.