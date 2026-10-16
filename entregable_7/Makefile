NVCC = nvcc
NVCCFLAGS = -O3 -arch=sm_86 -Xcompiler -Wall
TARGET = nids_entrenamiento_real
SRC = nids_entrenamiento_real.cu

all: $(TARGET)

$(TARGET): $(SRC)
	$(NVCC) $(NVCCFLAGS) -o $(TARGET) $(SRC)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET) reporte_inspeccion.csv

.PHONY: all run clean
