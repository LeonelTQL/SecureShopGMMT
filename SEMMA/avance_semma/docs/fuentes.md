# Fuentes, muestreo y contrato de etiquetado — Sample

## Fuente principal: OWASP Benchmark Java 1.2

Fuente sugerida por §7.1 del PDF: [OWASP Benchmark](https://owasp.org/www-project-benchmark/).
Repositorio: https://github.com/OWASP-Benchmark/BenchmarkJava.
Versión fijada: `10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17`.
El manifiesto `data/raw/source_manifest.json` registra URL, revisión y SHA-256 del archivo.
`fetch_data.py` permite volver a descargarlo y verificarlo.

Se utilizan los resultados esperados oficiales `expectedresults-1.2.csv`, conservados
en `data/raw/`. `true` indica vulnerabilidad a la CWE objetivo; `false` significa que
la prueba no presenta esa vulnerabilidad concreta. No se infiere que todo el código
sea seguro. Es una suite construida deliberadamente, no una muestra de producción.

Se incluyen todas las pruebas con CWE cuyo mapeo a OWASP 2025 se documentó.
Se excluye CWE-501 para evitar atribuir una categoría sin correspondencia verificada;
los recuentos figuran en `data/raw/excluded_categories.json`. No se aplica un muestreo
para conseguir métricas favorables. Los IDs de prueba, anotaciones, comentarios y
el método `doGet` (con rutas que revelan la categoría) se eliminan. Se conserva
`doPost` con métodos posteriores y se incorpora el código de clases Helper referidas.
La URL de cada fila conserva la trazabilidad al archivo original.

**Licencia:** GPL-2.0-only. `data/raw/LICENSE-BenchmarkJava.txt` conserva el texto.
Los fragmentos derivados siguen sujetos a esa licencia; el CSV combinado no se declara
íntegramente CC0. La copia original del código permanece en el ZIP descargado.

## Casos controlados complementarios

Autoría: casos didácticos preparados para este avance, en `src/controlled.py`, CC0-1.0.
No se presentan como código obtenido de repositorios de terceros ni como aportes
ya revisados por los estudiantes. Requieren revisión técnica humana antes de entregar.
Son 35 pares vulnerable/mitigado, cinco escenarios con siete implementaciones cada uno:
autorización de objetos, autenticación, autorización de propiedades, autorización de
funciones y configuración debug de API en producción.

Cada par comparte grupo y partición. Las cinco primeras implementaciones se usan en
train, la sexta en validación y la séptima en test. No se multiplican registros mediante
renombrados o comentarios para alcanzar el mínimo: el volumen mínimo proviene de Benchmark.

Contrato de los fragmentos: son funciones o configuraciones de una API desplegada en
producción. `user` es una identidad ya autenticada salvo en los casos de autenticación.
Los identificadores y payloads proceden de clientes no confiables. Los datos son privados;
las operaciones administrativas requieren permisos; el modelo de cuenta tiene atributos
privilegiados que un usuario normal no debe modificar. Los tokens, cookies o cabeceras
recibidos no se consideran verificados de antemano. Los helpers `authorize`, `policy.enforce`,
`require_permission`, `verify_access_token`, `sessions.require_authenticated` y el decorador
`require_role` **rechazan** cuando la comprobación falla. El esquema de perfil permite
solo campos públicos y rechaza extras; los firmantes usan claves fuera del código y
validación de integridad. Estas condiciones son supuestos del ejemplo, no verificaciones
realizadas por el clasificador. Son fragmentos para clasificación, no aplicaciones ejecutables.

La mitigación se etiqueta respecto al riesgo mostrado. La configuración `debug=False`
no demuestra que todas las demás configuraciones de la aplicación sean seguras.
El ejemplo de login requiere además sesión, políticas y otros controles no mostrados.

## Correspondencias y cautelas

Los identificadores del catálogo se tomaron de §4 del PDF y se contrastaron con
[OWASP Top 10:2025](https://top10.owasp.org/2025/) y
[OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/).
`docs/cwe_owasp.csv` distingue relaciones documentadas de CWE con Top 10 y las
asignaciones de API basadas en el contexto del ejemplo. No hay equivalencia automática
entre una categoría de aplicaciones y una de API. Las categorías de API solo se asignan
a los casos controlados donde está declarado ese contexto.

## Por qué se descarta el CSV anterior como fuente de entrenamiento

`../code_vulnerabilities.csv` contiene 1.000 filas, diez fragmentos distintos y etiquetas
SQLi/XSS sin clase segura. Se conserva intacto y no se mezcla con este dataset.
Los resultados guardados de los talleres tampoco se reutilizan como evaluación.

## Independencia de las particiones

Antes de dividir Benchmark se agrupan componentes conectados de similitud coseno ≥0,90
de TF-IDF de caracteres de longitud cinco y grupos con igual estructura normalizada.
Este TF-IDF se usa exclusivamente para descontaminar el conjunto y no entra en el modelo.
El TF-IDF de clasificación se ajusta después **solo con train**. Los grupos se separan
aproximadamente 70/15/15 con semillas 42 y 43. No se fuerza una proporción exacta
rompiendo grupos. El manifiesto `partitions.csv` permite auditar cada asignación.
El umbral de clones es una elección previa de preparación, no un hiperparámetro optimizado
con las métricas de test. Sigue siendo posible compartir patrones semánticos no detectados.
