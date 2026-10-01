# SecureShopGMMT

| # | Activo | Tipo | ¿Qué consecuencia tiene para Secure Shop que este activo sea accedido, modificado o quede indisponible? |
|---|---|---|---|
| 1 | Datos personales de usuarios | Información | Podría provocar exposición de información privada, alteración de datos personales o impedir la correcta gestión de los usuarios. |
| 2 | Base de datos de usuarios | Datos | Podrían robarse, modificarse o eliminarse cuentas y datos, afectando el acceso y funcionamiento de las cuentas de los clientes. |
| 3 | Microservicio de usuarios | Software | Podría permitir operaciones no autorizadas, alterar la gestión de usuarios o impedir el acceso y administración de cuentas. |
| 4 | Catálogo de productos | Información | Podrían conocerse o modificarse precios, características y disponibilidad de productos, o impedir que los clientes consulten el catálogo. |
| 5 | Base de datos de productos | Datos | Podrían alterarse o eliminarse productos, precios y stock, causando información incorrecta y problemas en las ventas. |
| 6 | Microservicio de productos | Software | Podría manipularse la gestión de productos o dejar a la tienda sin capacidad para consultar y administrar su catálogo. |
| 7 | Información de órdenes | Información | Podrían exponerse o modificarse compras, cantidades, clientes y valores, afectando la privacidad y confiabilidad de los pedidos. |
| 8 | Base de datos de órdenes | Datos | Podrían consultarse, modificarse o eliminarse órdenes, impidiendo mantener un registro confiable y procesar correctamente las compras. |
| 9 | Microservicio de órdenes | Servicio | Podrían ejecutarse operaciones no autorizadas, manipular pedidos o impedir que los clientes creen y gestionen órdenes. |
| 10 | API Gateway | Infraestructura | Podría permitir acceso no autorizado o manipulación de las comunicaciones y, si queda indisponible, impedir el acceso a todos los microservicios de Secure Shop. |
| 11 | Credenciales de usuarios | Información | El acceso o modificación no autorizada podría permitir la suplantación de usuarios y el acceso a funciones restringidas; su indisponibilidad impediría la autenticación. |
| 12 | Tokens de autenticación | Datos | Si son obtenidos o alterados, un atacante podría suplantar sesiones y realizar acciones sin autorización; si no están disponibles, los usuarios podrían perder acceso a los servicios protegidos. |
| 13 | Configuración del API Gateway | Software | Su acceso o modificación podría revelar o alterar rutas, controles de acceso y políticas de seguridad; su indisponibilidad podría afectar la comunicación con los microservicios. |
| 14 | Servidor de despliegue | Infraestructura | Un acceso o modificación no autorizada podría comprometer la ejecución de la aplicación; si queda indisponible, los servicios de Secure Shop podrían dejar de funcionar. |
| 15 | Logs y registros de auditoría | Datos | Su acceso podría revelar información sensible, su modificación permitiría ocultar actividades maliciosas y su indisponibilidad dificultaría detectar e investigar incidentes de seguridad. |