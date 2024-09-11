# Api-Product-Client
# Products API

Esta es una API RESTful para gestionar productos y clientes, desarrollada con Flask. La API permite realizar operaciones CRUD (Crear, Leer, Actualizar, Eliminar) sobre productos y clientes y proporciona funcionalidades adicionales como limitación de tasa de solicitudes, manejo de errores y registros de auditoría.

## Características

- **CRUD de Productos**: Permite crear, leer, actualizar y eliminar productos.
- **CRUD de Clientes**: Permite crear, leer, actualizar y eliminar clientes.
- **Validación de Datos**: Uso de Marshmallow para validar los datos de entrada.
- **Manejo de Errores**: Captura y maneja errores de HTTP y errores inesperados.
- **Limitación de Tasa**: Utiliza `flask-limiter` para controlar la tasa de solicitudes por IP.
- **Registro de Auditoría**: Registra cada solicitud entrante y cambios significativos en los registros de auditoría.
- **Pruebas Unitarias**: Incluye pruebas unitarias utilizando `unittest`.

## Requisitos

- Python 3.7 o superior
- Flask
- Flask-SQLAlchemy
- Marshmallow
- Flask-Limiter
- Werkzeug

## Uso
Para ejecutar la aplicación, usa el siguiente comando:
python app.py
La API estará disponible en http://localhost:7002/.

## Endpoints Disponibles:
- GET /products: Obtiene una lista de todos los productos.
- GET /products/<id>: Obtiene un producto específico por su ID.
- POST /product: Crea un nuevo producto.
- PUT /product/<id>: Actualiza un producto existente por su ID.
- DELETE /product/<id>: Elimina un producto existente por su ID.
- POST /clients/bulk: Crea múltiples clientes de una vez.
- POST /products/bulk: Crea múltiples productos de una vez.

## Limitación de Tasa
La aplicación utiliza Flask-Limiter para limitar la tasa de solicitudes y evitar el abuso:

- Límite por defecto: 30 solicitudes por minuto.
- Límite personalizado:
- /: 5 solicitudes por minuto.
- /products: 10 solicitudes por minuto.
- /products/<id>: 5 solicitudes por minuto.

## Pruebas
Para ejecutar las pruebas unitarias, ejecuta:
python app.py test

## Configuración de Logging
La aplicación utiliza el módulo logging para registrar todas las operaciones. Hay tres tipos de registros:

Consola: Los registros se muestran en la consola.
Archivo de Registro General: Guarda los registros generales en flask.log.
Archivo de Registro de Auditoría: Guarda los registros de auditoría en audit.log.
Contribuciones
Las contribuciones son bienvenidas. Por favor, abre un "issue" o envía un "pull request" para mejoras o correcciones.

## Licencia
Esta aplicación se distribuye bajo la licencia MIT. Consulta el archivo LICENSE para más detalles.
Este archivo README proporciona una descripción general de la aplicación, instrucciones de instalación, uso de la API, pruebas, y configuración de registros. Puedes personalizarlo según tus necesidades.
