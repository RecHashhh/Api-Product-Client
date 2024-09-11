# app.py

# Configuración y Aplicación
from flask import Flask, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import scoped_session, sessionmaker
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.config import dictConfig
from uuid import uuid4
import os
import json
import jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields, validate, ValidationError
from werkzeug.exceptions import HTTPException
from functools import wraps
import unittest 
app = Flask(__name__)
port_number = 7002  # puerto de trabajo

# Configuración de logging
dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s %(filename)s:%(lineno)d - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "audit": {
                "format": "[%(asctime)s] [AUDIT] %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "default",
            },
            "file": {
                "class": "logging.FileHandler",
                "filename": "flask.log",
                "formatter": "default",
            },
            "audit_file": {
                "class": "logging.FileHandler",
                "filename": "audit.log",
                "formatter": "audit",
            }
        },
        "root": {"level": "DEBUG", "handlers": ["console", "file"]},
        "loggers": {
            "audit": {"level": "INFO", "handlers": ["audit_file"], "propagate": False}
        }
    }
)

# Configuración de la base de datos
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'appH.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["30 per minute"])

# Configura la sesión dentro del contexto de la aplicación
def setup_session():
    global Session
    Session = scoped_session(sessionmaker(bind=db.engine))

# Logger de auditoría
audit_logger = app.logger.getChild('audit')

# Modelos
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Client(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email
        }

class Product(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'quantity': self.quantity
        }

# Esquemas
class ClientSchema(Schema):
    id = fields.Str(dump_only=True)  # Solo para serialización
    name = fields.Str(required=True, validate=validate.Length(min=1, max=80))
    email = fields.Email(required=True, validate=validate.Length(max=120))

class ProductSchema(Schema):
    id = fields.Str(dump_only=True)  # Solo para serialización (no se requiere en POST o PUT)
    name = fields.Str(required=True, validate=validate.Length(min=1, max=80))
    description = fields.Str(validate=validate.Length(max=200))
    price = fields.Float(required=True, validate=validate.Range(min=0))
    quantity = fields.Int(required=True, validate=validate.Range(min=0))

client_schema = ClientSchema()
client_schema_list = ClientSchema(many=True)
product_schema = ProductSchema()

# Rutas
@app.route('/')
@limiter.limit('5 per minute', override_defaults=True)
def home():
    return "Welcome to the Products API!"

@app.route('/products')
@limiter.limit('10 per minute', override_defaults=True)
def get_products():
    app.logger.info("LogInfo: Get products")
    products = Product.query.all()
    return jsonify([product.to_dict() for product in products])

@app.route('/products/<id>')
@limiter.limit('5 per minute', override_defaults=True)
def get_product(id):
    session = Session()
    product = session.get(Product, id)
    if not product:
        return f'Product with id {id} not found', 404
    return jsonify(product.to_dict())

@app.route('/product', methods=['POST'])
def post_product():
    try:
        data = product_schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400

    new_product = Product(
        name=data['name'],
        description=data.get('description', ''),
        price=data['price'],
        quantity=data.get('quantity', 0)
    )
    db.session.add(new_product)
    db.session.commit()
    audit_logger.info(f"Created product: {new_product.to_dict()}")
    return jsonify(new_product.to_dict()), 201

@app.route('/clients/bulk', methods=['POST'])
def post_clients_bulk():
    try:
        data = request.json
        if not isinstance(data, list):
            raise ValidationError("Expected a list of clients.")
        
        clients = []
        for item in data:
            client_data = client_schema.load(item)
            new_client = Client(
                name=client_data['name'],
                email=client_data['email']
            )
            db.session.add(new_client)
            clients.append(new_client)
        db.session.commit()
        return jsonify([client.to_dict() for client in clients]), 201
    except ValidationError as err:
        return jsonify(err.messages), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/products/bulk', methods=['POST'])
def post_products_bulk():
    try:
        data = request.json
        if not isinstance(data, list):
            raise ValidationError("Expected a list of products.")
        
        products = []
        for item in data:
            product_data = product_schema.load(item)
            new_product = Product(
                name=product_data['name'],
                description=product_data.get('description', ''),
                price=product_data['price'],
                quantity=product_data.get('quantity', 0)
            )
            db.session.add(new_product)
            products.append(new_product)
        db.session.commit()
        return jsonify([product.to_dict() for product in products]), 201
    except ValidationError as err:
        return jsonify(err.messages), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/product/<product_id>', methods=['PUT'])
def put_product(product_id):
    data = request.json
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.quantity = data.get('quantity', product.quantity)
    
    db.session.commit()
    
    return jsonify({
        'id': product.id,
        'name': product.name,
        'description': product.description,
        'price': product.price,
        'quantity': product.quantity
    }), 200

@app.route('/product/<product_id>', methods=['DELETE'])
def delete_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    
    db.session.delete(product)
    db.session.commit()
    
    return jsonify({'message': 'Product deleted'}), 200

# Autenticación y Autorización
SECRET_KEY = '1234'  # Cambia esto por una clave secreta más segura
JWT_EXPIRATION_DELTA = timedelta(hours=1)  # Tiempo de expiración del token

@app.route('/register', methods=['POST'])
def register():
    """Registrar un nuevo usuario."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'User already exists.'}), 400

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully.'}), 201

@app.route('/login', methods=['POST'])
def login():
    """Autenticar a un usuario y generar un token JWT."""
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        return jsonify({'error': 'Invalid username or password.'}), 401

    expiration = datetime.utcnow() + JWT_EXPIRATION_DELTA
    token = jwt.encode({'user_id': user.id, 'exp': expiration}, SECRET_KEY, algorithm='HS256')

    return jsonify({'token': token}), 200

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing.'}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token.'}), 401

        g.user_id = data['user_id']
        return f(*args, **kwargs)
    return decorator

@app.route('/protected')
@token_required
def protected():
    """Ruta protegida que solo usuarios autenticados pueden acceder."""
    return jsonify({'message': 'You have access to this protected route.'})

# Manejo de Errores
@app.errorhandler(HTTPException)
def handle_http_exception(e):
    response = jsonify({
        'error': e.description,
        'status_code': e.code
    })
    response.status_code = e.code
    return response


#SECCIÓN DE TESTEO
# Pruebas
class APITestCase(unittest.TestCase):
    def setUp(self):
        """Configuración inicial antes de cada prueba."""
        self.app = app.test_client()
        self.app.testing = True
        self.ctx = app.app_context()
        self.ctx.push()
        db.create_all()

    def tearDown(self):
        """Limpieza después de cada prueba."""
        db.session.remove()
        db.drop_all()
        self.ctx.pop()

    def test_register(self):
        """Prueba de la ruta para registrar un nuevo usuario."""
        response = self.app.post('/register', json={
            'username': 'testuser',
            'password': 'testpassword'
        })
        self.assertEqual(response.status_code, 201)
        self.assertIn('User registered successfully', response.get_data(as_text=True))

    def test_login_success(self):
    """Prueba de la ruta para iniciar sesión con credenciales correctas."""
    # Primero, registramos un usuario
    self.app.post('/register', json={
        'username': 'testuser',
        'password': 'testpassword'
    })

    response = self.app.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    self.assertEqual(response.status_code, 200)
    data = json.loads(response.data)
    self.assertIn('token', data)  # Verifica que el token esté en la respuesta

    def test_login_failure(self):
        """Prueba de la ruta para iniciar sesión con credenciales incorrectas."""
        response = self.app.post('/login', json={
            'username': 'wronguser',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 401)
        self.assertIn('Invalid username or password', response.get_data(as_text=True))

    # Incluye las pruebas anteriores para productos
    def test_get_products(self):
        """Prueba de la ruta para obtener todos los productos."""
        response = self.app.get('/products')
        self.assertEqual(response.status_code, 200)

    def test_post_product(self):
        """Prueba de la ruta para agregar un nuevo producto."""
        response = self.app.post('/product', json={
            'name': 'Test Product',
            'description': 'This is a test product.',
            'price': 19.99,
            'quantity': 10
        })
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertEqual(data['name'], 'Test Product')

    def test_put_product(self):
    """Prueba de la ruta para actualizar un producto existente."""
    # Primero, creamos un producto
    product = Product(
        name='Update Test Product',
        description='Original description',
        price=29.99,
        quantity=5
    )
    db.session.add(product)
    db.session.commit()

    response = self.app.put(f'/product/{product.id}', json={
        'name': 'Updated Product',
        'description': 'Updated description',
        'price': 39.99,
        'quantity': 15
    })
    self.assertEqual(response.status_code, 200)
    data = json.loads(response.data)
    self.assertEqual(data['name'], 'Updated Product')

    def test_delete_product(self):
    """Prueba de la ruta para eliminar un producto existente."""
    # Primero, creamos un producto
    product = Product(
        name='Delete Test Product',
        description='To be deleted',
        price=49.99,
        quantity=8
    )
    db.session.add(product)
    db.session.commit()

    response = self.app.delete(f'/product/{product.id}')
    self.assertEqual(response.status_code, 200)
    data = json.loads(response.data)
    self.assertEqual(data['message'], 'Product deleted')

        
#FIN SECCION DE TESTEO

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        unittest.main(argv=['first-arg-is-ignored'], exit=False)
    else:
        app.run(debug=True, host='0.0.0.0', port=port_number)