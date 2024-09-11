import unittest
import json
from app import app, db, Product, Client  # Adjust import based on your file structure

class APITestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up the test client and database."""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        cls.client = app.test_client()
        with app.app_context():
            db.create_all()

    @classmethod
    def tearDownClass(cls):
        """Tear down the database after tests."""
        with app.app_context():
            db.drop_all()

    def test_create_product(self):
        """Test creating a product."""
        response = self.client.post('/product', json={
            'name': 'Test Product',
            'description': 'Test Description',
            'price': 99.99,
            'quantity': 10
        })
        self.assertEqual(response.status_code, 201)
        self.assertIn('Test Product', response.get_data(as_text=True))

    def test_get_products(self):
        """Test retrieving all products."""
        self.client.post('/product', json={
            'name': 'Test Product',
            'description': 'Test Description',
            'price': 99.99,
            'quantity': 10
        })
        response = self.client.get('/products')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Test Product', response.get_data(as_text=True))

    def test_get_product(self):
        """Test retrieving a specific product by ID."""
        new_product = self.client.post('/product', json={
            'name': 'Unique Product',
            'description': 'Unique Description',
            'price': 199.99,
            'quantity': 20
        })
        product_id = json.loads(new_product.data)['id']
        response = self.client.get(f'/products/{product_id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Unique Product', response.get_data(as_text=True))

    def test_update_product(self):
        """Test updating a product."""
        new_product = self.client.post('/product', json={
            'name': 'Update Product',
            'description': 'Old Description',
            'price': 49.99,
            'quantity': 5
        })
        product_id = json.loads(new_product.data)['id']
        response = self.client.put(f'/product/{product_id}', json={
            'name': 'Updated Product',
            'description': 'New Description',
            'price': 59.99,
            'quantity': 10
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('Updated Product', response.get_data(as_text=True))

    def test_delete_product(self):
        """Test deleting a product."""
        new_product = self.client.post('/product', json={
            'name': 'Delete Product',
            'description': 'Delete Description',
            'price': 29.99,
            'quantity': 2
        })
        product_id = json.loads(new_product.data)['id']
        response = self.client.delete(f'/product/{product_id}')
        self.assertEqual(response.status_code, 200)
        self.assertIn('Product with id', response.get_data(as_text=True))

    def test_bulk_create_clients(self):
        """Test bulk creation of clients."""
        response = self.client.post('/clients/bulk', json=[
            {'name': 'Client A', 'email': 'clienta@example.com'},
            {'name': 'Client B', 'email': 'clientb@example.com'}
        ])
        self.assertEqual(response.status_code, 201)
        self.assertIn('Client A', response.get_data(as_text=True))

    def test_bulk_create_products(self):
        """Test bulk creation of products."""
        response = self.client.post('/products/bulk', json=[
            {'name': 'Bulk Product A', 'description': 'Bulk Description A', 'price': 149.99, 'quantity': 15},
            {'name': 'Bulk Product B', 'description': 'Bulk Description B', 'price': 249.99, 'quantity': 25}
        ])
        self.assertEqual(response.status_code, 201)
        self.assertIn('Bulk Product A', response.get_data(as_text=True))

if __name__ == '__main__':
    unittest.main()
