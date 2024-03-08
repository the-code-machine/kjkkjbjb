from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, firestore
from flask_cors import CORS
import dns.resolver
import requests
import string
import random
app = Flask(__name__)
CORS(app)

# Initialize Firestore DB
cred = credentials.Certificate("api/cognito-sati-firebase-adminsdk-tkghu-2491dadf30.json")  # Provide path to your service account key JSON file
firebase_admin.initialize_app(cred)
db = firestore.client()

def generate_complex_id(length=6):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))
id=generate_complex_id()
email=""
password=""
userType=""
# Function to send email from Gmail
def send_email_to_express_api(to_email):
    api_url = 'https://wxyaze-sarthak-io.vercel.app/sendEmail'  # Update with your Express API URL
    data = {
        'to': to_email,
        'subject': 'Welcome to Cognito🥳!',
        'body': 'Welcome to our platform!',
        'id':id,
    }

    try:
        # Make POST request to Express API
        response = requests.post(api_url, json=data)
        if response.status_code == 200:
            print("Email sent successfully")
            return True
        else:
            print("Error sending email")
            return False
    except Exception as e:
        print("Error:", e)
        return False


def check_domain(email):
    domain = email.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if mx_records:
            return True
    except:
        return False
disposable_domains = ['satiengg.in']  # Add more domains as needed
def is_disposable(email):
    domain = email.split('@')[-1]
    if domain in disposable_domains:
        return True
    return False

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # Extract email and password from request data
    email = data.get('email')
    password = data.get('password')
    userType = data.get('userType')

    # Check if email or password is missing
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Query Firestore to check if user exists and credentials are correct
    user_ref = db.collection('Users').document(userType).collection(userType).where('email', '==', email).limit(1)
    user_docs = user_ref.get()

    if len(user_docs) == 0:
        return jsonify({'error': 'User does not exist'}), 404

    user_data = user_docs[0].to_dict()
    if user_data['password'] != password:
        return jsonify({'error': 'Incorrect password'}), 401

    return jsonify({'message': 'Login successful'}), 200


# Route to handle registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Extract email, password, and user type from request data
    email = data.get('email')
    password = data.get('password')
    userType = data.get('userType')

    # Check if email, password, or user type is missing
    if not email or not password or not userType:
        return jsonify({'error': 'Email, password, and userType are required'}), 400
     

    if not check_domain(email):
        return jsonify({'error': 'Domain does not have valid MX records'}), 422
    
    if not is_disposable(email):
        return jsonify({'error': 'Domain outside of this organisation is not allowed'}), 423
        # Check if user already exists
    user_ref = db.collection('Users').document(userType).collection(userType).document(email)
    if user_ref.get().exists:
        return jsonify({'error': 'User already exists'}), 409
    if not send_email_to_express_api(email):
        return jsonify({'error': 'Email Address not found.'}), 423
    return jsonify({'message': 'Otp is sent to your email.'}), 201

@app.route('/verfication', methods=['POST'])
def verfication():
    data = request.get_json()
    otp = data.get('otp')
    if otp==id:
        user_ref = db.collection('Users').document(userType).collection(userType).document(email)
         # Store user data in Firestore
        user_data = {'email': email, 'password': password}  # You should hash the password before storing it
        user_ref.set(user_data)
        return jsonify({'message': 'User Registered Successfully'}), 202
    return jsonify({'message': 'Otp is not valid.'}), 405
if __name__ == '__main__':
    app.run(debug=True)


