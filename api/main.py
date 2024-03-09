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
    return ''.join(random.choices(string.digits, k=length))
# Function to send email from Gmail
def send_email_to_express_api(to_email,otp):
    api_url = 'https://wxyaze-sarthak-io.vercel.app/sendEmail'  # Update with your Express API URL
    data = {
        'to': to_email,
        'subject': 'Welcome to Cognito🥳!',
        'body': 'Welcome to our platform!',
        'id':otp,
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


@app.route('/sendOtp', methods=['POST'])
def otpsend():
    data = request.get_json()

    # Extract email, password, and user type from request data
    email = data.get('email')
    password = data.get('password')
    userType = data.get('userType')
    user_ref = db.collection('Users').document(userType).collection(userType).where('email', '==', email).limit(1)
    user_docs = user_ref.get()

    if len(user_docs) == 1:
        return jsonify({'error': 'User Already Exist'}), 404
    # Check if email, password, or user type is missing
    if not email or not password or not userType:
        return jsonify({'error': 'Email, password, and userType are required'}), 400
     
    if not check_domain(email):
        return jsonify({'error': 'Domain does not have valid MX records'}), 422
    
    if not is_disposable(email):
        return jsonify({'error': 'Domain outside of this organisation is not allowed'}), 423

    # Generate OTP
    otp = generate_complex_id(6)

    # Save OTP in Firestore
    user_otp_ref = db.collection('Users').document(userType).collection(userType).document(email)
    user_otp_ref.set({'otp': otp})

    # Send OTP to the user's email
    if not send_email_to_express_api(email, otp):
        return jsonify({'error': 'Failed to send OTP'}), 500
    
    return jsonify({'message': 'OTP is sent to your email.'}), 201


@app.route('/sendOtpPassword', methods=['POST'])
def otpreset():
    data = request.get_json()

    # Extract email, password, and user type from request data
    email = data.get('email')
    password = data.get('password')
    userType = data.get('userType')

    user_ref = db.collection('Users').document(userType).collection(userType).where('email', '==', email).limit(1)
    user_docs = user_ref.get()

    if len(user_docs) == 0:
        return jsonify({'error': 'User does not exist'}), 404
    # Check if email, password, or user type is missing
    if not email or not password or not userType:
        return jsonify({'error': 'Email, password, and userType are required'}), 400
     
    if not check_domain(email):
        return jsonify({'error': 'Domain does not have valid MX records'}), 422
    
    if not is_disposable(email):
        return jsonify({'error': 'Domain outside of this organisation is not allowed'}), 423

    # Generate OTP
    otp = generate_complex_id(6)

    # Save OTP in Firestore
    user_otp_ref = db.collection('Users').document(userType).collection(userType).document(email)
    user_otp_ref.set({'otp': otp})

    # Send OTP to the user's email
    if not send_email_to_express_api(email, otp):
        return jsonify({'error': 'Failed to send OTP'}), 500
    
    return jsonify({'message': 'OTP is sent to your email.'}), 201

@app.route('/verification', methods=['POST'])
def verification():
    data = request.get_json()
    email = data.get('email')
    userType = data.get('userType')
    otp = data.get('otp')
    
    # Retrieve stored OTP from Firestore
    user_otp_ref = db.collection('Users').document(userType).collection(userType).document(email)
    stored_otp = user_otp_ref.get().to_dict().get('otp', None)

    # Check if the OTP matches
    if stored_otp and otp == stored_otp:
        # Delete OTP from Firestore after successful verification
        user_otp_ref.delete()
        return jsonify({'message': 'User Registered Successfully'}), 202
    
    return jsonify({'error': 'Invalid OTP.'}), 405

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    userType = data.get('userType')
    user_ref = db.collection('Users').document(userType).collection(userType).document(email)
    user_data = {'email': email, 'password': password}  # You should hash the password before storing it
    user_ref.set(user_data)
    return jsonify({'message': 'User Registered Successfully'}), 202
    


if __name__ == '__main__':
    app.run(debug=True)
