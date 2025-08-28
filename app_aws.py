from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import uuid
import boto3
from botocore.exceptions import ClientError
import json
from dotenv import load_dotenv
from decimal import Decimal
import logging

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-this-in-production')

# AWS Configuration
AWS_REGION = 'us-east-1'
USERS_TABLE = 'courierbuddy_users'
PARCELS_TABLE = 'courierbuddy_parcels'
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:604665149129:courier_buddy_topic'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize AWS clients
try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    sns_client = boto3.client('sns', region_name=AWS_REGION)
    users_table = dynamodb.Table(USERS_TABLE)
    parcels_table = dynamodb.Table(PARCELS_TABLE)
    logger.info("AWS services initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize AWS services: {e}")
    raise

def to_decimal(value):
    if isinstance(value, float):
        return Decimal(str(value))
    return value

def serialize_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, Decimal):
        return float(obj)
    return obj

def deserialize_item(item):
    if not item:
        return None
    result = {}
    for key, value in item.items():
        if isinstance(value, str) and 'T' in value:
            try:
                result[key] = datetime.fromisoformat(value)
            except ValueError:
                result[key] = value
        elif isinstance(value, Decimal):
            result[key] = float(value)
        else:
            result[key] = value
    return result

def send_notification(message, subject="CourierBuddy Notification"):
    try:
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        logger.info(f"SNS notification sent: {response['MessageId']}")
        return True
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {e}")
        return False

# User Management
def get_user(email):
    try:
        response = users_table.get_item(Key={'email': email})
        return deserialize_item(response.get('Item'))
    except ClientError as e:
        logger.error(f"Error getting user {email}: {e}")
        return None

def create_user(email, password, name, phone, address, role):
    try:
        user_data = {
            'email': email,
            'password': generate_password_hash(password),
            'name': name,
            'phone': phone,
            'address': address,
            'role': role,
            'created_at': datetime.now().isoformat()
        }
        users_table.put_item(
            Item=user_data,
            ConditionExpression='attribute_not_exists(email)'
        )
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return False
        logger.error(f"Error creating user {email}: {e}")
        return False

# Pickup Management
def create_pickup(sender_email, pickup_address, delivery_address, package_details):
    try:
        pickup_id = f"parcel_{str(uuid.uuid4())[:8]}"
        pickup_request = {
            'pickup_id': pickup_id,
            'sender_email': sender_email,
            'pickup_address': pickup_address,
            'delivery_address': delivery_address,
            'package_details': package_details,
            'status': 'pending',
            'assigned_agent': None,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        parcels_table.put_item(Item=pickup_request)
        send_notification(
            f"New pickup scheduled by {sender_email}: {pickup_address} → {delivery_address}",
            "New Pickup Scheduled"
        )
        return pickup_id
    except ClientError as e:
        logger.error(f"Error creating pickup: {e}")
        return None

def get_pickup(pickup_id):
    try:
        response = parcels_table.get_item(Key={'pickup_id': pickup_id})
        return deserialize_item(response.get('Item'))
    except ClientError as e:
        logger.error(f"Error getting pickup {pickup_id}: {e}")
        return None

def update_pickup_status(pickup_id, status, agent_email=None):
    try:
        update_exp = "SET #status = :status, updated_at = :updated_at"
        vals = {':status': status, ':updated_at': datetime.now().isoformat()}
        names = {'#status': 'status'}
        if agent_email:
            update_exp += ", assigned_agent = :agent_email"
            vals[':agent_email'] = agent_email
        parcels_table.update_item(
            Key={'pickup_id': pickup_id},
            UpdateExpression=update_exp,
            ExpressionAttributeValues=vals,
            ExpressionAttributeNames=names
        )
        parcel = get_pickup(pickup_id)
        send_notification(
            f"Pickup {pickup_id} status updated: {status}",
            "Pickup Status Update"
        )
        return True
    except ClientError as e:
        logger.error(f"Error updating pickup status: {e}")
        return False

# Flask Routes (sample)
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            # Handle both JSON and form data
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form
            
            # Extract and validate data with defaults
            email = data.get('email', '').strip() if data.get('email') else ''
            password = data.get('password', '').strip() if data.get('password') else ''
            name = data.get('name', '').strip() if data.get('name') else ''
            phone = data.get('phone', '').strip() if data.get('phone') else ''
            address = data.get('address', '').strip() if data.get('address') else ''
            role = data.get('role', '').strip() if data.get('role') else ''
            
            # Validation - check for empty values
            if not email:
                error_msg = 'Email is required.'
                if request.is_json:
                    return jsonify({'success': False, 'message': error_msg}), 400
                flash(error_msg, 'error')
                return render_template('signup.html')
            
            if not password:
                error_msg = 'Password is required.'
                if request.is_json:
                    return jsonify({'success': False, 'message': error_msg}), 400
                flash(error_msg, 'error')
                return render_template('signup.html')
            
            if not name:
                error_msg = 'Name is required.'
                if request.is_json:
                    return jsonify({'success': False, 'message': error_msg}), 400
                flash(error_msg, 'error')
                return render_template('signup.html')
            
            if not role:
                error_msg = 'Role is required.'
                if request.is_json:
                    return jsonify({'success': False, 'message': error_msg}), 400
                flash(error_msg, 'error')
                return render_template('signup.html')
            
            if len(password) < 6:
                error_msg = 'Password must be at least 6 characters long.'
                if request.is_json:
                    return jsonify({'success': False, 'message': error_msg}), 400
                flash(error_msg, 'error')
                return render_template('signup.html')
            
            if role not in ['user', 'courier', 'admin']:
                error_msg = 'Please select a valid user type.'
                if request.is_json:
                    return jsonify({'success': False, 'message': error_msg}), 400
                flash(error_msg, 'error')
                return render_template('signup.html')
            
            # Check if user already exists
            if get_user_by_email(email) or get_delivery_agent_by_email(email):
                error_msg = 'Email already exists. Please choose a different one.'
                if request.is_json:
                    return jsonify({'success': False, 'message': error_msg}), 400
                flash(error_msg, 'error')
                return render_template('signup.html')
            
            # Create user
            success = False
            if role == 'courier':
                success = create_delivery_agent(email, password, name, phone)
            else:
                success = create_user(email, password, name, phone, address, role)
            
            if success:
                send_notification(f"New user registered: {email} ({role})", "New User Registration")
                success_msg = 'Account created successfully! Please sign in.'
                if request.is_json:
                    return jsonify({'success': True, 'message': success_msg})
                flash(success_msg, 'success')
                return redirect(url_for('login'))
            else:
                error_msg = 'Failed to create account. Please try again.'
                if request.is_json:
                    return jsonify({'success': False, 'message': error_msg}), 500
                flash(error_msg, 'error')
                return render_template('signup.html')
                
        except Exception as e:
            logger.error(f"Signup error: {e}")
            error_msg = 'An error occurred during signup. Please try again.'
            if request.is_json:
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, 'error')
            return render_template('signup.html')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        password = data.get('password')
        user = get_user(email)
        if user and check_password_hash(user['password'], password):
            session['email'] = email
            session['role'] = user['role']
            session['name'] = user['name']
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    # Implement role-based dashboard rendering
    if 'email' not in session:
        flash('Please login first', 'info')
        return redirect(url_for('login'))
    # You can return dashboard page based on user role
    return render_template('dashboard.html', name=session.get('name'), role=session.get('role'))

@app.route('/schedule_pickup', methods=['GET', 'POST'])
def schedule_pickup():
    if 'email' not in session:
        flash('Login required', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        data = request.form
        pickup_address = data.get('pickup_address')
        delivery_address = data.get('delivery_address')
        package_details = data.get('package_details')
        pickup_id = create_pickup(session['email'], pickup_address, delivery_address, package_details)
        if pickup_id:
            flash('Pickup scheduled successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Error scheduling pickup', 'error')
    return render_template('schedule_pickup.html')

@app.route('/update_status/<pickup_id>', methods=['POST'])
def update_status(pickup_id):
    data = request.form
    new_status = data.get('status')
    agent_email = data.get('agent_email')
    success = update_pickup_status(pickup_id, new_status, agent_email)
    if success:
        flash('Status updated', 'success')
    else:
        flash('Update failed', 'error')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


