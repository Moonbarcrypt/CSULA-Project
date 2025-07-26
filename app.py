# Import necessary modules from Flask and Flask-SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify 
from flask_sqlalchemy import SQLAlchemy
import os 
from sqlalchemy.exc import IntegrityError 
import base64 
import random 
import re     

# --- App Configuration ---
app = Flask(__name__)

# Configure SQLite database file path
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iot_devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

# IMPORTANT: Set a strong, random secret key for security in production!
app.config['SECRET_KEY'] = 'your_new_strong_random_secret_key_for_iot_app_CHANGE_THIS_IN_PROD!' 

# Initialize SQLAlchemy with the Flask app
db = SQLAlchemy(app)

# --- Database Model Definitions ---
# Defines the 'device' table structure in the database (for whitelisted devices)
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=False) 
    assigned_number = db.Column(db.Integer, unique=True, nullable=False)
    device_name = db.Column(db.String(100), nullable=False)
    encrypted_device_name = db.Column(db.String(200), nullable=False) 
    mac_address = db.Column(db.String(17), unique=True, nullable=False) 
    
    # String representation for debugging
    def __repr__(self):
        return f"Device('{self.user_name}', '{self.assigned_number}', '{self.device_name}', '{self.encrypted_device_name}', '{self.mac_address}')"

# NEW MODEL: Defines the 'quarantined_device' table structure
class QuarantinedDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False)

    def __repr__(self):
        return f"QuarantinedDevice('{self.mac_address}')"


# --- Helper Function for Number Assignment ---
# Calculates the next available unique assigned number
def get_next_assigned_number():
    max_number_device = Device.query.order_by(Device.assigned_number.desc()).first()
    
    if max_number_device:
        return max_number_device.assigned_number + 1
    else:
        return 1001 

# --- Encryption Simulation Function ---
# This function simulates encryption using Base64 encoding.
def simulate_encrypt(data_string):
    encoded_bytes = base64.b64encode(data_string.encode('utf-8'))
    return encoded_bytes.decode('utf-8')

# --- Random MAC Address Generation Function ---
# Generates a random, plausible-looking MAC address.
def generate_random_mac():
    return ':'.join(['{:02x}'.format(random.randint(0x00, 0xFF)) for _ in range(6)]).upper()

# --- Simulated Network Device Detection Function ---
# This function now generates dummy MAC addresses to simulate detection.
# It will generate a few random MACs that are *not* currently registered
# to show up as "unregistered".
def get_network_mac_addresses():
    detected_macs = set()
    
    # Add a few random MAC addresses that are likely NOT registered
    for _ in range(3): # Generate 3 random "unregistered" MACs
        detected_macs.add(generate_random_mac())

    # To make the demo more dynamic, let's also add some MACs from currently
    # registered devices to the 'detected' list, so the "unregistered" list
    # only shows truly new ones.
    # We'll fetch existing MACs from the DB later in the /api/scan_network route.
    
    return detected_macs

# --- Routes Definition ---

# Home page route
@app.route('/')
def index():
    return render_template('index.html')

# Device registration form (GET request)
@app.route('/register', methods=['GET'])
def register():
    return render_template('register.html')

# Handles device registration form submission (POST request)
@app.route('/register_device', methods=['POST'])
def register_device():
    user_name = request.form.get('user_name') 
    device_name = request.form.get('device_name')
    # Re-enable MAC address input from form for demo purposes
    mac_address = request.form.get('mac_address') 

    # Validate MAC address format (simple check)
    if mac_address:
        mac_address = mac_address.strip().replace('-', ':').upper()
        if not re.fullmatch(r'([0-9A-F]{2}:){5}[0-9A-F]{2}', mac_address):
            flash('Invalid MAC address format. Please use XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX.', 'error')
            return render_template('register.html', error="Invalid MAC address format.")
    else:
        # If MAC is not provided, generate a random one (fallback)
        mac_address = generate_random_mac()
        while Device.query.filter_by(mac_address=mac_address).first():
            mac_address = generate_random_mac()


    if user_name and device_name:
        try:
            # Check if MAC address already exists in DB (for manual input)
            existing_mac = Device.query.filter_by(mac_address=mac_address).first()
            if existing_mac:
                flash(f'Device with MAC address {mac_address} is already registered.', 'error')
                return render_template('register.html', error=f"MAC address {mac_address} already registered.")

            assigned_number = get_next_assigned_number()
            encrypted_name = simulate_encrypt(device_name.strip())

            new_device = Device(
                user_name=user_name.strip(), 
                assigned_number=assigned_number, 
                device_name=device_name.strip(),
                encrypted_device_name=encrypted_name,
                mac_address=mac_address 
            )

            db.session.add(new_device)
            db.session.commit()

            # NEW LOGIC: If this device was previously quarantined, unquarantine it
            quarantined_entry = QuarantinedDevice.query.filter_by(mac_address=mac_address).first()
            if quarantined_entry:
                db.session.delete(quarantined_entry)
                db.session.commit()
                flash(f'Device {device_name} registered and unquarantined successfully!', 'success')
            else:
                flash('Device registered successfully!', 'success') 
            
            return redirect(url_for('whitelist'))
        except Exception as e:
            db.session.rollback() 
            app.logger.error(f"Error registering device: {e}") 
            flash('An error occurred during registration. Please try again.', 'error') 
            return render_template('register.html', error="An error occurred during registration. Please try again.")
    else:
        flash('Please enter all required fields.', 'error') 
        return render_template('register.html', error="Please enter all required fields.")

# Displays the list of whitelisted devices
@app.route('/whitelist')
def whitelist():
    registered_devices = Device.query.order_by(Device.assigned_number).all()
    return render_template(
        'whitelist.html', 
        devices=registered_devices
    )

# Displays the Network Scan page (initial load)
@app.route('/network_scan')
def network_scan_page():
    return render_template('network_scan.html')

# API ROUTE: To perform the actual scan and return JSON
@app.route('/api/scan_network', methods=['GET'])
def api_scan_network():
    registered_macs = {d.mac_address for d in Device.query.all()}
    quarantined_macs_db = {q.mac_address for q in QuarantinedDevice.query.all()} 
    
    detected_macs = get_network_mac_addresses()
    
    # Add some registered MACs to detected_macs to simulate them being seen
    num_to_add = min(len(registered_macs), 2) 
    if num_to_add > 0:
        detected_macs.update(random.sample(list(registered_macs), num_to_add))

    unregistered_macs = detected_macs - registered_macs - quarantined_macs_db

    return jsonify(
        unregistered_macs=list(unregistered_macs),
        quarantined_macs=list(quarantined_macs_db)
    )

# API ROUTE: To quarantine a device
@app.route('/api/quarantine_device', methods=['POST'])
def api_quarantine_device():
    mac_address = request.json.get('mac_address')
    if not mac_address:
        return jsonify(success=False, message="MAC address is required."), 400

    try:
        if QuarantinedDevice.query.filter_by(mac_address=mac_address).first():
            return jsonify(success=False, message=f"MAC {mac_address} is already quarantined."), 409 

        new_quarantined = QuarantinedDevice(mac_address=mac_address)
        db.session.add(new_quarantined)
        db.session.commit()
        return jsonify(success=True, message=f"MAC {mac_address} quarantined successfully!")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error quarantining MAC {mac_address}: {e}")
        return jsonify(success=False, message="An error occurred during quarantine."), 500

# API ROUTE: To unquarantine a device (if needed manually, though registration handles it)
# This route is now explicitly added for manual unquarantine from the network scan page
@app.route('/api/unquarantine_device', methods=['POST'])
def api_unquarantine_device():
    mac_address = request.json.get('mac_address')
    if not mac_address:
        return jsonify(success=False, message="MAC address is required."), 400

    try:
        quarantined_entry = QuarantinedDevice.query.filter_by(mac_address=mac_address).first()
        if quarantined_entry:
            db.session.delete(quarantined_entry)
            db.session.commit()
            return jsonify(success=True, message=f"MAC {mac_address} unquarantined successfully!")
        else:
            return jsonify(success=False, message=f"MAC {mac_address} not found in quarantine list."), 404
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error unquarantining MAC {mac_address}: {e}")
        return jsonify(success=False, message="An error occurred during unquarantine."), 500


# Handles deletion of a specific device (POST request)
@app.route('/delete/<int:device_id>', methods=['POST'])
def delete_device(device_id):
    device = Device.query.get_or_404(device_id) 
    try:
        db.session.delete(device)
        db.session.commit()
        flash('Device deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting device {device_id}: {e}")
        flash('An error occurred while deleting the device.', 'error')
    return redirect(url_for('whitelist'))

# Handles displaying and processing the form for editing a specific device
@app.route('/edit/<int:device_id>', methods=['GET', 'POST'])
def edit_device(device_id):
    device = Device.query.get_or_404(device_id) 

    if request.method == 'POST':
        user_name = request.form['user_name'].strip()
        device_name = request.form['device_name'].strip()
        
        try:
            device.user_name = user_name
            device.device_name = device_name
            device.encrypted_device_name = simulate_encrypt(device_name)
            
            db.session.commit()
            flash('Device updated successfully!', 'success')
            return redirect(url_for('whitelist'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating device {device_id}: {e}")
            flash('An error occurred while updating the device.', 'error')
            return render_template('edit_device.html', device=device, error="An error occurred during update.")
            
    return render_template('edit_device.html', device=device) 

# --- Application Entry Point ---
# This block runs when you execute app.py directly
if __name__ == '__main__':
    with app.app_context():
        # Drop and recreate all tables for a clean slate in development
        db.drop_all() 
        print("Dropped all existing tables.")
        db.create_all() 
        print("Recreated all tables.")
        
        # Print paths for debugging
        print(f"Flask instance path: {app.instance_path}")
        print(f"Database path: {os.path.join(app.instance_path, 'iot_devices.db')}")
        
        # Function to add initial dummy data
        def add_dummy_data():
            current_device_count = Device.query.count()
            print(f"Current device count before dummy data check: {current_device_count}")

            if current_device_count == 0: 
                print("Adding dummy data...")
                # Generate random MAC addresses for dummy data
                devices_to_add = [
                    {'user_name': 'Dichill', 'device_name': 'Alexa', 'assigned_number': 1001, 'mac_address': generate_random_mac()},
                    {'user_name': 'Juan', 'device_name': 'Connected Camera', 'assigned_number': 1002, 'mac_address': generate_random_mac()},
                    {'user_name': 'Fahat', 'device_name': 'Smart TV', 'assigned_number': 1003, 'mac_address': generate_random_mac()},
                    {'user_name': 'Charlie', 'device_name': 'Ring Camera', 'assigned_number': 1004, 'mac_address': generate_random_mac()}
                ]
                for data in devices_to_add:
                    try:
                        encrypted_name_dummy = simulate_encrypt(data['device_name'])
                        
                        existing_device = Device.query.filter_by(assigned_number=data['assigned_number']).first()
                        if not existing_device:
                            device = Device(
                                user_name=data['user_name'], 
                                assigned_number=data['assigned_number'], 
                                device_name=data['device_name'],
                                encrypted_device_name=encrypted_name_dummy,
                                mac_address=data['mac_address'] 
                            )
                            db.session.add(device)
                        else:
                            print(f"Skipping dummy device {data['assigned_number']} as it already exists.")
                    except IntegrityError:
                        db.session.rollback()
                        print(f"IntegrityError: Device with assigned number {data['assigned_number']} or MAC {data['mac_address']} already exists. Rolling back.")
                    except Exception as e:
                        db.session.rollback()
                        print(f"Error adding dummy device {data['assigned_number']}: {e}")
            
                try:
                    db.session.commit()
                    print("Dummy data added successfully.")
                except Exception as e:
                    db.session.rollback()
                    print(f"Error committing dummy data: {e}")
            else:
                print("Database already contains data, skipping dummy data addition.")
        
        add_dummy_data() 

    # Run the Flask development server
    app.run(debug=True)

