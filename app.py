import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import re # Import regular expression module for MAC validation
import random # For generating random MACs if not provided
from datetime import datetime # Import datetime for timestamps

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'iot_devices.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# IMPORTANT: Change this to a strong, random key in production!
# You can generate one with: import os; os.urandom(24).hex()
app.secret_key = 'your_super_secret_key_here_please_change_this_to_a_long_random_string' 

db = SQLAlchemy(app)

# Define the Device model
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=False)
    device_name = db.Column(db.String(100), nullable=False)
    mac_address = db.Column(db.String(17), unique=True, nullable=True) # MAC address can be null for non-network devices
    is_whitelisted = db.Column(db.Boolean, default=False)
    is_watchlist = db.Column(db.Boolean, default=False)
    
    # New fields for Device Type, Last Seen, and Status
    device_type = db.Column(db.String(50), nullable=True) # e.g., "Laptop", "Phone", "Smart TV"
    last_seen = db.Column(db.DateTime, nullable=True) # Timestamp of last detection
    status = db.Column(db.String(20), default='Offline') # e.g., "Online", "Offline", "Unknown"

    def __repr__(self):
        return f'<Device {self.device_name} ({self.mac_address})>'

# Helper function to validate MAC address format
def is_valid_mac(mac):
    # Regex for MAC address (e.g., AA:BB:CC:DD:EE:FF or AA-BB-CC-DD:EE:FF)
    if mac is None:
        return True # Allow None if MAC is optional
    return re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac)

# Function to create dummy data
def create_dummy_data():
    if Device.query.count() == 0: # Only add if database is empty
        print("Adding dummy data...")
        current_time = datetime.now()
        dummy_devices = [
            Device(user_name='John Doe', device_name='Johns Laptop', mac_address='00:1A:2B:3C:4D:5E', 
                   is_whitelisted=True, is_watchlist=False, device_type='Laptop', last_seen=current_time, status='Online'),
            Device(user_name='Jane Smith', device_name='Smart TV', mac_address='00:1A:2B:3C:4D:60', 
                   is_whitelisted=True, is_watchlist=False, device_type='Smart TV', last_seen=current_time, status='Online'),
            Device(user_name='Guest', device_name='Guest Phone', mac_address='00:1A:2B:3C:4D:62', 
                   is_whitelisted=False, is_watchlist=True, device_type='Smartphone', last_seen=current_time, status='Online'),
            Device(user_name='Home Automation', device_name='Smart Hub', mac_address='00:1A:2B:3C:4D:64', 
                   is_whitelisted=True, is_watchlist=False, device_type='Smart Hub', last_seen=current_time, status='Online'),
            Device(user_name='Unknown User', device_name='Suspicious Device', mac_address='00:1A:2B:3C:4D:66', 
                   is_whitelisted=False, is_watchlist=True, device_type='Unknown', last_seen=current_time, status='Online')
        ]
        db.session.add_all(dummy_devices)
        db.session.commit()
        print("Dummy data added successfully!")
    else:
        print("Database already contains data, skipping dummy data creation.")


# Create database tables if they don't exist, then add dummy data if empty
with app.app_context():
    # IMPORTANT: Drop all tables to ensure a clean slate for dummy data during development.
    # Do NOT use db.drop_all() in a production environment unless you intend to wipe all data.
    db.drop_all()
    print("Dropped all existing tables.")
    db.create_all()
    print("Recreated all tables.")
    create_dummy_data() # Call the dummy data function here

# --- Routes ---

@app.route('/')
def index():
    """Renders the home page."""
    return render_template('index.html')

@app.route('/device_list')
def device_list_page():
    """Renders the device list page, showing whitelisted and watchlisted devices."""
    whitelisted_devices = Device.query.filter_by(is_whitelisted=True).all()
    watchlist_devices = Device.query.filter_by(is_watchlist=True).all()
    
    return render_template('device_list.html', 
                           whitelisted_devices=whitelisted_devices,
                           watchlist_devices=watchlist_devices)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles device registration, automatically whitelisting new devices."""
    mac_address_prefill = request.args.get('mac') 
    
    if request.method == 'POST':
        user_name = request.form['user_name']
        device_name = request.form['device_name']
        mac_address = request.form['mac_address'].strip().upper() if request.form['mac_address'] else None
        device_type = request.form['device_type'] # Get device type from form
        
        if mac_address and not is_valid_mac(mac_address):
            flash('Invalid MAC address format. Please use AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF.', 'error')
            return render_template('register.html', mac_address_prefill=mac_address, user_name=user_name, device_name=device_name, device_type=device_type)

        if mac_address is None:
            def generate_random_mac():
                return ':'.join(['{:02x}'.format(random.randint(0x00, 0xFF)) for _ in range(6)]).upper()
            
            mac_address = generate_random_mac()
            while Device.query.filter_by(mac_address=mac_address).first():
                mac_address = generate_random_mac()

        if mac_address and Device.query.filter_by(mac_address=mac_address).first():
            flash('A device with this MAC address is already registered.', 'error')
            return render_template('register.html', mac_address_prefill=mac_address, user_name=user_name, device_name=device_name, device_type=device_type)
        
        # Automatically whitelist and do not watchlist new registrations
        new_device = Device(user_name=user_name, device_name=device_name, 
                            mac_address=mac_address, is_whitelisted=True, 
                            is_watchlist=False, device_type=device_type,
                            last_seen=datetime.now(), status='Online') # Set initial status and last_seen
        db.session.add(new_device)
        db.session.commit()

        flash('Device registered successfully and added to Network Devices!', 'success')
        return redirect(url_for('device_list_page'))
    
    return render_template('register.html', mac_address_prefill=mac_address_prefill)

@app.route('/edit_device/<int:device_id>', methods=['GET', 'POST'])
def edit_device(device_id):
    """Handles editing an existing device's details."""
    device = Device.query.get_or_404(device_id)
    if request.method == 'POST':
        device.user_name = request.form['user_name']
        device.device_name = request.form['device_name']
        device.device_type = request.form['device_type'] # Update device type
        # MAC address is not editable via this form as per the template
        # is_whitelisted and is_watchlist can be updated from the form
        device.is_whitelisted = 'is_whitelisted' in request.form
        device.is_watchlist = 'is_watchlist' in request.form

        # Ensure mutual exclusivity if both are submitted
        if device.is_whitelisted and device.is_watchlist:
            flash('A device cannot be both whitelisted and watchlisted. Please choose one.', 'error')
            return render_template('edit_device.html', device=device)
        
        db.session.commit()
        flash('Device updated successfully!', 'success')
        return redirect(url_for('device_list_page'))
    return render_template('edit_device.html', device=device)

@app.route('/delete_device/<int:device_id>', methods=['POST'])
def delete_device(device_id):
    """Handles deleting a device."""
    device = Device.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    flash('Device deleted successfully!', 'success')
    return redirect(url_for('device_list_page'))

@app.route('/toggle_whitelist/<int:device_id>', methods=['POST'])
def toggle_whitelist(device_id):
    """Toggles the whitelisted status of a device."""
    device = Device.query.get_or_404(device_id)
    device.is_whitelisted = not device.is_whitelisted
    # If whitelisted, ensure it's not watchlisted
    if device.is_whitelisted:
        device.is_watchlist = False
    db.session.commit()
    flash(f'{device.device_name} whitelist status updated.', 'info')
    return redirect(url_for('device_list_page'))

@app.route('/toggle_watchlist/<int:device_id>', methods=['POST'])
def toggle_watchlist(device_id):
    """Toggles the watchlisted status of a device."""
    device = Device.query.get_or_404(device_id)
    device.is_watchlist = not device.is_watchlist
    # If watchlisted, ensure it's not whitelisted
    if device.is_watchlist:
        device.is_whitelisted = False
    db.session.commit()
    flash(f'{device.device_name} watchlist status updated.', 'info')
    return redirect(url_for('device_list_page'))

@app.route('/network_scan', methods=['GET', 'POST'])
def network_scan_page():
    """
    Handles network scanning and displays results.
    Results are stored in the session for persistence.
    Updates status and last_seen for known devices.
    """
    scan_results = session.get('scan_results', []) 
    potential_intrusion_alert = session.get('potential_intrusion_alert', False)
    
    if request.method == 'POST':
        # Simulate network scan results
        # These MACs should ideally overlap with some dummy data MACs
        # and include some new/unknown ones.
        dummy_scan_data = [
            {'mac': '00:1A:2B:3C:4D:5E', 'ip': '192.168.1.101'}, # John's Laptop (Known)
            {'mac': '00:1A:2B:3C:4D:5F', 'ip': '192.168.1.102'}, # Unknown
            {'mac': '00:1A:2B:3C:4D:60', 'ip': '192.168.1.103'}, # Smart TV (Known)
            {'mac': '00:1A:2B:3C:4D:61', 'ip': '192.168.1.104'}, # Unknown
            {'mac': '00:1A:2B:3C:4D:64', 'ip': '192.168.1.105'}, # Smart Hub (Known)
            {'mac': 'AA:BB:CC:DD:EE:FF', 'ip': '192.168.1.106'}  # Another Unknown
        ]

        # Reset all existing devices to 'Offline' before processing current scan
        # This ensures devices not in the current scan are marked offline
        all_registered_devices = Device.query.all()
        for device in all_registered_devices:
            device.status = 'Offline'
        db.session.commit() # Commit this bulk update

        scan_results = []
        potential_intrusion_alert = False

        for item in dummy_scan_data:
            mac = item['mac']
            ip = item['ip']
            
            existing_device = Device.query.filter_by(mac_address=mac).first()
            
            if existing_device:
                # Device is known: update its status to Online and last_seen timestamp
                existing_device.status = 'Online'
                existing_device.last_seen = datetime.now()
                db.session.add(existing_device) # Add to session for commit
                
                scan_results.append({
                    'mac': mac,
                    'ip': ip,
                    'status': 'Known',
                    'device_name': existing_device.device_name,
                    'device_id': existing_device.id,
                    'device_type': existing_device.device_type, # Pass device type
                    'last_seen': existing_device.last_seen.strftime('%Y-%m-%d %H:%M:%S') # Format for display
                })
            else:
                # Device is unknown/new
                scan_results.append({
                    'mac': mac,
                    'ip': ip,
                    'status': 'Unknown',
                    'device_name': 'New Device', # Display this user-friendly name
                    'device_id': None, 
                    'device_type': 'Unknown', # Default type for unknown
                    'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S') # Last seen now
                })
                potential_intrusion_alert = True 
        
        db.session.commit() # Commit all updates (status and last_seen for known devices)

        session['scan_results'] = scan_results 
        session['potential_intrusion_alert'] = potential_intrusion_alert 

        if potential_intrusion_alert:
            flash('Potential Intrusion Alert! New devices detected on your network.', 'error')
        else:
            flash('Network scan completed. No new devices found.', 'success')

        return redirect(url_for('network_scan_page'))
    
    # On GET request, render the template with results retrieved from session
    return render_template('network_scan.html', 
                           scan_results=scan_results, 
                           potential_intrusion_alert=potential_intrusion_alert)

if __name__ == '__main__':
    app.run(debug=True)