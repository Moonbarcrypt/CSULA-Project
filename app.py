import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
import random
from datetime import datetime

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'iot_devices.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_super_secret_key_here_please_change_this_to_a_long_random_string' 

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

# --- Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    devices = db.relationship('Device', backref='owner', lazy=True) 
    alerts = db.relationship('Alert', backref='recipient', lazy=True) 

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    user_name = db.Column(db.String(100), nullable=False) 
    device_name = db.Column(db.String(100), nullable=False)
    mac_address = db.Column(db.String(17), unique=True, nullable=True) 
    is_whitelisted = db.Column(db.Boolean, default=False)
    is_watchlist = db.Column(db.Boolean, default=False)
    device_type = db.Column(db.String(50), nullable=True) 
    last_seen = db.Column(db.DateTime, nullable=True) 
    status = db.Column(db.String(20), default='Offline') 

    def __repr__(self):
        return f'<Device {self.device_name} ({self.mac_address}) by User {self.user_id}>'

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    is_read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Alert {self.id} for User {self.user_id}: {self.message[:20]}...>'

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper function to validate MAC address format
def is_valid_mac(mac):
    if mac is None: 
        return True 
    return re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac)

# Function to create dummy data
def create_dummy_data():
    if User.query.count() == 0: 
        print("Adding dummy user and data...")
        default_user = User(username='testuser')
        default_user.set_password('password') 
        db.session.add(default_user)
        db.session.commit() 

        current_time = datetime.now()
        dummy_devices = [
            Device(user_id=default_user.id, user_name='John Doe', device_name='Johns Laptop', mac_address='00:1A:2B:3C:4D:5E', 
                   is_whitelisted=True, is_watchlist=False, device_type='Laptop', last_seen=current_time, status='Online'),
            Device(user_id=default_user.id, user_name='Jane Smith', device_name='Smart TV', mac_address='00:1A:2B:3C:4D:60', 
                   is_whitelisted=True, is_watchlist=False, device_type='Smart TV', last_seen=current_time, status='Online'),
            Device(user_id=default_user.id, user_name='Guest', device_name='Guest Phone', mac_address='00:1A:2B:3C:4D:62', 
                   is_whitelisted=False, is_watchlist=True, device_type='Smartphone', last_seen=current_time, status='Online'),
            Device(user_id=default_user.id, user_name='Home Automation', device_name='Smart Hub', mac_address='00:1A:2B:3C:4D:64', 
                   is_whitelisted=True, is_watchlist=False, device_type='Smart Hub', last_seen=current_time, status='Online'),
            Device(user_id=default_user.id, user_name='Unknown User', device_name='Suspicious Device', mac_address='00:1A:2B:3C:4D:66', 
                   is_whitelisted=False, is_watchlist=True, device_type='Unknown', last_seen=current_time, status='Online')
        ]
        db.session.add_all(dummy_devices)

        dummy_alerts = [
            Alert(user_id=default_user.id, message='Initial setup complete! Welcome to Device Manager.', timestamp=datetime.now(), is_read=False),
            Alert(user_id=default_user.id, message='New device detected: 00:1A:2B:3C:4D:5F', timestamp=datetime.now(), is_read=False)
        ]
        db.session.add_all(dummy_alerts)

        db.session.commit()
        print("Dummy user and data added successfully!")
    else:
        print("Database already contains user data, skipping dummy data creation.")


with app.app_context():
    db.drop_all()
    print("Dropped all existing tables.")
    db.create_all()
    print("Recreated all tables.")
    create_dummy_data() 

# --- Routes ---

@app.route('/')
def index():
    """Renders the public home page."""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('device_list_page')) 
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next') 
            return redirect(next_page or url_for('device_list_page')) 
        else:
            flash('Login Unsuccessful. Please check username and password', 'error')
    return render_template('login.html')

@app.route('/register_user', methods=['GET', 'POST'])
@login_required
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register_user.html', username=username)
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register_user.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/device_list')
@login_required 
def device_list_page():
    """Renders the device list page, showing whitelisted and watchlisted devices for the current user."""
    whitelisted_devices = Device.query.filter_by(user_id=current_user.id, is_whitelisted=True).all()
    watchlist_devices = Device.query.filter_by(user_id=current_user.id, is_watchlist=True).all()
    
    return render_template('device_list.html', 
                           whitelisted_devices=whitelisted_devices,
                           watchlist_devices=watchlist_devices)

@app.route('/register', methods=['GET', 'POST'])
@login_required 
def register():
    """Handles device registration, automatically whitelisting new devices for the current user."""
    mac_address_prefill = request.args.get('mac') 
    
    if request.method == 'POST':
        user_name = request.form['user_name'] 
        device_name = request.form['device_name']
        mac_address = request.form['mac_address'].strip().upper()
        if not mac_address: 
            mac_address = None
            
        device_type = request.form['device_type'] 
        
        if mac_address and not is_valid_mac(mac_address):
            flash('Invalid MAC address format. Please use AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF.', 'error')
            return render_template('register.html', mac_address_prefill=mac_address, user_name=user_name, device_name=device_name, device_type=device_type)

        if mac_address is None:
            def generate_random_mac():
                return ':'.join(['{:02x}'.format(random.randint(0x00, 0xFF)) for _ in range(6)]).upper()
            
            mac_address = generate_random_mac()
            while Device.query.filter_by(mac_address=mac_address).first():
                mac_address = generate_random_mac()

        if Device.query.filter_by(user_id=current_user.id, mac_address=mac_address).first():
            flash('A device with this MAC address is already registered by you.', 'error')
            return render_template('register.html', mac_address_prefill=mac_address, user_name=user_name, device_name=device_name, device_type=device_type)
        
        new_device = Device(user_id=current_user.id, user_name=user_name, device_name=device_name, 
                            mac_address=mac_address, is_whitelisted=True, 
                            is_watchlist=False, device_type=device_type,
                            last_seen=datetime.now(), status='Online') 
        db.session.add(new_device)
        db.session.commit()

        flash('Device registered successfully and added to Network Devices!', 'success')
        return redirect(url_for('device_list_page'))
    
    return render_template('register.html', mac_address_prefill=mac_address_prefill)

@app.route('/edit_device/<int:device_id>', methods=['GET', 'POST'])
@login_required 
def edit_device(device_id):
    """Handles editing an existing device's details for the current user."""
    device = Device.query.filter_by(id=device_id, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        device.user_name = request.form['user_name']
        device.device_name = request.form['device_name']
        device.device_type = request.form['device_type'] 
        device.is_whitelisted = 'is_whitelisted' in request.form
        device.is_watchlist = 'is_watchlist' in request.form

        if device.is_whitelisted and device.is_watchlist:
            flash('A device cannot be both whitelisted and watchlisted. Please choose one.', 'error')
            return render_template('edit_device.html', device=device)
        
        db.session.commit()
        flash('Device updated successfully!', 'success')
        return redirect(url_for('device_list_page'))
    return render_template('edit_device.html', device=device)

@app.route('/delete_device/<int:device_id>', methods=['POST'])
@login_required 
def delete_device(device_id):
    """Handles deleting a device for the current user."""
    device = Device.query.filter_by(id=device_id, user_id=current_user.id).first_or_404()
    db.session.delete(device)
    db.session.commit()
    flash('Device deleted successfully!', 'success')
    return redirect(url_for('device_list_page'))

@app.route('/toggle_whitelist/<int:device_id>', methods=['POST'])
@login_required 
def toggle_whitelist(device_id):
    """Toggles the whitelisted status of a device for the current user."""
    device = Device.query.filter_by(id=device_id, user_id=current_user.id).first_or_404()
    device.is_whitelisted = not device.is_whitelisted
    if device.is_whitelisted:
        device.is_watchlist = False
    db.session.commit()
    flash(f'{device.device_name} whitelist status updated.', 'info')
    return redirect(url_for('device_list_page'))

@app.route('/toggle_watchlist/<int:device_id>', methods=['POST'])
@login_required 
def toggle_watchlist(device_id):
    """Toggles the watchlisted status of a device for the current user."""
    device = Device.query.filter_by(id=device_id, user_id=current_user.id).first_or_404()
    device.is_watchlist = not device.is_watchlist
    if device.is_watchlist:
        device.is_whitelisted = False
    db.session.commit()
    flash(f'{device.device_name} watchlist status updated.', 'info')
    return redirect(url_for('device_list_page'))

@app.route('/network_scan', methods=['GET', 'POST'])
@login_required 
def network_scan_page():
    """
    Handles network scanning and displays results for the current user.
    Updates status and last_seen for known devices.
    Creates alerts for new/unknown devices.
    """
    scan_results = session.get('scan_results', []) 
    
    if request.method == 'POST':
        # Reset all existing devices for the current user to 'Offline' before processing current scan
        all_user_devices = Device.query.filter_by(user_id=current_user.id).all()
        for device in all_user_devices:
            device.status = 'Offline'
        db.session.commit() 

        # Simulate network scan data (can be tailored per user if needed later)
        # Ensure some MACs are 'known' (from dummy data) and some are 'unknown'
        dummy_scan_data = [
            {'mac': '00:1A:2B:3C:4D:5E', 'ip': '192.168.1.101'}, # John's Laptop (Known)
            {'mac': '00:1A:2B:3C:4D:5F', 'ip': '192.168.1.102'}, # Unknown (will generate alert)
            {'mac': '00:1A:2B:3C:4D:60', 'ip': '192.168.1.103'}, # Smart TV (Known)
            {'mac': '00:1A:2B:3C:4D:61', 'ip': '192.168.1.104'}, # Unknown (will generate alert)
            {'mac': '00:1A:2B:3C:4D:64', 'ip': '192.168.1.105'}, # Smart Hub (Known)
            {'mac': 'AA:BB:CC:DD:EE:FF', 'ip': '192.168.1.106'}  # Another Unknown (will generate alert)
        ]

        scan_results = []
        new_devices_found_in_scan = False

        for item in dummy_scan_data:
            mac = item['mac']
            ip = item['ip']
            
            existing_device = Device.query.filter_by(user_id=current_user.id, mac_address=mac).first()
            
            if existing_device:
                existing_device.status = 'Online'
                existing_device.last_seen = datetime.now()
                db.session.add(existing_device) 
                
                scan_results.append({
                    'mac': mac,
                    'ip': ip,
                    'status': 'Known',
                    'device_name': existing_device.device_name,
                    'device_id': existing_device.id,
                    'device_type': existing_device.device_type, 
                    'last_seen': existing_device.last_seen.strftime('%Y-%m-%d %H:%M:%S') 
                })
            else:
                scan_results.append({
                    'mac': mac,
                    'ip': ip,
                    'status': 'Unknown',
                    'device_name': 'New Device', 
                    'device_id': None, 
                    'device_type': 'Unknown', 
                    'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
                })
                new_devices_found_in_scan = True 

                # Create an alert only if this specific MAC address hasn't triggered an alert before for this user
                # or if the previous alert for this MAC was marked as read.
                # This prevents spamming alerts for the same unknown device on every scan.
                existing_alert_for_mac = Alert.query.filter_by(user_id=current_user.id, message=f'New unknown device detected: {mac}', is_read=False).first()
                if not existing_alert_for_mac:
                    new_alert = Alert(user_id=current_user.id, message=f'New unknown device detected: {mac}', timestamp=datetime.now(), is_read=False)
                    db.session.add(new_alert)
        
        db.session.commit() 

        session['scan_results'] = scan_results 
        
        # Flash message based on new_devices_found_in_scan
        if new_devices_found_in_scan:
            flash('Potential Intrusion Alert! New devices detected on your network.', 'error')
        else:
            flash('Network scan completed. No new devices found.', 'success')

        return redirect(url_for('network_scan_page'))
    
    # On GET request, render the template with results retrieved from session
    # We no longer use potential_intrusion_alert directly in the template,
    # relying on flash messages and the 'Unknown' status in scan_results table.
    return render_template('network_scan.html', scan_results=scan_results)

@app.route('/alerts')
@login_required
def alerts_page():
    """Displays a list of alerts for the current user."""
    all_alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.timestamp.desc()).all()
    return render_template('alerts.html', alerts=all_alerts)

@app.route('/mark_alert_read/<int:alert_id>', methods=['POST'])
@login_required
def mark_alert_read(alert_id):
    """Marks a specific alert as read for the current user."""
    alert = Alert.query.filter_by(id=alert_id, user_id=current_user.id).first_or_404()
    alert.is_read = True
    db.session.commit()
    flash('Alert marked as read.', 'info')
    return redirect(url_for('alerts_page'))

@app.context_processor
def inject_unread_alerts_count():
    """Injects the count of unread alerts into all templates."""
    if current_user.is_authenticated:
        unread_count = Alert.query.filter_by(user_id=current_user.id, is_read=False).count()
        return dict(unread_alerts_count=unread_count)
    return dict(unread_alerts_count=0) # No unread alerts if not logged in


if __name__ == '__main__':
    app.run(debug=True)
    