from flask import Flask, render_template, request, jsonify, url_for, Response, send_file
import requests
import hashlib
from .pass_strength import check_password_strength
from .anonymization import anonymize_data
from .password_generator import generate_password
from .integrity_checker import calculate_file_hash
from .secure_notes import encrypt_note, decrypt_note
from .ip_tracker import get_ip_info
from .email_validator import validate_email
import os
from werkzeug.utils import secure_filename
import base64
import pandas as pd
import re
import io
import qrcode
from PIL import Image

def create_app():
    app = Flask(__name__, static_folder='static')
    app.config['SECRET_KEY'] = 'dev'
    
    @app.route('/')
    def home():
        return render_template('home.html')
    
    @app.route('/toolbox')
    def toolbox():
        return render_template('toolbox.html')
    
    @app.route('/anonymize', methods=['GET', 'POST'])
    def anonymize():
        if request.method == 'GET':
            return render_template('anonymize.html')
        
        if request.method == 'POST':
            if 'file' not in request.files:
                return 'No file uploaded', 400
            
            file = request.files['file']
            if file.filename == '':
                return 'No file selected', 400
                
            # Read masking options from form
            mask_email = 'mask_email' in request.form
            mask_phone = 'mask_phone' in request.form
            mask_credit_card = 'mask_credit_card' in request.form
            mask_ssn = 'mask_ssn' in request.form

            try:
                # Read CSV file
                df = pd.read_csv(file)
                
                # Apply masking based on selected options
                for column in df.columns:
                    if mask_email and 'email' in column.lower():
                        df[column] = df[column].apply(lambda x: mask_email_address(x) if pd.notna(x) else x)
                    
                    if mask_phone and ('phone' in column.lower() or 'tel' in column.lower()):
                        df[column] = df[column].apply(lambda x: mask_phone_number(x) if pd.notna(x) else x)
                    
                    if mask_credit_card and ('card' in column.lower() or 'cc' in column.lower()):
                        df[column] = df[column].apply(lambda x: mask_credit_card_number(x) if pd.notna(x) else x)
                    
                    if mask_ssn and ('ssn' in column.lower() or 'social' in column.lower()):
                        df[column] = df[column].apply(lambda x: mask_ssn_number(x) if pd.notna(x) else x)

                # Convert to CSV and return
                output = io.StringIO()
                df.to_csv(output, index=False)
                output.seek(0)
                
                return Response(
                    output.getvalue(),
                    mimetype='text/csv',
                    headers={
                        'Content-Disposition': f'attachment; filename=masked_{secure_filename(file.filename)}'
                    }
                )

            except Exception as e:
                print(f"Error processing file: {str(e)}")
                return f'Error processing file: {str(e)}', 500
    
    @app.route('/password')
    def password():
        return render_template('password.html')
    
    @app.route('/check-pwned', methods=['POST'])
    def check_pwned():
        password = request.json.get('password', '')
        
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]
        
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(url)
        
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    return jsonify({
                        'found': True,
                        'count': int(count),
                        'message': f'This password has been exposed in {count} data breaches!'
                    })
            
            return jsonify({
                'found': False,
                'message': 'Good news! This password hasn\'t been found in any known data breaches.'
            })
        
        return jsonify({
            'error': 'Unable to check password status'
        }), 500
    
    @app.route('/check-strength', methods=['POST'])
    def check_strength():
        password = request.json.get('password', '')
        score = check_password_strength(password)
        strength_levels = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong']
        return jsonify({
            'strength': strength_levels[score]
        })
    
    @app.route('/generate-password', methods=['GET', 'POST'])
    def generate_password_route():
        generated_password = None
        if request.method == 'POST':
            length = int(request.form.get('length', 12))
            generated_password = generate_password(length)
        return render_template('generate_password.html', password=generated_password)
    
    @app.route('/check-integrity', methods=['GET', 'POST'])
    def check_integrity():
        file_hash = None
        error = None
        
        if request.method == 'POST':
            if 'file' not in request.files:
                error = 'No file uploaded'
            else:
                file = request.files['file']
                if file.filename == '':
                    error = 'No file selected'
                else:
                    try:
                        algorithm = request.form.get('algorithm', 'sha256')
                        file_hash = calculate_file_hash(file, algorithm)
                    except Exception as e:
                        error = f"Error calculating hash: {str(e)}"
                        
        return render_template('check_integrity.html', 
                             file_hash=file_hash, 
                             error=error)
    
    @app.route('/hash-generator', methods=['GET', 'POST'])
    def hash_generator():
        hash_result = None
        input_text = None
        
        if request.method == 'POST':
            input_text = request.form.get('input_text')
            algorithm = request.form.get('algorithm')
            
            if input_text:
                if algorithm == 'md5':
                    hash_result = hashlib.md5(input_text.encode()).hexdigest()
                elif algorithm == 'sha1':
                    hash_result = hashlib.sha1(input_text.encode()).hexdigest()
                elif algorithm == 'sha256':
                    hash_result = hashlib.sha256(input_text.encode()).hexdigest()
                elif algorithm == 'sha384':
                    hash_result = hashlib.sha384(input_text.encode()).hexdigest()
                elif algorithm == 'sha512':
                    hash_result = hashlib.sha512(input_text.encode()).hexdigest()
                elif algorithm == 'blake2b':
                    hash_result = hashlib.blake2b(input_text.encode()).hexdigest()
        
        return render_template('hash_generator.html', 
                             hash_result=hash_result, 
                             input_text=input_text)
    
    @app.route('/secure-notes', methods=['GET', 'POST'])
    def secure_notes_route():
        if request.method == 'POST':
            try:
                action = request.form.get('action')
                password = request.form.get('password')
                key = hashlib.sha256(password.encode()).digest()
                key = base64.urlsafe_b64encode(key)

                if action == 'encrypt':
                    note_content = request.form.get('note_content')
                    encrypted_note = encrypt_note(note_content, key)
                    return render_template('secure_notes.html', encrypted_note=encrypted_note)
                
                elif action == 'decrypt':
                    encrypted_note = request.form.get('encrypted_note')
                    decrypted_note = decrypt_note(encrypted_note, key)
                    return render_template('secure_notes.html', decrypted_note=decrypted_note)

            except Exception as e:
                return render_template('secure_notes.html', error=str(e))
        
        return render_template('secure_notes.html')
    
    @app.route('/validate-email', methods=['GET', 'POST'])
    def validate_email_route():
        validation_result = None
        if request.method == 'POST':
            email = request.form['email']
            is_valid, message = validate_email(email)
            validation_result = {'is_valid': is_valid, 'message': message}
        return render_template('validate_email.html', validation_result=validation_result)
    
    @app.route('/ip-tracker', methods=['GET', 'POST'])
    def ip_tracker_route():
        ip_info = None
        if request.method == 'POST':
            ip_address = request.form.get('ip_address')
            try:
                ip_info = get_ip_info(ip_address)
            except Exception as e:
                ip_info = {'error': str(e)}
        return render_template('ip_tracker.html', ip_info=ip_info)
    
    @app.route('/qr-generator', methods=['GET', 'POST'])
    def qr_generator():
        if request.method == 'POST':
            data = request.form.get('text', '')
            if data:
                try:
                    img_buffer = generate_qr_code(data)
                    return send_file(
                        img_buffer,
                        mimetype='image/jpeg',
                        as_attachment=True,
                        download_name='qrcode.jpg'
                    )
                except Exception as e:
                    return str(e), 400
                
        return render_template('qr_generator.html')
    
    return app 

# Add masking helper functions
def mask_email_address(email):
    if not isinstance(email, str):
        return email
    parts = email.split('@')
    if len(parts) != 2:
        return email
    username = parts[0]
    domain = parts[1]
    masked_username = username[0] + '*' * (len(username) - 1)
    return f'{masked_username}@{domain}'

def mask_phone_number(phone):
    if not isinstance(phone, str):
        return phone
    # Remove non-numeric characters
    nums = re.sub(r'\D', '', phone)
    if len(nums) >= 10:
        return f'(XXX) XXX-{nums[-4:]}'
    return phone

def mask_credit_card_number(cc):
    if not isinstance(cc, str):
        return cc
    nums = re.sub(r'\D', '', cc)
    if len(nums) >= 16:
        return f'XXXX-XXXX-XXXX-{nums[-4:]}'
    return cc

def mask_ssn_number(ssn):
    if not isinstance(ssn, str):
        return ssn
    nums = re.sub(r'\D', '', ssn)
    if len(nums) == 9:
        return f'XXX-XX-{nums[-4:]}'
    return ssn 

def generate_qr_code(data):
    """
    Generate a QR code from the provided data and save as JPG
    
    Args:
        data (str): The text or URL to encode in the QR code
        
    Returns:
        BytesIO: A buffer containing the JPG image of the QR code
    """
    try:
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            box_size=10,
            border=5,
            error_correction=qrcode.constants.ERROR_CORRECT_L
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        # Create image with white background
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to RGB mode (required for JPEG)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Save image to bytes as JPG
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='JPEG', quality=95)
        img_buffer.seek(0)
        
        return img_buffer
    except Exception as e:
        raise Exception(f"Error generating QR code: {str(e)}") 