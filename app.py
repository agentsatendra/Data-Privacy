from flask import Flask, render_template, request
import requests  # Make sure this is imported

app = Flask(__name__, static_folder='static')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ip-tracker', methods=['GET', 'POST'])
def ip_tracker():
    ip_data = None
    if request.method == 'POST':
        ip_address = request.form['ip']
        try:
            response = requests.get(f'http://ip-api.com/json/{ip_address}')
            ip_data = response.json()
        except:
            ip_data = None
    return render_template('ip_tracker.html', ip_data=ip_data) 