from flask import Flask, request, render_template, send_from_directory, redirect, url_for
import os
import socket
import json
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
MESSAGES_FILE = 'messages.json'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

if not os.path.exists(MESSAGES_FILE):
    with open(MESSAGES_FILE, 'w') as f:
        json.dump([], f)

def get_local_ip():
    """Get the local IP address of the machine"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

@app.route('/')
def index():
    files = os.listdir(UPLOAD_FOLDER)
    
    try:
        with open(MESSAGES_FILE, 'r') as f:
            messages = json.load(f)
    except:
        messages = []
    
    local_ip = get_local_ip()
    return render_template('index.html', files=files, messages=messages, local_ip=local_ip)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
    
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route('/delete/<filename>')
def delete_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return redirect(url_for('index'))

@app.route('/send_message', methods=['POST'])
def send_message():
    sender = request.form.get('sender', 'Anonymous')
    message_text = request.form.get('message', '')
    
    if message_text:
        try:
            with open(MESSAGES_FILE, 'r') as f:
                messages = json.load(f)
        except:
            messages = []
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        messages.append({
            'sender': sender,
            'text': message_text,
            'time': timestamp
        })
        
        with open(MESSAGES_FILE, 'w') as f:
            json.dump(messages, f)
    
    return redirect(url_for('index'))

@app.route('/clear_messages')
def clear_messages():
    with open(MESSAGES_FILE, 'w') as f:
        json.dump([], f)
    return redirect(url_for('index'))

@app.template_filter('file_icon')
def file_icon(filename):
    """Return an appropriate icon class based on file extension"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    if ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg']:
        return '📷'  # Image
    elif ext in ['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv']:
        return '🎬'  # Video
    elif ext in ['mp3', 'wav', 'ogg', 'flac', 'm4a']:
        return '🎵'  # Audio
    elif ext in ['doc', 'docx', 'txt', 'pdf', 'odt', 'rtf']:
        return '📄'  # Document
    elif ext in ['xls', 'xlsx', 'csv']:
        return '📊'  # Spreadsheet
    elif ext in ['zip', 'rar', '7z', 'tar', 'gz']:
        return '📦'  # Archive
    else:
        return '📎'  # Generic file

def create_templates():
    """Create the HTML template files"""
    os.makedirs('templates', exist_ok=True)
    
    with open('templates/index.html', 'w') as f:
        f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAN File Sharing</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }
        .section {
            flex: 1;
            min-width: 300px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        h1, h2 {
            color: #333;
        }
        ul {
            padding-left: 20px;
        }
        li {
            margin-bottom: 10px;
        }
        form {
            margin-bottom: 20px;
        }
        input, textarea, button {
            margin-top: 5px;
            padding: 8px;
            width: 100%;
            box-sizing: border-box;
        }
        button {
            background-color: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        .file-actions {
            display: flex;
            gap: 5px;
        }
        .message {
            background-color: #f1f1f1;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 10px;
        }
        .message-header {
            display: flex;
            justify-content: space-between;
            font-size: 0.9em;
            color: #666;
            margin-bottom: 5px;
        }
        .connection-info {
            background-color: #e9f7ef;
            padding: 10px;
            margin-bottom: 20px;
            border-radius: 5px;
            border-left: 5px solid #2ecc71;
        }
    </style>
</head>
<body>
    <h1>LAN File & Message Sharing</h1>
    
    <div class="connection-info">
        <p><strong>Your server is running at:</strong> http://{{ local_ip }}:5000</p>
        <p>Other devices on the same network can access this page using this address.</p>
    </div>

    <div class="container">
        <div class="section">
            <h2>File Sharing</h2>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <div>
                    <label for="file">Select File to Upload:</label>
                    <input type="file" id="file" name="file" required>
                </div>
                <button type="submit">Upload</button>
            </form>

            <h3>Available Files</h3>
            {% if files %}
                <ul>
                {% for file in files %}
                    <li>
                        {{ file|file_icon }} {{ file }}
                        <div class="file-actions">
                            <a href="{{ url_for('download_file', filename=file) }}">Download</a> | 
                            <a href="{{ url_for('delete_file', filename=file) }}" onclick="return confirm('Are you sure you want to delete this file?')">Delete</a>
                        </div>
                    </li>
                {% endfor %}
                </ul>
            {% else %}
                <p>No files available.</p>
            {% endif %}
        </div>

        <div class="section">
            <h2>Message Board</h2>
            <form action="/send_message" method="post">
                <div>
                    <label for="sender">Your Name:</label>
                    <input type="text" id="sender" name="sender" placeholder="Anonymous">
                </div>
                <div>
                    <label for="message">Message:</label>
                    <textarea id="message" name="message" rows="3" required></textarea>
                </div>
                <button type="submit">Send Message</button>
            </form>

            <h3>Messages</h3>
            {% if messages %}
                <div class="messages-container">
                    {% for message in messages|reverse %}
                        <div class="message">
                            <div class="message-header">
                                <span><strong>{{ message.sender }}</strong></span>
                                <span>{{ message.time }}</span>
                            </div>
                            <div class="message-content">
                                {{ message.text }}
                            </div>
                        </div>
                    {% endfor %}
                </div>
                <p><a href="{{ url_for('clear_messages') }}" onclick="return confirm('Are you sure you want to clear all messages?')">Clear all messages</a></p>
            {% else %}
                <p>No messages yet.</p>
            {% endif %}
        </div>
    </div>
    
    <script>
        // Auto-refresh page every 10 seconds
        setTimeout(function() {
            location.reload();
        }, 10000);
    </script>
</body>
</html>
        ''')

if __name__ == '__main__':
    create_templates()
    local_ip = get_local_ip()
    print(f"Server is running at http://{local_ip}:5000")
    print("Share this address with other devices on your network")
    app.run(host='0.0.0.0', port=5000, debug=True)
