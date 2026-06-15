from flask import Flask, render_template, request, redirect, session, jsonify, send_file
import sqlite3, os, hashlib
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pywt, numpy as np
import boto3
import io
import cv2

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Change this to a strong secret key
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database Setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                (id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, dob TEXT, phone TEXT, 
                address TEXT, gender TEXT, password TEXT, image_verify TEXT, stego_pin TEXT)''')
    
    # Files table
    c.execute('''CREATE TABLE IF NOT EXISTS files
                (id INTEGER PRIMARY KEY, owner_id INTEGER, filename TEXT, 
                encrypted_data BLOB, key BLOB, nonce BLOB, tag BLOB,
                FOREIGN KEY(owner_id) REFERENCES users(id))''')


    c.execute('''CREATE TABLE IF NOT EXISTS requests
            (id INTEGER PRIMARY KEY,
             file_id INTEGER,
             requester_id INTEGER,
             status TEXT DEFAULT 'pending',
             viewed BOOLEAN DEFAULT 0,  
             FOREIGN KEY(file_id) REFERENCES files(id),
             FOREIGN KEY(requester_id) REFERENCES users(id))''')
    
    # Add the viewed column if it doesn't exist
    c.execute("PRAGMA table_info(requests)")
    columns = [column[1] for column in c.fetchall()]
    if 'viewed' not in columns:
        c.execute("ALTER TABLE requests ADD COLUMN viewed BOOLEAN DEFAULT 0")
    if 'viewed_at' not in columns:
        c.execute("ALTER TABLE requests ADD COLUMN viewed_at TIMESTAMP")
    
    conn.commit()
    conn.close()

init_db()

def db_execute(query, args=(), fetchone=False, fetchall=False, dict_format=False):
    conn = sqlite3.connect('users.db')
    
    # Only set row_factory if we want dictionary results
    if dict_format:
        conn.row_factory = sqlite3.Row
    
    c = conn.cursor()
    c.execute(query, args)
    conn.commit()
    
    if fetchone:
        result = c.fetchone()
        if dict_format and result:
            result = dict(result)
    elif fetchall:
        result = c.fetchall()
        if dict_format and result:
            result = [dict(row) for row in result]
    else:
        result = None
    
    conn.close()
    return result

# Home Page
@app.route('/')
def home():
    return render_template('home.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         try:
#             image = request.files['image_verify']
#             if not image:
#                 return "Verification image required", 400
                
#             filename = secure_filename(image.filename)
#             image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             image.save(image_path)

#             # ⬇️ Hide email inside the image
#             hide_data_dwt(image_path, request.form['email'])

#             # Save user data in session
#             session['user_data'] = {
#                 'name': request.form['name'],
#                 'email': request.form['email'],
#                 'dob': request.form['dob'],
#                 'phone': request.form['phone'],
#                 'address': request.form['address'],
#                 'gender': request.form['gender'],
#                 'password': hashlib.sha256(request.form['password'].encode()).hexdigest(),
#                 'image_verify': filename
#             }
#             return redirect('/register_stego')
#         except Exception as e:
#             return f"Registration failed: {str(e)}", 400
#     return render_template('register_stage1.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            image = request.files['image_verify']
            if not image:
                return "Verification image required", 400
                
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)

            # Hide email in image
            hide_data_dwt(image_path, request.form['email'])

            session['user_data'] = {
                'name': request.form['name'],
                'email': request.form['email'],
                'dob': request.form['dob'],
                'phone': request.form['phone'],
                'address': request.form['address'],
                'gender': request.form['gender'],
                'password': hashlib.sha256(request.form['password'].encode()).hexdigest(),
                'image_verify': filename
            }
            return redirect('/register_stego')
        except Exception as e:
            return f"Registration failed: {str(e)}", 400
    return render_template('register_stage1.html')




# Registration Stage 2 (Steganography PIN)
@app.route('/register_stego', methods=['GET', 'POST'])
def register_stego():
    if 'user_data' not in session:
        return redirect('/register')
        
    if request.method == 'POST':
        try:
            stego_pin = request.form.get('stego_pin')
            if not stego_pin or len(stego_pin) != 4:
                return "Invalid PIN", 400
                
            # Save to DB
            user_data = session['user_data']
            db_execute(
                '''INSERT INTO users 
                (name, email, dob, phone, address, gender, password, image_verify, stego_pin) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (user_data['name'], user_data['email'], user_data['dob'],
                 user_data['phone'], user_data['address'], user_data['gender'],
                 user_data['password'], user_data['image_verify'], stego_pin)
            )
            
            session.pop('user_data', None)
            return redirect('/login')
        except sqlite3.IntegrityError:
            return "Email already registered", 400
        except Exception as e:
            return f"Registration failed: {str(e)}", 400
            
    return render_template('register_stage2.html')

# Login Stage 1 (Email/Password)
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         try:
#             email = request.form['email']
#             password = hashlib.sha256(request.form['password'].encode()).hexdigest()
 
#             user = db_execute(
#                 "SELECT * FROM users WHERE email = ? AND password = ?",
#                 (email, password),
#                 fetchone=True,
#                 dict_format=False  # Important for login
#             )
            
#             if user is not None:
#                 session['user_id'] = user[0]
#                 return redirect('/login_verify_image')
#             else:
#                 return "Invalid credentials", 401

#         except Exception as e:
#             return f"Login failed: {str(e)}", 400
#     return render_template('login_stage1.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = hashlib.sha256(request.form['password'].encode()).hexdigest()

            user = db_execute(
                "SELECT * FROM users WHERE email = ? AND password = ?",
                (email, password),
                fetchone=True,
                dict_format=False
            )

            if user is not None:
                session['user_id'] = user[0]
                session['expected_email'] = email  # ✅ Store expected email
                return redirect('/login_verify_image')
            else:
                return "Invalid credentials", 401

        except Exception as e:
            return f"Login failed: {str(e)}", 400

    return render_template('login_stage1.html')



# @app.route('/login_verify_image', methods=['GET', 'POST'])
# def login_verify_image():
#     if 'user_id' not in session or 'expected_email' not in session:
#         return redirect('/login')
        
#     if request.method == 'POST':
#         try:
#             uploaded_image = request.files['image_verify']
#             if not uploaded_image:
#                 return "Image required", 400

#             # Get original image filename
#             result = db_execute(
#                 'SELECT image_verify FROM users WHERE id=?',
#                 (session['user_id'],),
#                 fetchone=True
#             )
#             if not result:
#                 return "User not found", 404
                
#             # Save uploaded image temporarily
#             temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_verify.png')
#             uploaded_image.save(temp_path)

#             try:
#                 extracted_email = extract_data_dwt(temp_path)
#                 expected_email = session['expected_email']
                
#                 print(f"Extracted: {extracted_email}")
#                 print(f"Expected: {expected_email}")

#                 if extracted_email == expected_email:
#                     return redirect('/login_stego_pin')
#                 return f"Verification failed. Expected: {expected_email}, Got: {extracted_email}", 401
#             finally:
#                 if os.path.exists(temp_path):
#                     os.remove(temp_path)
#         except Exception as e:
#             print(f"Verification error: {str(e)}")
#             return f"Verification failed: {str(e)}", 400
            
#     return render_template('login_stage2.html')  



@app.route('/login_verify_image', methods=['GET', 'POST'])
def login_verify_image():
    if 'user_id' not in session:
        return redirect('/login')
        
    if request.method == 'POST':
        try:
            uploaded_image = request.files['image_verify']
            if not uploaded_image:
                return "Image required", 400

            # Get original image path from database
            result = db_execute(
                'SELECT image_verify FROM users WHERE id=?',
                (session['user_id'],),
                fetchone=True
            )
            if not result:
                return "User not found", 404
                
            original_path = os.path.join(app.config['UPLOAD_FOLDER'], result[0])

            # Save uploaded image temporarily
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_verify.png')
            uploaded_image.save(temp_path)

            try:
                # Compare images using perceptual hash
                if verify_image_match(original_path, temp_path):
                    return redirect('/login_stego_pin')
                return "Image verification failed: Images don't match", 401
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        except Exception as e:
            return f"Verification failed: {str(e)}", 400
            
    return render_template('login_stage2.html')

def verify_image_match(image_path1, image_path2, threshold=0.9):
    
    try:
        # Read images
        img1 = cv2.imread(image_path1)
        img2 = cv2.imread(image_path2)
        
        if img1 is None or img2 is None:
            return False
            
        # Resize to same dimensions
        img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))
        
        # Convert to HSV and calculate histogram
        img1_hsv = cv2.cvtColor(img1, cv2.COLOR_BGR2HSV)
        img2_hsv = cv2.cvtColor(img2, cv2.COLOR_BGR2HSV)
        
        hist1 = cv2.calcHist([img1_hsv], [0,1], None, [50,60], [0,180,0,256])
        hist2 = cv2.calcHist([img2_hsv], [0,1], None, [50,60], [0,180,0,256])
        
        # Normalize and compare
        cv2.normalize(hist1, hist1, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
        cv2.normalize(hist2, hist2, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
        
        similarity = cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL)
        return similarity >= threshold
        
    except Exception as e:
        print(f"Image comparison error: {str(e)}")
        return False


# Login Stage 3 (Steganography PIN)
@app.route('/login_stego_pin', methods=['GET', 'POST'])
def login_stego_pin():
    if 'user_id' not in session:
        return redirect('/login')
        
    if request.method == 'POST':
        try:
            entered_pin = request.form.get('stego_pin')
            if not entered_pin or len(entered_pin) != 4:
                return "Invalid PIN", 400
                
            db_pin = db_execute(
                'SELECT stego_pin FROM users WHERE id=?', 
                (session['user_id'],), 
                fetchone=True
            )[0]
            
            if entered_pin == db_pin:
                return redirect('/dashboard')
            return "Invalid PIN", 401
        except Exception as e:
            return f"PIN verification failed: {str(e)}", 400
    return render_template('login_stage3.html')

# AES Encryption
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, cipher.nonce, tag



# Improved DWT Steganography Functions
def hide_data_dwt(image_path, secret_data):
    """Hide data in image using DWT LSB steganography"""
    try:
        # Read image
        image = cv2.imread(image_path)
        if image is None:
            raise ValueError("Could not read image file")

        # Convert secret data to binary with termination marker
        secret_data += "####"
        binary_str = ''.join(format(ord(char), '08b') for char in secret_data)
        secret_bits = [int(bit) for bit in binary_str]

        # Use green channel (better for steganography)
        channel = image[:, :, 1].astype(np.float32)

        # Single level DWT
        coeffs = pywt.dwt2(channel, 'haar')
        cA, (cH, cV, cD) = coeffs

        # Flatten detail coefficients
        cD_flat = cD.flatten()

        # Check capacity
        if len(secret_bits) > len(cD_flat):
            raise ValueError("Message too large for cover image")

        # Embed bits in LSBs
        for i in range(len(secret_bits)):
            cD_flat[i] = (int(cD_flat[i]) & ~1) | secret_bits[i]

        # Reshape and reconstruct
        cD_modified = cD_flat.reshape(cD.shape)
        coeffs_modified = (cA, (cH, cV, cD_modified))
        stego_channel = pywt.idwt2(coeffs_modified, 'haar')

        # Handle size mismatches
        if stego_channel.shape != channel.shape:
            stego_channel = stego_channel[:channel.shape[0], :channel.shape[1]]

        # Update channel
        image[:, :, 1] = np.clip(stego_channel, 0, 255).astype(np.uint8)

        # Save as PNG to prevent compression artifacts
        cv2.imwrite(image_path, image, [cv2.IMWRITE_PNG_COMPRESSION, 0])
        
        print(f"Successfully embedded data in {image_path}")
        return image_path
        
    except Exception as e:
        print(f"Error in hide_data_dwt: {str(e)}")
        raise

def extract_data_dwt(image_path):
    """Extract hidden data from image using DWT LSB steganography"""
    try:
        # Read image
        image = cv2.imread(image_path)
        if image is None:
            raise ValueError("Could not read image file")

        # Use same channel as embedding
        channel = image[:, :, 1].astype(np.float32)

        # Perform DWT
        coeffs = pywt.dwt2(channel, 'haar')
        cA, (cH, cV, cD) = coeffs

        # Extract LSBs
        cD_flat = cD.flatten()
        extracted_bits = [str(int(pixel) & 1) for pixel in cD_flat]

        # Convert to bytes
        binary_str = ''.join(extracted_bits)
        chars = []
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if len(byte) < 8:
                break
            chars.append(chr(int(byte, 2)))

        extracted_text = ''.join(chars)

        # Find termination marker
        end_marker = extracted_text.find("####")
        if end_marker != -1:
            return extracted_text[:end_marker]
            
        return extracted_text
        
    except Exception as e:
        print(f"Error in extract_data_dwt: {str(e)}")
        raise

@app.route('/debug_files')
def debug_files():
    if 'user_id' not in session:
        return redirect('/login')
    
    files = db_execute('SELECT id, owner_id, filename FROM files', fetchall=True)
    users = db_execute('SELECT id, email FROM users', fetchall=True)
    
    return f"""
    <h1>Database Debug</h1>
    <h2>Files</h2>
    <pre>{files}</pre>
    <h2>Users</h2>
    <pre>{users}</pre>
    """

@app.route('/file_upload', methods=['GET', 'POST'])
def file_upload():
    if 'user_id' not in session:
        return redirect('/login')
        
    if request.method == 'POST':
        try:
            # Check if file was submitted
            if 'file' not in request.files:
                return render_template('file_upload.html', error="No file selected")
                
            file = request.files['file']
            
            # Check if filename is empty
            if file.filename == '':
                return render_template('file_upload.html', error="No file selected")
                
            # Validate file extension (example: allow only text files)
            allowed_extensions = {'txt'}
            if '.' not in file.filename or file.filename.split('.')[-1].lower() not in allowed_extensions:
                return render_template('file_upload.html', error="Invalid file type")
            
            # Secure filename and save temporarily
            filename = secure_filename(file.filename)
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{filename}")
            file.save(temp_path)
            
            # Generate encryption key
            key = get_random_bytes(16)  # 128-bit key
            
            # Encrypt the file
            ciphertext, nonce, tag = encrypt_file(temp_path, key)
            
            # Save to database
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('''INSERT INTO files 
                      (owner_id, filename, encrypted_data, key, nonce, tag) 
                      VALUES (?, ?, ?, ?, ?, ?)''',
                      (session['user_id'], filename, ciphertext, key, nonce, tag))
            conn.commit()
            conn.close()
            
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
            
            # Display results
            return render_template('file_upload.html',
                                encrypted_text=ciphertext.hex()[:100] + "... [truncated]",
                                encryption_key=key.hex())
                                
        except Exception as e:
            # Clean up if error occurred
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.remove(temp_path)
            return render_template('file_upload.html', error=f"Error: {str(e)}")
    
    # GET request - show upload form
    return render_template('file_upload.html')


@app.route('/request_file/<int:file_id>', methods=['POST'])
def create_file_request(file_id):
    if 'user_id' not in session:
        return jsonify(success=False, message="Unauthorized"), 401
    
    try:
        # Verify the file exists and isn't owned by the current user
        file = db_execute(
            'SELECT id FROM files WHERE id=? AND owner_id!=?',
            (file_id, session['user_id']),
            fetchone=True
        )
        if not file:
            return jsonify(success=False, message="File not found"), 404
        
        # Check if request already exists
        existing_request = db_execute(
            'SELECT id FROM requests WHERE file_id=? AND requester_id=?',
            (file_id, session['user_id']),
            fetchone=True
        )
        if existing_request:
            return jsonify(success=False, message="Request already exists"), 400
        
        # Create new request
        db_execute(
            'INSERT INTO requests (file_id, requester_id, status) VALUES (?, ?, ?)',
            (file_id, session['user_id'], 'pending')
        )
        
        return jsonify(success=True)
    
    except Exception as e:
        print(f"Error creating file request: {str(e)}")
        return jsonify(success=False, message="Internal server error"), 500

@app.route('/request_file', methods=['GET'])
def show_request_file_page():
    if 'user_id' not in session:
        return redirect('/login')
    
    try:
        # Get available files (excluding current user's files)
        available_files = db_execute('''
            SELECT 
                f.id,
                u.email as owner_email,
                f.filename,
                COALESCE(
                    (SELECT r.status FROM requests r 
                     WHERE r.file_id = f.id AND r.requester_id = ?),
                    'none'
                ) as request_status
            FROM files f
            JOIN users u ON f.owner_id = u.id
            WHERE f.owner_id != ?
            ORDER BY f.id
        ''', (session['user_id'], session['user_id']), fetchall=True, dict_format=True)
               
        incoming_requests = db_execute('''
                    SELECT 
                        r.id, 
                        f.filename, 
                        u.email as requester_email, 
                        r.status,
                        r.viewed,
                        r.viewed_at
                    FROM requests r
                    JOIN files f ON r.file_id = f.id
                    JOIN users u ON r.requester_id = u.id
                    WHERE f.owner_id = ?
                    ORDER BY r.id
                ''', (session['user_id'],), fetchall=True, dict_format=True)
        
        print("DEBUG - Available files:", available_files)
        print("DEBUG - Incoming requests:", incoming_requests)
        
        return render_template('request_file.html', 
                            files=available_files,
                            requests=incoming_requests)
    except Exception as e:
        print(f"Error in show_request_file_page: {str(e)}")
        return f"Error loading request page: {str(e)}", 500
print(db_execute("SELECT id, status, viewed, viewed_at FROM requests", fetchall=True))

@app.route('/approve_request/<int:request_id>', methods=['POST'])
def approve_request(request_id):
    if 'user_id' not in session:
        return jsonify(success=False, message="Unauthorized"), 401
        
    try:
        # Verify request exists and user is owner
        request_data = db_execute(
            '''SELECT r.id, f.owner_id 
            FROM requests r JOIN files f ON r.file_id = f.id 
            WHERE r.id=?''',
            (request_id,),
            fetchone=True
        )
        
        if not request_data:
            return jsonify(success=False, message="Request not found"), 404
            
        if request_data[1] != session['user_id']:
            return jsonify(success=False, message="Unauthorized"), 403
            
        # Approve request and reset viewed status
        db_execute(
            '''UPDATE requests 
            SET status="approved", viewed=0 
            WHERE id=?''',
            (request_id,)
        )
        
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 400



@app.route('/view_file/<int:file_id>')
def view_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
        
    try:
        # Verify access rights
        access = db_execute(
            '''SELECT f.filename, f.encrypted_data, f.key, f.nonce, f.tag
            FROM files f LEFT JOIN requests r ON f.id = r.file_id
            WHERE f.id=? AND (f.owner_id=? OR (r.requester_id=? AND r.status="approved"))''',
            (file_id, session['user_id'], session['user_id']),
            fetchone=True
        )
        
        if not access:
            return "Access denied or file not found", 403
            
        # If this is a requester (not owner), mark as viewed
        if not db_execute(
            'SELECT 1 FROM files WHERE id=? AND owner_id=?',
            (file_id, session['user_id']),
            fetchone=True
        ):
            db_execute(
                '''UPDATE requests 
                SET viewed=1, viewed_at=CURRENT_TIMESTAMP 
                WHERE file_id=? AND requester_id=? AND status="approved"''',
                (file_id, session['user_id'])
            )
            
        filename, encrypted_data, key, nonce, tag = access
        
        # Decrypt the file
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_text = cipher.decrypt_and_verify(encrypted_data, tag).decode('utf-8')

        return render_template('view_file.html', 
                        filename=filename, 
                        file_content=decrypted_text,  # Changed from decrypted_text
                        display_type='text')
        
        # return render_template('view_file.html', 
        #                     filename=filename, 
        #                     decrypted_text=decrypted_text)




    except Exception as e:
        print(f"Error viewing file: {str(e)}")
        return f"Error viewing file: {str(e)}", 400

# Download File
@app.route('/download_file/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect('/login')
        
    try:
        # Verify access rights (same as view_file)
        access = db_execute(
            '''SELECT f.filename, f.encrypted_data, f.key, f.nonce, f.tag
            FROM files f LEFT JOIN requests r ON f.id = r.file_id
            WHERE f.id=? AND (f.owner_id=? OR (r.requester_id=? AND r.status="approved"))''',
            (file_id, session['user_id'], session['user_id']),
            fetchone=True
        )
        
        if not access:
            return "Access denied or file not found", 403
            
        filename, encrypted_data, key, nonce, tag = access
        
        # Decrypt the file
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_text = cipher.decrypt_and_verify(encrypted_data, tag).decode('utf-8')
        
        # Create in-memory file
        mem_file = io.BytesIO(decrypted_text.encode())
        mem_file.seek(0)
        
        return send_file(
            mem_file,
            as_attachment=True,
            download_name=f"{filename}_decrypted.txt",
            mimetype='text/plain'
        )
    except Exception as e:
        return f"Error downloading file: {str(e)}", 400

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)


































































































# from flask import Flask, render_template, request, redirect, session
# import sqlite3, os, hashlib
# from werkzeug.utils import secure_filename
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# import pywt, numpy as np
# import boto3
# from flask import send_file
# import io

# app = Flask(__name__)
# app.secret_key = "your_secret_key"
# UPLOAD_FOLDER = 'static/uploads'


# def init_db():
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('''CREATE TABLE IF NOT EXISTS users 
#                 (id INTEGER PRIMARY KEY, name TEXT, email TEXT, dob TEXT, phone TEXT, 
#                 address TEXT, gender TEXT, password TEXT, image_verify TEXT, stego_pin TEXT)''')
#     c.execute('''CREATE TABLE IF NOT EXISTS files
#                 (id INTEGER PRIMARY KEY, owner_id INTEGER, filename TEXT, 
#                 encrypted_data BLOB, key BLOB, nonce BLOB)''')
#     c.execute('''CREATE TABLE IF NOT EXISTS requests
#                 (id INTEGER PRIMARY KEY, file_id INTEGER, requester_id INTEGER, 
#                 status TEXT, FOREIGN KEY(file_id) REFERENCES files(id))''')
#     conn.commit()
#     conn.close()
# init_db()

# # Home Page
# @app.route('/')
# def home():
#     return render_template('home.html')

# # Registration Stage 1
# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         # Save user data to session
#         session['user_data'] = {
#             'name': request.form['name'],
#             'email': request.form['email'],
#             'dob': request.form['dob'],
#             'phone': request.form['phone'],
#             'address': request.form['address'],
#             'gender': request.form['gender'],
#             'password': hashlib.sha256(request.form['password'].encode()).hexdigest(),
#             'image_verify': request.files['image_verify'].filename
#         }
#         # Save image
#         image = request.files['image_verify']
#         if image:
#             filename = secure_filename(image.filename)
#             image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
#         return redirect('/register_stego')
#     return render_template('register_stage1.html')

# # Registration Stage 2 (Steganography PIN)
# @app.route('/register_stego', methods=['GET', 'POST'])
# def register_stego():
#     if request.method == 'POST':
#         stego_pin = request.form['stego_pin']
#         # Save to DB
#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('INSERT INTO users (name, email, dob, phone, address, gender, password, image_verify, stego_pin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
#                   (session['user_data']['name'], session['user_data']['email'], session['user_data']['dob'],
#                    session['user_data']['phone'], session['user_data']['address'], session['user_data']['gender'],
#                    session['user_data']['password'], session['user_data']['image_verify'], stego_pin))
#         conn.commit()
#         conn.close()
#         return redirect('/login')
#     return render_template('register_stage2.html')

# # Login Stage 1 (Email/Password)
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = hashlib.sha256(request.form['password'].encode()).hexdigest()
#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('SELECT * FROM users WHERE email=? AND password=?', (email, password))
#         user = c.fetchone()
#         conn.close()
#         if user:
#             session['user_id'] = user[0]
#             return redirect('/login_verify_image')
#     return render_template('login_stage1.html')

# # Login Stage 2 (Image Verification)
# @app.route('/login_verify_image', methods=['GET', 'POST'])
# def login_verify_image():
#     if request.method == 'POST':
#         # Check if uploaded image matches DB record
#         user_id = session['user_id']
#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('SELECT image_verify FROM users WHERE id=?', (user_id,))
#         db_image = c.fetchone()[0]
#         conn.close()
#         uploaded_image = request.files['image_verify'].filename
#         if uploaded_image == db_image:
#             return redirect('/login_stego_pin')
#     return render_template('login_stage2.html')

# # Login Stage 3 (Steganography PIN)
# @app.route('/login_stego_pin', methods=['GET', 'POST'])
# def login_stego_pin():
#     if request.method == 'POST':
#         entered_pin = request.form['stego_pin']
#         user_id = session['user_id']
#         conn = sqlite3.connect('users.db')
#         c = conn.cursor()
#         c.execute('SELECT stego_pin FROM users WHERE id=?', (user_id,))
#         db_pin = c.fetchone()[0]
#         conn.close()
#         if entered_pin == db_pin:
#             return redirect('/dashboard')
#     return render_template('login_stage3.html')

# # AES Encryption
# def encrypt_file(file_path, key):
#     data = open(file_path, 'rb').read()
#     cipher = AES.new(key, AES.MODE_EAX)
#     ciphertext, tag = cipher.encrypt_and_digest(data)
#     return ciphertext, cipher.nonce, tag

# # DWT Data Hiding
# def hide_data_dwt(image_path, secret_data):
#     image = np.load(image_path)
#     coeffs = pywt.dwt2(image, 'haar')
#     LL, (LH, HL, HH) = coeffs
#     # Embed secret_data into LH band
#     LH_modified = LH + (secret_data * 0.01)
#     return pywt.idwt2((LL, (LH_modified, HL, HH)), 'haar')


# def upload_to_s3(file_path, bucket_name):
#     s3 = boto3.client('s3')
#     s3.upload_file(file_path, bucket_name, secure_filename(file_path))

# # File Upload & Encryption
# @app.route('/upload', methods=['POST'])
# def upload_file():
#     if 'file' not in request.files:
#         return redirect('/file_upload')
#     file = request.files['file']
#     if file.filename == '':
#         return redirect('/file_upload')
    
#     # Save file temporarily
#     file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
#     file.save(file_path)
    
#     # AES Encryption
#     key = get_random_bytes(16)  # 128-bit key
#     ciphertext, nonce, tag = encrypt_file(file_path, key)
    
#     # DWT Steganography (optional)
#     stego_image = hide_data_dwt("static/cover_image.jpg", ciphertext)
    
#     # Save to database (pseudo-code)
#     db.execute('INSERT INTO files (owner_id, filename, encrypted_data, key) VALUES (?, ?, ?, ?)',
#                [session['user_id'], file.filename, ciphertext, key])
    
#     return render_template('file_upload.html', 
#                          encrypted_text=ciphertext.hex(),
#                          encryption_key=key.hex())

# # File Request Handling
# @app.route('/request_file/<int:file_id>', methods=['POST'])
# def request_file(file_id):
#     db.execute('INSERT INTO requests (file_id, requester_id, status) VALUES (?, ?, ?)',
#                [file_id, session['user_id'], 'pending'])
#     return jsonify(success=True)

# # Approve Request
# @app.route('/approve_request/<int:request_id>', methods=['POST'])
# def approve_request(request_id):
#     db.execute('UPDATE requests SET status="approved" WHERE id=?', [request_id])
#     return jsonify(success=True)

# # View Decrypted File
# @app.route('/view_file/<int:file_id>')
# def view_file(file_id):
#     # Fetch file from database
#     conn = sqlite3.connect('users.db')
#     c = conn.cursor()
#     c.execute('SELECT filename, encrypted_data, key FROM files WHERE id=?', (file_id,))
#     file_data = c.fetchone()
#     conn.close()

#     if not file_data:
#         return "File not found!", 404

#     filename, encrypted_data, key = file_data

#     # Decrypt the file (AES)
#     try:
#         cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)  # Ensure nonce is stored during encryption
#         decrypted_text = cipher.decrypt(encrypted_data).decode('utf-8')
#     except Exception as e:
#         return f"Decryption failed: {str(e)}", 400

#     return render_template('view_file.html', 
#                          filename=filename, 
#                          decrypted_text=decrypted_text)

# # Optional: Direct download endpoint
# @app.route('/download_file/<int:file_id>')
# def download_file(file_id):
#     # Fetch and decrypt (same logic as above)
#     decrypted_text = "Decrypted content from database"
#     filename = "example.txt"

#     # Return as downloadable file
#     return send_file(
#         io.BytesIO(decrypted_text.encode()),
#         as_attachment=True,
#         download_name=f"{filename}.txt",
#         mimetype='text/plain'
#     )
# # Dashboard
# @app.route('/dashboard')
# def dashboard():
#     return render_template('dashboard.html')

# if __name__ == '__main__':
#     app.run(debug=True)