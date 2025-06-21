from flask import Flask, render_template, request, redirect, url_for, flash, session
import hashlib
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import os
import mysql.connector
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Thay bằng khóa bí mật mạnh hơn

# Kết nối MySQL
db = mysql.connector.connect(
    host="localhost",
    user="root",  # Thay bằng username MySQL của bạn
    password="choinhanh12",  # Thay bằng password MySQL
    database="user_auth"
)
cursor = db.cursor()

# Khóa Triple DES (24 byte)
TRIPLE_DES_KEY = b'sixteen_byte_key12345678'  # Thay bằng khóa an toàn hơn
IV = b'12345678'  # Vector khởi tạo (8 byte)

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def generate_salt():
    return os.urandom(16).hex()  # Tạo Salt 16 byte

def triple_des_encrypt(data):
    cipher = DES3.new(TRIPLE_DES_KEY, DES3.MODE_CBC, IV)
    padded_data = pad(data.encode(), DES3.block_size)
    encrypted = cipher.encrypt(padded_data)
    return encrypted.hex()

def triple_des_decrypt(encrypted_data):
    cipher = DES3.new(TRIPLE_DES_KEY, DES3.MODE_CBC, IV)
    decrypted = cipher.decrypt(bytes.fromhex(encrypted_data))
    return unpad(decrypted, DES3.block_size).decode()

def process_password(username, password, salt):
    # Băm mật khẩu + salt
    hashed_password = hash_sha256(password + salt)
    # Băm username
    hashed_username = hash_sha256(username)
    # Kết hợp và băm lại
    combined_hash = hash_sha256(hashed_password + hashed_username)
    # Mã hóa bằng Triple DES
    encrypted_password = triple_des_encrypt(combined_hash)
    return encrypted_password

# Kiểm tra vai trò admin
def is_admin(username):
    cursor.execute("SELECT role FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    return result and result[0] == 'admin'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        salt = generate_salt()
        encrypted_password = process_password(username, password, salt)
        
        try:
            cursor.execute(
                "INSERT INTO users (username, salt, encrypted_password, role) VALUES (%s, %s, %s, 'user')",
                (username, salt, encrypted_password)
            )
            db.commit()
            flash('Đăng ký thành công!', 'success')
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash('Tên người dùng đã tồn tại!', 'error')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cursor.execute(
            "SELECT salt, encrypted_password, fail_attempts, is_locked, role FROM users WHERE username = %s",
            (username,)
        )
        user = cursor.fetchone()
        
        if not user:
            flash('Tên người dùng không tồn tại!', 'error')
            return redirect(url_for('login'))
        
        salt, stored_encrypted_password, fail_attempts, is_locked, role = user
        
        if is_locked:
            flash('Tài khoản bị khóa!', 'error')
            return redirect(url_for('login'))
        
        encrypted_password = process_password(username, password, salt)
        
        if encrypted_password == stored_encrypted_password:
            # Đăng nhập thành công
            cursor.execute(
                "UPDATE users SET fail_attempts = 0 WHERE username = %s",
                (username,)
            )
            cursor.execute(
                "INSERT INTO login_logs (username, status) VALUES (%s, 'success')",
                (username,)
            )
            db.commit()
            session['username'] = username
            session['role'] = role  # Lưu vai trò vào session
            flash('Đăng nhập thành công!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Đăng nhập thất bại
            fail_attempts += 1
            if fail_attempts >= 5:
                cursor.execute(
                    "UPDATE users SET is_locked = TRUE WHERE username = %s",
                    (username,)
                )
                flash('Tài khoản bị khóa do nhập sai quá 5 lần!', 'error')
            else:
                cursor.execute(
                    "UPDATE users SET fail_attempts = %s WHERE username = %s",
                    (fail_attempts, username)
                )
                flash(f'Sai mật khẩu! Bạn còn {5 - fail_attempts} lần thử.', 'error')
            cursor.execute(
                "INSERT INTO login_logs (username, status) VALUES (%s, 'failure')",
                (username,)
            )
            db.commit()
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        flash('Vui lòng đăng nhập!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        username = session['username']
        
        cursor.execute(
            "SELECT salt, encrypted_password FROM users WHERE username = %s",
            (username,)
        )
        user = cursor.fetchone()
        salt, stored_encrypted_password = user
        
        # Kiểm tra mật khẩu cũ
        encrypted_old_password = process_password(username, old_password, salt)
        if encrypted_old_password != stored_encrypted_password:
            flash('Mật khẩu cũ không đúng!', 'error')
            return redirect(url_for('change_password'))
        
        # Tạo Salt mới và xử lý mật khẩu mới
        new_salt = generate_salt()
        new_encrypted_password = process_password(username, new_password, new_salt)
        
        cursor.execute(
            "UPDATE users SET salt = %s, encrypted_password = %s WHERE username = %s",
            (new_salt, new_encrypted_password, username)
        )
        db.commit()
        flash('Đổi mật khẩu thành công!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Vui lòng đăng nhập!', 'error')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/admin', methods=['GET'])
def admin():
    if 'username' not in session:
        flash('Vui lòng đăng nhập!', 'error')
        return redirect(url_for('login'))
    
    if not is_admin(session['username']):
        flash('Bạn không có quyền truy cập trang quản trị!', 'error')
        return redirect(url_for('index'))
    
    cursor.execute("SELECT username, is_locked, created_at FROM users")
    users = cursor.fetchall()
    
    cursor.execute("SELECT username, status, timestamp FROM login_logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    
    return render_template('admin.html', users=users, logs=logs)

@app.route('/admin/unlock/<username>')
def unlock_account(username):
    if 'username' not in session or not is_admin(session['username']):
        flash('Bạn không có quyền thực hiện hành động này!', 'error')
        return redirect(url_for('index'))
    
    cursor.execute(
        "UPDATE users SET is_locked = FALSE, fail_attempts = 0 WHERE username = %s",
        (username,)
    )
    db.commit()
    flash(f'Tài khoản {username} đã được mở khóa!', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete/<username>')
def delete_account(username):
    if 'username' not in session or not is_admin(session['username']):
        flash('Bạn không có quyền thực hiện hành động này!', 'error')
        return redirect(url_for('index'))
    
    cursor.execute("DELETE FROM users WHERE username = %s", (username,))
    cursor.execute("DELETE FROM login_logs WHERE username = %s", (username,))
    db.commit()
    flash(f'Tài khoản {username} đã bị xóa!', 'success')
    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)  # Xóa vai trò khỏi session
    flash('Đăng xuất thành công!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
