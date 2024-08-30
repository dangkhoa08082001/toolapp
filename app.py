
API_BASE = "http://localhost:8000"
import base64
import random
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import hashlib
import logging
import requests


app = Flask(__name__)

# Cấu hình logging để theo dõi lỗi
logging.basicConfig(level=logging.DEBUG)

def get_db_connection():
    conn = sqlite3.connect('users.db') 
    conn.row_factory = sqlite3.Row
    return conn
@app.route('/load_post_schedules', methods=['GET'])
def load_post_schedules():
    try:
        # Ghi lại URL yêu cầu
        app.logger.info(f"Received request with identifier: {request.args.get('identifier')}")
        
        identifier = request.args.get('identifier')  # Email hoặc Username
        
        if not identifier:
            app.logger.warning("Identifier is required")
            return jsonify({"message": "Identifier is required"}), 400

        conn = get_db_connection()

        # Tìm ID người dùng dựa trên email hoặc username
        user = conn.execute('SELECT id FROM users WHERE email=? OR username=?', (identifier, identifier)).fetchone()
        if user:
            user_id = user['id']

            # Tìm dữ liệu liên quan trong bảng post_schedules
            query = '''
                SELECT ps.id AS schedule_id, ps.platforms, ps.post_id, ps.schedule_date, ps.status, 
                       p.title AS post_title, p.content AS post_content, p.image_urls AS post_image_urls
                FROM post_schedules ps
                JOIN posts p ON ps.post_id = p.id
                WHERE p.user_id = ?
            '''
            data = conn.execute(query, (user_id,)).fetchall()

            # Tạo danh sách dữ liệu với thứ tự các trường mong muốn
            result = [
                {
                    "id": row['schedule_id'],
                    "platforms": row['platforms'],
                    "post": {
                        "id": row['post_id'],
                        "title": row['post_title'],
                        "content": row['post_content'],
                        "image_urls": row['post_image_urls']
                    },
                    "schedule_date": row['schedule_date'],
                    "status": row['status']
                } for row in data
            ]
            conn.close()

            app.logger.info("Data retrieved successfully")
            return jsonify(result), 200
        else:
            conn.close()
            app.logger.warning(f"User not found for identifier: {identifier}")
            return jsonify({"message": "User not found"}), 404

    except Exception as e:
        app.logger.error(f"Load post schedules error: {e}")
        return jsonify({"message": "An error occurred while loading post schedules."}), 500
@app.route('/save_post_schedules', methods=['POST'])
def save_post_schedules():
    try:
        data = request.json
        post_schedule_id = data.get('post_schedule_id')
        platforms = data.get('platforms')

        if not post_schedule_id or platforms is None:
            return jsonify({"message": "Post schedule ID and platforms are required"}), 400

        conn = get_db_connection()

        # Cập nhật dữ liệu vào bảng post_schedules
        conn.execute('''
            UPDATE post_schedules
            SET platforms = ?
            WHERE id = ?
        ''', (', '.join(platforms), post_schedule_id))

        conn.commit()
        conn.close()

        return jsonify({"message": "Post schedules updated successfully"}), 200

    except Exception as e:
        app.logger.error(f"Save post schedules error: {e}")
        return jsonify({"message": "An error occurred while saving post schedules."}), 500


@app.route('/platforms', methods=['GET'])
def get_platforms():
    try:
        conn = get_db_connection()
        platforms = conn.execute('SELECT id, name FROM platforms').fetchall()
        conn.close()

        # Chuyển đổi dữ liệu sang dạng JSON
        result = [
            {
                "id": platform['id'],
                "name": platform['name']
            } for platform in platforms
        ]

        return jsonify(result), 200
    except Exception as e:
        app.logger.error(f"Error fetching platforms: {e}")
        return jsonify({"message": "An error occurred while fetching platforms."}), 500

def hash_password_sha256(password):
    # Mã hóa mật khẩu đầu vào bằng SHA-256
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password_sha256(input_password, stored_password):
    hashed_input_password = hash_password_sha256(input_password)
    return hashed_input_password == stored_password


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json

        if not data:
            return jsonify({"message": "No data provided"}), 400

        identifier = data.get('identifier')
        password = data.get('password')

        if not identifier or not password:
            return jsonify({"message": "Identifier and password are required."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        if '@' in identifier:
            # Truy vấn theo email
            cursor.execute('SELECT password FROM users WHERE email = ?', (identifier,))
        else:
            # Truy vấn theo username
            cursor.execute('SELECT password FROM users WHERE username = ?', (identifier,))

        user = cursor.fetchone()
        conn.close()

        if user:
            stored_password = user[0]
            if hash_password_sha256(password) == stored_password:
                return jsonify({"message": "Login successful", "username": identifier}), 200
            else:
                return jsonify({"message": "Invalid username or password"}), 401
        else:
            return jsonify({"message": "Invalid username or password"}), 401
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        return jsonify({"message": f"An error occurred during login: {str(e)}"}), 500


@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        phone = data.get('phone')
        address = data.get('address')
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username=? OR email=?', (username, email)).fetchone()

        if existing_user:
            return jsonify({"message": "Username or email already exists"}), 409

        # Mã hóa mật khẩu
        hashed_password = hash_password_sha256(password) 

        # Lưu thông tin người dùng mới vào cơ sở dữ liệu
        conn.execute(
            'INSERT INTO users (username, email, password, phone, address) VALUES (?, ?, ?, ?, ?)',
            (username, email, hashed_password, phone, address)
        )
        conn.commit()
        conn.close()

        return jsonify({"message": "Registration successful"}), 201
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({"message": "Failed to register. Please try again later."}), 500

    
@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    try:
        data = request.json
        email = data.get('email')

        if not email:
            return jsonify({"message": "Email is required"}), 400

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()

        if user:
            confirmation_code = generate_otp()
            conn.execute('UPDATE users SET confirmation_code=? WHERE email=?', (confirmation_code, email))
            conn.commit()
            conn.close()

            send_email(email, confirmation_code)

            return jsonify({"message": "Confirmation code sent to email"}), 200
        else:
            conn.close()
            return jsonify({"message": "Email not found in the database"}), 404
    except sqlite3.Error as db_error:
        app.logger.error(f"Database error during password reset: {db_error}")
        return jsonify({"message": "A database error occurred during password reset."}), 500
    except Exception as e:
        app.logger.error(f"Forgot password error: {e}")
        return jsonify({"message": "An error occurred during password reset."}), 500


def generate_otp():
    return random.randint(100000, 999999)

def send_email(email, confirmation_code):
    sender_email = "cubom882001@gmail.com"
    password = "rzac qtqo xpkr uuzc"

    msg = MIMEText(f"Your confirmation code is {confirmation_code}")
    msg['Subject'] = 'Password Reset Confirmation Code'
    msg['From'] = sender_email
    msg['To'] = email

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
    except Exception as e:
        app.logger.error(f"Error sending email: {e}")

@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        data = request.json
        email = data.get('email')
        new_password = data.get('new_password')
        confirmation_code = data.get('confirmation_code')

        if not email or not new_password or not confirmation_code:
            return jsonify({"message": "Missing required fields"}), 400

        # Kiểm tra mã xác nhận
        conn = get_db_connection()
        user_entry = conn.execute(
            'SELECT * FROM users WHERE email=? AND confirmation_code=?',
            (email, confirmation_code)
        ).fetchone()

        if not user_entry:
            return jsonify({"message": "Invalid confirmation code"}), 400

        # Cập nhật mật khẩu mới
        hashed_password = hash_password_sha256(new_password)
        conn.execute(
            'UPDATE users SET password=? WHERE email=?',
            (hashed_password, email)
        )
        conn.commit()
        conn.close()

        return jsonify({"message": "Password updated successfully"}), 200
    except Exception as e:
        app.logger.error(f"Password reset error: {e}")
        return jsonify({"message": "Failed to reset password. Please try again later."}), 500



    
@app.route('/get_user_profile/<identifier>', methods=['GET'])
def get_user_profile(identifier):
    conn = get_db_connection()
    
    if '@' in identifier:
        user = conn.execute('SELECT username, email, phone, address, avatar FROM users WHERE email=?', (identifier,)).fetchone()
    else:
        user = conn.execute('SELECT username, email, phone, address, avatar FROM users WHERE username=?', (identifier,)).fetchone()
    
    conn.close()
    
    if user:
        response = {
            'username': user['username'],
            'email': user['email'],
            'phone': user['phone'],
            'address': user['address']
        }
        
        if user['avatar']:
            response['avatar'] = base64.b64encode(user['avatar']).decode('utf-8')
        
        return jsonify(response), 200
    else:
        return jsonify({"message": "User not found"}), 404

@app.route('/update_profile', methods=['POST'])
def update_profile():
    email = request.form.get('email')
    phone = request.form.get('phone')
    address = request.form.get('address')
    avatar_file = request.files.get('avatar')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    if not any([phone, address, avatar_file]):
        return jsonify({"error": "At least one field (phone, address, avatar) must be provided"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        if avatar_file:
            avatar_data = avatar_file.read()
            cursor.execute('UPDATE users SET phone = ?, address = ?, avatar = ? WHERE email = ?',
                           (phone, address, avatar_data, email))
        else:
            cursor.execute('UPDATE users SET phone = ?, address = ? WHERE email = ?',
                           (phone, address, email))

        if cursor.rowcount == 0:
            return jsonify({"error": "User not found"}), 404

        conn.commit()
        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        conn.close()

@app.route('/get_user_id', methods=['POST'])
def get_user_id():
    try:
        data = request.json
        identifier = data.get('identifier')  # Có thể là username hoặc email

        conn = get_db_connection()
        user = conn.execute('SELECT id FROM users WHERE email=? OR username=?', (identifier, identifier)).fetchone()
        conn.close()

        if user:
            return jsonify({"user_id": user['id']}), 200
        else:
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        app.logger.error(f"Get user ID error: {e}")
        return jsonify({"message": "An error occurred while getting user ID."}), 500

@app.route('/load_posts', methods=['GET'])
def load_posts():
    try:
        identifier = request.args.get('identifier')  # Email hoặc Username

        conn = get_db_connection()

        # Tìm ID người dùng dựa trên email hoặc username
        user = conn.execute('SELECT id FROM users WHERE email=? OR username=?', (identifier, identifier)).fetchone()
        if user:
            user_id = user['id']

            # Tìm dữ liệu liên quan trong bảng posts
            data = conn.execute('SELECT id, title, content, image_urls FROM posts WHERE user_id=?', (user_id,)).fetchall()

            # Tạo danh sách dữ liệu với thứ tự các trường mong muốn
            result = [
                {
                    "id": row['id'],
                    "title": row['title'],
                    "content": row['content'],
                    "image_urls": row['image_urls']
                } for row in data
            ]
            conn.close()

            return jsonify(result), 200
        else:
            conn.close()
            return jsonify({"message": "User not found"}), 404

    except Exception as e:
        app.logger.error(f"Load posts error: {e}")
        return jsonify({"message": "An error occurred while loading posts."}), 500

@app.route('/add_post', methods=['POST'])
def add_post():
    try:
        data = request.json
        title = data.get('title')
        content = data.get('content')
        image_urls = data.get('image_urls')
        user_id = data.get('user_id')  # Giả sử 'user_id' là ID người dùng

        conn = get_db_connection()

        # Kiểm tra kết nối cơ sở dữ liệu
        if not conn:
            return jsonify({"message": "Database connection failed"}), 500

        # Thực hiện truy vấn thêm dữ liệu bài viết
        conn.execute('INSERT INTO posts (user_id, title, content, image_urls) VALUES (?, ?, ?, ?)', 
                     (user_id, title, content, image_urls))
        conn.commit()
        conn.close()

        return jsonify({"message": "Post added successfully"}), 200
    except sqlite3.OperationalError as e:
        app.logger.error(f"Database operational error: {e}")
        return jsonify({"message": "Database operational error"}), 500
    except Exception as e:
        app.logger.error(f"Add post error: {e}")
        return jsonify({"message": "An error occurred while adding the post."}), 500

@app.route('/update_post', methods=['POST'])
def update_post():
    try:
        data = request.json
        post_id = data.get('id')
        title = data.get('title')
        content = data.get('content')
        image_urls = data.get('image_urls')
        user_id = data.get('user_id')  # Lấy user_id từ request

        conn = get_db_connection()
        conn.execute('UPDATE posts SET title=?, content=?, image_urls=?, user_id=? WHERE id=?',
                     (title, content, image_urls, user_id, post_id))  # Thêm user_id vào truy vấn SQL
        conn.commit()
        conn.close()

        return jsonify({"message": "Post updated successfully"}), 200
    except Exception as e:
        app.logger.error(f"Update post error: {e}")
        return jsonify({"message": "An error occurred while updating the post."}), 500

@app.route('/delete_post/<post_id>', methods=['DELETE'])
def delete_post(post_id):
    try:
        app.logger.info(f"Attempting to delete post with ID: {post_id}")
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()

        app.logger.info(f"Rows affected: {rows_affected}")

        if rows_affected == 0:
            return jsonify({"message": "No post found with the given ID"}), 404

        return jsonify({"message": "Post deleted successfully"}), 200
    except Exception as e:
        app.logger.error(f"Delete post error: {e}")
        return jsonify({"message": "An error occurred while deleting the post."}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
