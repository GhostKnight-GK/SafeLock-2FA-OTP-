from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import random
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.secret_key = '23n31a6216' 
bcrypt = Bcrypt(app)

# MongoDB Atlas configuration
MONGO_URI = "mongodb+srv://safelock_user:hTm_9-3CD7NRQsa@cluster0.h5r2sgl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client["safelock_db"]
users_collection = db["users"]
 
# Gmail SMTP credentials — replace with your email & app password
EMAIL_ADDRESS = 'safelock.official13@gmail.com'
EMAIL_PASSWORD = 'iqrw elqs spig rnst'

def send_otp_email(to_email, otp):
    msg = EmailMessage()
    msg['Subject'] = 'Your SafeLock OTP Code'
    msg['From'] = 'SafeLock <safelock.official13@gmail.com>'
    msg['To'] = to_email
    msg.set_content(f'Your OTP code is: {otp}')

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"OTP sent to {to_email}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def send_custom_email(to_email, subject, body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = 'SafeLock <safelock.official13@gmail.com>'
    msg['To'] = to_email
    msg.set_content(body)

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')

        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            flash('Email already registered, please login.')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert created_at timestamp
        users_collection.insert_one({
            "email": email,
            "password": hashed_password,
            "created_at": datetime.utcnow()
        })

        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        password = request.form.get('password')

        user = users_collection.find_one({"email": email})
        if not user or not bcrypt.check_password_hash(user['password'], password):
            flash('Invalid email or password.')
            return redirect(url_for('login'))

        otp = f"{random.randint(100000, 999999)}"
        print(f"Generated OTP for {email} is {otp}")
        session['otp'] = otp
        session['email'] = email

        if send_otp_email(email, otp):
            flash('OTP sent to your email.')
            return redirect(url_for('otp'))
        else:
            flash('Failed to send OTP email. Try again.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if request.method == 'POST':
        # Combine otp1 to otp6 from the form inputs
        entered_otp = ''.join([
            request.form.get(f'otp{i}') or '' for i in range(1, 7)
        ])

        if 'otp' not in session:
            flash('Session expired. Please login again.')
            return redirect(url_for('login'))

        if entered_otp == session.get('otp'):
            session.pop('otp')  # Remove OTP after verification
            session['authenticated'] = True

            # Update last_login for the user
            users_collection.update_one(
                {"email": session['email']},
                {"$set": {"last_login": datetime.utcnow()}}
            )

            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Please try again.')
            return redirect(url_for('otp'))

    return render_template('otp.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        flash('Please login first.')
        return redirect(url_for('login'))

    user = users_collection.find_one({"email": session.get('email')})
    user_created_date = user.get('created_at').strftime('%Y-%m-%d') if user and user.get('created_at') else None
    last_login = user.get('last_login').strftime('%Y-%m-%d %H:%M') if user and user.get('last_login') else None

    return render_template('dashboard.html',
                           user_created_date=user_created_date,
                           last_login=last_login)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

# --- Forgot Password Routes ---

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').lower()
        user = users_collection.find_one({"email": email})

        if not user:
            flash('Email not registered.')
            return redirect(url_for('forgot_password'))

        reset_token = secrets.token_urlsafe(32)
        expiry = datetime.utcnow() + timedelta(minutes=30)

        users_collection.update_one(
            {"email": email},
            {"$set": {"reset_token": reset_token, "reset_token_expiry": expiry}}
        )

        reset_link = f"http://localhost:5000/reset-password/{reset_token}"
        subject = "SafeLock Password Reset Request"
        body = f"Click the link below to reset your password:\n\n{reset_link}\n\nThis link expires in 30 minutes."

        send_custom_email(email, subject, body)

        flash('Password reset link sent to your email.')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = users_collection.find_one({"reset_token": token})

    if not user:
        flash('Invalid or expired reset token.')
        return redirect(url_for('login'))

    # Check expiry
    if user.get("reset_token_expiry") < datetime.utcnow():
        flash('Reset token expired.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('reset_password', token=token))

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        users_collection.update_one(
            {"email": user['email']},
            {"$set": {"password": hashed_password},
             "$unset": {"reset_token": "", "reset_token_expiry": ""}}
        )

        flash('Password reset successful! Please login.')
        return redirect(url_for('login'))

    return render_template('reset_password.html')


if __name__ == '__main__':
    app.run(debug=True)
