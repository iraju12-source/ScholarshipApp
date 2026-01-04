import os
import sqlite3
import shutil
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.secret_key = "karkai_nandre_super_secret"

# Configuration
UPLOAD_FOLDER = 'uploads'
IMAGE_FOLDER = 'images' 
BACKUP_FOLDER = 'backups'
DB_NAME = 'karkai_system.db'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['IMAGE_FOLDER'] = os.path.join('static', 'images')
app.config['BACKUP_FOLDER'] = BACKUP_FOLDER

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(IMAGE_FOLDER, exist_ok=True)
os.makedirs(BACKUP_FOLDER, exist_ok=True)

# ==========================================
# AUTOMATED BACKUP LOGIC
# ==========================================
def backup_database():
    """Creates a timestamped copy of the database file."""
    if os.path.exists(DB_NAME):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"backup_{timestamp}.db"
        backup_path = os.path.join(app.config['BACKUP_FOLDER'], backup_filename)
        try:
            shutil.copy2(DB_NAME, backup_path)
            print(f"[*] Automated Backup Created: {backup_filename}")
        except Exception as e:
            print(f"[!] Backup Failed: {e}")

# Initialize and start the scheduler
# use_reloader=False in app.run is required to prevent double-initialization
scheduler = BackgroundScheduler()
# Runs once every 24 hours
scheduler.add_job(func=backup_database, trigger="interval", hours=24)
scheduler.start()

# ==========================================
# DATABASE HELPERS
# ==========================================
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    # Users table
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL, 
        password TEXT NOT NULL,
        role TEXT NOT NULL, 
        full_name TEXT)''')
    
    # Complete Applications table
    conn.execute('''CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER UNIQUE,
        full_name TEXT, dob TEXT, gender TEXT, 
        mobile_primary TEXT, mobile_secondary TEXT, email TEXT,
        address TEXT, district TEXT, pincode TEXT, aadhaar_number TEXT,
        aadhaar_card_file TEXT, sslc_marksheet_file TEXT, 
        hsc_marksheet_file TEXT, semester_marksheet_file TEXT,
        sslc_school TEXT, sslc_marks TEXT, sslc_percent TEXT,
        hsc_school TEXT, hsc_marks TEXT, hsc_percent TEXT,
        current_college TEXT, current_course TEXT, cgpa TEXT, semester_marks TEXT,
        father_name TEXT, father_occupation TEXT, mother_name TEXT, mother_occupation TEXT,
        dependents TEXT, annual_income TEXT, other_scholarship TEXT, 
        scholarship_details TEXT, housing_type TEXT, talents TEXT,
        ref1_name TEXT, ref1_contact TEXT, ref1_relation TEXT,
        ref2_name TEXT, ref2_contact TEXT, ref2_relation TEXT,
        written_test_pdf TEXT,
        status TEXT DEFAULT 'Submitted',
        assigned_to INTEGER,
        coordinator_remarks TEXT, evaluator_score INTEGER, evaluator_remarks TEXT,
        details_marks INTEGER, comm_marks INTEGER, econ_marks INTEGER, 
        parent_marks INTEGER, own_remarks_marks INTEGER, acad_marks INTEGER, 
        written_marks INTEGER, talent_marks INTEGER,
        evaluator_recommendation TEXT, evaluator_comments TEXT,
        interview_marks INTEGER, final_decision TEXT, final_comments TEXT,
        interview_doc TEXT,
        submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(student_id) REFERENCES users(id),
        FOREIGN KEY(assigned_to) REFERENCES users(id))''')
        
    # Pre-populate Admin
    admin_exists = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    if not admin_exists:
        admin_password = generate_password_hash("admin123")
        conn.execute("INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)", 
                     ("admin", admin_password, "admin", "System Administrator"))
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: 
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# CORE ROUTES
# ==========================================
@app.route('/')
def home():
    if 'user_id' in session: 
        return redirect(url_for('dashboard_router'))
    return redirect(url_for('login'))

@app.route('/fix_db')
def fix_db():
    conn = get_db()
    try:
        conn.execute("ALTER TABLE applications ADD COLUMN assigned_to INTEGER")
        conn.commit()
        return "Column added successfully!"
    except Exception as e:
        return f"Error: {e}"
    finally:
        conn.close()
        
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], p):
            # FIX: Added 'username' to the session update to fix the welcome message display
            session.update({
                'user_id': user['id'], 
                'role': user['role'], 
                'name': user['full_name'],
                'username': user['username']
            })
            return redirect(url_for('dashboard_router'))
        flash("Invalid username or password")
    return render_template('login.html')

@app.route('/dashboard_router')
@login_required
def dashboard_router():
    role = session.get('role')
    if role == 'admin': return redirect(url_for('dash_admin'))
    if role == 'coordinator': return redirect(url_for('dash_coordinator'))
    if role == 'evaluator': return redirect(url_for('dash_evaluator'))
    return redirect(url_for('dash_student'))

@app.route('/scholarship_details')
def scholarship_details():
    """Renders the split-screen scholarship information page."""
    return render_template('scholarship_details.html')

@app.route('/dash_admin')
@login_required
def dash_admin():
    if session.get('role') != 'admin': return redirect(url_for('home'))
    conn = get_db()
    apps = conn.execute("SELECT a.*, u.full_name as evaluator_name FROM applications a LEFT JOIN users u ON a.assigned_to = u.id").fetchall()
    evals = conn.execute("SELECT id, username, full_name, role FROM users WHERE role != 'student'").fetchall()
    conn.close()
    return render_template('dash_admin.html', apps=apps, evaluators=evals)

@app.route('/dash_coordinator')
@login_required
def dash_coordinator():
    if session.get('role') != 'coordinator': return redirect(url_for('home'))
    conn = get_db()
    apps = conn.execute("SELECT a.*, u.full_name as evaluator_name FROM applications a LEFT JOIN users u ON a.assigned_to = u.id").fetchall()
    evals = conn.execute("SELECT id, full_name FROM users WHERE role = 'evaluator'").fetchall()
    conn.close()
    return render_template('dash_coordinator.html', apps=apps, evaluators=evals)

@app.route('/dash_evaluator')
@login_required
def dash_evaluator():
    if session.get('role') != 'evaluator': return redirect(url_for('home'))
    conn = get_db()
    apps = conn.execute("SELECT * FROM applications WHERE assigned_to = ?", (session['user_id'],)).fetchall()
    conn.close()
    return render_template('dash_evaluator.html', apps=apps)

@app.route('/dash_student')
@login_required
def dash_student():
    conn = get_db()
    app_data = conn.execute("SELECT * FROM applications WHERE student_id = ?", (session['user_id'],)).fetchone()
    conn.close()
    return render_template('dash_student.html', application=app_data)

# ==========================================
# USER MANAGEMENT ROUTES
# ==========================================
@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if session.get('role') not in ['admin', 'coordinator']:
        return redirect(url_for('login'))

    full_name = request.form.get('full_name')
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')

    if not full_name or not username or not password:
        flash("All fields are required!")
        return redirect(url_for('dashboard_router') + '#users')

    try:
        db = get_db()
        hashed_pw = generate_password_hash(password)
        db.execute(
            'INSERT INTO users (full_name, username, password, role) VALUES (?, ?, ?, ?)',
            (full_name, username, hashed_pw, role)
        )
        db.commit()
        flash(f"Account for {full_name} created successfully!")
    except Exception as e:
        flash("Error creating account. Username might already exist.")
    finally:
        db.close()
    
    return redirect(url_for('dashboard_router') + '#users')
    
@app.route('/edit_user', methods=['POST'])
@login_required
def edit_user():
    if session.get('role') not in ['admin', 'coordinator']:
        return redirect(url_for('login'))
    
    user_id = request.form.get('user_id')
    new_username = request.form.get('username')
    new_full_name = request.form.get('full_name')
    new_role = request.form.get('role')
    new_password = request.form.get('password')
    
    db = get_db()
    try:
        if new_password and new_password.strip() != "":
            hashed_pw = generate_password_hash(new_password)
            db.execute('''UPDATE users SET username = ?, password = ?, full_name = ?, role = ? 
                          WHERE id = ?''', (new_username, hashed_pw, new_full_name, new_role, user_id))
        else:
            db.execute('''UPDATE users SET username = ?, full_name = ?, role = ? 
                          WHERE id = ?''', (new_username, new_full_name, new_role, user_id))
        db.commit()
        flash('Account updated successfully!')
    except Exception as e:
        flash('Update failed.')
    finally:
        db.close()
    
    return redirect(url_for('dashboard_router') + '#users')

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if session.get('role') != 'admin':
        flash("Unauthorized action.")
        return redirect(url_for('dashboard_router'))

    db = get_db()
    try:
        # 1. Prevent self-deletion
        if user_id == session.get('user_id'):
            flash("You cannot delete your own account while logged in.")
            return redirect(url_for('dashboard_router') + '#users')

        # 2. Prevent deletion if linked to scholarship records (student or evaluator)
        linked_apps = db.execute('''SELECT id FROM applications 
                                    WHERE student_id = ? OR assigned_to = ?''', 
                                    (user_id, user_id)).fetchone()
        
        if linked_apps:
            flash("Cannot delete user: This account has linked scholarship application records.")
        else:
            db.execute('DELETE FROM users WHERE id = ?', (user_id,))
            db.commit()
            flash("User account deleted successfully.")
    except Exception as e:
        flash(f"Error during deletion: {e}")
    finally:
        db.close()

    return redirect(url_for('dashboard_router') + '#users')

# ==========================================
# APPLICATION & EVALUATION ROUTES
# ==========================================
@app.route('/update_schema_v2')
def update_schema_v2():
    conn = get_db()
    cols = [
        "details_marks INTEGER", "comm_marks INTEGER", "econ_marks INTEGER", 
        "parent_marks INTEGER", "own_remarks_marks INTEGER", "acad_marks INTEGER", 
        "written_marks INTEGER", "talent_marks INTEGER",
        "evaluator_recommendation TEXT", "evaluator_comments TEXT",
        "interview_marks INTEGER", "final_decision TEXT", "final_comments TEXT",
        "interview_doc TEXT"
    ]
    for col in cols:
        try:
            conn.execute(f"ALTER TABLE applications ADD COLUMN {col}")
        except: pass
    conn.commit()
    conn.close()
    return "Schema updated successfully!"

@app.route('/assign_evaluator', methods=['POST'])
@login_required
def assign_evaluator():
    if session.get('role') not in ['admin', 'coordinator']: return "Unauthorized", 403
    app_id = request.form.get('app_id')
    eval_id = request.form.get('evaluator_id')
    conn = get_db()
    conn.execute("UPDATE applications SET assigned_to = ?, status = 'Assigned' WHERE id = ?", (eval_id, app_id))
    conn.commit()
    conn.close()
    flash("Application successfully assigned to evaluator.")
    return redirect(request.referrer)

@app.route('/view_application/<int:app_id>')
@login_required
def view_application(app_id):
    conn = get_db()
    app_data = conn.execute("SELECT * FROM applications WHERE id = ?", (app_id,)).fetchone()
    conn.close()

    if not app_data:
        flash("Application not found.")
        return redirect(url_for('dashboard_router'))

    if session.get('role') == 'evaluator' and app_data['assigned_to'] != session.get('user_id'):
        flash("Unauthorized access.")
        return redirect(url_for('dash_evaluator'))

    return render_template('view_full.html', app=app_data)

@app.route('/submit_evaluation', methods=['POST'])
@login_required
def submit_evaluation():
    f = request.form
    hsc_percent = float(f.get('hsc_percent') or 0)
    hsc_score = hsc_percent / 4
    
    manual_fields = [
        'details_marks', 'comm_marks', 'econ_marks', 'parent_marks', 
        'own_remarks_marks', 'written_marks', 'talent_marks'
    ]
    manual_sum = sum(int(f.get(x) or 0) for x in manual_fields)
    eval_total = round(min(80, hsc_score + manual_sum), 2)

    conn = get_db()
    conn.execute("""
        UPDATE applications SET 
            details_marks=?, comm_marks=?, econ_marks=?, parent_marks=?, 
            own_remarks_marks=?, written_marks=?, talent_marks=?,
            evaluator_recommendation=?, evaluator_comments=?, evaluator_score=?, status='Evaluated'
        WHERE id=?
    """, (f.get('details_marks'), f.get('comm_marks'), f.get('econ_marks'), f.get('parent_marks'),
          f.get('own_remarks_marks'), f.get('written_marks'), f.get('talent_marks'),
          f.get('evaluator_recommendation'), f.get('evaluator_comments'), eval_total, f.get('app_id')))
    conn.commit()
    conn.close()
    return redirect(url_for('dash_evaluator'))

@app.route('/final_approval', methods=['POST'])
@login_required
def final_approval():
    if session.get('role') not in ['admin', 'coordinator']: return "Unauthorized", 403
    
    app_id = request.form.get('app_id')
    interview_marks = int(request.form.get('interview_marks') or 0)
    file = request.files.get('interview_doc')
    
    doc_filename = ""
    if file and file.filename != '':
        doc_filename = f"interview_{app_id}_{secure_filename(file.filename)}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], doc_filename))

    conn = get_db()
    conn.execute("""
        UPDATE applications SET 
            interview_marks=?, final_decision=?, final_comments=?, 
            interview_doc=?, status='Finalized' 
        WHERE id=?
    """, (interview_marks, request.form.get('final_decision'), 
          request.form.get('final_comments'), doc_filename, app_id))
    
    conn.commit()
    conn.close()
    flash("Application successfully finalized.")
    return redirect(request.referrer)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        n = request.form.get('full_name')
        if not u or not p or not n:
            flash("All fields are required!")
            return render_template('register.html')
        try:
            conn = get_db()
            conn.execute("INSERT INTO users (username, password, role, full_name) VALUES (?, ?, 'student', ?)", 
                         (u, generate_password_hash(p), n))
            conn.commit()
            conn.close()
            flash("Registration successful!")
            return redirect(url_for('login'))
        except: flash("Username already exists.")
    return render_template('register.html')

@app.route('/apply', methods=['POST'])
@login_required
def apply():
    conn = get_db()
    def up(field):
        file = request.files.get(field)
        if file and file.filename != '':
            filename = f"{session['user_id']}_{field}_{secure_filename(file.filename)}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return filename
        return ""

    f = request.form
    data = (
        session['user_id'], f.get('full_name'), f.get('dob'), f.get('gender'), 
        f.get('mobile_primary'), f.get('mobile_secondary'), f.get('email'), 
        f.get('address'), f.get('district'), f.get('pincode'), f.get('aadhaar_number'),
        up('aadhaar_card_file'), up('sslc_marksheet_file'), up('hsc_marksheet_file'), up('semester_marksheet_file'),
        f.get('sslc_school'), f.get('sslc_marks'), f.get('sslc_percent'),
        f.get('hsc_school'), f.get('hsc_marks'), f.get('hsc_percent'),
        f.get('current_college'), f.get('current_course'), f.get('cgpa'), f.get('semester_marks'),
        f.get('father_name'), f.get('father_occupation'), f.get('mother_name'), f.get('mother_occupation'),
        f.get('dependents'), f.get('annual_income'), f.get('other_scholarship', 'No'), f.get('scholarship_details'), 
        f.get('housing_type'), f.get('talents'), 
        f.get('ref1_name'), f.get('ref1_contact'), f.get('ref1_relation'),
        f.get('ref2_name'), f.get('ref2_contact'), f.get('ref2_relation'), 
        up('answer_sheet')
    )
    
    try:
        conn.execute(f'''INSERT INTO applications (
            student_id, full_name, dob, gender, mobile_primary, mobile_secondary, email, 
            address, district, pincode, aadhaar_number, aadhaar_card_file, sslc_marksheet_file, 
            hsc_marksheet_file, semester_marksheet_file, sslc_school, sslc_marks, sslc_percent,
            hsc_school, hsc_marks, hsc_percent, current_college, current_course, cgpa, semester_marks,
            father_name, father_occupation, mother_name, mother_occupation, dependents,
            annual_income, other_scholarship, scholarship_details, housing_type, talents,
            ref1_name, ref1_contact, ref1_relation, ref2_name, ref2_contact, ref2_relation, written_test_pdf
        ) VALUES ({",".join(["?"]*42)})''', data)
        conn.commit()
        flash("form submitted successfully")
    except sqlite3.IntegrityError:
        flash("form has been already submitted")
    finally:
        conn.close()
    return redirect(url_for('dash_student'))

@app.route('/download/<filename>')
@login_required
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    # use_reloader=False prevents the scheduler thread from double-starting
    app.run(debug=True, use_reloader=False)