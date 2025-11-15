import os
import logging
import re
import json
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, flash, session, jsonify, send_file
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai
import markdown
from sqlalchemy import create_engine, Column, String, Integer, Text, DateTime, Boolean, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import tempfile

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "defaultsecretkey")

# Database configuration
engine = create_engine(os.getenv("DATABASE_URL", "sqlite:///docgenai.db"))
Base = declarative_base()

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
EXPORT_FOLDER = os.getenv("EXPORT_FOLDER", "exports")
ALLOWED_EXTENSIONS = {'.py', '.js', '.java', '.cpp', '.c', '.html', '.css', '.php', '.rb', '.go', '.ts', '.rs', '.swift', '.kt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['EXPORT_FOLDER'] = EXPORT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB limit

# Configure logging
logging.basicConfig(level=logging.INFO)

# Configure Gemini API
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("models/gemini-2.0-flash")

# Database Models (keep the same)
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(120), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Documentation(Base):
    __tablename__ = 'documentations'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    title = Column(String(200), nullable=False)
    filename = Column(String(200))
    code_content = Column(Text)
    documentation_content = Column(Text)
    metrics = Column(Text)
    template = Column(String(50), default='standard')
    language = Column(String(50))
    is_favorite = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(engine)

# Create session factory
SessionLocal = sessionmaker(bind=engine)

# Language mapping and templates (keep the same)
LANGUAGE_MAP = {
    '.py': 'Python',
    '.js': 'JavaScript',
    '.java': 'Java',
    '.cpp': 'C++',
    '.c': 'C',
    '.html': 'HTML',
    '.css': 'CSS',
    '.php': 'PHP',
    '.rb': 'Ruby',
    '.go': 'Go',
    '.ts': 'TypeScript',
    '.rs': 'Rust',
    '.swift': 'Swift',
    '.kt': 'Kotlin'
}

DOC_TEMPLATES = {
    'standard': {
        'name': 'Standard Documentation',
        'sections': ['overview', 'features', 'architecture', 'setup', 'limitations', 'conclusion']
    },
    'api': {
        'name': 'API Documentation',
        'sections': ['overview', 'endpoints', 'authentication', 'examples', 'error_codes', 'rate_limiting']
    },
    'minimal': {
        'name': 'Minimal Documentation',
        'sections': ['overview', 'usage', 'examples']
    },
    'comprehensive': {
        'name': 'Comprehensive Documentation',
        'sections': ['overview', 'features', 'architecture', 'installation', 'configuration', 'usage', 'api', 'testing', 'deployment', 'troubleshooting']
    }
}

# Configure PDFKit with your wkhtmltopdf path
try:
    import pdfkit
    # Add this line - point to your installed wkhtmltopdf executable
    PDFKIT_CONFIG = pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe')
except ImportError:
    PDFKIT_CONFIG = None
    logging.warning("PDFKit not installed. PDF export will not work.")

# Helper functions (keep the same)
def allowed_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS

def strip_first_line(text):
    return '\n'.join(text.split('\n')[1:])

def normalize_whitespace(text):
    return re.sub(r'\n\s*\n+', '\n\n', text.strip())

def markdown_to_html(md_text):
    return markdown.markdown(md_text)

def analyze_code(code):
    lines = code.splitlines()
    total_lines = len(lines)
    
    non_empty_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
    logic_lines = len(non_empty_lines)
    comment_lines = len([line for line in lines if line.strip().startswith('#')])
    
    keywords = ['if ', 'for ', 'while ', 'def ', 'class ', 'try:', 'except ', 'switch ', 'case ', 'else ', 'elif ']
    complexity_score = sum(1 for line in non_empty_lines for keyword in keywords if keyword in line)
    
    quality_score = 0
    if total_lines > 0:
        comment_ratio = comment_lines / total_lines
        complexity_ratio = complexity_score / max(logic_lines, 1)
        
        if 0.2 <= comment_ratio <= 0.3:
            quality_score += 30
        elif 0.1 <= comment_ratio <= 0.4:
            quality_score += 20
        else:
            quality_score += 10
            
        if complexity_ratio < 0.3:
            quality_score += 40
        elif complexity_ratio < 0.6:
            quality_score += 25
        else:
            quality_score += 10
            
        if logic_lines > 10:
            quality_score += 30
    
    return {
        'total_lines': total_lines,
        'logic_lines': logic_lines,
        'comment_lines': comment_lines,
        'comment_ratio': f"{(comment_lines / total_lines * 100):.1f}%" if total_lines > 0 else "0%",
        'complexity_score': complexity_score,
        'quality_score': min(quality_score, 100)
    }

def generate_doc(code, filename, template='standard'):
    file_ext = os.path.splitext(filename)[1].lower()
    language = LANGUAGE_MAP.get(file_ext, 'the provided code')
    
    template_info = DOC_TEMPLATES.get(template, DOC_TEMPLATES['standard'])
    sections = template_info['sections']
    
    prompt = f"""
    **ROLE:** You are an expert software architect and technical writer.
    **TASK:** Generate comprehensive documentation for the {language} code using the {template} template.
    **INSTRUCTIONS:** 
    - Analyze the code's purpose, structure, and key functionalities.
    - Output MUST be a valid JSON object with the following keys: {json.dumps(sections)}.
    - The value for each key must be a string written in clear, professional Markdown format.
    - Be concise but thorough. Do not make up information not present in the code.
    - Adapt the documentation to the code's complexity and purpose.

    **CODE TO ANALYZE:**
    ```{language}
    {code}
    ```

    **OUTPUT (JSON ONLY):**
    """

    try:
        response = model.generate_content(prompt)
        response_text = response.text.strip().replace('```json', '').replace('```', '')
        response_json = json.loads(response_text)
        
        final_markdown = f"# Project Documentation\n\n"
        
        for i, section in enumerate(sections, 1):
            if section in response_json:
                final_markdown += f"## {i}. {section.replace('_', ' ').title()}\n{response_json[section]}\n\n"
        
        return final_markdown
    except Exception as e:
        logging.error(f"Documentation generation error: {e}")
        return "Error: Unable to generate documentation at this time. Please try again later."

def save_documentation(user_id, title, filename, code_content, documentation_content, metrics, template, language):
    db_session = SessionLocal()
    try:
        doc = Documentation(
            user_id=user_id,
            title=title,
            filename=filename,
            code_content=code_content,
            documentation_content=documentation_content,
            metrics=json.dumps(metrics),
            template=template,
            language=language
        )
        db_session.add(doc)
        db_session.commit()
        return doc.id
    except Exception as e:
        logging.error(f"Error saving documentation: {e}")
        db_session.rollback()
        return None
    finally:
        db_session.close()

def get_user_documentations(user_id, limit=10, offset=0):
    db_session = SessionLocal()
    try:
        docs = db_session.query(Documentation).filter(
            Documentation.user_id == user_id
        ).order_by(
            Documentation.created_at.desc()
        ).offset(offset).limit(limit).all()
        return docs
    except Exception as e:
        logging.error(f"Error fetching documentations: {e}")
        return []
    finally:
        db_session.close()

# NEW: PDF Generation with PDFKit
def generate_pdf(html_content, title):
    """Generate PDF from HTML content using PDFKit"""
    try:
        import pdfkit
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as output_file:
            # Configure PDF options
            options = {
                'page-size': 'A4',
                'margin-top': '2cm',
                'margin-right': '2cm',
                'margin-bottom': '2cm',
                'margin-left': '2cm',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None,
                'header-left': title,
                'header-right': 'Page [page] of [toPage]',
                'header-font-size': '8',
                'footer-center': 'Generated by DocGenAI',
                'footer-font-size': '8'
            }
            
            # Generate PDF
            pdfkit.from_string(html_content, output_file.name, options=options, configuration=PDFKIT_CONFIG)
            return output_file.name
            
    except ImportError:
        logging.error("PDFKit not installed. Please install it with: pip install pdfkit")
        return None
    except Exception as e:
        logging.error(f"PDF generation failed: {e}")
        return None

def get_user_analytics(user_id):
    db_session = SessionLocal()
    try:
        total_docs = db_session.query(func.count(Documentation.id)).filter(
            Documentation.user_id == user_id
        ).scalar()
        
        favorite_docs = db_session.query(func.count(Documentation.id)).filter(
            Documentation.user_id == user_id,
            Documentation.is_favorite == True
        ).scalar()
        
        popular_language = db_session.query(
            Documentation.language,
            func.count(Documentation.id)
        ).filter(
            Documentation.user_id == user_id
        ).group_by(
            Documentation.language
        ).order_by(
            func.count(Documentation.id).desc()
        ).first()
        
        recent_activity = db_session.query(Documentation).filter(
            Documentation.user_id == user_id
        ).order_by(
            Documentation.created_at.desc()
        ).limit(5).all()
        
        return {
            'total_docs': total_docs or 0,
            'favorite_docs': favorite_docs or 0,
            'popular_language': popular_language[0] if popular_language else 'None',
            'recent_activity': recent_activity
        }
    except Exception as e:
        logging.error(f"Analytics error: {e}")
        return {'total_docs': 0, 'favorite_docs': 0, 'popular_language': 'None', 'recent_activity': []}
    finally:
        db_session.close()

# Routes (keep the same)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        db_session = SessionLocal()
        try:
            existing_user = db_session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                flash('Username or email already exists')
                return render_template('register.html')
            
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password_hash=hashed_password)
            db_session.add(new_user)
            db_session.commit()
            
            flash('Registration successful! Please log in.')
            return redirect('/login')
        except Exception as e:
            logging.error(f"Registration error: {e}")
            flash('Registration failed. Please try again.')
        finally:
            db_session.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db_session = SessionLocal()
        try:
            user = db_session.query(User).filter(User.username == username).first()
            
            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                session['username'] = user.username
                flash('Login successful!')
                return redirect('/')
            else:
                flash('Invalid credentials')
        except Exception as e:
            logging.error(f"Login error: {e}")
            flash('Login failed. Please try again.')
        finally:
            db_session.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect('/')

@app.route('/')
def index():
    return render_template('index.html', username=session.get('username'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    analytics = get_user_analytics(session['user_id'])
    recent_docs = get_user_documentations(session['user_id'], limit=10)
    
    return render_template('dashboard.html', 
                         analytics=analytics,
                         recent_docs=recent_docs,
                         username=session['username'])

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect('/login')
    
    page = request.args.get('page', 1, type=int)
    limit = 10
    offset = (page - 1) * limit
    
    docs = get_user_documentations(session['user_id'], limit=limit, offset=offset)
    total_docs = len(get_user_documentations(session['user_id']))
    total_pages = (total_docs + limit - 1) // limit
    
    return render_template('history.html', docs=docs, page=page, total_pages=total_pages)

@app.route('/result', methods=['POST'])
def result():
    if 'user_id' not in session:
        flash('Please log in to generate documentation')
        return redirect('/login')
    
    code = ''
    title = request.form.get('title', 'Untitled Documentation')
    template = request.form.get('template', 'standard')
    pasted_code = request.form.get('code')
    uploaded_file = request.files.get('file')
    filename = "pasted_code.py"

    if pasted_code and pasted_code.strip():
        code = pasted_code.strip()
        logging.info("Code received from pasted input.")
    elif uploaded_file and allowed_file(uploaded_file.filename):
        filename = secure_filename(uploaded_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(file_path)
        try:
            with open(file_path, 'r') as f:
                code = f.read()
            logging.info(f"File uploaded and read: {filename}")
        except Exception as e:
            logging.error(f"Error reading file: {e}")
            flash("Error reading the uploaded file. Please try again.")
            return redirect('/')
        finally:
            if os.path.exists(file_path):
                os.remove(file_path)
    else:
        flash("Please upload a valid code file or paste code.")
        return redirect('/')

    if not code.strip():
        flash("No valid code provided.")
        return redirect('/')
    
    documentation_md = generate_doc(code, filename, template)
    documentation_md = strip_first_line(documentation_md)
    documentation_md = normalize_whitespace(documentation_md)
    documentation_html = markdown_to_html(documentation_md)
    
    code_metrics = analyze_code(code)
    
    file_ext = os.path.splitext(filename)[1].lower()
    language = LANGUAGE_MAP.get(file_ext, 'Unknown')
    
    doc_id = save_documentation(
        session['user_id'], title, filename, code, documentation_md, 
        code_metrics, template, language
    )
    
    return render_template('result.html', 
                         documentation=documentation_html,
                         metrics=code_metrics,
                         doc_id=doc_id,
                         title=title,
                         template=template,
                         now=datetime.now())

@app.route('/export/<int:doc_id>/<format_type>')
def export_documentation(doc_id, format_type):
    if 'user_id' not in session:
        return redirect('/login')
    
    db_session = SessionLocal()
    try:
        doc = db_session.query(Documentation).filter(
            Documentation.id == doc_id,
            Documentation.user_id == session['user_id']
        ).first()
        
        if not doc:
            flash('Documentation not found')
            return redirect('/history')
        
        if format_type == 'pdf':
            # Convert markdown to HTML for PDF
            html_content = markdown_to_html(doc.documentation_content)
            
            # Create styled HTML for PDF
            styled_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>{doc.title}</title>
                <style>
                    body {{ 
                        font-family: 'Arial', sans-serif; 
                        margin: 40px; 
                        line-height: 1.6; 
                        color: #333;
                    }}
                    h1 {{ 
                        color: #2d3748; 
                        border-bottom: 3px solid #667eea;
                        padding-bottom: 10px;
                    }}
                    h2 {{ color: #667eea; margin-top: 30px; }}
                    h3 {{ color: #4a5568; }}
                    code {{ 
                        background: #f7fafc; 
                        padding: 2px 6px; 
                        border-radius: 4px; 
                        font-family: 'Monaco', 'Menlo', monospace;
                    }}
                    pre {{ 
                        background: #2d3748; 
                        color: #e2e8f0; 
                        padding: 15px; 
                        border-radius: 8px; 
                        overflow-x: auto;
                        border-left: 4px solid #667eea;
                    }}
                    blockquote {{ 
                        border-left: 4px solid #667eea;
                        padding-left: 20px;
                        margin: 20px 0;
                        color: #718096;
                        font-style: italic;
                    }}
                    .header {{ 
                        text-align: center; 
                        margin-bottom: 40px;
                        padding-bottom: 20px;
                        border-bottom: 2px solid #e2e8f0;
                    }}
                    .meta {{ 
                        color: #718096; 
                        font-size: 14px;
                        margin-bottom: 30px;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>{doc.title}</h1>
                    <div class="meta">
                        <strong>Generated by DocGenAI</strong> | 
                        Language: {doc.language} | 
                        Template: {doc.template} | 
                        Date: {doc.created_at.strftime('%Y-%m-%d %H:%M')}
                    </div>
                </div>
                {html_content}
            </body>
            </html>
            """
            
            # Generate PDF
            pdf_path = generate_pdf(styled_html, doc.title)
            if pdf_path:
                return send_file(pdf_path, as_attachment=True, download_name=f'{doc.title}.pdf')
            else:
                flash('PDF generation failed. Please ensure wkhtmltopdf is installed and configured.')
                return redirect('/history')
                
        elif format_type == 'markdown':
            md_path = os.path.join(app.config['EXPORT_FOLDER'], f'doc_{doc_id}.md')
            with open(md_path, 'w', encoding='utf-8') as f:
                f.write(doc.documentation_content)
            return send_file(md_path, as_attachment=True, download_name=f'{doc.title}.md')
            
        elif format_type == 'html':
            html_content = markdown_to_html(doc.documentation_content)
            html_path = os.path.join(app.config['EXPORT_FOLDER'], f'doc_{doc_id}.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(f"""<!DOCTYPE html>
                <html>
                <head>
                    <title>{doc.title}</title>
                    <meta charset="UTF-8">
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                        h1, h2, h3 {{ color: #333; }}
                        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 4px; }}
                        pre {{ background: #2d3748; color: white; padding: 15px; border-radius: 8px; overflow-x: auto; }}
                    </style>
                </head>
                <body>
                    <h1>{doc.title}</h1>
                    <div class="meta">
                        <strong>Generated by DocGenAI</strong> | 
                        Date: {doc.created_at.strftime('%Y-%m-%d %H:%M')}
                    </div>
                    {html_content}
                </body>
                </html>""")
            return send_file(html_path, as_attachment=True, download_name=f'{doc.title}.html')
            
    except Exception as e:
        logging.error(f"Export error: {e}")
        flash('Export failed')
    finally:
        db_session.close()
    
    return redirect('/history')

@app.route('/api/generate', methods=['POST'])
def api_generate():
    data = request.get_json()
    
    if not data or 'code' not in data:
        return jsonify({'error': 'No code provided'}), 400
    
    code = data['code']
    filename = data.get('filename', 'code.py')
    template = data.get('template', 'standard')
    
    try:
        documentation_md = generate_doc(code, filename, template)
        code_metrics = analyze_code(code)
        
        return jsonify({
            'documentation': documentation_md,
            'metrics': code_metrics,
            'status': 'success'
        })
    except Exception as e:
        logging.error(f"API generation error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    if not os.path.exists(EXPORT_FOLDER):
        os.makedirs(EXPORT_FOLDER)
    app.run(debug=True)