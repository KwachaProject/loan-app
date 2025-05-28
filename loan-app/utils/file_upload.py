import os
from werkzeug.utils import secure_filename
from datetime import datetime

UPLOAD_FOLDER = 'uploads/documents'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_document(file, customer_id, document_type):
    if file and allowed_file(file.filename):
        # Create unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{customer_id}_{document_type}_{timestamp}.{ext}"
        filename = secure_filename(filename)
        
        # Ensure upload directory exists
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        # Save file
        file.save(filepath)
        return filename, filepath
    return None, None