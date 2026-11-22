from flask import Blueprint, request, send_from_directory, abort

uploads_api = Blueprint('uploads', __name__)

@uploads_api.route('/')
def get_upload():
   name = request.args.get("name", "")
   # Refuse any path component: only plain file names inside uploads/ are allowed
   if not name or "/" in name or "\\" in name or ".." in name:
      abort(400)
   # send_from_directory also rejects paths escaping the directory (safe_join)
   return send_from_directory('uploads', name)
 