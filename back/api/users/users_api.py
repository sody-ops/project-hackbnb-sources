from flask import Blueprint

users_api = Blueprint('users', __name__)


@users_api.route('/me', methods=['GET'])
def get_current_user_details():
    # No session/auth implemented yet: the endpoint is intentionally unauthenticated.
    return {'error': 'User not logged in'}, 401
