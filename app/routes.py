from flask import Blueprint, request, jsonify, send_file, current_app
from app.utils import verify_jwt
from google.cloud import datastore
import requests, io, mimetypes


# blueprint init export
api_routes = Blueprint('api', __name__)



##########################
##    ENDPOINTS BELOW   ##
##########################

# Decode the JWT supplied in the Authorization header
@api_routes.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


###############Routing endpoints start here##########
@api_routes.route('/')
def index():
    return "Please navigate to /users/login to login to this API"\
    

#Endpoint desing to return the full list of users that are within the googlestore database
#Will need to verify that user is admin throught the jwt verification
@api_routes.route('/users', methods=["GET"])
def get_users():
    payload = verify_jwt(request)
    sub = payload['sub']
    valid_jwt = False
    admin_jwt = False

    query = current_app.datastore_client.query(kind='users')
    users = query.fetch()

    #Complie all users
    user_dict = []
    for user in users:
        user_data = user.copy()
        returned_user_data = {}
        returned_user_data['id'] = user.key.id
        returned_user_data['role'] = user_data['role']
        returned_user_data['sub'] = user_data['sub']
        user_dict.append(returned_user_data)
        if user_data['sub'] == sub:
            valid_jwt = True
            if 'admin' in user_data['role']:
                admin_jwt = True

    #return expected
    if valid_jwt:
        if admin_jwt:
            return jsonify(user_dict), 200
        else:
            return jsonify({"Error":"You don't have permission on this resource"}), 403
    
    else:
        return jsonify({"Error": "Unauthorized"}), 401
    


#Endpoint that returns information on a specific user
#Will need to have admin role OR be requesting your own information
@api_routes.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    payload = verify_jwt(request)
    sub = payload['sub']

    user_key = current_app.datastore_client.key('users', user_id)
    user = current_app.datastore_client.get(user_key)

    if user:
        user_data = user.copy()
        user_data['id'] = user.key.id
        if user_data['role'] == 'admin' or user_data['sub'] == sub:
            return jsonify(user_data), 200

    return jsonify({"Error": "You don't have permission on this resource"}), 403




#For creating or updating a users avatar picture
#The JWT must belong to the user_id that is being passed to update
@api_routes.route('/users/<int:user_id>/avatar', methods=["POST", "GET"])
def get_user_pic(user_id):
    payload = verify_jwt(request)
    sub = payload['sub']

    user_key = current_app.datastore_client.key('users', user_id)
    user = current_app.current_app.datastore_client.get(user_key)

    if not user:
        return jsonify({"Error": "User not found"}), 404
    if user['sub'] != sub:
        return jsonify({"Error": "You don't have permission on this resource"}), 403
    # if 'tag' in request.form:
    #     tag = request.form['tag']

    bucket = current_app.storage_client.get_bucket(current_app.config.get('PHOTO_BUCKET'))
    filename = f"{user_id}_avtr"
    blob = bucket.blob(filename)

    #For getting the users avatar image
    if request.method == "GET":
        if not blob.exists():
            return jsonify({"Error": "Not found"}), 404

        file_obj = io.BytesIO()

        blob.download_to_file(file_obj)

        mime_type = blob.content_type
        extension = mimetypes.guess_extension(mime_type)

        file_obj.seek(0)

        return send_file(
            file_obj,
            mimetype=blob.content_type, 
            download_name=f'{filename}{extension}'
        )

    #for updating or creating an avatar image for the user
    elif request.method == "POST":
        if 'file' not in request.files:
            return jsonify({'Error': 'The request body is invalid'}), 400
        
        file_obj = request.files['file']
        file_obj.seek(0)
        blob.upload_from_file(file_obj, content_type=file_obj.content_type)

        user['avatar_url'] = f'{current_app.config.get("SITE_URL")}/users/{user_id}/avatar'
        current_app.datastore_client.put(user)
        
        return {'avatar_url': f'{current_app.config.get("SITE_URL")}/users/{user_id}/avatar'}, 200
    

#Delete the users avatar
@api_routes.route('/users/<int:user_id>/avatar', methods=["DELETE"])
def delete_user_avatar(user_id):
    payload = verify_jwt(request)
    sub = payload['sub']

    user_key = current_app.datastore_client.key('users', user_id)
    user = current_app.datastore_client.get(user_key)

    if not user:
        return jsonify({"Error": "User not found"}), 404
    if user['sub'] != sub:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    bucket = current_app.storage_client.get_bucket(current_app.config.get('PHOTO_BUCKET'))
    blob = bucket.blob(f"{user_id}_avtr")

    if not blob.exists():
        return jsonify({"Error": "Not found"}), 404

    blob.delete()

    user.pop('avatar_url')
    current_app.datastore_client.put(user)

    return '', 204




#Creating a course, need to have admin privliges
@api_routes.route('/courses', methods=['POST'])
def create_course():
    payload = verify_jwt(request)
    sub = payload['sub']

    query = current_app.datastore_client.query(kind='users')
    query.add_filter('sub', '=', sub)
    user = list(query.fetch())
    
    if not user or 'admin' not in user[0]['role']:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    content = request.get_json()

    if not content or not all(key in content for key in ['subject', 'number', 'title', 'term', 'instructor_id']):
        return jsonify({"Error": "The request body is invalid"}), 400

    instructor_key = current_app.datastore_client.key('users', content['instructor_id'])
    instructor = current_app.datastore_client.get(instructor_key)

    if not instructor or 'instructor' not in instructor['role']:
        return jsonify({"Error": "The request body is invalid"}), 400

    course_key = current_app.datastore_client.key('courses')
    course = datastore.Entity(key=course_key)

    course.update({
        'subject': content['subject'],
        'number': content['number'],
        'title': content['title'],
        'term': content['term'],
        'instructor_id': content['instructor_id']
    })

    current_app.datastore_client.put(course)

    course['id'] = course.key.id
    course['self'] = f'{current_app.config.get("SITE_URL")}/courses/{course.key.id}'
    return jsonify(course), 201



#Getting the courses info and listing per page
@api_routes.route('/courses', methods=['GET'])
def get_courses():
    offset = request.args.get('offset', default=0, type=int)
    limit = request.args.get('limit', default=3, type=int)

    query = current_app.datastore_client.query(kind='courses')
    query.order = ['subject']

    courses = list(query.fetch(offset=offset, limit=limit))
    total_courses = list(query.fetch())
    next_offset = offset + limit if len(courses) == limit and (offset + limit) < len(total_courses) else None

    course_list = []
    for course in courses:
        course_data = course.copy()
        course_data['id'] = course.key.id
        course_data['self'] = f'{current_app.config.get("SITE_URL")}/courses/{course.key.id}'
        course_list.append(course_data)
    
    response = {
        'courses': course_list,
        'next': f'{current_app.config.get("SITE_URL")}/courses?offset={next_offset}&limit={limit}' if next_offset is not None else None
    }
    
    return jsonify(response), 200



@api_routes.route('/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    course_key = current_app.datastore_client.key('courses', course_id)
    course = current_app.datastore_client.get(course_key)

    if not course:
        return jsonify({"Error": "Not found"}), 404

    course_data = course.copy()
    course_data['id'] = course.key.id
    course_data['self'] = f'{current_app.config.get("SITE_URL")}/courses/{course.key.id}'

    return jsonify(course_data), 200




@api_routes.route('/courses/<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    payload = verify_jwt(request)
    sub = payload['sub']

    #verify admin role
    query = current_app.datastore_client.query(kind='users')
    query.add_filter('sub', '=', sub)
    user = list(query.fetch())
    
    if not user or 'admin' not in user[0]['role']:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    course_key = current_app.datastore_client.key('courses', course_id)
    course = current_app.datastore_client.get(course_key)

    if not course:
        return jsonify({"Error": "Not found"}), 403

    content = request.get_json()

    if 'subject' in content:
        course['subject'] = content['subject']
    if 'number' in content:
        course['number'] = content['number']
    if 'title' in content:
        course['title'] = content['title']
    if 'term' in content:
        course['term'] = content['term']
    if 'instructor_id' in content:
        instructor_key = current_app.datastore_client.key('users', content['instructor_id'])
        instructor = current_app.datastore_client.get(instructor_key)
        if not instructor or 'instructor' not in instructor['role']:
            return jsonify({"Error": "The request body is invalid"}), 400
        course['instructor_id'] = content['instructor_id']

    current_app.datastore_client.put(course)

    course_data = course.copy()
    course_data['id'] = course.key.id
    course_data['self'] = f'{current_app.config.get("SITE_URL")}/courses/{course.key.id}'

    return jsonify(course_data), 200





@api_routes.route('/courses/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    payload = verify_jwt(request)
    sub = payload['sub']

    query = current_app.datastore_client.query(kind='users')
    query.add_filter('sub', '=', sub)
    user = list(query.fetch())

    if not user:
        return jsonify({"Error": "Unauthorized"}), 401

    user_role = user[0]['role']

    if 'admin' not in user_role:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    course_key = current_app.datastore_client.key('courses', course_id)
    course = current_app.datastore_client.get(course_key)

    if not course:
        return jsonify({"Error": "No course with this ID exists."}), 403

    enrollment_query = current_app.datastore_client.query(kind='enrollments')
    enrollment_query.add_filter('course_id', '=', course_id)
    enrollments = list(enrollment_query.fetch())

    for enrollment in enrollments:
        current_app.datastore_client.delete(enrollment.key)

    current_app.datastore_client.delete(course_key)

    return '', 204




#Getting all the students that are enrolled within a courseid
@api_routes.route('/courses/<int:course_id>/students', methods=['GET'])
def get_course_enrollment(course_id):
    payload = verify_jwt(request)
    sub = payload['sub']

    query = current_app.datastore_client.query(kind='users')
    query.add_filter('sub', '=', sub)
    user = list(query.fetch())

    if not user:
        return jsonify({"Error": "Unauthorized"}), 401

    user_role = user[0]['role']
    user_id = user[0].key.id

    course_key = current_app.datastore_client.key('courses', course_id)
    course = current_app.datastore_client.get(course_key)

    if not course:
        return jsonify({"Error": "No course with id"}), 403

    if 'admin' not in user_role and course['instructor_id'] != user_id:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    enrollment_query = current_app.datastore_client.query(kind='enrollments')
    enrollment_query.add_filter('course_id', '=', course_id)
    enrollments = list(enrollment_query.fetch())

    student_ids = [enrollment['student_id'] for enrollment in enrollments]

    return jsonify(student_ids), 200





#ENROLL OR UNENROLL STUDENTS IN A COURSE
@api_routes.route('/courses/<int:course_id>/students', methods=['PATCH'])
def update_enrollment(course_id):
    payload = verify_jwt(request)
    sub = payload['sub']

    query = current_app.datastore_client.query(kind='users')
    query.add_filter('sub', '=', sub)
    user = list(query.fetch())

    if not user:
        return jsonify({"Error": "Unauthorized"}), 401

    user_role = user[0]['role']

    course_key = current_app.datastore_client.key('courses', course_id)
    course = current_app.datastore_client.get(course_key)

    if not course:
        return jsonify({"Error": "No course with id"}), 403

    if 'admin' not in user_role and course['instructor_id'] != user[0]['id']:
        return jsonify({"Error": "You don't have permission on this resource"}), 403

    content = request.get_json()
    students_to_add = content.get("add", [])
    students_to_remove = content.get("remove", [])

    if set(students_to_add).intersection(students_to_remove):
        return jsonify({"Error": "Enrollment invalid: overlapping values in add and renove"}), 409

    student_query = current_app.datastore_client.query(kind='users')
    student_query.add_filter('role', '=', 'student')
    valid_students = {user.key.id for user in student_query.fetch()}

    if not set(students_to_add).issubset(valid_students) or not set(students_to_remove).issubset(valid_students):
        return jsonify({"Error": "Enrollment  invalid: invalid student IDs"}), 409

    for student_id in students_to_add:
        enrollment_key = current_app.datastore_client.key('enrollments', f"{course_id}_{student_id}")
        if not current_app.datastore_client.get(enrollment_key):
            enrollment = datastore.Entity(key=enrollment_key)
            enrollment.update({
                'course_id': course_id,
                'student_id': student_id
            })
            current_app.datastore_client.put(enrollment)

    for student_id in students_to_remove:
        enrollment_key = current_app.datastore_client.key('enrollments', f"{course_id}_{student_id}")
        if current_app.datastore_client.get(enrollment_key):
            current_app.datastore_client.delete(enrollment_key)

    return '', 200

        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@api_routes.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()
    if not content.get('password'):
        return jsonify({'Error': 'The request body is invalid'}), 400
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':current_app.config.get('CLIENT_ID'),
            'client_secret':current_app.config.get('CLIENT_SECRET')
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + current_app.config.get('DOMAIN') + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    if r.json().get('error'):
        return jsonify({"Error": 'Unauthorized'}), 401
    token = r.json()['id_token']
    return jsonify({'token': token}), 200