'''
from . import app,db
from flask import request,make_response
from .models import Users,Funds
from werkzeug.security import generate_password_hash,check_password_hash
import jwt 
from datetime import datetime,timedelta
@app.route('/signup',methods=["POST"])
def signup():
    data=request.json
    email=data.get("email")
    password=data.get("password")
    firstName=data.get("firstName")
    lastName=data.get("lastName")

    if firstName and lastName and email and password:
        user=Users.query.filter_by(email=email).first()
        if user:
            return make_response({"message":"Please sign in"},200)
        user=Users(
            email=email,
            password=generate_password_hash(password),
            firstName=firstName,
            lastName=lastName
            )
        db.session.add(user)
        db.session.commit()
        return make_response({"message":"User created"},201)
    return make_response({"message":"unable to create User"},500)

@app.route('/login',methods=["POST"])
def login():
    auth=request.json
    if not auth or not auth.get("email") or not auth.get("password"):
        return make_response({"message":"Proper credentials were not proviced"},401)
    user=Users.query.filter_by(email=auth.get("email")).first()
    if not user:
        return make_response({"message":"please create an acccount"},401)
    if check_password_hash(user.password,auth.get("password")):
        token=jwt.encode({
            "id":user.id,
            "exp":datetime.utcnow()+timedelta(minutes=30)
        },
        "secret",
        algorithm="HS256")
        return make_response({"token":token}, 201)
    return make_response("PLEASE CHECK YOUR CREDENTIALS",401)
 '''
from flask import Flask, Response

app = Flask(__name__)

@app.route('/continue')
def continue_request():
    return Response(status=100)  # HTTP 100 Continue

@app.route('/ok')
def ok():
    return "Everything is OK!", 200  # HTTP 200 OK

@app.route('/create', methods=['POST'])
def create():
    return "Resource created", 201  # HTTP 201 Created

@app.route('/accept', methods=['POST'])
def accept():
    return "Request accepted", 202  # HTTP 202 Accepted

@app.route('/delete', methods=['DELETE'])
def delete():
    return '', 204  # HTTP 204 No Content

@app.route('/redirect')
def redirect_permanently():
    return '', 301, {'Location': 'http://example.com/new-url'}  # HTTP 301 Moved Permanently

@app.route('/temp-redirect')
def redirect_temporarily():
    return '', 302, {'Location': 'http://example.com/temp-url'}  # HTTP 302 Found

@app.route('/not-modified')
def not_modified():
    return '', 304  # HTTP 304 Not Modified

@app.route('/bad-request')
def bad_request():
    return "Bad Request", 400  # HTTP 400 Bad Request

@app.route('/unauthorized')
def unauthorized():
    return "Unauthorized", 401  # HTTP 401 Unauthorized

@app.route('/forbidden')
def forbidden():
    return "Forbidden", 403  # HTTP 403 Forbidden

@app.route('/not-found')
def not_found():
    return "Not Found", 404  # HTTP 404 Not Found

@app.route('/method-not-allowed', methods=['GET'])
def method_not_allowed():
    return "Method Not Allowed", 405  # HTTP 405 Method Not Allowed

@app.route('/server-error')
def server_error():
    return "Internal Server Error", 500  # HTTP 500 Internal Server Error

@app.route('/bad-gateway')
def bad_gateway():
    return "Bad Gateway", 502  # HTTP 502 Bad Gateway

@app.route('/service-unavailable')
def service_unavailable():
    return "Service Unavailable", 503  # HTTP 503 Service Unavailable

@app.route('/gateway-timeout')
def gateway_timeout():
    return "Gateway Timeout", 504  # HTTP 504 Gateway Timeout

if __name__ == '__main__':
    app.run(debug=True)
