from flask import jsonify, request
from passlib.hash import pbkdf2_sha256
import pymongo
import os, re
import random
from datetime import datetime, timedelta
# from flask_mail import Mail, Message
import string
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from bson import json_util, ObjectId
import json
from dotenv import load_dotenv


# mail = Mail()
load_dotenv()

client = pymongo.MongoClient(os.getenv("DB_STRING"))
db = client["PMR-New"]
users_collection = db.users

class User:
    # ------------ SignUp function ------------
    def signUp(self):
        fullname = request.json.get('name')
        email = request.json.get('email')
        password = request.json.get('password')

        if not all([email, password, fullname]):
            return jsonify({"error": "Please fill all the fields"}), 400
        
        email_regex = "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_regex, email):
            return jsonify({"error": "Invalid email format"}), 400
        if len(password) < 8:
            return jsonify({"error": "Password should be at least 8 characters long"}), 400
        
        hashed_password = pbkdf2_sha256.encrypt(password)

    # ------------- Checking if User Exists or not-----------------

        existing_user = users_collection.find_one({"email": email, "isVerifed": True})
        if existing_user:
            return jsonify({"error": "User with this email already exists and is verified"}), 400

        otp = self.generate_otp()

    # ------------- Updating OTP if user asked again------------------
        unverified_user = users_collection.find_one({"email": email, "isVerifed": False})
        if unverified_user:
            users_collection.update_one(
                {"_id": unverified_user["_id"]},
                {
                    "$set": {
                        "fullName": fullname,
                        "password": hashed_password,
                        "otp": otp,
                        "otp_expiration": datetime.utcnow() + timedelta(minutes=10)  # update to expire in 10 minutes
                    }
                }
            )

        # ------------------ Entering User in database as unverified and with OTP ---------------------
        else:
            users_collection.insert_one({
                "fullName" : fullname,
                "email": email,
                "password": hashed_password,
                "isVerifed": False,
                "otp": otp,
                "otp_expiration": datetime.utcnow() + timedelta(minutes=10),
                "isAdmin": False
            })

        return otp
    

    # ---------------- OTP Verification Function --------------------
    def VerifyOtp(self, email, otp):
        
        user_record = users_collection.find_one({"email": email, "otp": otp})
        if not user_record:
            return jsonify({"error": "Invalid OTP or email"}), 400
        current_time = datetime.utcnow()
        if current_time > user_record["otp_expiration"]:
            return jsonify({"error": "OTP has expired"}), 400
        if user_record["isVerifed"]:
            return jsonify({"error": "User is already verified"}), 400
        
        # Update the user to set isVerified to true and remove the OTP fields
        users_collection.update_one(
            {"_id": user_record["_id"]},
            {
                "$set": {"isVerifed": True},
                "$unset": {"otp": 1, "otp_expiration": 1}
            }
        )
        return jsonify({"message": "User verified successfully"})
    


    # ----------- Function to Check User email ----------------
    def verifyUser(self, email):
        user_record = users_collection.find_one({"email": email, "isVerifed": True})
        if not user_record:
            return False
        return True


    # ----------- Function to Update New Password --------------------
    def update_password(self, email, password):
        user_record = users_collection.find_one({"email": email, "isVerifed": True})
        if not user_record:
            return jsonify({"error": "User does not exist"}), 400
        hashed_password = pbkdf2_sha256.encrypt(password)
        users_collection.update_one(
            {"_id": user_record["_id"]},
            {
                "$set": {
                    "password": hashed_password,
                }
            }
        )
        return jsonify({"success": "Password Reset Successfully"})

    #------------ OTP Generation ------------------
    def generate_otp(self):
        characters = string.ascii_letters + string.digits  # A-Z, a-z, 0-9
        otp = ''.join(random.choice(characters) for i in range(6))
        return otp


    #------------ Login Function ------------------
    def login(self):
        email = request.json.get('email')
        password = request.json.get('password')

        if not all([email, password]):
            return jsonify({"error": "Email and password are required"}), 400
        
        user_record = users_collection.find_one({"email": email})
        if not user_record:
            return jsonify({"error": "User does not exist"}), 400

        if not pbkdf2_sha256.verify(password, user_record["password"]):
            return jsonify({"error": "Incorrect password"}), 400

        # If the user is unverified
        if not user_record["isVerifed"]:
            return jsonify({"error": "Please verify your email before logging in"}), 400
        
        additional_claims = {"email": user_record["email"], "fullName":user_record['fullName']}
        access_token = create_access_token(identity=str(user_record["_id"]), additional_claims=additional_claims, expires_delta=timedelta(days=2))
        return jsonify({"token": access_token})

    
    #------------ Function to Validate Admin ------------------
    def validate_admin(self, current_user_id):
        # Retrieve the current user's record from the database
        current_user = users_collection.find_one({"_id": convertId(current_user_id)})
   
        if not current_user or not current_user.get('isAdmin', False):
            return jsonify({"error": "Fobidden: You do not have admin permissions"}), 403
        
        # Use json_util to handle MongoDB specific objects.
        user_data = json_util.dumps({"isAdmin": True, "userData": current_user})
    
        return user_data, 200


    #------------ Remove user function ------------------
    def remove_user(self, current_user_id ,user_id):
        print (current_user_id)
        print(user_id['$oid'])
        current_user = users_collection.find_one({"_id": convertId(current_user_id)})

        # Check if the user is admin
        if not current_user or not current_user.get('isAdmin', False):
            return jsonify({"error": "You do not have permission to remove users"}), 403

        # Proceed with removing the user
        result = users_collection.delete_one({"_id": convertId(user_id['$oid'])})
        if result.deleted_count:
            return jsonify({"message": "User removed successfully"})
        else:
            return jsonify({"error": "User not found"}), 404
        
    
    #------------ Fetch users function ------------------
    def get_all_users(self, current_user_id):
        current_user = users_collection.find_one({"_id": convertId(current_user_id)})

        if not current_user or not current_user.get('isAdmin', False):
            return jsonify({"error": "You do not have permission to view all users"}), 403

        # Fetch all users from the database where isVerified is true, excluding their passwords
        users_cursor = users_collection.find({"isVerifed": True, "isAdmin":False}, {'password': 0})
        users_list = list(users_cursor)
        
        users_json = json.loads(json_util.dumps(users_list))
    
        return jsonify(users_json), 200
    
    def get_current_user(self, current_user_id):
        current_user = users_collection.find_one({"_id": convertId(current_user_id)}, {'password': 0})
        user_json = json.loads(json_util.dumps(current_user))
        return user_json


# Helper function to convert String Id to ObjectId format
def convertId(id):
    try:
        # Convert the ID to ObjectId if it's not already an ObjectId
        if not isinstance(id, ObjectId):
            current_user_id = ObjectId(id)
    except Exception as e:
        print("Invalid user ID format:", e)
        return jsonify({"error": "Invalid user ID format"}), 400
    
    return current_user_id