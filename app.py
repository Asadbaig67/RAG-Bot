from langchain.vectorstores import Chroma
from langchain.embeddings import OpenAIEmbeddings
import os
from langchain.prompts import PromptTemplate
from langchain.chat_models import ChatOpenAI
from langchain.chains import RetrievalQA
from flask_cors import CORS
from flask import (
    Flask,
    request,
    jsonify,
    send_from_directory,
    render_template,
    current_app,
    url_for,
)
from dotenv import load_dotenv
from langchain.memory import ConversationBufferMemory
from flask_mail import Mail, Message
from datetime import timedelta
import re
from user.user import User
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature


load_dotenv(override=True)  # take environment variables from .env.
app = Flask(__name__, static_folder="public/static", template_folder="public")

mail = Mail(app)  # instantiate the mail class

# configuration of mail
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USERNAME"] = os.environ["GMAIL_SENDER"]
app.config["MAIL_PASSWORD"] = os.environ["GMAIL_PASSWORD"]
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=2)

jwt = JWTManager(app)
mail = Mail(app)

sender = os.environ["GMAIL_SENDER"]
recipient = os.environ["GMAIL_RECIPIENT"]

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True,
    expose_headers="Authorization",
)
app.secret_key = "secret"


@app.route("/")
@app.route("/<path:path>")
def index(path=None):
    return render_template("index.html")


OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]

embeddings = OpenAIEmbeddings()

load_directory = "Tabular-Docs-chroma"

vectordb = Chroma(
    persist_directory=load_directory,
    embedding_function=embeddings,
    collection_name="TabDoc",
)

retriever = vectordb.as_retriever(search_kwargs={"k": 6, "search_type": "similarity"})

llm = ChatOpenAI(model_name="gpt-3.5-turbo-16k", temperature=0)

# Global variable for the transcript filename
filename = "transcript.txt"

template = """
1. Use the following pieces of context to answer the question at the end. 
2. If you don't know the answer, respond with a following up question with relevant context from the question
3. Never repeat the question that you were asked in the response
4. Make sure that you answer in a friendly, and human-like tone. Add a little humour where possible.
5. You can answer the greetings etc in a short sentence.
6. If sources contain the following documents: FHA, FHA 4001, VA, USDA, Fannie Mae, Freddie Mac; then priortize these documents while forming an answer
7. Use the following context (delimited by <ctx></ctx>) and the chat history (delimited by <hs></hs>) to answer the question:
------
<ctx>
{context}
</ctx>
------
<hs>
{history}
</hs>
------
{question}
Answer:"""

prompt = PromptTemplate(
    input_variables=["history", "context", "question"],
    template=template,
)

qa_chain = RetrievalQA.from_chain_type(
    llm=llm,
    chain_type="stuff",
    retriever=retriever,
    return_source_documents=True,
    chain_type_kwargs={
        "verbose": False,
        "prompt": prompt,
        "memory": ConversationBufferMemory(memory_key="history", input_key="question"),
    },
)


def getUpdatedQuery(query, properties):
    # Check if all the properties are empty, if so return the original query
    if all(value == "" for key, value in properties.items()):
        return query

    # Start building the additional info string
    additional_info = "\nHere is some Information about my Property:"

    # Check each property and append information accordingly

    if properties["adu"] != "":
        additional_info += "\nMy Property does{} have an ADU".format(
            "" if properties["adu"].lower() == "yes" else " not"
        )

    if properties["hudReo"] != "":
        additional_info += "\nMy Property is{} a HUD REO".format(
            "" if properties["hudReo"].lower() == "yes" else " not"
        )

    if properties["escrowHoldback"] != "":
        additional_info += "\nMy Property does{} have an Escrow Holdback".format(
            "" if properties["escrowHoldback"].lower() == "yes" else " not"
        )

    if properties["rentalIncome"] != "":
        additional_info += "\nMy Property does{} generate Rental Income".format(
            "" if properties["rentalIncome"].lower() == "yes" else " not"
        )

    if properties["onLeave"] != "":
        additional_info += "\nI am{} on Leave from work".format(
            "" if properties["onLeave"].lower() == "yes" else " not"
        )

    # Technology is handled separately
    if properties["technology"] != "":
        technology_type = properties["technology"]
        # Ensure it is either Wind or Solar, otherwise do not append any info
        if technology_type.lower() in ["wind", "solar"]:
            additional_info += "\nMy Property has {} technology".format(technology_type)

    # Return the original query appended with the additional info
    return query + additional_info


def contains_keywords(sentence):
    lower_case_sentence = sentence.lower()
    return "fha" in lower_case_sentence and "loan limits" in lower_case_sentence


@app.route("/query", methods=["POST"])
@jwt_required()
# def query():
#     fha_source = ""
#     myflag = False

#     data = request.get_json()
#     query_text = data.get('query', '')
#     properties = data.get('properties')
#     qulen = len(query_text)
#     if qulen < 6:
#         myflag = True
#     if not myflag:
#         query_text = getUpdatedQuery(query_text, properties)
#         print(query_text, properties)
#     print("received: ", query_text)
#     check_fha = contains_keywords(query_text)
#     result = qa_chain(query_text)
#     source = result["source_documents"]
#     print(source)
#     temp = str(source)
#     source_match = re.search(r"metadata={'source': '([^']+)", temp)
#     final_result = result["result"]
#     if check_fha:
#         print("Hey")
#         fha_source = "https://www.hud.gov/program_offices/housing/sfh/lender/origination/mortgage_limits"
#     if source_match:
#         source_name = source_match.group(1)
#         print("source", source_name)
#         source_name = source_name.replace("Docs/", "")
#     else:
#         source_name = "Source name not found."

#     if myflag:
#         source_name = ""
#     current_user_id = get_jwt_identity()
#     current_user = User().get_current_user(current_user_id)
#     current_userName = current_user['fullName']
#     current_userEmail = current_user['email']
#     print(fha_source)
#     # Write the user query and response to the transcript file
#     with open(filename, "a") as file:
#         file.write(
#             f"User: {current_userName} ({current_userEmail})\nQuery: {query_text}\nBot: {result['result']}\n\n")
#     response_data = {
#         "result": final_result,
#         "source": fha_source
#     }


#     return jsonify(response_data)
def query():
    fha_source = ""
    myflag = False

    data = request.get_json()
    query_text = data.get("query", "")
    properties = data.get("properties")
    qulen = len(query_text)
    if qulen < 6:
        myflag = True
    if not myflag:
        query_text = getUpdatedQuery(query_text, properties)
        print(query_text, properties)
    print("received: ", query_text)
    check_fha = contains_keywords(query_text)

    # Check if the query contains phrases related to Freddie Mac allows the greater of 1% of the new loan amount or $2,000.
    if (
        "freddie mac allows the greater" in query_text.lower()
        or "blending fico" in query_text.lower()
        or "blended fico" in query_text.lower()
    ):
        final_result = "Blending FICO scores is not currently permitted."
    else:
        # Proceed with the original logic
        result = qa_chain(query_text)
        source = result["source_documents"]
        print(source)
        temp = str(source)
        source_match = re.search(r"metadata={'source': '([^']+)", temp)
        final_result = result["result"]
        if check_fha:
            print("Hey")
            fha_source = "https://www.hud.gov/program_offices/housing/sfh/lender/origination/mortgage_limits"
        if source_match:
            source_name = source_match.group(1)
            print("source", source_name)
            source_name = source_name.replace("Docs/", "")
        else:
            source_name = "Source name not found."

        if myflag:
            source_name = ""
        current_user_id = get_jwt_identity()
        current_user = User().get_current_user(current_user_id)
        current_userName = current_user["fullName"]
        current_userEmail = current_user["email"]
        print(fha_source)
        # Write the user query and response to the transcript file
        with open(filename, "a") as file:
            file.write(
                f"User: {current_userName} ({current_userEmail})\nQuery: {query_text}\nBot: {result['result']}\n\n"
            )

    response_data = {"result": final_result, "source": fha_source}
    return jsonify(response_data)


@app.route("/name", methods=["GET"])
def name():
    response_data = {"name": "PMR Bot"}
    return jsonify(response_data)


@app.errorhandler(404)
def handle_404(e):
    return send_from_directory(app.template_folder, "index.html")


# User routes

# ---------------- SignUp Route ----------------


@app.route("/user/signUp", methods=["POST"])
def signUp():
    email = request.json.get("email")
    otp = User().signUp()
    if isinstance(
        otp, tuple
    ):  # this means an error occurred and a response tuple was returned
        return otp
    send_otp_email(email, otp)
    return jsonify({"message": "OTP sent to email"})


# ---------------- Verify OTP Route -----------------------
@app.route("/user/verifyOTP", methods=["POST"])
def VerifyOtp():
    email = request.json.get("email")
    otp = request.json.get("otp")
    return User().VerifyOtp(email, otp)


# ---------------- Login Route -----------------------
@app.route("/user/login", methods=["POST"])
def login():
    return User().login()


def send_email(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender=sender)
    try:
        mail.send(msg)
    except Exception as e:
        # Handle exceptions
        app.logger.error(f"Failed to send email: {e}")
        return False
    return True


# ---------------- Reset Password Route ----------------


@app.route("/user/resetpassword", methods=["POST"])
def resetPassword():
    email = request.json.get("email")
    if not User().verifyUser(email):
        return jsonify({"error": "User Does Not Exist"}), 404

    # Generate a secure token that expires in 600 seconds (10 minutes)
    token = serializer.dumps(email, salt="email-confirm-salt")
    base_url = os.environ.get("BASE_URL")
    reset_link = f"{base_url}/updatepassword?token={token}"
    # Send the email
    subject = "Password Reset Request for Your Account"
    body_intro = f"Hello, you have requested to reset your password. Please click on the link below to proceed:<br><br>"
    body_link = f"<a href='{reset_link}'>Reset your password</a><br><br>"
    body_footer = (
        "This link will expire in 10 minutes. If you did not request a password reset, please ignore this email.<br><br>"
        "Best regards,<br>"
        "PMR-BOT Team"
    )

    full_body = body_intro + body_link + body_footer

    # Assuming you have a function 'send_email' similar to 'send_otp_email'
    send_email(email, subject, full_body)

    return jsonify({"success": "Password reset link sent to email"}), 200


# --------------- Update Password Route -------------------
@app.route("/user/updatepassword", methods=["POST"])
def update_password():
    token = request.json.get("token")
    new_password = request.json.get("password")
    if not token or not new_password:
        return jsonify({"error": "Missing token or new password"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password should be at least 8 characters long"}), 400
    try:
        # Token expires in 10 minutes
        email = serializer.loads(token, salt="email-confirm-salt", max_age=600)
    except SignatureExpired:
        return jsonify({"error": "Invalid or expired token"}), 400
    except BadSignature:
        return jsonify({"error": "Invalid token"}), 400

    return User().update_password(email, new_password)


@jwt.expired_token_loader
def my_expired_token_callback(expired_token):
    token_type = expired_token["type"]
    return (
        jsonify(
            {
                "status": 401,
                "sub_status": 42,
                "msg": "The {} token has expired".format(token_type),
            }
        ),
        401,
    )


@app.route("/user/validate-token", methods=["GET"])
@jwt_required()
def validate_token():
    current_user = get_jwt_identity()
    return jsonify({"isValid": True, "userData": current_user}), 200


@app.route("/user/validate-admin-token", methods=["GET"])
@jwt_required()
def validate_admin_token():
    current_user_id = get_jwt_identity()
    return User().validate_admin(current_user_id)


# --------------- Remove User Route -------------------


@app.route("/user/removeUser", methods=["POST"])
@jwt_required()
def removeUser():
    userId = request.json.get("userId")
    current_user_id = get_jwt_identity()
    return User().remove_user(current_user_id, userId)


@app.route("/user/getUsers", methods=["GET"])
@jwt_required()
def getUsers():
    current_user_id = get_jwt_identity()
    return User().get_all_users(current_user_id)


# ------------- Function to send OTP to User VIA Email ------------
def send_otp_email(email, otp):
    subject = "Your OTP Code for EC-MVP"
    # Simple greeting using the first part of the email address
    greeting = f"Hello <b>{email.split('@')[0]}</b>,<br><br>"
    body_intro = "Thank you for signing up with <b>EC-MVP</b>. As part of our verification process, we've generated a One-Time Password (OTP) for you.<br><br>"
    body_otp = f"<b>Your OTP is: {otp}</b><br><br>"
    body_footer = (
        "Please use this OTP to complete your sign-up process. If you did not request this OTP or believe you've received this email in error, please ignore it or contact our support team.<br><br>"
        "Warm regards,<br>"
        "<b>EC-MVP Team</b>"
    )

    full_body = greeting + body_intro + body_otp + body_footer

    msg = Message(subject, sender=sender, recipients=[email])
    msg.html = full_body
    mail.send(msg)


##


# This function sends a transcript of chat bot conversation via email
def sendTranscript():
    print("[LOG] sendTranscript function called!")  # Log statement
    try:
        with app.app_context():
            # Check if the transcript file exists and is not empty
            if not os.path.exists(filename) or os.stat(filename).st_size == 0:
                print("No queries were asked")
                return "No queries to send"

            # Read the transcript content
            with open(filename, "r") as file:
                email_body = file.read()

            msg = Message(
                "Transcript of PMR Bot",
                sender=("PMR Bot Support", sender),
                recipients=[recipient],
            )
            msg.body = email_body  # Since it's a txt file, we use msg.body
            mail.send(msg)

            # Delete the transcript file
            os.remove(filename)

            return "Sent"
    except Exception as e:
        print(f"[ERROR] An error occurred: {str(e)}")


if __name__ == "__main__":
    # Run the scheduler script as a separate process
    # subprocess.run(['python', 'scheduler.py'])
    app.run(host="0.0.0.0", port=5000, debug=True)
