#!/usr/bin/env python3

from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    Server,
    DatastoreType,
)
from pytm.pytm import TLSVersion

tm = TM("GymCoach App Threat Model")
tm.description = (
    "Web application for users and coaches to manage workouts, classes and progress. "
    "Architecture: HTML/JS frontend served by a Node.js/Express backend with MongoDB Atlas."
)
tm.isOrdered = True
tm.mergeResponses = True
tm.assumptions = [
    "All external traffic to the application is over HTTPS through a cloud provider (e.g. Render/Heroku/Nginx).",
    "MongoDB Atlas is configured with authentication and network access control (IP allow-list / VPC peering).",
    "Passwords are stored hashed and never in plaintext.",
    "Admins/coaches use the same web interface but have elevated privileges managed by application roles.",
]

# --- Boundaries ---

internet = Boundary("Internet")

app_boundary = Boundary("Application Boundary")  # Node.js server / hosting platform

cloud_db_boundary = Boundary("MongoDB Atlas Boundary")

# --- Actors ---

user = Actor("End User")
user.inBoundary = internet
user.description = "Gym app user that registers, logs in and manages personal workouts."

coach = Actor("Coach / Admin")
coach.inBoundary = internet
coach.description = "Coach with elevated permissions to manage users, exercises and classes."

# --- Servers / Components ---

frontend = Server("Web Frontend (HTML/JS)")
frontend.inBoundary = internet
frontend.OS = "Browser"
frontend.description = "Static HTML/CSS/JS served to the user browser."
frontend.controls.sanitizesInput = False     # mostly client-side validation
frontend.controls.encodesOutput = True       # DOM/templating encodes output

api_server = Server("Node.js Express API")
api_server.inBoundary = app_boundary
api_server.OS = "Linux"
api_server.description = (
    "Node.js/Express backend defined in Server.js. "
    "Handles routes /users, /exercises, /clases and renders views."
)
api_server.controls.isHardened = False
api_server.controls.sanitizesInput = True    # validation for body/query params
api_server.controls.encodesOutput = True
api_server.controls.authorizesSource = True  # session/JWT/role-based checks
api_server.sourceFiles = [
    "BACK/Controllers/Router.js",
    "BACK/Controllers/User.js",
    "BACK/Controllers/Exercises.js",
    "BACK/Controllers/Clases.js",
]

# --- Datastores ---

app_db = Datastore("MongoDB Atlas - App Database")
app_db.inBoundary = cloud_db_boundary
app_db.OS = "MongoDB Atlas"
app_db.type = DatastoreType.SQL  # MongoDB is a document store
app_db.inScope = True
app_db.controls.isHardened = True
app_db.maxClassification = Classification.RESTRICTED
app_db.storesPII = True          # users, emails, maybe health-ish info
app_db.storesSensitiveData = True
app_db.port = 27017
app_db.protocol = "TLS over TCP"

# --- Data Objects ---

credentials = Data("User Credentials")
credentials.description = "Email and password used to authenticate users and coaches."
credentials.classification = Classification.SENSITIVE
credentials.isPII = True
credentials.isStored = True
credentials.isDestEncryptedAtRest = True      # hashed passwords in DB

profile_data = Data("User Profile Data")
profile_data.description = "User and coach profile data (name, email, role, BMI, etc.)."
profile_data.classification = Classification.RESTRICTED
profile_data.isPII = True
profile_data.isStored = True
profile_data.isDestEncryptedAtRest = True

workout_data = Data("Workout and Routine Data")
workout_data.description = "Exercises, routines, goals, progress records."
workout_data.classification = Classification.SENSITIVE
workout_data.isStored = True
workout_data.isDestEncryptedAtRest = True

class_schedule = Data("Class Schedule Data")
class_schedule.description = "Classes, schedules, coach assignments."
class_schedule.classification = Classification.SENSITIVE
class_schedule.isStored = True
class_schedule.isDestEncryptedAtRest = True

session_token = Data(
    name="Session / Auth Token",
    description="Session cookie or JWT used to maintain authenticated sessions.",
    classification=Classification.SENSITIVE,
)

# --- Dataflows: Users <-> Frontend ---

user_to_frontend = Dataflow(user, frontend, "HTTP(S) Requests from User")
user_to_frontend.protocol = "HTTPS"
user_to_frontend.dstPort = 443

frontend_to_user = Dataflow(frontend, user, "HTML/JS/CSS Responses to User")
frontend_to_user.protocol = "HTTPS"
frontend_to_user.dstPort = 443

coach_to_frontend = Dataflow(coach, frontend, "HTTP(S) Requests from Coach/Admin")
coach_to_frontend.protocol = "HTTPS"
coach_to_frontend.dstPort = 443

frontend_to_coach = Dataflow(frontend, coach, "HTML/JS/CSS Responses to Coach/Admin")
frontend_to_coach.protocol = "HTTPS"
frontend_to_coach.dstPort = 443

# --- Dataflows: Frontend <-> API Server ---

frontend_to_api = Dataflow(frontend, api_server, "API Calls (login, register, CRUD)")
frontend_to_api.protocol = "HTTPS"
frontend_to_api.dstPort = 443
frontend_to_api.tlsVersion = TLSVersion.TLSv12
frontend_to_api.data = [credentials, profile_data, workout_data, class_schedule, session_token]
frontend_to_api.usesSessionTokens = True

api_to_frontend = Dataflow(api_server, frontend, "API Responses (JSON / HTML)")
api_to_frontend.protocol = "HTTPS"
api_to_frontend.dstPort = 443
api_to_frontend.tlsVersion = TLSVersion.TLSv12
api_to_frontend.data = [profile_data, workout_data, class_schedule, session_token]

# --- Dataflows: API Server <-> MongoDB Atlas ---

api_to_db_auth = Dataflow(api_server, app_db, "Store / Read Credentials")
api_to_db_auth.protocol = "TLS"
api_to_db_auth.dstPort = 27017
api_to_db_auth.data = credentials

db_to_api_auth = Dataflow(app_db, api_server, "Return Credentials / Auth Data")
db_to_api_auth.protocol = "TLS"
db_to_api_auth.dstPort = 27017
db_to_api_auth.data = credentials

api_to_db_profile = Dataflow(api_server, app_db, "Store / Read User Profiles")
api_to_db_profile.protocol = "TLS"
api_to_db_profile.dstPort = 27017
api_to_db_profile.data = profile_data

db_to_api_profile = Dataflow(app_db, api_server, "Return User Profiles")
db_to_api_profile.protocol = "TLS"
db_to_api_profile.dstPort = 27017
db_to_api_profile.data = profile_data

api_to_db_workouts = Dataflow(api_server, app_db, "CRUD Workouts and Routines")
api_to_db_workouts.protocol = "TLS"
api_to_db_workouts.dstPort = 27017
api_to_db_workouts.data = workout_data

db_to_api_workouts = Dataflow(app_db, api_server, "Return Workouts and Routines")
db_to_api_workouts.protocol = "TLS"
db_to_api_workouts.dstPort = 27017
db_to_api_workouts.data = workout_data

api_to_db_classes = Dataflow(api_server, app_db, "CRUD Classes and Schedules")
api_to_db_classes.protocol = "TLS"
api_to_db_classes.dstPort = 27017
api_to_db_classes.data = class_schedule

db_to_api_classes = Dataflow(app_db, api_server, "Return Classes and Schedules")
db_to_api_classes.protocol = "TLS"
db_to_api_classes.dstPort = 27017
db_to_api_classes.data = class_schedule

# Relacionar token de sesión con los flujos más importantes
session_token.traverses = [
    frontend_to_api,
    api_to_frontend,
]
session_token.processedBy = [api_server]

if __name__ == "__main__":
    tm.process()