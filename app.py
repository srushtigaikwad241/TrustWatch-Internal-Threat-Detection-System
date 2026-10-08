from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    send_from_directory
)

from database import get_connection

from functools import wraps

import os
from datetime import datetime


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

# Used for Flask session management
# Change this to your own random secret in a real deployment.
app.secret_key = "trust-watch-secret-key-2026"


# ============================================================
# LOGIN REQUIRED DECORATOR
# ============================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# ADMIN REQUIRED DECORATOR
# ============================================================

def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            return jsonify({
                "error": "Unauthorized"
            }), 401

        if session.get("role") != "Admin":

            return jsonify({
                "error": "Admin access required"
            }), 403

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    if "user_id" in session:

        if session.get("role") == "Admin":

            return redirect(
                url_for("dashboard")
            )

        return redirect(
            url_for("user_dashboard")
        )

    return redirect(
        url_for("login")
    )


# ============================================================
# LOGIN PAGE
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":

        return render_template(
            "login.html"
        )


    email = request.form.get(
        "email",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    ).strip()


    if not email or not password:

        return render_template(
            "login.html",
            error="Please enter email and password."
        )


    connection = get_connection()


    if not connection:

        return render_template(
            "login.html",
            error="Database connection failed."
        )


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                password,
                role,
                status
            FROM users
            WHERE email = %s
            """,
            (email,)
        )


        user = cursor.fetchone()


        if not user:

            return render_template(
                "login.html",
                error="Invalid email or password."
            )


        # ----------------------------------------------------
        # DEMO PASSWORD CHECK
        # ----------------------------------------------------
        #
        # Your current project uses plain-text demo passwords.
        # For production, use password hashing.
        #

        if password != user["password"]:

            return render_template(
                "login.html",
                error="Invalid email or password."
            )


        # ----------------------------------------------------
        # SUSPENDED USER
        # ----------------------------------------------------

        if user["status"] == "Suspended":

            return render_template(
                "login.html",
                error="Your account is suspended. Contact the administrator."
            )


        # ----------------------------------------------------
        # CREATE SESSION
        # ----------------------------------------------------

        session.clear()


        session["user_id"] = user["user_id"]

        session["name"] = user["name"]

        session["email"] = user["email"]

        session["role"] = user["role"]

        session["status"] = user["status"]


        # ----------------------------------------------------
        # CREATE LOGIN SESSION RECORD
        # ----------------------------------------------------

        ip_address = request.remote_addr

        device_info = request.headers.get(
            "User-Agent",
            "Unknown Device"
        )


        cursor.execute(
            """
            INSERT INTO sessions
            (
                user_id,
                login_time,
                ip_address,
                device_info,
                status
            )
            VALUES
            (
                %s,
                NOW(),
                %s,
                %s,
                'Active'
            )
            """,
            (
                user["user_id"],
                ip_address,
                device_info
            )
        )


        connection.commit()


        # ----------------------------------------------------
        # REDIRECT BY ROLE
        # ----------------------------------------------------

        if user["role"] == "Admin":

            return redirect(
                url_for("dashboard")
            )


        return redirect(
            url_for("user_dashboard")
        )


    except Exception as error:

        print(
            "Login error:",
            error
        )


        return render_template(
            "login.html",
            error="Login failed. Please try again."
        )


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    if session.get("role") != "Admin":

        return redirect(
            url_for("user_dashboard")
        )


    return render_template(
        "dashboard.html"
    )


# ============================================================
# USER DASHBOARD
# ============================================================

@app.route("/user-dashboard")
@login_required
def user_dashboard():

    connection = get_connection()


    if not connection:

        return render_template(
            "user_dashboard.html",
            error="Database connection failed."
        )


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                role,
                status,
                created_at
            FROM users
            WHERE user_id = %s
            """,
            (session["user_id"],)
        )


        user = cursor.fetchone()


        if not user:

            session.clear()

            return redirect(
                url_for("login")
            )


        # ----------------------------------------------------
        # SUSPENDED ACCOUNT
        # ----------------------------------------------------

        if user["status"] == "Suspended":

            session.clear()

            return render_template(
                "login.html",
                error="Your account has been suspended."
            )


        # ----------------------------------------------------
        # UPDATE SESSION STATUS
        # ----------------------------------------------------

        session["status"] = user["status"]

        session["name"] = user["name"]

        session["email"] = user["email"]

        session["role"] = user["role"]


        return render_template(
            "user_dashboard.html",
            user=user
        )


    except Exception as error:

        print(
            "User dashboard error:",
            error
        )


        return render_template(
            "user_dashboard.html",
            error="Unable to load user dashboard."
        )


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
@login_required
def logout():

    user_id = session.get(
        "user_id"
    )


    connection = get_connection()


    if connection:

        cursor = None


        try:

            cursor = connection.cursor()


            cursor.execute(
                """
                UPDATE sessions
                SET
                    logout_time = NOW(),
                    status = 'Ended'
                WHERE user_id = %s
                AND status = 'Active'
                ORDER BY session_id DESC
                LIMIT 1
                """,
                (user_id,)
            )


            connection.commit()


        except Exception as error:

            print(
                "Logout session update error:",
                error
            )


        finally:

            if cursor:

                cursor.close()

            connection.close()


    session.clear()


    return redirect(
        url_for("login")
    )


# ============================================================
# API - DASHBOARD STATISTICS
# ============================================================

@app.route("/api/stats")
@login_required
def api_stats():

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        # ----------------------------------------------------
        # USERS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(status = 'Active') AS active,
                SUM(status = 'Restricted') AS restricted,
                SUM(status = 'Suspended') AS suspended
            FROM users
            """
        )


        users = cursor.fetchone()


        # ----------------------------------------------------
        # ACTIVITIES
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total
            FROM activity_logs
            """
        )


        activities = cursor.fetchone()


        # ----------------------------------------------------
        # ALERTS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(severity = 'Critical') AS critical,
                SUM(severity = 'High') AS high,
                SUM(severity = 'Medium') AS medium,
                SUM(severity = 'Low') AS low
            FROM alerts
            """
        )


        alerts = cursor.fetchone()


        return jsonify({

            "users": {

                "total":
                    users["total"] or 0,

                "active":
                    users["active"] or 0,

                "restricted":
                    users["restricted"] or 0,

                "suspended":
                    users["suspended"] or 0
            },


            "activities": {

                "total":
                    activities["total"] or 0
            },


            "alerts": {

                "total":
                    alerts["total"] or 0,

                "critical":
                    alerts["critical"] or 0,

                "high":
                    alerts["high"] or 0,

                "medium":
                    alerts["medium"] or 0,

                "low":
                    alerts["low"] or 0
            }

        })


    except Exception as error:

        print(
            "Stats API error:",
            error
        )


        return jsonify({
            "error": "Unable to retrieve statistics."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - SECURITY ALERTS
# ============================================================

@app.route("/api/alerts")
@login_required
def api_alerts():

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT
                a.alert_id,
                a.user_id,
                u.name AS user_name,
                a.analysis_id,
                a.alert_type,
                a.severity,
                a.description,
                a.alert_time,
                a.status
            FROM alerts a
            LEFT JOIN users u
                ON a.user_id = u.user_id
            ORDER BY
                a.alert_time DESC
            LIMIT 100
            """
        )


        alerts = cursor.fetchall()


        return jsonify(
            alerts
        )


    except Exception as error:

        print(
            "Alerts API error:",
            error
        )


        return jsonify({
            "error": "Unable to retrieve alerts."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - ACTIVITIES
# ============================================================

@app.route("/api/activities")
@login_required
def api_activities():

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT
                al.log_id,
                al.user_id,
                u.name AS user_name,
                al.session_id,
                al.activity_type,
                al.resource,
                al.action,
                al.timestamp,
                al.ip_address,
                al.device_info
            FROM activity_logs al
            LEFT JOIN users u
                ON al.user_id = u.user_id
            ORDER BY
                al.timestamp DESC
            LIMIT 100
            """
        )


        activities = cursor.fetchall()


        return jsonify(
            activities
        )


    except Exception as error:

        print(
            "Activities API error:",
            error
        )


        return jsonify({
            "error": "Unable to retrieve activities."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - MY STATUS
# ============================================================

@app.route("/api/my-status")
@login_required
def my_status():

    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT
                user_id,
                name,
                role,
                status
            FROM users
            WHERE user_id = %s
            """,
            (session["user_id"],)
        )


        user = cursor.fetchone()


        if not user:

            return jsonify({
                "error": "User not found"
            }), 404


        # Keep Flask session synchronized
        session["status"] = user["status"]


        return jsonify({

            "user_id":
                user["user_id"],

            "name":
                user["name"],

            "role":
                user["role"],

            "status":
                user["status"]

        })


    except Exception as error:

        print(
            "Status API error:",
            error
        )


        return jsonify({
            "error": "Unable to retrieve status"
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - MY ACTIVITIES
# ============================================================

@app.route("/api/my-activities")
@login_required
def my_activities():

    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT
                log_id,
                user_id,
                session_id,
                activity_type,
                resource,
                action,
                timestamp,
                ip_address,
                device_info
            FROM activity_logs
            WHERE user_id = %s
            ORDER BY
                timestamp DESC
            LIMIT 50
            """,
            (session["user_id"],)
        )


        activities = cursor.fetchall()


        return jsonify(
            activities
        )


    except Exception as error:

        print(
            "My activities API error:",
            error
        )


        return jsonify({
            "error": "Unable to retrieve activities."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# USER MANAGEMENT PAGE
# ============================================================

@app.route("/users")
@login_required
def users():

    if session.get("role") != "Admin":

        return redirect(
            url_for("user_dashboard")
        )


    return render_template(
        "users.html"
    )


# ============================================================
# API - ALL USERS
# ============================================================

@app.route("/api/users")
@login_required
def users_api():

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT
                user_id,
                name,
                email,
                role,
                status,
                created_at
            FROM users
            ORDER BY user_id ASC
            """
        )


        users_data = cursor.fetchall()


        return jsonify(
            users_data
        )


    except Exception as error:

        print(
            "Users API error:",
            error
        )


        return jsonify({
            "error": "Unable to retrieve users."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - CHANGE USER STATUS
# ============================================================

@app.route(
    "/api/users/<int:user_id>/status",
    methods=["POST"]
)
@login_required
def update_user_status(user_id):

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    data = request.get_json(
        silent=True
    ) or {}


    new_status = data.get(
        "status"
    )


    allowed_statuses = [
        "Active",
        "Restricted",
        "Suspended"
    ]


    if new_status not in allowed_statuses:

        return jsonify({
            "error": "Invalid status."
        }), 400


    # Admin cannot change own account status
    if user_id == session.get("user_id"):

        return jsonify({
            "error": "Administrator cannot change their own status."
        }), 400


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed."
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        # Only normal users can be controlled
        cursor.execute(
            """
            SELECT
                user_id,
                name,
                role,
                status
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )


        user = cursor.fetchone()


        if not user:

            return jsonify({
                "error": "User not found."
            }), 404


        if user["role"] == "Admin":

            return jsonify({
                "error": "Administrator accounts cannot be changed from User Management."
            }), 400


        # ----------------------------------------------------
        # UPDATE STATUS
        # ----------------------------------------------------

        cursor.execute(
            """
            UPDATE users
            SET status = %s
            WHERE user_id = %s
            """,
            (
                new_status,
                user_id
            )
        )


        connection.commit()


        # ----------------------------------------------------
        # IF SUSPENDED, END ACTIVE SESSIONS
        # ----------------------------------------------------

        if new_status == "Suspended":

            cursor.execute(
                """
                UPDATE sessions
                SET
                    logout_time = NOW(),
                    status = 'Ended'
                WHERE user_id = %s
                AND status = 'Active'
                """,
                (user_id,)
            )


            connection.commit()


        return jsonify({

            "success": True,

            "message":
                f"{user['name']} status changed to {new_status}.",

            "user_id":
                user_id,

            "status":
                new_status

        })


    except Exception as error:

        connection.rollback()


        print(
            "User status error:",
            error
        )


        return jsonify({
            "error": "Unable to update user status."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - INCIDENTS
# ============================================================

@app.route("/api/incidents")
@login_required
def get_incidents():

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT
                i.incident_id,
                i.alert_id,
                i.incident_status,
                i.action_taken,
                i.resolved_by,
                i.resolved_on,
                i.notes,

                a.user_id,
                a.alert_type,
                a.severity,
                a.description,
                a.alert_time,

                u.name AS user_name

            FROM incidents i

            INNER JOIN alerts a
                ON i.alert_id = a.alert_id

            LEFT JOIN users u
                ON a.user_id = u.user_id

            ORDER BY
                i.incident_id DESC

            LIMIT 100
            """
        )


        incidents = cursor.fetchall()


        return jsonify(
            incidents
        )


    except Exception as error:

        print(
            "Incidents API error:",
            error
        )


        return jsonify({
            "error": "Unable to retrieve incidents."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - CREATE INCIDENT
# ============================================================

@app.route(
    "/api/incidents/create/<int:alert_id>",
    methods=["POST"]
)
@login_required
def create_incident(alert_id):

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        # ----------------------------------------------------
        # CHECK ALERT
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                alert_id,
                user_id,
                severity
            FROM alerts
            WHERE alert_id = %s
            """,
            (alert_id,)
        )


        alert = cursor.fetchone()


        if not alert:

            return jsonify({
                "error": "Alert not found."
            }), 404


        # ----------------------------------------------------
        # CHECK DUPLICATE INCIDENT
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                incident_id
            FROM incidents
            WHERE alert_id = %s
            LIMIT 1
            """,
            (alert_id,)
        )


        existing = cursor.fetchone()


        if existing:

            return jsonify({
                "error":
                    "An incident already exists for this alert.",
                "incident_id":
                    existing["incident_id"]
            }), 400


        # ----------------------------------------------------
        # CREATE INCIDENT
        # ----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO incidents
            (
                alert_id,
                incident_status,
                action_taken,
                notes
            )
            VALUES
            (
                %s,
                'Open',
                %s,
                %s
            )
            """,
            (
                alert_id,
                "Incident created from security alert.",
                "Created by administrator."
            )
        )


        connection.commit()


        incident_id = cursor.lastrowid


        return jsonify({

            "success": True,

            "message":
                "Security incident created successfully.",

            "incident_id":
                incident_id

        })


    except Exception as error:

        connection.rollback()


        print(
            "Create incident error:",
            error
        )


        return jsonify({
            "error": "Unable to create incident."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - UPDATE INCIDENT STATUS
# ============================================================

@app.route(
    "/api/incidents/<int:incident_id>/status",
    methods=["POST"]
)
@login_required
def update_incident_status(
    incident_id
):

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    data = request.get_json(
        silent=True
    ) or {}


    new_status = data.get(
        "status"
    )


    allowed_statuses = [
        "Open",
        "Investigating",
        "Resolved"
    ]


    if new_status not in allowed_statuses:

        return jsonify({
            "error": "Invalid incident status."
        }), 400


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor()


        if new_status == "Resolved":

            cursor.execute(
                """
                UPDATE incidents
                SET
                    incident_status = %s,
                    resolved_by = %s,
                    resolved_on = NOW()
                WHERE incident_id = %s
                """,
                (
                    new_status,
                    session.get(
                        "name",
                        "Admin"
                    ),
                    incident_id
                )
            )


        else:

            cursor.execute(
                """
                UPDATE incidents
                SET
                    incident_status = %s
                WHERE incident_id = %s
                """,
                (
                    new_status,
                    incident_id
                )
            )


        if cursor.rowcount == 0:

            return jsonify({
                "error": "Incident not found."
            }), 404


        connection.commit()


        return jsonify({

            "success": True,

            "message":
                "Incident status updated successfully.",

            "incident_id":
                incident_id,

            "status":
                new_status

        })


    except Exception as error:

        connection.rollback()


        print(
            "Incident status error:",
            error
        )


        return jsonify({
            "error": "Unable to update incident."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - INCIDENT DETAILS
# ============================================================

@app.route(
    "/api/incidents/<int:incident_id>/details",
    methods=["POST"]
)
@login_required
def update_incident_details(
    incident_id
):

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    data = request.get_json(
        silent=True
    ) or {}


    action_taken = data.get(
        "action_taken",
        ""
    ).strip()


    notes = data.get(
        "notes",
        ""
    ).strip()


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor()


        cursor.execute(
            """
            UPDATE incidents
            SET
                action_taken = %s,
                notes = %s
            WHERE incident_id = %s
            """,
            (
                action_taken,
                notes,
                incident_id
            )
        )


        if cursor.rowcount == 0:

            return jsonify({
                "error": "Incident not found."
            }), 404


        connection.commit()


        return jsonify({

            "success": True,

            "message":
                "Incident details updated successfully."

        })


    except Exception as error:

        connection.rollback()


        print(
            "Incident details error:",
            error
        )


        return jsonify({
            "error":
                "Unable to update incident details."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - SECURITY ANALYTICS
# ============================================================

@app.route("/api/analytics")
@login_required
def analytics():

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        # ----------------------------------------------------
        # USERS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(status = 'Active') AS active,
                SUM(status = 'Restricted') AS restricted,
                SUM(status = 'Suspended') AS suspended
            FROM users
            """
        )


        users = cursor.fetchone()


        # ----------------------------------------------------
        # ACTIVITIES
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total
            FROM activity_logs
            """
        )


        activities = cursor.fetchone()


        # ----------------------------------------------------
        # ALERTS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(severity = 'Critical') AS critical,
                SUM(severity = 'High') AS high,
                SUM(severity = 'Medium') AS medium,
                SUM(severity = 'Low') AS low
            FROM alerts
            """
        )


        alerts = cursor.fetchone()


        # ----------------------------------------------------
        # INCIDENTS
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                SUM(incident_status = 'Open') AS open_count,
                SUM(incident_status = 'Investigating') AS investigating,
                SUM(incident_status = 'Resolved') AS resolved
            FROM incidents
            """
        )


        incidents = cursor.fetchone()


        return jsonify({

            "users": {

                "total":
                    users["total"] or 0,

                "active":
                    users["active"] or 0,

                "restricted":
                    users["restricted"] or 0,

                "suspended":
                    users["suspended"] or 0
            },


            "activities": {

                "total":
                    activities["total"] or 0
            },


            "alerts": {

                "total":
                    alerts["total"] or 0,

                "critical":
                    alerts["critical"] or 0,

                "high":
                    alerts["high"] or 0,

                "medium":
                    alerts["medium"] or 0,

                "low":
                    alerts["low"] or 0
            },


            "incidents": {

                "open":
                    incidents["open_count"] or 0,

                "investigating":
                    incidents["investigating"] or 0,

                "resolved":
                    incidents["resolved"] or 0
            }

        })


    except Exception as error:

        print(
            "Analytics API error:",
            error
        )


        return jsonify({
            "error": "Unable to retrieve analytics."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - REPORT HISTORY
# ============================================================

@app.route("/api/reports")
@login_required
def get_reports():

    if session.get("role") != "Admin":

        return jsonify({
            "error": "Admin access required"
        }), 403


    connection = get_connection()


    if not connection:

        return jsonify({
            "error": "Database connection failed"
        }), 500


    cursor = None


    try:

        cursor = connection.cursor(
            dictionary=True
        )


        cursor.execute(
            """
            SELECT
                r.report_id,
                r.report_type,
                r.generated_on,
                r.description,
                r.file_path,
                u.name AS generated_by_name

            FROM reports r

            LEFT JOIN users u
                ON r.generated_by = u.user_id

            ORDER BY
                r.generated_on DESC

            LIMIT 100
            """
        )


        reports = cursor.fetchall()


        return jsonify(
            reports
        )


    except Exception as error:

        print(
            "Reports API error:",
            error
        )


        return jsonify({
            "error": "Unable to retrieve reports."
        }), 500


    finally:

        if cursor:

            cursor.close()

        connection.close()


# ============================================================
# API - GENERATE SECURITY REPORT
# ============================================================

@app.route(
    "/api/reports/generate",
    methods=["POST"]
)
@login_required
def generate_report():

    if session.get("role") != "Admin":
        return jsonify({
            "error": "Admin access required"
        }), 403

    connection = get_connection()

    if not connection:
        return jsonify({
            "error": "Database connection failed"
        }), 500

    cursor = None

    try:
        cursor = connection.cursor(
            dictionary=True
        )

        # --------------------------------------------------------
        # USER STATISTICS
        # --------------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(status = 'Active') AS active,
                SUM(status = 'Restricted') AS restricted,
                SUM(status = 'Suspended') AS suspended
            FROM users
            """
        )

        users = cursor.fetchone()

        # --------------------------------------------------------
        # ACTIVITY STATISTICS
        # --------------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total
            FROM activity_logs
            """
        )

        activities = cursor.fetchone()

        # --------------------------------------------------------
        # ALERT STATISTICS
        # --------------------------------------------------------

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(severity = 'Critical') AS critical,
                SUM(severity = 'High') AS high,
                SUM(severity = 'Medium') AS medium,
                SUM(severity = 'Low') AS low
            FROM alerts
            """
        )

        alerts = cursor.fetchone()

        # --------------------------------------------------------
        # INCIDENT STATISTICS
        # --------------------------------------------------------

        cursor.execute(
            """
            SELECT
                SUM(incident_status = 'Open') AS open_count,
                SUM(incident_status = 'Investigating') AS investigating,
                SUM(incident_status = 'Resolved') AS resolved
            FROM incidents
            """
        )

        incidents = cursor.fetchone()

        # --------------------------------------------------------
        # REPORT FOLDER
        # --------------------------------------------------------

        report_folder = os.path.abspath("reports")

        if not os.path.exists(report_folder):
            os.makedirs(report_folder)

        # --------------------------------------------------------
        # REPORT FILE NAME
        # --------------------------------------------------------

        report_time = datetime.now()

        file_name = (
            "security_report_"
            + report_time.strftime("%Y%m%d_%H%M%S")
            + ".txt"
        )

        file_path = os.path.join(
            report_folder,
            file_name
        )

        # --------------------------------------------------------
        # REPORT CONTENT
        # --------------------------------------------------------

        report_content = f"""
============================================================
                       TRUST WATCH
          INTERNAL THREAT DETECTION & PREVENTION SYSTEM
                       SECURITY REPORT
============================================================

Generated By : {session.get("name", "Admin")}
Generated On : {report_time.strftime("%Y-%m-%d %H:%M:%S")}

------------------------------------------------------------
USER SECURITY STATUS
------------------------------------------------------------

Total Users       : {users["total"] or 0}
Active Users      : {users["active"] or 0}
Restricted Users  : {users["restricted"] or 0}
Suspended Users   : {users["suspended"] or 0}

------------------------------------------------------------
ACTIVITY MONITORING
------------------------------------------------------------

Total Activities  : {activities["total"] or 0}

------------------------------------------------------------
SECURITY ALERTS
------------------------------------------------------------

Total Alerts      : {alerts["total"] or 0}
Critical Alerts   : {alerts["critical"] or 0}
High Alerts       : {alerts["high"] or 0}
Medium Alerts     : {alerts["medium"] or 0}
Low Alerts        : {alerts["low"] or 0}

------------------------------------------------------------
INCIDENT MANAGEMENT
------------------------------------------------------------

Open Incidents          : {incidents["open_count"] or 0}
Investigating Incidents : {incidents["investigating"] or 0}
Resolved Incidents      : {incidents["resolved"] or 0}

------------------------------------------------------------
TRUST WATCH COMPONENTS
------------------------------------------------------------

Activity Monitoring    : ENABLED
ML Anomaly Detection   : ENABLED
Security Alerts        : ENABLED
Incident Management    : ENABLED
User Access Control    : ENABLED
Security Reporting     : ENABLED

------------------------------------------------------------
SYSTEM DESCRIPTION
------------------------------------------------------------

Trust Watch is an Internal Threat Detection & Prevention
System designed to monitor authorized user activity,
identify abnormal behavior, generate security alerts,
manage incidents and provide administrative controls.

The system uses machine-learning based anomaly detection
together with security rules to identify potentially
suspicious activities.

============================================================
                      END OF REPORT
============================================================
"""

        # --------------------------------------------------------
        # SAVE REPORT FILE
        # --------------------------------------------------------

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as report_file:

            report_file.write(
                report_content
            )

        # --------------------------------------------------------
        # SAVE REPORT INFORMATION IN DATABASE
        # --------------------------------------------------------

        cursor.execute(
            """
            INSERT INTO reports
            (
                generated_by,
                report_type,
                description,
                file_path
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s
            )
            """,
            (
                session["user_id"],
                "Security Summary",
                "Trust Watch Security Summary Report",
                file_path
            )
        )

        report_id = cursor.lastrowid

        connection.commit()

        # --------------------------------------------------------
        # SUCCESS RESPONSE
        # --------------------------------------------------------

        return jsonify({
            "success": True,
            "message":
                "Security report generated successfully.",
            "report_id":
                report_id,
            "file_name":
                file_name,
            "file_path":
                file_path
        })

    except Exception as error:

        if connection:
            connection.rollback()

        print(
            "Report generation error:",
            error
        )

        return jsonify({
            "error":
                "Unable to generate security report."
        }), 500

    finally:

        if cursor:
            cursor.close()

        connection.close()


# ============================================================
# API - DOWNLOAD REPORT
# ============================================================

@app.route(
    "/api/reports/download/<filename>"
)
@login_required
def download_report(filename):

    if session.get("role") != "Admin":
        return jsonify({
            "error": "Admin access required"
        }), 403

    # --------------------------------------------------------
    # SECURITY VALIDATION
    # --------------------------------------------------------

    if (
        "/" in filename
        or "\\" in filename
        or not filename.endswith(".txt")
    ):
        return jsonify({
            "error": "Invalid report filename."
        }), 400

    report_folder = os.path.abspath(
        "reports"
    )

    file_path = os.path.join(
        report_folder,
        filename
    )

    if not os.path.isfile(
        file_path
    ):
        return jsonify({
            "error": "Report not found."
        }), 404

    return send_from_directory(
        report_folder,
        filename,
        as_attachment=True
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/api/health")
def health():

    connection = get_connection()

    if not connection:
        return jsonify({
            "status":
                "error",
            "database":
                "offline"
        }), 500

    connection.close()

    return jsonify({
        "status":
            "online",
        "database":
            "connected",
        "system":
            "Trust Watch"
    })


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    print()

    print("=" * 60)

    print(
        "                 TRUST WATCH"
    )

    print(
        "     INTERNAL THREAT DETECTION & PREVENTION SYSTEM"
    )

    print("=" * 60)

    print()

    print("Server starting...")

    print()

    print("Dashboard:")

    print(
        "http://127.0.0.1:5000/dashboard"
    )

    print()

    print("Login:")

    print(
        "http://127.0.0.1:5000/login"
    )

    print()

    print("=" * 60)

    print()

    app.run(
        host="127.0.0.1",
        port=5000,

        debug=True
    )