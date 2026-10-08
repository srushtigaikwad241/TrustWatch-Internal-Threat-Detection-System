import random
import time
from database import get_connection


users = list(range(2, 16))


normal_activities = [
    "Login",
    "File Access",
    "File Download",
    "Logout"
]


suspicious_activities = [
    "Failed Login",
    "File Access",
    "File Download"
]


resources = [
    "student_records.pdf",
    "employee_data.xlsx",
    "project_files.zip",
    "database_backup.sql",
    "confidential_report.pdf"
]


# ==========================================
# GET USER STATUS
# ==========================================

def get_user_status(user_id):

    connection = get_connection()

    if not connection:
        return None

    cursor = connection.cursor(dictionary=True)

    query = """
        SELECT name, role, status
        FROM users
        WHERE user_id = %s
    """

    cursor.execute(query, (user_id,))

    user = cursor.fetchone()

    cursor.close()
    connection.close()

    return user


# ==========================================
# GENERATE ACTIVITY
# ==========================================

def generate_activity():

    user_id = random.choice(users)

    user = get_user_status(user_id)

    if not user:
        return None

    name = user["name"]
    status = user["status"]


    # ======================================
    # SUSPENDED USER
    # ======================================

    if status == "Suspended":

        print(
            f"[BLOCKED] {name} "
            f"(User {user_id}) is Suspended. "
            f"No activity generated."
        )

        return None


    # ======================================
    # RESTRICTED USER
    # ======================================

    if status == "Restricted":

        print(
            f"[RESTRICTED] {name} "
            f"(User {user_id}) activity blocked."
        )

        return (
            user_id,
            None,
            "Blocked Activity",
            "Restricted Account",
            "Activity Blocked",
            f"192.168.1.{user_id}",
            "Windows-PC"
        )


    # ======================================
    # ACTIVE USER
    # ======================================

    if user_id <= 9:

        activity_type = random.choice(
            normal_activities
        )

        device_info = "Windows-PC"

    else:

        activity_type = random.choice(
            suspicious_activities
        )

        device_info = "Unknown-Device"


    resource = random.choice(resources)

    action = activity_type

    ip_address = f"192.168.1.{user_id}"


    print(
        f"[ACTIVITY] {name} | "
        f"User {user_id} | "
        f"{activity_type} | "
        f"{resource}"
    )


    return (
        user_id,
        None,
        activity_type,
        resource,
        action,
        ip_address,
        device_info
    )


# ==========================================
# INSERT ACTIVITY
# ==========================================

def insert_activity(data):

    if data is None:
        return


    connection = get_connection()

    if not connection:
        return


    cursor = connection.cursor()


    query = """
        INSERT INTO activity_logs
        (
            user_id,
            session_id,
            activity_type,
            resource,
            action,
            ip_address,
            device_info
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """


    cursor.execute(query, data)

    connection.commit()

    cursor.close()

    connection.close()


# ==========================================
# START SIMULATOR
# ==========================================

print()
print("======================================")
print("       TRUST WATCH ACTIVITY MONITOR")
print("======================================")
print()
print("Checking user status before activity...")
print("Press CTRL+C to stop.")
print()


try:

    while True:

        activity = generate_activity()

        if activity is not None:

            insert_activity(activity)

        time.sleep(3)


except KeyboardInterrupt:

    print()
    print("Activity simulator stopped.")