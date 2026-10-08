import mysql.connector

def get_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="TrustWatch@26",
            database="internal_threat_detection"
        )

        if connection.is_connected():
            print("Successfully connected to MySQL!")

        return connection

    except mysql.connector.Error as err:
        print("Database connection error:", err)
        return None


connection = get_connection()

if connection:
    cursor = connection.cursor()

    query = """
        INSERT INTO activity_logs
        (user_id, session_id, activity_type, resource, action, ip_address, device_info)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """

    values = (
        1,
        None,
        "LOGIN",
        "System",
        "User logged in",
        "127.0.0.1",
        "Windows PC"
    )

    cursor.execute(query, values)

    connection.commit()

    print("Activity log inserted successfully!")

    cursor.close()
    connection.close()