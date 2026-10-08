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

    except mysql.connector.Error as error:
        print("Error connecting to MySQL:", error)
        return None