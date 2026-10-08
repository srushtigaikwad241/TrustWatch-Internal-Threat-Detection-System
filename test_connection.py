from database import get_connection

connection = get_connection()

if connection:
    print("Database connection test successful!")

    connection.close()
    print("Connection closed.")
else:
    print("Database connection failed.")