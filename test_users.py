from database import get_connection

connection = get_connection()

if connection:
    cursor = connection.cursor()

    cursor.execute("SELECT user_id, name, email, role, status FROM users")

    users = cursor.fetchall()

    print("\nUsers in Database:")
    print("-" * 60)

    for user in users:
        print(user)

    print("-" * 60)
    print("Total users:", len(users))

    cursor.close()
    connection.close()