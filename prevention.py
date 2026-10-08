from database import get_connection


def restrict_user(user_id):
    connection = get_connection()

    if not connection:
        return

    cursor = connection.cursor()

    query = """
    UPDATE users
    SET status = 'Restricted'
    WHERE user_id = %s
    """

    cursor.execute(query, (user_id,))
    connection.commit()

    if cursor.rowcount > 0:
        print(f"User {user_id} has been restricted.")
    else:
        print(f"User {user_id} not found.")

    cursor.close()
    connection.close()


def suspend_user(user_id):
    connection = get_connection()

    if not connection:
        return

    cursor = connection.cursor()

    query = """
    UPDATE users
    SET status = 'Suspended'
    WHERE user_id = %s
    """

    cursor.execute(query, (user_id,))
    connection.commit()

    if cursor.rowcount > 0:
        print(f"User {user_id} has been suspended.")
    else:
        print(f"User {user_id} not found.")

    cursor.close()
    connection.close()


if __name__ == "__main__":

    user_id = int(input("Enter test user ID: "))

    choice = input(
        "Enter action (restrict/suspend): "
    ).lower()

    if choice == "restrict":
        restrict_user(user_id)

    elif choice == "suspend":
        suspend_user(user_id)

    else:
        print("Invalid action.")