from sklearn.ensemble import IsolationForest
from database import get_connection
from prevention import restrict_user, suspend_user


def analyze_activities():

    connection = get_connection()

    if not connection:
        print("Database connection failed.")
        return

    cursor = connection.cursor(dictionary=True)

    # Read existing activity logs
    query = """
        SELECT
            log_id,
            user_id,
            activity_type,
            resource,
            action,
            timestamp,
            ip_address,
            device_info
        FROM activity_logs
        ORDER BY log_id
    """

    cursor.execute(query)

    records = cursor.fetchall()

    if not records:

        print("No activity records found.")

        cursor.close()
        connection.close()

        return

    # ------------------------------------------------
    # Create ML features from existing database fields
    # ------------------------------------------------

    feature_data = []

    for row in records:

        # Activity risk
        failed_login = (
            1 if row["activity_type"] == "Failed Login"
            else 0
        )

        file_access = (
            1 if row["activity_type"] == "File Access"
            else 0
        )

        file_download = (
            1 if row["activity_type"] == "File Download"
            else 0
        )

        unknown_device = (
            1 if row["device_info"] == "Unknown-Device"
            else 0
        )

        # Confidential resources have higher risk
        confidential_resource = (
            1
            if row["resource"] in [
                "database_backup.sql",
                "confidential_report.pdf",
                "employee_data.xlsx"
            ]
            else 0
        )

        # Hour from timestamp
        login_hour = row["timestamp"].hour

        # Unusual working hours
        unusual_hour = (
            1
            if login_hour < 8 or login_hour > 20
            else 0
        )

        feature_data.append([
            failed_login,
            file_access,
            file_download,
            unknown_device,
            confidential_resource,
            unusual_hour
        ])

    # ------------------------------------------------
    # Machine Learning
    # ------------------------------------------------

    model = IsolationForest(
        contamination=0.30,
        random_state=42
    )

    model.fit(feature_data)

    predictions = model.predict(feature_data)

    scores = model.decision_function(feature_data)

    print("\n======================================")
    print("       INTERNAL THREAT DETECTION")
    print("======================================\n")

    for row, prediction, score in zip(
        records,
        predictions,
        scores
    ):

        user_id = row["user_id"]
        log_id = row["log_id"]

        # Convert ML anomaly score into risk score
        risk_score = 50 - (score * 200)

        risk_score = max(
            0,
            min(100, risk_score)
        )

        # ------------------------------------------------
        # Suspicious activity
        # ------------------------------------------------

        if prediction == -1:

            status = "Suspicious"

            if risk_score >= 80:

                severity = "Critical"

            elif risk_score >= 60:

                severity = "High"

            elif risk_score >= 40:

                severity = "Medium"

            else:

                severity = "Low"

            print("--------------------------------------")
            print(f"Log ID       : {log_id}")
            print(f"User ID      : {user_id}")
            print(f"Activity     : {row['activity_type']}")
            print(f"Resource     : {row['resource']}")
            print(f"Device       : {row['device_info']}")
            print(f"Status       : {status}")
            print(f"Risk Score   : {risk_score:.2f}")
            print(f"Severity     : {severity}")

            # ------------------------------------------------
            # Save ML result
            # ------------------------------------------------

            analysis_query = """
                INSERT INTO ml_analysis_results
                (
                    log_id,
                    risk_score,
                    is_anomalous,
                    model_name
                )
                VALUES (%s, %s, %s, %s)
            """

            cursor.execute(
                analysis_query,
                (
                    log_id,
                    float(risk_score),
                    True,
                    "Isolation Forest"
                )
            )

            analysis_id = cursor.lastrowid

            # ------------------------------------------------
            # Create alert
            # ------------------------------------------------

            alert_query = """
                INSERT INTO alerts
                (
                    user_id,
                    analysis_id,
                    alert_type,
                    severity,
                    description
                )
                VALUES (%s, %s, %s, %s, %s)
            """

            description = (
                "Suspicious activity detected. "
                f"Activity: {row['activity_type']}, "
                f"Resource: {row['resource']}, "
                f"Device: {row['device_info']}, "
                f"IP: {row['ip_address']}"
            )

            cursor.execute(
                alert_query,
                (
                    user_id,
                    analysis_id,
                    "Anomalous User Behavior",
                    severity,
                    description
                )
            )

            # ------------------------------------------------
            # Automatic prevention
            # ------------------------------------------------

            connection.commit()

            if risk_score >= 80:

                print(
                    f"PREVENTION: User {user_id} "
                    f"will be SUSPENDED."
                )

                suspend_user(user_id)

            elif risk_score >= 60:

                print(
                    f"PREVENTION: User {user_id} "
                    f"will be RESTRICTED."
                )

                restrict_user(user_id)

        # ------------------------------------------------
        # Normal activity
        # ------------------------------------------------

        else:

            status = "Normal"

            risk_score = 50 - (score * 100)

            risk_score = max(
                0,
                min(100, risk_score)
            )

            print("--------------------------------------")
            print(f"Log ID       : {log_id}")
            print(f"User ID      : {user_id}")
            print(f"Activity     : {row['activity_type']}")
            print(f"Status       : {status}")
            print(f"Risk Score   : {risk_score:.2f}")

            # Save normal ML result
            analysis_query = """
                INSERT INTO ml_analysis_results
                (
                    log_id,
                    risk_score,
                    is_anomalous,
                    model_name
                )
                VALUES (%s, %s, %s, %s)
            """

            cursor.execute(
                analysis_query,
                (
                    log_id,
                    float(risk_score),
                    False,
                    "Isolation Forest"
                )
            )

    connection.commit()

    cursor.close()
    connection.close()

    print("\n======================================")
    print("Threat analysis completed successfully!")
    print("======================================\n")


if __name__ == "__main__":
    analyze_activities()