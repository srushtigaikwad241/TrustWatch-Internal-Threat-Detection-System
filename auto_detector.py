import time
from datetime import datetime

import mysql.connector
import pandas as pd
from sklearn.ensemble import IsolationForest

from database import get_connection


# ============================================================
# SETTINGS
# ============================================================

CHECK_INTERVAL = 3
MODEL_NAME = "Isolation Forest"

last_log_id = 0


# ============================================================
# GET NEW ACTIVITIES
# ============================================================

def get_new_activities():

    connection = get_connection()

    if not connection:
        return []

    cursor = None

    try:

        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                a.log_id,
                a.user_id,
                u.name AS user_name,
                a.activity_type,
                a.resource,
                a.action,
                a.timestamp,
                a.ip_address,
                a.device_info
            FROM activity_logs a
            LEFT JOIN users u
                ON a.user_id = u.user_id
            WHERE a.log_id > %s
            ORDER BY a.log_id ASC
        """, (last_log_id,))

        return cursor.fetchall()

    except Exception as error:

        print("Error reading activities:", error)

        return []

    finally:

        if cursor:
            cursor.close()

        connection.close()


# ============================================================
# GET TRAINING DATA
# ============================================================

def get_training_data():

    connection = get_connection()

    if not connection:
        return pd.DataFrame()

    cursor = None

    try:

        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                activity_type,
                resource,
                action,
                timestamp,
                ip_address,
                device_info
            FROM activity_logs
            ORDER BY log_id DESC
            LIMIT 300
        """)

        rows = cursor.fetchall()

        if not rows:
            return pd.DataFrame()

        return pd.DataFrame(rows)

    except Exception as error:

        print("Training data error:", error)

        return pd.DataFrame()

    finally:

        if cursor:
            cursor.close()

        connection.close()


# ============================================================
# CONVERT ACTIVITY INTO ML FEATURES
# ============================================================

def create_features(data):

    if data.empty:
        return pd.DataFrame()

    df = data.copy()


    # --------------------------------------------------------
    # Convert text to lowercase
    # --------------------------------------------------------

    df["activity_type"] = (
        df["activity_type"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    df["resource"] = (
        df["resource"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    df["action"] = (
        df["action"]
        .fillna("")
        .astype(str)
        .str.lower()
    )

    df["device_info"] = (
        df["device_info"]
        .fillna("")
        .astype(str)
        .str.lower()
    )


    # --------------------------------------------------------
    # Time features
    # --------------------------------------------------------

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    df["hour"] = (
        df["timestamp"]
        .dt.hour
        .fillna(12)
    )


    # --------------------------------------------------------
    # Activity indicators
    # --------------------------------------------------------

    df["failed_login"] = (
        df["activity_type"]
        .str.contains(
            "failed|login failed|authentication failed",
            regex=True,
            na=False
        )
        .astype(int)
    )


    df["file_download"] = (
        df["activity_type"]
        .str.contains(
            "download|export",
            regex=True,
            na=False
        )
        .astype(int)
    )


    df["file_access"] = (
        df["activity_type"]
        .str.contains(
            "file|access|read",
            regex=True,
            na=False
        )
        .astype(int)
    )


    df["unknown_device"] = (
        df["device_info"]
        .str.contains(
            "unknown|unrecognized|new device",
            regex=True,
            na=False
        )
        .astype(int)
    )


    # --------------------------------------------------------
    # Sensitive resource
    # --------------------------------------------------------

    sensitive_words = (
        "confidential|employee|database|backup|"
        "admin|password|security|financial"
    )

    df["sensitive_resource"] = (
        df["resource"]
        .str.contains(
            sensitive_words,
            regex=True,
            na=False
        )
        .astype(int)
    )


    # --------------------------------------------------------
    # Suspicious action
    # --------------------------------------------------------

    suspicious_words = (
        "delete|export|privilege|unauthorized|"
        "suspicious|modify|remove"
    )

    df["suspicious_action"] = (
        df["action"]
        .str.contains(
            suspicious_words,
            regex=True,
            na=False
        )
        .astype(int)
    )


    # --------------------------------------------------------
    # Unusual working hour
    # --------------------------------------------------------

    df["unusual_hour"] = (
        (df["hour"] < 7) |
        (df["hour"] > 22)
    ).astype(int)


    # --------------------------------------------------------
    # Activity frequency
    # --------------------------------------------------------

    df["activity_count"] = 1


    feature_columns = [
        "hour",
        "failed_login",
        "file_download",
        "file_access",
        "unknown_device",
        "sensitive_resource",
        "suspicious_action",
        "unusual_hour",
        "activity_count"
    ]


    return df[feature_columns]


# ============================================================
# CALCULATE RISK SCORE
# ============================================================

def calculate_risk_score(features, anomaly):

    score = 0


    if features["failed_login"] == 1:
        score += 25


    if features["file_download"] == 1:
        score += 20


    if features["file_access"] == 1:
        score += 10


    if features["unknown_device"] == 1:
        score += 20


    if features["sensitive_resource"] == 1:
        score += 15


    if features["suspicious_action"] == 1:
        score += 20


    if features["unusual_hour"] == 1:
        score += 10


    # Isolation Forest detected anomaly
    if anomaly == -1:
        score += 20


    return min(score, 100)


# ============================================================
# GET SEVERITY
# ============================================================

def get_severity(risk_score):

    if risk_score >= 90:
        return "Critical"

    elif risk_score >= 75:
        return "High"

    elif risk_score >= 50:
        return "Medium"

    else:
        return "Low"


# ============================================================
# SAVE ML RESULT
# ============================================================

def save_analysis(
    log_id,
    risk_score,
    is_anomalous
):

    connection = get_connection()

    if not connection:
        return None

    cursor = None

    try:

        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO ml_analysis_results
            (
                log_id,
                risk_score,
                is_anomalous,
                model_name
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s
            )
        """, (
            log_id,
            risk_score,
            is_anomalous,
            MODEL_NAME
        ))

        connection.commit()

        return cursor.lastrowid

    except Exception as error:

        print("ML result save error:", error)

        return None

    finally:

        if cursor:
            cursor.close()

        connection.close()


# ============================================================
# CREATE ALERT
# ============================================================

def create_alert(
    user_id,
    analysis_id,
    severity,
    description
):

    connection = get_connection()

    if not connection:
        return

    cursor = None

    try:

        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO alerts
            (
                user_id,
                analysis_id,
                alert_type,
                severity,
                description
            )
            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s
            )
        """, (
            user_id,
            analysis_id,
            "ML Anomaly Detection",
            severity,
            description
        ))

        connection.commit()

        print(
            f"[ALERT] User {user_id} | "
            f"{severity} | {description}"
        )

    except Exception as error:

        print("Alert creation error:", error)

    finally:

        if cursor:
            cursor.close()

        connection.close()


# ============================================================
# ANALYZE ACTIVITIES
# ============================================================

def analyze_activities(activities):

    global last_log_id

    if not activities:
        return


    # --------------------------------------------------------
    # Training data
    # --------------------------------------------------------

    training_data = get_training_data()


    if training_data.empty:

        print(
            "[ML] Not enough training data."
        )

        last_log_id = activities[-1]["log_id"]

        return


    X_train_all = create_features(
        training_data
    )


    if len(X_train_all) < 10:

        print(
            "[ML] Waiting for more training data..."
        )

        last_log_id = activities[-1]["log_id"]

        return


    # --------------------------------------------------------
    # Isolation Forest
    # --------------------------------------------------------

    model = IsolationForest(
        n_estimators=100,
        contamination=0.10,
        random_state=42
    )


    model.fit(X_train_all)


    # --------------------------------------------------------
    # Analyze new activities
    # --------------------------------------------------------

    new_df = pd.DataFrame(
        activities
    )


    X_new = create_features(
        new_df
    )


    predictions = model.predict(
        X_new
    )


    scores = model.decision_function(
        X_new
    )


    for index, activity in enumerate(activities):

        prediction = predictions[index]

        ml_score = scores[index]


        is_anomalous = (
            prediction == -1
        )


        feature_row = X_new.iloc[index]


        risk_score = calculate_risk_score(
            feature_row,
            prediction
        )


        severity = get_severity(
            risk_score
        )


        analysis_id = save_analysis(
            activity["log_id"],
            risk_score,
            is_anomalous
        )


        print(
            "\n------------------------------------------------"
        )

        print(
            f"Activity ID : {activity['log_id']}"
        )

        print(
            f"User        : {activity['user_name']}"
        )

        print(
            f"Activity    : {activity['activity_type']}"
        )

        print(
            f"Resource    : {activity['resource']}"
        )

        print(
            f"ML Score    : {ml_score:.4f}"
        )

        print(
            f"Risk Score  : {risk_score}/100"
        )

        print(
            f"Anomaly     : {is_anomalous}"
        )

        print(
            f"Severity    : {severity}"
        )


        # ----------------------------------------------------
        # Create alert only for meaningful threats
        # ----------------------------------------------------

        if is_anomalous and risk_score >= 50:

            description = (
                f"Isolation Forest detected unusual behavior "
                f"for user {activity['user_name']}. "
                f"Activity: {activity['activity_type']}, "
                f"Resource: {activity['resource']}, "
                f"Risk Score: {risk_score}/100."
            )


            if analysis_id:

                create_alert(
                    activity["user_id"],
                    analysis_id,
                    severity,
                    description
                )


    last_log_id = activities[-1]["log_id"]


# ============================================================
# INITIALIZE LAST LOG ID
# ============================================================

def initialize_last_log_id():

    global last_log_id

    connection = get_connection()

    if not connection:
        return

    cursor = None

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT COALESCE(MAX(log_id), 0)
            FROM activity_logs
        """)

        result = cursor.fetchone()

        last_log_id = result[0]


    except Exception as error:

        print(
            "Initialization error:",
            error
        )


    finally:

        if cursor:
            cursor.close()

        connection.close()


# ============================================================
# MAIN LOOP
# ============================================================

def main():

    print()
    print("=" * 60)
    print("       TRUST WATCH ML DETECTOR")
    print("=" * 60)
    print()
    print("Model       : Isolation Forest")
    print("Mode        : Real-time activity analysis")
    print("Interval    :", CHECK_INTERVAL, "seconds")
    print()
    print("Detector is running...")
    print("Press Ctrl+C to stop.")
    print()


    initialize_last_log_id()


    while True:

        try:

            activities = get_new_activities()


            if activities:

                analyze_activities(
                    activities
                )


            time.sleep(
                CHECK_INTERVAL
            )


        except KeyboardInterrupt:

            print()
            print(
                "ML Detector stopped."
            )

            break


        except Exception as error:

            print(
                "Detector error:",
                error
            )

            time.sleep(
                CHECK_INTERVAL
            )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()