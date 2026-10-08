import pandas as pd
from sklearn.ensemble import IsolationForest
from database import get_connection
import joblib


def load_activity_data():
    connection = get_connection()

    if not connection:
        print("Database connection failed.")
        return None

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
    """

    try:
        df = pd.read_sql(query, connection)
        return df

    except Exception as e:
        print("Error loading activity data:", e)
        return None

    finally:
        connection.close()


def prepare_features(df):
    # Convert timestamp to datetime
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Extract hour from timestamp
    df["activity_hour"] = df["timestamp"].dt.hour

    # Create numerical features
    df["activity_code"] = df["activity_type"].astype("category").cat.codes

    # Number of characters in resource
    df["resource_length"] = (
        df["resource"]
        .fillna("")
        .astype(str)
        .str.len()
    )

    # Number of characters in action
    df["action_length"] = (
        df["action"]
        .fillna("")
        .astype(str)
        .str.len()
    )

    # Features used by Isolation Forest
    features = [
        "activity_hour",
        "activity_code",
        "resource_length",
        "action_length"
    ]

    return df, features


def train_model():

    print("\n========== INTERNAL THREAT DETECTION ==========")
    print("Loading activity data...")

    df = load_activity_data()

    if df is None or df.empty:
        print("No activity data found.")
        return

    print("Activity records found:", len(df))

    # Prepare ML features
    df, features = prepare_features(df)

    X = df[features]

    # Isolation Forest model
    model = IsolationForest(
        n_estimators=100,
        contamination=0.30,
        random_state=42
    )

    # Train model
    model.fit(X)

    # Predict anomalies
    df["prediction"] = model.predict(X)

    # Calculate anomaly score
    df["anomaly_score"] = model.decision_function(X)

    # Convert prediction to readable status
    df["status"] = df["prediction"].apply(
        lambda x: "Suspicious" if x == -1 else "Normal"
    )

    # Display results
    print("\n========== ML ANALYSIS RESULTS ==========")

    for _, row in df.iterrows():

        print(
            f"Log ID: {row['log_id']} | "
            f"User ID: {row['user_id']} | "
            f"Activity: {row['activity_type']} | "
            f"Status: {row['status']} | "
            f"Score: {row['anomaly_score']:.4f}"
        )

    # Save trained model
    model_file = "threat_detection_model.pkl"

    joblib.dump(model, model_file)

    print("\n==========================================")
    print("ML model trained successfully!")
    print(f"Model saved as: {model_file}")
    print("==========================================")


if __name__ == "__main__":
    train_model()