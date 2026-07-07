import joblib
import os
import xgboost as xgb  # Keep this imported so Python knows the class definition

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

feature_path = os.path.join(BASE_DIR, "feature_columns(3).pkl")
model_path = os.path.join(BASE_DIR, "model(3).pkl")

print("Testing feature columns...")
cols = joblib.load(feature_path)
print("✅ Feature columns loaded")

print("Testing model...")
try:
    # Reverting back to joblib since it's a binary pickle file
    model = joblib.load(model_path)
    print("✅ Model loaded successfully!")
    print(f"Model type: {type(model)}")

except Exception as e:
    print(f"❌ Loading failed. Error details: {e}")