from flask import Flask, request, jsonify
from flask_cors import CORS

import pandas as pd
import numpy as np
import joblib
import os
import re
import math

from urllib.parse import urlparse
import tldextract

app = Flask(__name__)
CORS(app)

# ============================================
# Load model and feature columns
# ============================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "model(3).pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "feature_columns(3).pkl")

model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURES_PATH)
if __name__ == "__main__":
    app.run(debug=True, port=5000)