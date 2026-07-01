import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

print("⏳ Generating highly-weighted threat signatures...")

np.random.seed(42)
num_samples = 6000

# Generate robust base variations
url_length = np.random.randint(12, 35, num_samples)
has_at = np.random.choice([0, 1], num_samples, p=[0.99, 0.01])
dots = np.random.randint(1, 3, num_samples)
redirect = np.random.choice([0, 1], num_samples, p=[0.99, 0.01])
is_ip = np.random.choice([0, 1], num_samples, p=[0.995, 0.005])
labels = np.ones(num_samples) # Default: 1 (Safe)

# Inject Aggressive Phishing Variants (Force the model to see extreme bad links)
for i in range(num_samples // 2):
    labels[i] = -1 # Phishing Flag
    
    # Mix up the attack vectors so it learns multiple patterns
    vector_type = i % 4
    if vector_type == 0:
        is_ip[i] = 1
        url_length[i] = np.random.randint(45, 110)
    elif vector_type == 1:
        url_length[i] = np.random.randint(80, 160)
        dots[i] = np.random.randint(3, 7)
    elif vector_type == 2:
        has_at[i] = 1
        url_length[i] = np.random.randint(50, 90)
    elif vector_type == 3:
        redirect[i] = 1
        dots[i] = np.random.randint(3, 5)

X = pd.DataFrame({
    'url_length': url_length,
    'has_at_symbol': has_at,
    'dot_count': dots,
    'has_redirect': redirect,
    'is_ip': is_ip
})
y = labels

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("🤖 Training deep threat-weighted Random Forest...")
# class_weight='balanced' forces the model to treat phishing errors with massive severity
model = RandomForestClassifier(
    n_estimators=200, 
    max_depth=15, 
    class_weight='balanced_subsample', 
    random_state=42
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(f"🎯 Alignment Stability: {accuracy_score(y_test, y_pred) * 100:.2f}%")

joblib.dump(model, 'phishing_detector.pkl')
print("✅ Success! Perfected 'phishing_detector.pkl' exported.")