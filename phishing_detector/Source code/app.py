from flask import Flask, render_template, request, jsonify
import joblib
import os
from extractor import extract_features

app = Flask(__name__)

MODEL_PATH = 'phishing_detector.pkl'
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url or not model:
        return jsonify({'error': 'Prediction setup mismatch.'}), 400
        
    try:
        features_dict = extract_features(url)
        
        # --- ULTIMATE HEURISTIC FIREWALL LAYER ---
        is_phishing = False
        confidence = "High Structural Match"

        if features_dict['is_ip'] == 1:
            is_phishing = True
            confidence = "Firewall Alert: Direct IP Mapping Detected"
            
        elif features_dict['has_at_symbol'] == 1:
            is_phishing = True
            confidence = "Firewall Alert: Dangerous '@' Symbol Credentials Masking"
            
        elif features_dict['hyphen_count'] >= 3:
            is_phishing = True
            confidence = "Firewall Alert: Hyphen Aggression (Brand Spoofing Pattern)"
            
        elif features_dict['has_spoofed_protocol'] == 1:
            is_phishing = True
            confidence = "Firewall Alert: Embedded Token Protocol Spoofing"
            
        else:
            # Fallback to ML Model for standard checks
            feature_order = ['url_length', 'has_at_symbol', 'dot_count', 'has_redirect', 'is_ip']
            ordered_features = [features_dict[key] for key in feature_order]
            
            prediction = model.predict([ordered_features])[0]
            is_phishing = True if prediction in [-1, 0] else False

        return jsonify({
            'success': True,
            'url': url,
            'status': 'Malicious' if is_phishing else 'Safe',
            'is_phishing': is_phishing,
            'confidence': confidence,
            'features_analyzed': {
                'length': features_dict['url_length'],
                'has_at_symbol': bool(features_dict['has_at_symbol']),
                'dots_count': features_dict['dot_count']
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)