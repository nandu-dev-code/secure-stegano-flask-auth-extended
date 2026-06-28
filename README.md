# Secure Stegano Flask (Extended)
Keeps your existing flow and adds Audio+Video steganography.

## Configure DB
Edit `app.py`: set `DB_URI` to your MySQL connection, e.g.
mysql+pymysql://root:YOURPASSWORD@localhost/stegano_db

## Run
python -m venv .venv
# activate venv
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000

## Notes
- Audio: WAV only (LSB in samples).
- Video: payload appended as trailer; use non-streaming local files.
