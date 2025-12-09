from detector import detect_threat
from db_client import save_threats

sample_log = "User tried to login with ' OR 1=1 -- and failed multiple times."
detected = detect_threat(sample_log)
save_threats(detected)
