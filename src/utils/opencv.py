import logging
import cv2
import time
import hashlib
import threading

def scan_qr_code(timeout=300):
    """Scans for a QR code using a headless OpenCV build (no GUI)."""
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        logging.error("Could not open camera.")
        return None

    detector = cv2.QRCodeDetector()
    logging.info("Camera activated. Hold the QR code in front of the camera...")

    start_time = time.time()
    data = None

    while time.time() - start_time < timeout:
        ret, frame = cap.read()
        if not ret:
            logging.debug("Failed to grab frame.")
            continue

        data, bbox, _ = detector.detectAndDecode(frame)
        if data:
            logging.info(f"QR code detected.")
            break

        time.sleep(0.1)

    cap.release()
    if not data:
        logging.warning("No QR code detected within timeout.")
    return data


# ===== Existing working code below =====
CAMERA_DEVICE = 0
FRAME_WIDTH = 160
FRAME_HEIGHT = 120
CAPTURE_DURATION = 5

def record_clip(duration=5):
    cap = cv2.VideoCapture(CAMERA_DEVICE)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

    start_time = time.time()
    frames = []

    while time.time() - start_time < duration:
        ret, frame = cap.read()
        if ret:
            frames.append(frame.tobytes())
        time.sleep(0.1)

    cap.release()
    return b"".join(frames)

def hash_data(data):
    return hashlib.sha256(data).digest()

def feed_bytes(entropy_bytes):
    with open("/dev/urandom", "ab") as urandom:
        urandom.write(entropy_bytes)

def entropy_thread():
    while True:
        clip_data = record_clip(CAPTURE_DURATION)
        if not clip_data:
            continue
        entropy = hash_data(clip_data)
        feed_bytes(entropy)

def record_until_enter_and_feed():
    cap = cv2.VideoCapture(CAMERA_DEVICE)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

    stop_flag = False

    logging.info("Recording started. Press Enter to stop...")

    def wait_for_enter():
        nonlocal stop_flag
        input()
        stop_flag = True
        logging.info("Recording stopped by Enter key.")

    threading.Thread(target=wait_for_enter, daemon=True).start()

    logging.info("Writing frames to /dev/random ...")
    count = 0
    while not stop_flag:
        time.sleep(0.5)
        ret, frame = cap.read()
        if not ret:
            logging.warning("Frame capture failed.")
            break

        frame_bytes = frame.tobytes()

        try:
            with open("/dev/random", "ab") as rnd:
                rnd.write(frame_bytes)
                count += 1
                if count % 5 == 0:
                    logging.info(f"Wrote {count} frames to /dev/random")
        except PermissionError:
            logging.error("Permission denied: Need root privileges to write to /dev/random.")
            break

    cap.release()
