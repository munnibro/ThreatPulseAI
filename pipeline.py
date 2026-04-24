import threading
import time
from packet_capture import start_capture_thread, packet_queue
from ml_engine import encode_packet as analyze_packet   # assuming function name
from database import insert_packet, insert_threat  # adjust if needed
from websocket_server import broadcast, start_ws_server
import asyncio

def processing_loop():
    print("[PIPELINE] Started processing loop...")

    while True:
        try:
            if packet_queue.empty():
                time.sleep(0.01)
                continue

            packet = packet_queue.get()

            # ── STEP 1: AI ANALYSIS ─────────────
            result = analyze_packet(packet)

            is_threat = result.get("is_threat", False)
            score     = result.get("threat_score", 0.0)
            detail    = result.get("threat_detail")

            # ── STEP 2: SAVE PACKET ─────────────
            packet_id = insert_packet(packet, score, is_threat)

            # ── STEP 3: SAVE THREAT ─────────────
            if is_threat and detail:
                insert_threat(detail, packet_id)

            # ── STEP 4: (OPTIONAL) LOG ──────────
            if is_threat:
                print(f"[THREAT] {detail.get('type')} | {score}")

        except Exception as e:
            print("[PIPELINE ERROR]", e)


            if __name__ == "__main__":
              print("🚀 Starting ThreatPulse AI Pipeline...\n")


              if is_threat and detail:
                insert_threat(detail, packet_id)

            #  SEND LIVE ALERT
    try:
        asyncio.run(broadcast({
            "type": "threat",
            "data": detail
        }))
    except:
        pass
              # Start WebSocket server in background
    ws_thread = threading.Thread(
    target=start_ws_server,
    daemon=True
)
    ws_thread.start()

    # ── START PACKET CAPTURE ─────────────
    capture_thread, stop_event = start_capture_thread(
        iface=None,
        packet_filter="ip"
    )
    # ── START PROCESSING THREAD ──────────
    processing_thread = threading.Thread(
        target=processing_loop,
        daemon=True
    )
    processing_thread.start()
    print("✅ System running (Capture + AI + DB)\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping...")
        stop_event.set()