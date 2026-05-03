from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from asyncio import Queue
import threading

from sniffer import start_sniffing, stop_sniffing

app = FastAPI()

packet_queue = Queue()
sniffer_thread = None


# ---------------------------
# Callback from sniffer
# ---------------------------
def packet_callback(data):
    import asyncio
    asyncio.run(packet_queue.put(data))


# ---------------------------
# Start Sniffing API
# ---------------------------
@app.get("/start")
def start():
    global sniffer_thread

    if sniffer_thread is None or not sniffer_thread.is_alive():
        sniffer_thread = threading.Thread(
            target=start_sniffing,
            args=(packet_callback,),
            daemon=True
        )
        sniffer_thread.start()

    return {"status": "started"}


# ---------------------------
# Stop Sniffing API
# ---------------------------
@app.get("/stop")
def stop():
    stop_sniffing()
    return {"status": "stopped"}


# ---------------------------
# WebSocket Endpoint
# ---------------------------
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()

    try:
        while True:
            # ✅ Stop if client disconnected
            if ws.client_state.name != "CONNECTED":
                print("Client not connected anymore")
                break

            data = await packet_queue.get()

            try:
                await ws.send_json(data)

            except Exception:
                # Happens when client disconnects suddenly
                print("Send failed, client likely disconnected")
                break

    except WebSocketDisconnect:
        print("Client disconnected cleanly")

    except Exception as e:
        print("WebSocket error:", e)