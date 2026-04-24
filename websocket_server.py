import asyncio
import websockets
import json

connected_clients = set()

async def handler(websocket):
    connected_clients.add(websocket)
    print("[WS] Client connected")

    try:
        async for _ in websocket:
            pass
    except:
        pass
    finally:
        connected_clients.remove(websocket)
        print("[WS] Client disconnected")


async def broadcast(message: dict):
    if not connected_clients:
        return

    data = json.dumps(message)

    await asyncio.gather(*[
        client.send(data)
        for client in connected_clients
    ])


def start_ws_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    server = websockets.serve(handler, "0.0.0.0", 8765)

    print("🌐 WebSocket running on ws://localhost:8765")

    loop.run_until_complete(server)
    loop.run_forever()