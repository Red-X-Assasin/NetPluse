Run NetPulse
    Open a terminal in c:\Users\User\Downloads\NetPulse
Install dependencies if not already:
    C:/Python314/python.exe -m pip install -r requirements.txt
Start the app:
    C:/Python314/python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
Then open:
http://127.0.0.1:8000/

Note: packet capture usually needs admin/root privileges on Windows. If the UI starts but capture fails, run the terminal as Administrator.
