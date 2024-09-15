import frida
import sys

def on_message(message, data):
    """
    Callback function to handle messages from the Frida script.
    """
    if message['type'] == 'send':
        print(f"[FRIDA] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[FRIDA ERROR] {message['stack']}")

def start_network_monitoring(package_name):
    """
    Attaches to a running process on the mobile device and monitors network traffic.
    
    :param package_name: The package name of the app to monitor.
    """
    try:
        device = frida.get_usb_device()
        pid = device.spawn([package_name])
        session = device.attach(pid)

        script = session.create_script("""
        // Frida script to monitor network traffic
        Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
            onEnter: function(args) {
                send("Connect called with socket descriptor: " + args[0]);
            }
        });
        """)
        script.on('message', on_message)
        script.load()

        print(f"Monitoring network traffic for {package_name}...")
        device.resume(pid)
        sys.stdin.read()
    except Exception as e:
        print(f"Failed to monitor network traffic: {e}")

