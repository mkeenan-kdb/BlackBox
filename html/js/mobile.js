function onDeviceReady() {
    alert("Device is ready to use!");
    alert(device);
    socket.sendCmd("deviceInfo",device);
}
