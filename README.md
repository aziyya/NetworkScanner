# **🛜 Network Scanner Web 🛜**  
This web application allows you to scan and display nearby Wi-Fi networks along with their signal strength, security type, and other details.  
It is designed to be used on Windows systems, utilizing the netsh command to scan for available networks.  

## **Features**  
- Detects and lists available Wi-Fi networks and displays details such as SSID, signal strength, MAC address, security type, encryption method, and channel.  
- Displays a bar chart showing the signal strength of nearby networks.  
- Visualizes the distribution of network security types (Secure, Moderate, Weak, Insecure) in a doughnut chart.  

## **Requirements**  
Python 3.x  
Flask  
Windows Operating System (the netsh command used to scan Wi-Fi networks is only available on Windows)  
