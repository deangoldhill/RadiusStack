# RadiusStack

A complete, modern, containerized RADIUS authentication stack designed for ease of deployment, security, and extensive API-driven management. RadiusStack bundles FreeRADIUS, MariaDB, and a custom Node.js REST API inside a streamlined Docker Compose environment, paired with a sleek, responsive Web UI.

Useful for managing Wi-Fi access points, remote access, or network appliance logins, RadiusStack provides full control over users, usage plans, profile attributes, and feature riich monitoring and analytics.
Designed for security and simplicity. 

## Key Features
* **Modern Web Interface:** WebUI frontend for managing NAS clients, users, profiles, plans etc. Also view logs for all containers within the webui.
* **Full REST API:** The managment application is an API server. The Webui only interacts with the API and therefore doesn't have access to the backend database.
* **Advanced Security:** Supports Time-Based One-Time Passwords (TOTP) for radius users and Webui administrators
* **Intelligent Backups:** Export and safely restore JSON-based database configurations across version upgrades.
* **Automated Certificate Generation:** One-click custom SSL/EAP certificate generation or direct file uploads.
* **Live Analytics:** Monitor active sessions, view authentication/accounting logs, and detailed administration audit log.
* **High Availability:** Full config, object and session sync between members. See the wiki for more details. 

## Documentation

For full installation instructions, feature breakdowns, and management guides, please visit the **[RadiusStack Wiki](https://github.com/deangoldhill/RadiusStack/wiki)**.

---

<img width="1888" height="962" alt="image" src="https://github.com/user-attachments/assets/14cebbd2-aaed-418a-afa7-97c7669fe869" />
<img width="1700" height="688" alt="image" src="https://github.com/user-attachments/assets/58238fa6-dbcd-4f00-9848-3a1b7f977b02" />
<img width="1685" height="323" alt="image" src="https://github.com/user-attachments/assets/f0b15a8b-02dc-4c73-808f-14fdeb20eafa" />
<img width="1689" height="464" alt="image" src="https://github.com/user-attachments/assets/5ff147ed-9e6d-4bda-bd51-8bcb9209d36f" />
<img width="1665" height="517" alt="image" src="https://github.com/user-attachments/assets/c788d08b-84ff-425b-92f6-1523e35312bb" />
<img width="1688" height="923" alt="image" src="https://github.com/user-attachments/assets/e404f667-894f-4ed5-816a-1bf66eff2447" />
<img width="1691" height="681" alt="image" src="https://github.com/user-attachments/assets/b12d2c6f-e188-4994-9f1b-e940083abcca" />
<img width="1699" height="906" alt="image" src="https://github.com/user-attachments/assets/7e5a2d5a-9a82-4cf4-a19c-950fd99c7556" />

















