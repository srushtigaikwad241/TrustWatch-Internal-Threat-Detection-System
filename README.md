# TrustWatch – Internal Threat Detection & Prevention System

**Monitor activity. Identify suspicious behavior. Improve security awareness.**

TrustWatch is a cybersecurity project designed to help monitor user activities and identify potentially suspicious behavior within a system. It aims to provide a centralized interface for activity monitoring, security alerts, and incident management.

The project is being developed as part of my Diploma in Computer Engineering studies at Government Polytechnic Pune.

## Overview

Insider threats can arise when authorized accounts or users perform unusual or unauthorized activities. TrustWatch aims to help administrators review activity records, recognize suspicious patterns, and take appropriate security actions.

## Key Features

- **User Activity Monitoring:** Record and review relevant user activities.
- **Suspicious Activity Detection:** Identify potentially unusual behavior based on implemented detection rules.
- **Security Alerts:** Display alerts for activities that require attention.
- **Incident Management:** Support the review and tracking of security-related events.
- **Access Control:** Support authorized administrative actions where implemented.
- **Activity Logs:** Maintain records that can help with security reviews.
- **Admin Dashboard:** Provide a centralized view of available security information.

*Note: The availability of each feature depends on the current implementation of the project.*

## Technology Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **Database:** MySQL
- **Development Tools:** Visual Studio Code, Git, GitHub

## Project Architecture

1. The user interacts with the web interface.
2. The Flask backend processes application requests.
3. MySQL stores the configured application data and activity records.
4. The detection logic evaluates relevant activity data.
5. The dashboard displays available logs, alerts, and incident information.

## Project Structure

```text
TrustWatch-Internal-Threat-Detection-System/
├── app.py
├── templates/
├── static/
│   ├── css/
│   ├── js/
│   └── images/
├── database/
├── requirements.txt
├── .gitignore
└── README.md
```

*Update this structure to match the actual folders and files in your repository.*

## Getting Started

### Prerequisites

- Python installed
- MySQL Server installed and running
- Visual Studio Code or another code editor
- Git

### Installation

**1. Clone the repository**

```bash
git clone https://github.com/srushtigaikwad241/TrustWatch-Internal-Threat-Detection-System.git
```

**2. Open the project directory**

```bash
cd TrustWatch-Internal-Threat-Detection-System
```

**3. Create a virtual environment**

```bash
python -m venv venv
```

Activate it on Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

**4. Install dependencies**

If `requirements.txt` exists:

```bash
pip install -r requirements.txt
```

Otherwise, install the packages listed in your project's actual dependency configuration.

**5. Configure the database**

- Start your MySQL server.
- Create the required database.
- Configure the database connection using your local environment settings.
- Run the SQL schema or setup script provided with the project.

Do not upload database passwords, secret keys, or other credentials to GitHub.

**6. Start the application**

If `app.py` is the Flask entry point:

```bash
python app.py
```

Open the local URL printed by Flask in your browser. A common development address is `http://127.0.0.1:5000`, but use the address shown by your application.

## Security and Responsible Use

TrustWatch is an educational project for learning about activity monitoring and security incident management. Test it only in environments and with accounts you are authorized to use.

The system should not be considered a production-grade security solution without appropriate testing, validation, and security review.

## Future Improvements

- Improve suspicious-activity detection.
- Add richer alert filtering and reporting.
- Strengthen authentication and role-based access control.
- Improve audit logging and incident history.
- Add automated testing and deployment documentation.
- Evaluate detection accuracy using suitable test data.

## Learning Outcomes

Through this project, I am developing practical experience with Python, Flask, MySQL, web development, database integration, and cybersecurity concepts.

## Author

**Srushti Gaikwad**

Diploma in Computer Engineering – Third Year  
Government Polytechnic Pune

GitHub: [@srushtigaikwad241](https://github.com/srushtigaikwad241)

---

*TrustWatch is an educational project under development.*
