# Cloud-Based Secure File Management System

## Overview
This project is a secure file management web application developed using ASP.NET Core. It enables users to safely upload, manage, and access files with role-based access control. The system integrates with cloud storage (AWS S3) to securely store files and ensures sensitive data is fully protected.

## Features
- **User Authentication & Authorization:** Secure login system with role-based access control.
- **File Upload & Download:** Users can upload files to cloud storage and download them securely.
- **Admin Dashboard:** Manage users, monitor uploads/downloads, view logs, and generate reports.
- **Logging & Monitoring:** Track user activity and maintain detailed audit trails.
- **Secure Cloud Storage:** Files are stored on AWS S3 with proper security policies.
- **Error Handling:** Graceful handling of errors with custom error pages.
- **Responsive UI:** Modern and responsive interface built with Bootstrap.

## Technologies Used
- **Backend:** ASP.NET Core 8.0, C#
- **Frontend:** HTML, CSS, Bootstrap
- **Database:** SQL Server (or another relational database)
- **Cloud Storage:** AWS S3
- **Logging:** Built-in ASP.NET Core logging
- **Development Tools:** Visual Studio, Git, PowerShell

## Project Structure
- `Controllers/` – Handles HTTP requests and routing.
- `Models/` – Contains data models and view models.
- `Views/` – Razor views for UI rendering.
- `Services/` – Implements business logic, including AWS S3 integration.
- `wwwroot/` – Static files such as CSS, JS, and images.
- `Program.cs` – Application entry point.
- `SecureFileUploadPortal.sln` – Visual Studio solution file.

## Usage
1. **Register or Login:** Users can create an account or log in with existing credentials.  
2. **Upload Files:** Navigate to the file upload section and select files to upload to S3.  
3. **Admin Management:** Admins can view user activity, manage users, and download logs or reports.  
4. **File Access:** Users can view and download files they have permission to access.

## Security Considerations
- Passwords are securely hashed and stored.  
- Sensitive configuration files (e.g., `appsettings.json`) are excluded from Git.  
- Role-based authorization prevents unauthorized access.  
- Cloud storage uses secure credentials and strict access policies.  
