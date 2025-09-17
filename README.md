# Vulnerable JWT Privilege Escalation Lab (in progress)

This lab demonstrates a critical privilege escalation vulnerability in a web application that arises from unsynchronized JWT claims. When a user's privileges are updated, the existing JWT is not properly invalidated or re-issued, allowing an attacker to exploit a timing window to elevate their role to Admin.

## Table of Contents

- [Overview](#overview)
- [Vulnerability Description](#vulnerability-description)
- [Setup Instructions](#setup-instructions)
- [Application Endpoints](#application-endpoints)
- [Exploitation Steps](#exploitation-steps)
- [Remediation](#remediation)
- [Disclaimer](#disclaimer)

## Overview

This is a simple web application with three user roles: **Admin**, **Supervisor**, and **Read-Only**.
- **Admin:** Full access, can manage users.
- **Supervisor:** Can perform specific privileged actions (e.g., approve reports).
- **Read-Only:** Can only view content.

User authentication is handled via JSON Web Tokens (JWTs). The vulnerability lies in how user role updates are handled in conjunction with active JWTs.

## Vulnerability Description

The application suffers from a privilege escalation vulnerability due to a lack of synchronization between the user's role stored in the backend database and the `role` claim within their active JWT.

When a user's profile is updated (e.g., changing their email, or in a simulated scenario, an Admin demoting another user's role), the backend database is updated, but the *existing* JWT held by the user is not immediately invalidated or re-issued with the new role.

If an attacker, who has been granted a lower privilege role (e.g., a "Read-Only" user whose role is about to be updated to "Admin" by a legitimate admin), makes a request using their old, lower-privilege JWT *after* their role has been updated in the database but *before* their JWT is refreshed, the backend *might* perform a database lookup for their role. However, if the JWT itself contains the role, and the application prioritizes the JWT claim over a fresh database lookup for every request, a critical race condition emerges.

**The exploit specifically targets a scenario where a lower-privilege user can initiate an "update profile" action (like changing their email). If the backend logic *temporarily* assigns them an "Admin" role during this update process (a common flaw in multi-step update flows, or if a bug exists where role updates are mishandled), and the JWT isn't immediately re-issued, the user's existing JWT, now backed by a database entry with "Admin" privileges, allows them to craft a new JWT (or reuse the old one in certain scenarios) that reflects the higher privilege.**

More practically, the vulnerability can be explained as:
1. A legitimate Admin initiates an action that *should* update a Read-Only user's role (e.g., from `Read-Only` to `Supervisor`).
2. Due to a bug, the `update_user_profile` function (or a similar process) *briefly* grants the user `Admin` privileges in the database while processing the update (e.g., during a complex transaction, or due to incorrect `UPDATE` statements).
3. The Read-Only user (the attacker), while their role is temporarily `Admin` in the database, quickly sends a request that forces the application to re-issue *their own* JWT, but now with `Admin` claims, *before* their role is reverted or correctly set to `Supervisor`.
4. This results in the attacker obtaining a JWT with `Admin` privileges, which persists until they log out and back in.

## Setup Instructions

This lab can be easily set up using Docker.

### Prerequisites

- Docker
- Docker Compose

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/vulnerable-jwt-lab.git
cd vulnerable-jwt-lab
