# CSE447 Lab Project

Develop/reuse existing system/app/webpage with the following features:

✅* The system must include Login and Registration modules for secure user authentication and account management.

✅* During registration, all user information (e.g., username, email, contact info) must be encrypted before storage and decrypted upon retrieval.

✅* Passwords must be hashed and salted before storage.

⏭️* A verification function must enforce two-step authentication, validating both primary credentials and a second factor before granting access. (Skipped: Vercel does not allow email sending)

✅* A Key Management Module must handle key generation, distribution, storage, and rotation.

✅* Users must be able to create, view, and edit posts and view or update profiles, with all data automatically encrypted before storage and decrypted on retrieval.

✅* All critical data (user information, posts, keys, etc.) must be stored in encrypted form to prevent plaintext access even if the database is compromised.

✅* Message Authentication Codes (MAC) such as CBC-MAC or HMAC must verify data integrity and detect unauthorized modifications.

✅* The system must **exclusively use asymmetric encryption algorithms** (e.g., RSA and ECC); symmetric encryption is not allowed.

✅* The system must implement **at least two different asymmetric encryption algorithms**. A single algorithm cannot be used for all encryption operations. For example, if **RSA** is used for one part of the encryption process, another asymmetric technique such as **ECC** must be used for a different part.

✅* Role-Based Access Control (RBAC) must define separate privileges for administrators and regular users to restrict sensitive operations.

✅* Secure session management must protect authentication tokens and prevent session hijacking.

✅ Note: All **encryption algorithms** must be implemented from scratch. Using built-in encryption functions or methods provided by frameworks such as Laravel, Flask, or similar is not allowed.