The password logins of the users: the `CK.tUserPassword` table of the password hashes (PBKDF2), the "Basic" login provider and the handlers of the commands of CK.IO.User.UserPassword.

Main types: `UserPasswordTable` (the `IBasicAuthenticationProvider`), `UserPasswordLoginProvider` and `Package`, with its
optional `IUserPasswordMigrator` that migrates the passwords of an external system on login.
