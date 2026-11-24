The Cris commands of the password logins: a user changes, adds or removes its own password, and an administration command creates or updates the password of any user.

`ISetPasswordCommand` (the user changes its own password), `IAddPasswordCommand` and `IRemovePasswordCommand` (the user
adds a password or removes it: a sign-in method) and `ICreateOrUpdatePasswordCommand` (provisioning) are definitions
only. They require the Critical authentication level (a recent login). The handlers are in CK.DB.User.UserPassword.

See the [README](https://github.com/signature-opensource/CK-DB-User-UserPassword/blob/stable/CK.IO.User.UserPassword/README.md).
