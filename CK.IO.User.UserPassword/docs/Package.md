The Cris commands of the password logins (definitions only): `ISetPasswordCommand` (the user changes its own password),
`IAddPasswordCommand` and `IRemovePasswordCommand` (the user adds a password or removes it: a sign-in method) and
`ICreateOrUpdatePasswordCommand` (provisioning). They require the Critical authentication level (a recent login).
The handlers are in CK.DB.User.UserPassword.
