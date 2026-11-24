Adds temporary passwords to CK.DB.User.UserPassword: an `IsTemporary` bit on `CK.tUserPassword`, set by the SetPassword command and exposed on the user profile as `IsTemporaryPassword`.

Main types: `UserPasswordResetTable` and `SetPasswordCommandHandler`, that handles the `ISetPasswordCommand` extended by
CK.IO.User.UserPassword.Reset.
