Adds e-mail login to CK.DB.User.UserPassword: the "Basic" provider also accepts the primary and validated e-mail address of a user (`CK.tActorEMail`) as its login identifier.

`UserPasswordEMailLoginTable` specializes `UserPasswordTable`: it becomes the single `IBasicAuthenticationProvider` of
the application.
