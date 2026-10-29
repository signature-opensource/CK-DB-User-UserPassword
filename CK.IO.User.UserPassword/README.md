# CK.IO.User.UserPassword

The Cris command surface of the password logins: definitions only, no implementation, so that a client (a TypeScript
front-end, a remote party) can depend on the contract without the database layer. The handlers are in
CK.DB.User.UserPassword.

## The commands

| Command | What | Level |
|---|---|---|
| [`ISetPasswordCommand`](ISetPasswordCommand.cs) | The user changes its own password (`ActorId` must be `UserId`). Update only: the user must already have a password. | `Critical` |
| [`ICreateOrUpdatePasswordCommand`](ICreateOrUpdatePasswordCommand.cs) | Sets the password of any user: provisioning, an administration command. Its [`CreationMode`](CreationMode.cs) (create or update, create only, update only), `WithCheckLogin` and `WithActualLogin` map to the `UCLMode` of `UserPasswordTable.CreateOrUpdatePasswordUserAsync`. | `Critical` |

Both are `ICommandCurrentCulture` (their messages are in the caller's language) and answer an
`ICrisBasicCommandResult`. [`IncomingValidators`](IncomingValidators.cs) checks them when they enter the System: a
positive `UserId`, a non empty `Password`, a defined `CreationMode`, and `ActorId` = `UserId` for `ISetPasswordCommand`
(resource names `User.InvalidUserId`, `User.InvalidPassword`, `User.InvalidCreationMode`, `User.ActorAndUserMustMatch`).

## Why the Critical level

Changing a password takes over an account: a session at the `Normal` level (or a party that calls on behalf of the
user, that never reaches `Critical` alone) must not be able to do it. The `Critical` level is a **recent login**: it is
checked when the command is received, like any authentication level.

A user interface must therefore expect a refusal when the login is not recent anymore and offer to log in again:

- with an Authentication Center (CK.AppIdentity.Cris.AuthCenter), the lifetime of the `Critical` level is configured
  per scheme ("AuthCenter:CriticalLifetime", "AuthCenter:CriticalLifetimes:&lt;scheme&gt;");
- with WebFrontAuth (CK.AspNet.Auth), a login reaches `Critical` only for the schemes listed in
  `WebFrontAuthOptions.SchemesCriticalTimeSpan`: without it, these commands are always refused.

## CK.IO.User.UserPassword.Reset

Its [`ISetPasswordCommand`](../CK.IO.User.UserPassword.Reset/ISetPasswordCommand.cs) extends this one with
`IsTemporary` (a temporary password, false by default: setting a password clears any temporary state).
