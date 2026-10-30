using CK.Auth;
using CK.Cris;

namespace CK.IO.User.UserPassword;

/// <summary>
/// The current user, that has no password yet (a user created by a remote login, a passkey only user), adds one: a new
/// sign-in method (the "Basic" scheme, with its user name). Create only: <see cref="ISetPasswordCommand"/> changes an
/// existing password.
/// <para>
/// Adding a login method requires the <see cref="ICommandAuthCritical">Critical</see> level (a recent login), and it is
/// refused while impersonating. An application that doesn't want its users to fall back to a password refuses this
/// command (an incoming validator of its own).
/// </para>
/// </summary>
public interface IAddPasswordCommand : ICommand<ICrisBasicCommandResult>, ICommandCurrentCulture, ICommandAuthCritical, ICommandAuthImpersonation
{
    /// <summary>
    /// Gets or sets the password to add.
    /// </summary>
    [Sensitive]
    string Password { get; set; }
}
