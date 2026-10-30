using CK.Auth;
using CK.Cris;

namespace CK.IO.User.UserPassword;

/// <summary>
/// The current user removes its password: it can no more log in with the "Basic" scheme (a user that migrates to a
/// better method: a passkey, a remote provider...).
/// <para>
/// Removing a login method requires the <see cref="ICommandAuthCritical">Critical</see> level (a recent login), and it
/// is refused while impersonating. The "last login method" rule applies: the password is not removed when the user has
/// no other way to log in (no other row in <c>CK.vUserAuthProvider</c>).
/// </para>
/// </summary>
public interface IRemovePasswordCommand : ICommand<ICrisBasicCommandResult>, ICommandCurrentCulture, ICommandAuthCritical, ICommandAuthImpersonation
{
}
