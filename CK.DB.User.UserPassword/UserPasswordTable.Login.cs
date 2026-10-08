using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using CK.IO.Authentication.Basic;
using System.Threading.Tasks;

namespace CK.DB.User.UserPassword;

public abstract partial class UserPasswordTable
{
    /// <summary>
    /// Handles the <see cref="IBasicLoginCommand"/> of the new authentication (CK.AuthenticationInfo): the session is opened
    /// by the authentication center with a <see cref="BasicLoginPayload"/> (the "Basic" provider of CK.DB.Auth is this
    /// table). A package that implements an authentication provider handles its login commands.
    /// <para>
    /// The password is <c>[Sensitive]</c>: when the command is relayed by a front to a remote authentication center, it is
    /// encrypted for the authentication center and decrypted there, before this handler.
    /// </para>
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="opener">The session opener.</param>
    /// <returns>The session result.</returns>
    [CommandHandler]
    public virtual ValueTask<ISessionResult> HandleBasicLoginAsync( IActivityMonitor monitor, IBasicLoginCommand cmd, IAuthenticationSessionOpener opener )
    {
        return opener.OpenSessionAsync( monitor, cmd, BasicLoginPayload.Scheme, new BasicLoginPayload( cmd.UserName, cmd.Password ), cmd.RememberMe );
    }
}
