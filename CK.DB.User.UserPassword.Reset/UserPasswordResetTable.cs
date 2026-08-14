using CK.Core;
using CK.DB.Auth;
using CK.SqlServer;
using System.Threading;
using System.Threading.Tasks;

namespace CK.DB.User.UserPassword.Reset;

/// <summary>
/// Specializes <see cref="UserPassword.UserPasswordTable"/> to expose the <c>IsTemporary</c>
/// bit brought by this package.
/// <para>
/// The base <see cref="UserPassword.UserPasswordTable.SetPasswordAsync"/> is left untouched: it
/// calls the procedure without the extension parameter, which defaults to null and therefore
/// preserves the current state.
/// </para>
/// </summary>
[SqlTable( "tUserPassword", Package = typeof( Package ) )]
[Versions( "1.0.0" )]
public abstract class UserPasswordResetTable : UserPassword.UserPasswordTable
{
    /// <summary>
    /// Changes the password of a PasswordUser and sets whether it is a temporary one.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="actorId">The acting actor identifier.</param>
    /// <param name="userId">The user identifier that must have a new password.</param>
    /// <param name="password">The new password to set. Can not be null nor empty.</param>
    /// <param name="isTemporary">
    /// True to flag the password as temporary: the user will have to choose a new one.
    /// False clears any previous temporary state.
    /// </param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The awaitable.</returns>
    public Task SetPasswordAsync( ISqlCallContext ctx,
                                  int actorId,
                                  int userId,
                                  string password,
                                  bool isTemporary,
                                  CancellationToken cancellationToken = default )
    {
        Throw.CheckNotNullOrEmptyArgument( password );
        var hasher = UserPasswordPackage.CreatePasswordHasher();
        return PasswordUserUCLAsync( ctx,
                                     actorId,
                                     userId,
                                     hasher.HashPassword( password ),
                                     UCLMode.UpdateOnly,
                                     loginFailureCode: null,
                                     isTemporary,
                                     cancellationToken );
    }

    /// <summary>
    /// Low level stored procedure that carries the <c>IsTemporary</c> extension parameter.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="actorId">The acting actor identifier.</param>
    /// <param name="userId">The user identifier.</param>
    /// <param name="pwdHash">The raw hash (no more than 64 bytes).</param>
    /// <param name="mode">Configures Create, Update and/or WithLogin behaviors.</param>
    /// <param name="loginFailureCode">Login failure code.</param>
    /// <param name="isTemporary">
    /// Null to leave the current state untouched, true or false to set it.
    /// </param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The operation result.</returns>
    [SqlProcedure( "transform:sUserPasswordUCL" )]
    protected abstract Task<UCLResult> PasswordUserUCLAsync( ISqlCallContext ctx,
                                                             int actorId,
                                                             int userId,
                                                             byte[]? pwdHash,
                                                             UCLMode mode,
                                                             int? loginFailureCode,
                                                             bool? isTemporary,
                                                             CancellationToken cancellationToken = default );
}
