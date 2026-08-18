using CK.Core;
using CK.DB.Auth;
using CK.SqlServer;
using System.Threading;
using System.Threading.Tasks;

namespace CK.DB.User.UserPassword.Reset;

/// <summary>
/// Extends <c>CK.tUserPassword</c> with the <c>IsTemporary</c> bit brought by this package.
/// <para>
/// This is a plain <see cref="SqlTable"/> that targets the same physical table as
/// <see cref="UserPassword.UserPasswordTable"/> instead of specializing it: a real object has a single
/// <c>FinalImplementation</c>, so specializing <c>UserPasswordTable</c> would raise a class ambiguity
/// with any other package doing the same (<c>CK.DB.User.UserPassword.EMailLogin</c>) as well as an
/// interface ambiguity on <see cref="IBasicAuthenticationProvider"/>. This is the standard CK.DB table
/// extension pattern, see <c>CK.DB.User.NamedUser.NamedUserTable</c>.
/// </para>
/// <para>
/// The login and the regular password creation APIs stay on <see cref="UserPassword.UserPasswordTable"/>:
/// they call the procedure without the extension parameter, which defaults to null and therefore
/// preserves the current state.
/// </para>
/// </summary>
[SqlTable( "tUserPassword", Package = typeof( Package ) )]
[Versions( "1.0.0" )]
public abstract class UserPasswordResetTable : SqlTable
{
    // UserPasswordTable is required so that CK.tUserPassword is set up before the IsTemporary column
    // is added to it.
    void StObjConstruct( UserPassword.UserPasswordTable userPasswordTable )
    {
    }

    /// <summary>
    /// Gets the User password package: hashing must use the very same hasher as the base table.
    /// </summary>
    [InjectObject]
    public UserPassword.Package UserPasswordPackage { get; protected set; }

    /// <summary>
    /// Associates a PasswordUser to an existing user and sets whether its password is a temporary one.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="actorId">The acting actor identifier.</param>
    /// <param name="userId">The user identifier that must have a password.</param>
    /// <param name="password">The password to set. Can not be null nor empty.</param>
    /// <param name="mode">Optionnaly configures Create, Update only or WithLogin behavior.</param>
    /// <param name="isTemporary">
    /// True to flag the password as temporary: the user will have to choose a new one.
    /// False clears any previous temporary state.
    /// </param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The result.</returns>
    public Task<UCLResult> CreateOrUpdatePasswordUserAsync( ISqlCallContext ctx,
                                                            int actorId,
                                                            int userId,
                                                            string password,
                                                            UCLMode mode,
                                                            bool isTemporary,
                                                            CancellationToken cancellationToken = default )
    {
        Throw.CheckNotNullOrEmptyArgument( password );
        var hasher = UserPasswordPackage.CreatePasswordHasher();
        return PasswordUserUCLAsync( ctx,
                                     actorId,
                                     userId,
                                     hasher.HashPassword( password ),
                                     mode,
                                     loginFailureCode: null,
                                     isTemporary,
                                     cancellationToken );
    }

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
        => CreateOrUpdatePasswordUserAsync( ctx, actorId, userId, password, UCLMode.UpdateOnly, isTemporary, cancellationToken );

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
