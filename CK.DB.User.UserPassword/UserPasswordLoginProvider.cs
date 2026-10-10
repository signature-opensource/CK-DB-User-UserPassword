using CK.Core;
using CK.DB.Auth;
using CK.IO.Authentication.Basic;
using CK.SqlServer;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CK.DB.User.UserPassword;

/// <summary>
/// The "Basic" <see cref="ILoginProvider"/>: a user name and a password, checked by the <see cref="UserPasswordTable"/>.
/// Its payload is the <see cref="IBasicLoginCommand"/> itself (like the "Weak" provider and its command): the Basic
/// scheme exists only with this package ("Package First").
/// <para>
/// The payload holds the password: it is never logged (a Poco's ToString may print its JSON).
/// </para>
/// </summary>
public sealed class UserPasswordLoginProvider : ILoginProvider
{
    /// <summary>
    /// The "Basic" scheme (and provider name).
    /// </summary>
    public const string Scheme = "Basic";

    readonly UserPasswordTable _table;
    readonly IAuthenticationDatabaseService _db;

    /// <summary>
    /// Initializes a new <see cref="UserPasswordLoginProvider"/>.
    /// </summary>
    /// <param name="table">The user password table.</param>
    /// <param name="db">The authentication database service.</param>
    public UserPasswordLoginProvider( UserPasswordTable table, IAuthenticationDatabaseService db )
    {
        _table = table;
        _db = db;
    }

    /// <inheritdoc />
    public IReadOnlyCollection<string> ProviderNames => [Scheme];

    /// <summary>
    /// Throws: the payload of the Basic provider is the <see cref="IBasicLoginCommand"/>, it cannot be created here.
    /// </summary>
    /// <param name="scheme">The scheme.</param>
    /// <returns>Never.</returns>
    public object CreatePayload( string scheme ) => throw new ArgumentException( $"The payload of the '{Scheme}' provider is the IBasicLoginCommand: it cannot be created.", nameof( scheme ) );

    /// <inheritdoc />
    public async ValueTask<ActorLoginResult> LoginAsync( IActivityMonitor monitor, string scheme, object payload, bool actualLogin = true )
    {
        if( payload is not IBasicLoginCommand cmd )
        {
            // Never the payload's text in the message: it may hold a password.
            throw new ArgumentException( $"The payload of the '{Scheme}' provider must be a IBasicLoginCommand, not a '{payload?.GetType().Name}'.", nameof( payload ) );
        }
        using var ctx = new SqlStandardCallContext( monitor );
        var r = await _table.LoginUserAsync( ctx, cmd.UserName, cmd.Password, actualLogin ).ConfigureAwait( false );
        return await _db.ToUserLoginResultAsync( ctx, r ).ConfigureAwait( false );
    }
}
